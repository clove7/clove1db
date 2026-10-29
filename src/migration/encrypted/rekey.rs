//! Moving the protected fields of a database from one set of keys to another, while the whole
//! database is copied (see `convert` and `history`).
//!
//! Every value that can be made again from what is stored is: a sealed value is opened with the old
//! keys and sealed with the new ones, and the fingerprints beside it are made again. A verification
//! hash and a search fingerprint cannot be made again (the secret and the text are not stored), so
//! they are copied as they are, and when the roots change the key each was made with is carried over,
//! sealed under the new roots, in the table `__carried_keys`. The description of the tables
//! (`_clove_meta`) gets the settings checks the new keys make. Nothing here reads a value into a
//! message, a name or an event.
use super::{convert::MainHooks, history::HistoryHooks};
use crate::{
    crypto::{LockedDataKey, LockedKey, ct_eq},
    field_crypto::{
        FieldKeys, Method, Row, SealedSpec, apply_checks, carried, keystore, open_stored, read_stored,
        reseal_history_doc, reseal_row, settings_checks,
    },
    metadata::{
        store::read_meta,
        types::{CloveMeta, META_TABLE},
    },
    units::{ClError, Result},
};
use redb::{Database, ReadableDatabase, ReadableTable};
use std::sync::Arc;

/// The table of the keys carried over to new roots (see `field_crypto::carried`).
const CARRIED: &str = "__carried_keys";
/// The table that holds the locked data key of a database whose protected fields have keys of their
/// own (see `field_crypto::keystore`).
const FIELD_KEYS: &str = "__field_keys";

/// The lock of the data key of the new file: kept in the keys file, and also in the main file when
/// the protected fields have keys of their own and the keys file is next to it.
pub(crate) struct NewLock {
    pub locked: LockedDataKey,
    pub in_main: bool,
}

/// The locked data key a main file keeps for its protected fields, if it keeps one.
pub(crate) fn read_locked(from: &impl ReadableDatabase) -> Result<Option<LockedDataKey>> {
    let read = from.begin_read().map_err(io)?;
    let table = match read.open_table(keystore::TABLE) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(other) => return Err(other.into()),
    };
    let (Some(read_lock), Some(search_lock)) = (table.get("read").map_err(io)?, table.get("search").map_err(io)?) else {
        return Ok(None);
    };
    Ok(Some(LockedDataKey {
        read: LockedKey::from_bytes(read_lock.value().to_vec()),
        search: LockedKey::from_bytes(search_lock.value().to_vec()),
    }))
}

fn bad(why: &str) -> ClError {
    ClError::MigrationError(why.to_string())
}

fn io(e: impl std::fmt::Display) -> ClError {
    ClError::MigrationError(e.to_string())
}

/// A table with protected fields as the program declares it.
#[derive(Clone)]
pub(crate) struct Declared {
    pub table: String,
    pub specs: &'static [SealedSpec],
}

struct Resolved {
    table: String,
    table_id: String,
    specs: &'static [SealedSpec],
}

/// The change of keys of one database: the old and the new keys, the tables they apply to, and the
/// carried keys of the new file.
pub(crate) struct Rekey {
    old: Arc<FieldKeys>,
    new: Arc<FieldKeys>,
    tables: Vec<Resolved>,
    /// The table `__carried_keys` of the old file existed.
    had_carried: bool,
    /// The whole table of the new file, by entry name.
    written: Vec<(String, Vec<u8>)>,
    lock: NewLock,
}

/// The entries of `__carried_keys` of the old file: `None` when the file has no such table.
fn read_entries(from: &impl ReadableDatabase) -> Result<Option<Vec<(String, Vec<u8>)>>> {
    let read = from.begin_read().map_err(io)?;
    let table = match read.open_table(carried::TABLE) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(other) => return Err(other.into()),
    };
    let mut out = Vec::new();
    for row in table.iter().map_err(io)? {
        let (name, stored) = row.map_err(io)?;
        out.push((name.value().to_string(), stored.value().to_vec()));
    }
    Ok(Some(out))
}

/// The tables of the file that have protected fields, as (name, identity). If there are any, every
/// one of them is declared and each declaration is what the file holds (anything else is refused,
/// before anything is written).
pub(crate) fn check(from: &impl ReadableDatabase, declared: &[Declared]) -> Result<Vec<(String, String)>> {
    let meta = read_meta(from)?.ok_or_else(|| bad("the file has no description of its tables"))?;
    Ok(resolve(&meta, declared)?.into_iter().map(|t| (t.table, t.table_id)).collect())
}

fn resolve(meta: &CloveMeta, declared: &[Declared]) -> Result<Vec<Resolved>> {
    let mut tables = Vec::new();
    for table in &meta.tables {
        let Some(found) = declared.iter().find(|d| d.table == table.name) else {
            if table.sealed.is_empty() {
                continue;
            }
            return Err(bad("a table has protected fields that the program did not declare; nothing was changed"));
        };
        let table_id = table.table_id.clone().ok_or_else(|| bad("a table with protected fields has no identity; nothing was changed"))?;
        let mut stored: Vec<u32> = table.sealed.iter().map(|f| f.id).collect();
        let mut given: Vec<u32> = found.specs.iter().map(|s| s.id).collect();
        stored.sort_unstable();
        given.sort_unstable();
        if stored != given {
            return Err(bad("the protected fields declared for a table are not the ones the file holds; nothing was changed"));
        }
        tables.push(Resolved { table: table.name.clone(), table_id, specs: found.specs });
    }
    if declared.iter().any(|d| !meta.tables.iter().any(|t| t.name == d.table)) {
        return Err(bad("a table declared with protected fields is not in the file; nothing was changed"));
    }
    Ok(tables)
}

impl Rekey {
    /// Read the old file, take the carried keys it has, and work out the ones the new roots need.
    /// Writes nothing.
    pub(crate) fn plan(
        from: &impl ReadableDatabase,
        declared: &[Declared],
        old: Arc<FieldKeys>,
        new: Arc<FieldKeys>,
        lock: NewLock,
    ) -> Result<Self> {
        let meta = read_meta(from)?.ok_or_else(|| bad("the file has no description of its tables"))?;
        let tables = resolve(&meta, declared)?;
        // the carried keys the old file has are in place in `old` before anything is derived from it
        let entries = read_entries(from)?;
        let had_carried = entries.is_some();
        let old_entries = entries.unwrap_or_default();
        for (name, stored) in &old_entries {
            let (table_id, field) = name.rsplit_once(':').ok_or_else(|| bad("an entry of the carried keys has a name that is not one"))?;
            let field_id: u32 = field.parse().map_err(|_| bad("an entry of the carried keys has a name that is not one"))?;
            if let Some((kind, key)) = carried::open_entry(&old, table_id, field_id, stored)? {
                old.install_carried(kind, table_id, field_id, key);
            }
        }
        let mut items = Vec::new();
        for t in &tables {
            items.extend(carried::carry_plan(&old, &new, &t.table_id, t.specs)?);
        }
        // the new roots use the carried keys from here on (the checks of the settings need them)
        carried::install_items(&new, &items);
        let written = carried::next_table(&old, &new, &old_entries, &items)?;
        Ok(Self { old, new, tables, had_carried, written, lock })
    }

    /// The lock of the data key of the new file.
    pub(crate) fn lock(&self) -> &NewLock {
        &self.lock
    }

    /// The keys the new file was made with (the carried ones in place).
    pub(crate) fn new_keys(&self) -> &FieldKeys {
        &self.new
    }

    /// The keys of the old file and of the new one, to seal and open attachments with.
    pub(crate) fn both_keys(&self) -> (Arc<FieldKeys>, Arc<FieldKeys>) {
        (self.old.clone(), self.new.clone())
    }

    /// Whether the new file gets the table of carried keys.
    fn writes_carried(&self) -> bool {
        self.had_carried || !self.written.is_empty()
    }

    fn resolved(&self, table: &str) -> Option<&Resolved> {
        self.tables.iter().find(|t| t.table == table)
    }

    /// The new description: every protected field of the declared tables has the check the new keys
    /// make.
    fn remake_meta(&self, old: &[u8]) -> Result<Vec<u8>> {
        let mut meta: CloveMeta = serde_json::from_slice(old).map_err(|_| bad("the description of the tables cannot be read"))?;
        for t in &self.tables {
            let checks = settings_checks(&self.new, &t.table_id, t.specs)?;
            let entry = meta
                .tables
                .iter_mut()
                .find(|m| m.name == t.table)
                .ok_or_else(|| bad("a declared table is not in the description"))?;
            apply_checks(&mut entry.sealed, &checks);
        }
        serde_json::to_vec(&meta).map_err(io)
    }

    /// The check of one row of a declared table: every protected value opens to the same value with
    /// the new keys as with the old, and everything else is the very text it was.
    fn check_row(&self, t: &Resolved, key: &str, old: &[u8], new: &[u8]) -> Result<()> {
        let (a, b) = (Row::parse(old)?, Row::parse(new)?);
        let mut changed: Vec<&str> = Vec::new();
        for spec in t.specs {
            if matches!(spec.method, Method::Hash | Method::SearchPrint) {
                continue;
            }
            changed.push(spec.key);
            let (Some(x), Some(y)) = (a.get(spec.key), b.get(spec.key)) else {
                return Err(bad("a row lost a protected field; nothing was changed"));
            };
            let before = open_stored(&self.old, &t.table_id, spec.id, key, &read_stored(x)?)?;
            let after = open_stored(&self.new, &t.table_id, spec.id, key, &read_stored(y)?)?;
            if !ct_eq(before.as_bytes(), after.as_bytes()) {
                return Err(bad("a protected value is not the same after the change; nothing was changed"));
            }
        }
        if !a.same_but(&b, &changed) {
            return Err(bad("a row holds other data than it did; nothing was changed"));
        }
        Ok(())
    }

    /// The hooks for the history file.
    pub(crate) fn history(&self) -> History<'_> {
        History(self)
    }
}

impl MainHooks for Rekey {
    fn changes(&self, table: &str) -> bool {
        table == META_TABLE || self.resolved(table).is_some()
    }

    fn map_row(&mut self, table: &str, key: &str, old: &[u8]) -> Result<Option<Vec<u8>>> {
        if table == META_TABLE {
            return Ok(Some(self.remake_meta(old)?));
        }
        let Some(t) = self.resolved(table) else { return Ok(None) };
        Ok(Some(reseal_row(&self.old, &self.new, &t.table_id, t.specs, key, old)?))
    }

    fn extra_tables(&mut self, to: &Database) -> Result<()> {
        if !self.writes_carried() && !self.lock.in_main {
            return Ok(());
        }
        let tx = to.begin_write().map_err(io)?;
        if self.writes_carried() {
            carried::write_all(&tx, &self.written)?;
        }
        if self.lock.in_main {
            keystore::write(&tx, &self.lock.locked)?;
        }
        tx.commit().map_err(io)?;
        Ok(())
    }

    fn extra_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        if self.writes_carried() {
            names.push(CARRIED.to_string());
        }
        if self.lock.in_main {
            names.push(FIELD_KEYS.to_string());
        }
        names
    }

    fn replaces(&self, table: &str) -> bool {
        table == CARRIED || table == FIELD_KEYS
    }

    fn verify_row(&mut self, table: &str, key: &str, old: &[u8], new: &[u8]) -> Result<()> {
        if table == META_TABLE {
            // the new description is the old one with the checks the new keys make, and nothing else
            let again = self.remake_meta(old)?;
            let (x, y): (serde_json::Value, serde_json::Value) = (
                serde_json::from_slice(&again).map_err(io)?,
                serde_json::from_slice(new).map_err(io)?,
            );
            return if x == y { Ok(()) } else { Err(bad("the description of the tables is not what it should be")) };
        }
        let t = self.resolved(table).ok_or_else(|| bad("a row of a table the change does not know"))?;
        self.check_row(t, key, old, new)
    }

    fn verify_extra(&mut self, to: &Database) -> Result<()> {
        let read = to.begin_read().map_err(io)?;
        let found: Vec<(String, Vec<u8>)> = match read.open_table(carried::TABLE) {
            Ok(table) => {
                let mut v = Vec::new();
                for row in table.iter().map_err(io)? {
                    let (k, s) = row.map_err(io)?;
                    v.push((k.value().to_string(), s.value().to_vec()));
                }
                v
            }
            Err(redb::TableError::TableDoesNotExist(_)) => Vec::new(),
            Err(other) => return Err(other.into()),
        };
        if self.writes_carried() && found != self.written {
            return Err(bad("the carried keys in the new file are not the ones that were made"));
        }
        if !self.writes_carried() && !found.is_empty() {
            return Err(bad("the new file holds carried keys the change did not make"));
        }
        // the lock of the new file is the one that was made: the keys of the new file open with it
        match (read_locked(to)?, self.lock.in_main) {
            (Some(stored), true) if stored == self.lock.locked => {}
            (None, false) => {}
            _ => return Err(bad("the lock of the data key in the new file is not the one that was made")),
        }
        // every entry of the new table opens with the new keys, to the key that was meant
        for (name, stored) in &found {
            let (table_id, field) = name.rsplit_once(':').ok_or_else(|| bad("a carried key has a name that is not one"))?;
            let field_id: u32 = field.parse().map_err(|_| bad("a carried key has a name that is not one"))?;
            carried::open_entry(&self.new, table_id, field_id, stored)?;
        }
        Ok(())
    }
}

/// [`Rekey`] for the history file: the saved versions of a declared table.
pub(crate) struct History<'a>(&'a Rekey);

impl HistoryHooks for History<'_> {
    fn changes(&self, table: &str) -> bool {
        self.0.resolved(table).is_some()
    }

    fn map_row(&mut self, table: &str, _key: &str, old: &[u8]) -> Result<Option<Vec<u8>>> {
        let Some(t) = self.0.resolved(table) else { return Ok(None) };
        Ok(Some(reseal_history_doc(&self.0.old, &self.0.new, &t.table_id, t.specs, old)?))
    }

    fn verify_row(&mut self, table: &str, _key: &str, old: &[u8], new: &[u8]) -> Result<()> {
        use crate::backup::codec::decode_record;
        let t = self.0.resolved(table).ok_or_else(|| bad("a record of a table the change does not know"))?;
        let unreadable = |_| bad("a record of the backup history cannot be read");
        let (a, b) = (decode_record("", "", old).map_err(unreadable)?, decode_record("", "", new).map_err(unreadable)?);
        if a.key != b.key {
            return Err(bad("a record of the backup history names another row"));
        }
        match (&a.data, &b.data) {
            (None, None) => Ok(()),
            (Some(x), Some(y)) => self.0.check_row(t, &a.key, x, y),
            _ => Err(bad("a record of the backup history lost or gained its data")),
        }
    }
}

/// The table of a declared type, as `T::SEALED` gives its fields.
pub(crate) fn declare<T: crate::field_crypto::SealedFields>(table: &str) -> Declared {
    Declared { table: table.to_string(), specs: T::SEALED }
}
