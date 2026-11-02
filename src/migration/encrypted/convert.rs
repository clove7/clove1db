//! The tables of a database's main file: which there are, what each becomes in the new file, the
//! copy, and the check that nothing was left behind.
//!
//! Every table of the old file is either copied, rebuilt from the new rows, or left out on purpose
//! (the change log and its table images are written again). A table that is none of these is not
//! guessed at: planning stops with an error before any file is touched.
use super::rows::{
    BatchLimits, Copied, copy_bytes_table, copy_bytes_table_as, copy_bytes_to_bytes, copy_bytes_to_text,
    copy_number_keyed_bytes, io,
};
use crate::journal::{CHANGES, CONSUMERS, ChangeKind, SEQ, put_number};
use crate::metadata::store::read_meta;
use crate::metadata::types::META_TABLE;
use crate::units::{ClError, Result};
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle};

const LAST_WRITE: &str = "__lastwrite";
const UNIQUE_KEYS: &str = "__unique_keys";
const UNIQUE_ROWS: &str = "__unique_rows";
/// Small tables of text keys and byte values that are copied as they are.
const PLAIN_SYSTEM: [&str; 6] =
    ["__unique_definitions", "__id_contracts", "__blob_refs", "__field_keys", "__inx_catalog_meta", "__carried_keys"];
/// The durable list of the indexes the program declared. The index file itself is not copied: it
/// is built again from this list when the database opens.
const INDEX_CATALOG: &str = "__inx_catalog";
const INDEXER: &str = "__indexer";
const RESET_PREFIX: &str = "__reset_";

/// What a table of the old file becomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// The rows of a registered table: copied unchanged.
    User,
    /// A small system table: copied unchanged.
    System,
    /// The registered readers of the change log: copied, without the one the library keeps for its
    /// own indexes (it registers itself again and the indexes are built again).
    Consumers,
    /// The counters of the change log: copied, then moved on past the new entries.
    Seq,
    UniqueKeys,
    UniqueRows,
    /// The catalog of the declared indexes: copied.
    Catalog,
    /// When each row was last written: rebuilt from the new rows.
    LastWrite,
    /// The change log: written again (one `TableReset` for each table).
    Changes,
    /// The image of a table that a `TableReset` of the old log points to: dropped with the old log.
    Snapshot,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Item {
    pub name: String,
    pub kind: Kind,
    pub entries: u64,
}

/// Every table of the old file and what happens to it.
#[derive(Clone, Debug)]
pub(crate) struct Plan {
    pub items: Vec<Item>,
    /// The registered tables, in the order of their description.
    pub user_tables: Vec<String>,
}

fn unknown(name: &str) -> ClError {
    ClError::MigrationError(format!(
        "the file holds a table this version does not know how to move ({name}); nothing was changed"
    ))
}

fn entries(read: &redb::ReadTransaction, name: &str, kind: Kind) -> Result<u64> {
    let n = match kind {
        Kind::User | Kind::System | Kind::Consumers | Kind::Seq | Kind::Snapshot => {
            read.open_table(TableDefinition::<&str, &[u8]>::new(name)).map_err(io)?.len().map_err(io)?
        }
        Kind::UniqueKeys => read.open_table(TableDefinition::<&[u8], &str>::new(name)).map_err(io)?.len().map_err(io)?,
        Kind::UniqueRows => read.open_table(TableDefinition::<&[u8], &[u8]>::new(name)).map_err(io)?.len().map_err(io)?,
        Kind::LastWrite => read.open_table(TableDefinition::<&[u8], u64>::new(name)).map_err(io)?.len().map_err(io)?,
        Kind::Changes | Kind::Catalog => {
            read.open_table(TableDefinition::<u64, &[u8]>::new(name)).map_err(io)?.len().map_err(io)?
        }
    };
    Ok(n)
}

/// What a change of the rows needs to do inside the copy of the main file. The copy itself stays
/// in this module (batches, the log, the rebuilt tables); a change only says which tables it
/// rewrites and rewrites their rows. The bytes of a row are given and returned as they are stored:
/// nothing here parses them, so a field the change does not touch stays byte for byte.
pub(crate) trait MainHooks {
    /// Whether this table (a registered one, or `_clove_meta`, or `__field_keys`, ...) is rewritten.
    fn changes(&self, _table: &str) -> bool {
        false
    }
    /// The new bytes of one row of a table for which [`MainHooks::changes`] is true; `None` copies
    /// the row as it is.
    fn map_row(&mut self, _table: &str, _key: &str, _old: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
    /// Tables that are written whole instead of copied (for example a table of keys that the old
    /// file did not have). Called before the log of the new file is built, so the images in it are
    /// taken from the tables as they are then.
    fn extra_tables(&mut self, _to: &Database) -> Result<()> {
        Ok(())
    }
    /// The names of the tables `extra_tables` writes, so the check knows them.
    fn extra_names(&self) -> Vec<String> {
        Vec::new()
    }
    /// Whether this table of the old file is left out of the copy because `extra_tables` writes it
    /// whole (a table of keys that is made again from the old one).
    fn replaces(&self, _table: &str) -> bool {
        false
    }
    /// The check of what `extra_tables` wrote, once the copy is done.
    fn verify_extra(&mut self, _to: &Database) -> Result<()> {
        Ok(())
    }
    /// The check of one row of a rewritten table, instead of comparing bytes.
    fn verify_row(&mut self, _table: &str, _key: &str, _old: &[u8], _new: &[u8]) -> Result<()> {
        Ok(())
    }
}

/// No change of any row: the copy is byte for byte.
pub(crate) struct NoHooks;

impl MainHooks for NoHooks {}

/// Read the old file and decide what happens to each of its tables. Reads only.
pub(crate) fn plan_main(from: &impl ReadableDatabase) -> Result<Plan> {
    plan_main_with(from, false)
}

/// [`plan_main`]; with `allow_sealed` a table that has protected fields is planned like any other
/// (a change that rewrites their rows says so through its hooks), otherwise it is refused.
pub(crate) fn plan_main_with(from: &impl ReadableDatabase, allow_sealed: bool) -> Result<Plan> {
    let meta = read_meta(from)?.ok_or_else(|| ClError::MigrationError("the file has no description of its tables".into()))?;
    // The protected fields are sealed with keys that depend on how the database is protected as a
    // whole, so they have to be sealed again; a change that does not do that refuses them.
    if !allow_sealed && meta.tables.iter().any(|t| !t.sealed.is_empty()) {
        return Err(ClError::MigrationError(
            "this database has protected fields: changing how the whole database is protected is not available for it; nothing was changed".into(),
        ));
    }
    let user_tables: Vec<String> = meta.tables.iter().map(|t| t.name.clone()).collect();
    let read = from.begin_read().map_err(io)?;
    if read.list_multimap_tables().map_err(io)?.next().is_some() {
        return Err(ClError::MigrationError(
            "the file holds a table this version does not know how to move (a multimap); nothing was changed".into(),
        ));
    }
    let mut names: Vec<String> = read.list_tables().map_err(io)?.map(|t| t.name().to_string()).collect();
    names.sort();
    let mut items = Vec::new();
    for name in names {
        let kind = if name == META_TABLE || PLAIN_SYSTEM.contains(&name.as_str()) {
            Kind::System
        } else if user_tables.contains(&name) {
            Kind::User
        } else if name == SEQ.name() {
            Kind::Seq
        } else if name == CHANGES.name() {
            Kind::Changes
        } else if name == CONSUMERS.name() {
            Kind::Consumers
        } else if name == LAST_WRITE {
            Kind::LastWrite
        } else if name == UNIQUE_KEYS {
            Kind::UniqueKeys
        } else if name == UNIQUE_ROWS {
            Kind::UniqueRows
        } else if name == INDEX_CATALOG {
            Kind::Catalog
        } else if name.starts_with(RESET_PREFIX) {
            Kind::Snapshot
        } else {
            return Err(unknown(&name));
        };
        let count = entries(&read, &name, kind)?;
        items.push(Item { name, kind, entries: count });
    }
    Ok(Plan { items, user_tables })
}

fn json_key(table: &str, row: &str) -> Vec<u8> {
    // the form `lastwrite` keys its rows by (checked by a test against `lastwrite::get`)
    serde_json::to_vec(&(table, row)).expect("strings serialize")
}

/// What the copy did, by table.
#[derive(Clone, Debug, Default)]
pub(crate) struct Moved {
    pub copied: Vec<(String, u64)>,
    pub rebuilt: Vec<(String, u64)>,
    pub left_out: Vec<String>,
    pub largest_batch_bytes: usize,
}

fn note(moved: &mut Moved, name: &str, done: Copied) {
    moved.copied.push((name.to_string(), done.rows));
    moved.largest_batch_bytes = moved.largest_batch_bytes.max(done.largest_batch_bytes);
}

/// Write the new file's tables from the old one. `to` must be empty (a file just made).
pub(crate) fn copy_main(from: &impl ReadableDatabase, to: &Database, plan: &Plan, limits: BatchLimits) -> Result<Moved> {
    copy_main_with(from, to, plan, limits, &mut NoHooks)
}

/// [`copy_main`], with the rows of the tables the hooks rewrite changed on the way.
pub(crate) fn copy_main_with(
    from: &impl ReadableDatabase,
    to: &Database,
    plan: &Plan,
    limits: BatchLimits,
    hooks: &mut dyn MainHooks,
) -> Result<Moved> {
    let mut moved = Moved::default();
    {
        // every system table exists in the new file, and the registered tables even when empty
        let write = to.begin_write().map_err(io)?;
        crate::journal::initialize(&write)?;
        for table in &plan.user_tables {
            write.open_table(TableDefinition::<&str, &[u8]>::new(table)).map_err(io)?;
        }
        write.commit().map_err(io)?;
    }
    for item in &plan.items {
        let name = item.name.as_str();
        match item.kind {
            Kind::System if hooks.replaces(name) => moved.left_out.push(item.name.clone()),
            Kind::User | Kind::System if hooks.changes(name) => {
                let done = copy_bytes_table_as(from, to, name, name, limits, &mut |k, v| {
                    Ok(Some(hooks.map_row(name, k, v)?.unwrap_or_else(|| v.to_vec())))
                })?;
                note(&mut moved, name, done);
            }
            Kind::User | Kind::System | Kind::Seq => {
                let done = copy_bytes_table(from, to, name, limits, &mut |_, v| Ok(v.to_vec()))?;
                note(&mut moved, name, done);
            }
            Kind::Consumers => {
                let done = copy_bytes_table_as(from, to, name, name, limits, &mut |k, v| {
                    Ok((k != INDEXER).then(|| v.to_vec()))
                })?;
                note(&mut moved, name, done);
            }
            Kind::UniqueKeys => note(&mut moved, name, copy_bytes_to_text(from, to, name, limits)?),
            Kind::UniqueRows => note(&mut moved, name, copy_bytes_to_bytes(from, to, name, limits)?),
            Kind::Catalog => note(&mut moved, name, copy_number_keyed_bytes(from, to, name, limits)?),
            Kind::LastWrite | Kind::Changes | Kind::Snapshot => moved.left_out.push(item.name.clone()),
        }
    }
    hooks.extra_tables(to)?;
    rebuild_journal(to, plan, limits, &mut moved)?;
    Ok(moved)
}

/// The change log of the new file: empty but for one `TableReset` for each registered table, each
/// with the image of the table as it is now. The log goes on from where the old one ended and its
/// floor is the first new entry, so a reader that was up to date takes each table again, and a
/// reader that was behind is told its place is gone.
fn rebuild_journal(to: &Database, plan: &Plan, limits: BatchLimits, moved: &mut Moved) -> Result<()> {
    let (head_old, generation) = {
        let read = to.begin_read().map_err(io)?;
        (crate::journal::read_number(&read, "head")?, crate::journal::read_number(&read, "reset_generation")?)
    };
    let mut snapshots = Vec::new();
    for (i, table) in plan.user_tables.iter().enumerate() {
        let snapshot = format!("{RESET_PREFIX}{}", generation + 1 + i as u64);
        // the image of the table, in batches
        let done = copy_bytes_table_as(to, to, table, &snapshot, limits, &mut |_, v| Ok(Some(v.to_vec())))?;
        moved.largest_batch_bytes = moved.largest_batch_bytes.max(done.largest_batch_bytes);
        // the attachments the table has, as the log image records them
        {
            let read = to.begin_read().map_err(io)?;
            let refs = read.open_table(crate::journal_blob::REFS).map_err(io)?;
            let write = to.begin_write().map_err(io)?;
            {
                let mut out = write
                    .open_table(TableDefinition::<&str, &[u8]>::new(&format!("{snapshot}_blobs")))
                    .map_err(io)?;
                for row in refs.iter().map_err(io)? {
                    let (k, v) = row.map_err(io)?;
                    let (name, _): (String, String) = serde_json::from_str(k.value())?;
                    if &name == table {
                        out.insert(k.value(), v.value()).map_err(io)?;
                    }
                }
            }
            write.commit().map_err(io)?;
        }
        snapshots.push((table.clone(), snapshot, done.rows));
    }
    // the log entries, the counters and the order of the writes
    let write = to.begin_write().map_err(io)?;
    let mut head = head_old;
    let mut bytes = 0u64;
    {
        let mut log = write.open_table(CHANGES).map_err(io)?;
        for (table, snapshot, _) in &snapshots {
            head += 1;
            let row = ChangeKind::TableReset { table: table.clone(), snapshot: snapshot.clone() }.encode()?;
            bytes += 8 + row.len() as u64;
            log.insert(head, row.as_slice()).map_err(io)?;
        }
    }
    put_number(&write, "reset_generation", generation + snapshots.len() as u64)?;
    put_number(&write, "head", head)?;
    put_number(&write, "floor", head_old + 1)?;
    put_number(&write, "journal_bytes", bytes)?;
    write.open_table(CONSUMERS).map_err(io)?.remove(INDEXER).map_err(io)?;
    write.commit().map_err(io)?;
    moved.rebuilt.push((CHANGES.name().to_string(), snapshots.len() as u64));
    // when each row was last written: the sequence of the `TableReset` of its table
    let def = TableDefinition::<&[u8], u64>::new(LAST_WRITE);
    let mut total = 0u64;
    for (i, table) in plan.user_tables.iter().enumerate() {
        let seq = head_old + 1 + i as u64;
        let read = to.begin_read().map_err(io)?;
        let rows = read.open_table(TableDefinition::<&str, &[u8]>::new(table)).map_err(io)?;
        let mut iter = rows.iter().map_err(io)?;
        loop {
            let mut batch: Vec<Vec<u8>> = Vec::new();
            let mut size = 0usize;
            for row in iter.by_ref() {
                let (k, _) = row.map_err(io)?;
                let key = json_key(table, k.value());
                size += key.len();
                batch.push(key);
                if batch.len() >= limits.max_rows || size >= limits.max_bytes {
                    break;
                }
            }
            if batch.is_empty() {
                break;
            }
            let write = to.begin_write().map_err(io)?;
            {
                let mut t = write.open_table(def).map_err(io)?;
                for key in &batch {
                    t.insert(key.as_slice(), seq).map_err(io)?;
                }
            }
            write.commit().map_err(io)?;
            super::rows::injected_failure()?;
            total += batch.len() as u64;
        }
    }
    moved.rebuilt.push((LAST_WRITE.to_string(), total));
    for (_, snapshot, rows) in &snapshots {
        moved.rebuilt.push((snapshot.clone(), *rows));
    }
    Ok(())
}

/// Check the new file against the old one. Every table of the old file must have its counterpart
/// with the same number of entries (and the same bytes where it is copied unchanged), except the
/// log and its images, which must be what `rebuild_journal` makes; and the new file holds no table
/// that is not accounted for.
pub(crate) fn verify_main(from: &impl ReadableDatabase, to: &Database, plan: &Plan) -> Result<()> {
    verify_main_with(from, to, plan, &mut NoHooks)
}

/// [`verify_main`]; a table the hooks rewrite keeps its number of rows and its keys, and each of
/// its rows is checked by the hooks instead of being compared byte for byte.
pub(crate) fn verify_main_with(from: &impl ReadableDatabase, to: &Database, plan: &Plan, hooks: &mut dyn MainHooks) -> Result<()> {
    let bad = |why: String| ClError::MigrationError(format!("the new file does not match the old one: {why}"));
    let read_to = to.begin_read().map_err(io)?;
    let mut expected: Vec<String> = hooks.extra_names();
    for item in &plan.items {
        let name = item.name.as_str();
        match item.kind {
            // written whole by the hooks (named by `extra_names` if the new file has it), and checked
            // by them below
            Kind::System if hooks.replaces(name) => {}
            Kind::User | Kind::System | Kind::Seq => {
                expected.push(item.name.clone());
                let n = entries(&read_to, name, item.kind)?;
                if n != item.entries {
                    return Err(bad(format!("{name} has {n} entries, it had {}", item.entries)));
                }
                if item.kind == Kind::Seq {
                    // the counters of the log move on; the identity of the database and the
                    // generation of the readers must not
                    for key in ["db_uuid", "consumer_generation"] {
                        if seq_value(from, key)? != seq_value(to, key)? {
                            return Err(bad(format!("{key} of the log changed")));
                        }
                    }
                } else if matches!(item.kind, Kind::User | Kind::System) && hooks.changes(name) {
                    check_rows(from, to, name, hooks)?;
                } else if !same_bytes(from, to, name)? {
                    return Err(bad(format!("{name} holds other bytes")));
                }
            }
            Kind::Consumers => {
                expected.push(item.name.clone());
                let had_indexer = {
                    let read = from.begin_read().map_err(io)?;
                    let t = read.open_table(CONSUMERS).map_err(io)?;
                    t.get(INDEXER).map_err(io)?.is_some()
                };
                let want = item.entries - u64::from(had_indexer);
                let n = entries(&read_to, name, item.kind)?;
                if n != want {
                    return Err(bad(format!("{name} has {n} entries, {want} were expected")));
                }
            }
            Kind::UniqueKeys | Kind::UniqueRows | Kind::Catalog => {
                expected.push(item.name.clone());
                let n = entries(&read_to, name, item.kind)?;
                if n != item.entries {
                    return Err(bad(format!("{name} has {n} entries, it had {}", item.entries)));
                }
            }
            Kind::LastWrite | Kind::Changes | Kind::Snapshot => {}
        }
    }
    // the rebuilt tables
    let mut rows_total = 0u64;
    let generation = crate::journal::read_number(&read_to, "reset_generation")?;
    let tables = plan.user_tables.len() as u64;
    expected.push(CHANGES.name().to_string());
    expected.push(LAST_WRITE.to_string());
    // the tables the log makes in any new file: a file written before the log existed has none of them
    for name in [SEQ.name(), CONSUMERS.name(), "__blob_refs", "__unique_definitions", UNIQUE_KEYS, UNIQUE_ROWS, "__id_contracts"] {
        expected.push(name.to_string());
    }
    for (i, table) in plan.user_tables.iter().enumerate() {
        let snapshot = format!("{RESET_PREFIX}{}", generation - tables + 1 + i as u64);
        let rows = entries(&read_to, table, Kind::User)?;
        rows_total += rows;
        let image = entries(&read_to, &snapshot, Kind::Snapshot)?;
        if image != rows {
            return Err(bad(format!("the image of {table} in the log has {image} rows, the table has {rows}")));
        }
        expected.push(snapshot.clone());
        expected.push(format!("{snapshot}_blobs"));
    }
    if entries(&read_to, CHANGES.name(), Kind::Changes)? != tables {
        return Err(bad("the log does not hold one reset for each table".into()));
    }
    if entries(&read_to, LAST_WRITE, Kind::LastWrite)? != rows_total {
        return Err(bad("the record of the last write does not cover every row".into()));
    }
    hooks.verify_extra(to)?;
    // nothing unexpected in the new file, nothing missing from it
    let mut found: Vec<String> = read_to.list_tables().map_err(io)?.map(|t| t.name().to_string()).collect();
    found.sort();
    expected.sort();
    expected.dedup();
    if let Some(extra) = found.iter().find(|n| !expected.contains(n)) {
        return Err(bad(format!("the new file holds {extra}, which nothing accounts for")));
    }
    if let Some(missing) = expected.iter().find(|n| !found.contains(n)) {
        return Err(bad(format!("{missing} is missing from the new file")));
    }
    Ok(())
}

fn seq_value(db: &impl ReadableDatabase, key: &str) -> Result<Option<Vec<u8>>> {
    let read = db.begin_read().map_err(io)?;
    let table = read.open_table(SEQ).map_err(io)?;
    let value = table.get(key).map_err(io)?.map(|v| v.value().to_vec());
    Ok(value)
}

/// The rows of a rewritten table, one by one without holding either in memory: the same keys in
/// the same order, and each pair of values passed to the hooks.
fn check_rows(from: &impl ReadableDatabase, to: &Database, name: &str, hooks: &mut dyn MainHooks) -> Result<()> {
    let bad = |why: String| ClError::MigrationError(format!("the new file does not match the old one: {why}"));
    let def = TableDefinition::<&str, &[u8]>::new(name);
    let (a, b) = (from.begin_read().map_err(io)?, to.begin_read().map_err(io)?);
    let (ta, tb) = (a.open_table(def).map_err(io)?, b.open_table(def).map_err(io)?);
    let (mut ia, mut ib) = (ta.iter().map_err(io)?, tb.iter().map_err(io)?);
    loop {
        match (ia.next(), ib.next()) {
            (None, None) => return Ok(()),
            (Some(x), Some(y)) => {
                let ((ka, va), (kb, vb)) = (x.map_err(io)?, y.map_err(io)?);
                if ka.value() != kb.value() {
                    return Err(bad(format!("{name} has another row where {} was", ka.value())));
                }
                hooks.verify_row(name, ka.value(), va.value(), vb.value())?;
            }
            _ => return Err(bad(format!("{name} has another number of rows"))),
        }
    }
}

/// Whether two tables of text keys and byte values hold the same rows, compared one by one
/// without holding either in memory.
fn same_bytes(from: &impl ReadableDatabase, to: &Database, name: &str) -> Result<bool> {
    let def = TableDefinition::<&str, &[u8]>::new(name);
    let (a, b) = (from.begin_read().map_err(io)?, to.begin_read().map_err(io)?);
    let (ta, tb) = (a.open_table(def).map_err(io)?, b.open_table(def).map_err(io)?);
    let (mut ia, mut ib) = (ta.iter().map_err(io)?, tb.iter().map_err(io)?);
    loop {
        match (ia.next(), ib.next()) {
            (None, None) => return Ok(true),
            (Some(x), Some(y)) => {
                let ((ka, va), (kb, vb)) = (x.map_err(io)?, y.map_err(io)?);
                if ka.value() != kb.value() || va.value() != vb.value() {
                    return Ok(false);
                }
            }
            _ => return Ok(false),
        }
    }
}

/// The names of the tables for the report of a dry run: what is copied, rebuilt and left out.
pub(crate) fn describe(plan: &Plan) -> Vec<(String, &'static str, u64)> {
    plan.items
        .iter()
        .map(|i| {
            let how = match i.kind {
                Kind::LastWrite => "rebuilt",
                Kind::Changes | Kind::Snapshot => "written again",
                _ => "copied",
            };
            (i.name.clone(), how, i.entries)
        })
        .collect()
}
