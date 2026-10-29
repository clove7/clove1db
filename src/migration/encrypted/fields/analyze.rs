//! Reading a closed database to see what a change of how its fields are protected would do, and
//! whether it can be done. Nothing is written: the old files are opened to be read only. Every
//! reason the change cannot be made is found here, before the first file is made.
#![allow(dead_code)] // the run that makes the files is written next
use super::{
    api::{ChangeFields, KeyMode},
    plan::{self, StepKind, TablePlan},
};
use crate::{
    backup::codec::{decode_record, is_v2},
    crypto::{LockedDataKey, LockedKey},
    field_crypto::{self, FieldKeys, Method, Row, carried, keystore},
    handle::{DbOrRo, RedbOptions},
    metadata::{store::read_meta, types::CloveMeta},
    migration::encrypted::{
        attachments, convert, history,
        marker::{Root, Target},
        sidecars,
    },
    units::{ClError, Result},
};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use std::{fs, io::Read, path::PathBuf, sync::Arc};

/// redb's own file signature: an encrypted file never starts with it.
const PLAIN_SIGNATURE: [u8; 9] = [b'r', b'e', b'd', b'b', 0x1A, 0x0A, 0xA9, 0x0D, 0x0A];

pub(crate) struct Paths {
    pub dir: PathBuf,
    pub backup_dir: PathBuf,
    pub main: PathBuf,
    pub backup: PathBuf,
}

/// What was counted in one table.
#[derive(Clone, Debug, Default)]
pub(crate) struct Counts {
    pub rows: u64,
    pub versions: u64,
}

/// Everything read from the old files, and the plans made from it.
pub(crate) struct Analysis {
    pub paths: Paths,
    pub main: DbOrRo,
    pub backup: Option<DbOrRo>,
    pub main_plan: convert::Plan,
    pub history_plan: Option<history::Plan>,
    pub meta: CloveMeta,
    pub plans: Vec<TablePlan>,
    /// The identity each named table has now (`None`: it has no protected field yet).
    pub old_ids: Vec<Option<String>>,
    pub keys: Option<Arc<FieldKeys>>,
    /// Field-only keys made now because the database had none and the change needs them.
    pub made_keys: Option<LockedDataKey>,
    /// The locked data key of the fields' keys (the database's own, or the one made now).
    pub locked: Option<LockedDataKey>,
    pub counts: Vec<Counts>,
    /// Values that will be hashed (rows and versions), for the estimate.
    pub hash_values: u64,
    /// Versions that hold no value for a field, and were allowed to stay so.
    pub allowed_versions_without: Vec<(String, String, u64)>,
    pub targets: Vec<Target>,
    /// The tables whose attachments change place, and where to.
    pub moves: Vec<Move>,
    /// Disk the moved attachments need beyond the files that are replaced.
    pub attach_bytes: u64,
}

/// A table whose attachments change place with its keys.
#[derive(Clone, Debug)]
pub(crate) struct Move {
    pub table: String,
    /// To `{db}.pblobs` (the table gets its first protected field); otherwise back to `{db}.blobs`.
    pub to_protected: bool,
}

fn bad(why: impl Into<String>) -> ClError {
    ClError::MigrationError(why.into())
}

fn io(e: impl std::fmt::Display) -> ClError {
    ClError::MigrationError(e.to_string())
}

/// The locked data key stored in the main file, if there is one (read through any open handle).
fn read_locked(db: &impl ReadableDatabase) -> Result<Option<LockedDataKey>> {
    let read = db.begin_read().map_err(io)?;
    let table = match read.open_table(keystore::TABLE) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(other) => return Err(io(other)),
    };
    let (Some(r), Some(s)) = (table.get("read").map_err(io)?, table.get("search").map_err(io)?) else {
        return Ok(None);
    };
    Ok(Some(LockedDataKey { read: LockedKey::from_bytes(r.value().to_vec()), search: LockedKey::from_bytes(s.value().to_vec()) }))
}

/// Hand the carried keys this program can open to `keys` (the same as the open does).
fn load_carried(db: &impl ReadableDatabase, keys: &FieldKeys) -> Result<()> {
    carried::load(db, keys).map(|_| ())
}

/// The unique constraints stored for a table, as the paths they are on.
fn unique_paths(db: &impl ReadableDatabase, table: &str) -> Result<Vec<crate::fields::Path>> {
    let read = db.begin_read().map_err(io)?;
    let defs = match read.open_table(TableDefinition::<&str, &[u8]>::new("__unique_definitions")) {
        Ok(defs) => defs,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
        Err(other) => return Err(io(other)),
    };
    let Some(stored) = defs.get(table).map_err(io)? else { return Ok(Vec::new()) };
    let list: Vec<crate::unique::Unique> = serde_json::from_slice(stored.value())?;
    Ok(list.into_iter().flat_map(|u| u.paths).collect())
}

fn open_database(options: &RedbOptions, path: &std::path::Path, name: &'static str) -> Result<DbOrRo> {
    options.open_read_only_timed(path, name).0
}

/// Read the old files and plan the change. Writes nothing.
pub(crate) fn analyze(c: &ChangeFields) -> Result<Analysis> {
    let paths = c.paths();
    if c.tables.is_empty() {
        return Err(ClError::Validation("name at least one table whose fields are to change".into()));
    }
    if !paths.main.is_file() {
        return Err(ClError::Validation(format!("there is no database at {}", paths.main.display())));
    }
    // a database another program has open is refused first
    crate::handle::guard_open(&paths.main, false)?;
    let mut head = [0u8; 9];
    let n = fs::File::open(&paths.main).map_err(io)?.read(&mut head).map_err(io)?;
    let plain_file = n == 9 && head == PLAIN_SIGNATURE;
    match (&c.keys, plain_file) {
        (KeyMode::Whole(_), true) => return Err(ClError::Validation("the database is not encrypted as a whole: set the keys of its fields instead".into())),
        (KeyMode::Field(_) | KeyMode::None, false) => return Err(ClError::EncryptedOpenFailed),
        _ => {}
    }
    let options = RedbOptions {
        encryption: match &c.keys {
            KeyMode::Whole(handle) => Some(handle.clone()),
            _ => None,
        },
        cache_bytes: Some(crate::migration::encrypted::rows::PAGE_CACHE_BYTES),
        ..RedbOptions::default()
    };
    let main = open_database(&options, &paths.main, "main")?;
    let meta = read_meta(&main)?.ok_or_else(|| bad("the file has no description of its tables"))?;
    let main_plan = convert::plan_main_with(&main, true)?;
    let (backup, history_plan) = if paths.backup.is_file() {
        let db = open_database(&options, &paths.backup, "bak")?;
        let plan = history::plan_history(&db)?;
        (Some(db), Some(plan))
    } else {
        (None, None)
    };

    // what becomes of each named table
    let mut plans = Vec::new();
    let mut old_ids = Vec::new();
    for (name, specs) in &c.tables {
        let Some(table) = meta.tables.iter().find(|t| &t.name == name) else {
            return Err(ClError::Validation(format!("the database has no table '{name}'")));
        };
        plans.push(plan::plan_table(name, &table.sealed, specs)?);
        old_ids.push(table.table_id.clone());
    }

    // the keys: of the whole database, the ones the database has, or ones made now when it has none
    // and a change needs them
    let any_keys_needed = plans.iter().any(|p| {
        let n = p.needs();
        n.read || n.search
    });
    let mut made_keys = None;
    let mut existing_locked = None;
    let keys: Option<Arc<FieldKeys>> = match &c.keys {
        KeyMode::Whole(handle) => {
            let context = handle.context().cloned().ok_or(ClError::EncryptedOpenFailed)?;
            // the new files are made with this same handle, so they get the same data key and the same lock
            existing_locked = Some(context.locked_data_key().clone());
            Some(Arc::new(FieldKeys::with_context(context)?))
        }
        KeyMode::Field(config) => match read_locked(&main)? {
            Some(locked) => {
                let keys = keystore::open(config, &locked)?;
                existing_locked = Some(locked);
                Some(keys)
            }
            // protected fields and no lock in the main file: the lock is kept in a keys file elsewhere
            // (`field_keys_file`), and a new data key made now would not open those fields
            None if meta.tables.iter().any(|t| !t.sealed.is_empty()) => {
                return Err(ClError::Validation(
                    "this database keeps the lock of its field keys outside the main file (`field_keys_file`), which this version does not change; nothing was changed".into(),
                ));
            }
            None if any_keys_needed => {
                let (locked, keys) = keystore::create(config)?;
                made_keys = Some(locked);
                Some(keys)
            }
            None => None,
        },
        KeyMode::None => None,
    };
    if let Some(keys) = &keys {
        load_carried(&main, keys)?;
    }

    // a field kept as it is, whose settings sit behind a keyed fingerprint, is compared with the new
    // settings now that the keys are open
    if let Some(keys) = keys.as_ref() {
        for (plan, id) in plans.iter_mut().zip(&old_ids) {
            let Some(table_id) = id.as_deref() else { continue };
            for step in plan.steps.iter_mut().filter(|s| s.kind == StepKind::Keep) {
                let (Some(from), Some(to)) = (&step.from, &step.to) else { continue };
                if !matches!(to.method, Method::EncryptFullPrint | Method::EncryptPartPrints | Method::Hash | Method::SearchPrint) {
                    continue;
                }
                // a program that holds only the search key cannot compare a hash, and one without it no fingerprint
                let comparable = if to.method == Method::Hash { !keys.is_search_only() } else { keys.has_search() };
                let Some(stored) = from.check.as_deref().filter(|_| comparable) else { continue };
                let expected = field_crypto::settings_checks(keys, table_id, std::slice::from_ref(to))?;
                let same = expected[0].1.as_deref().is_some_and(|e| field_crypto::same_settings(stored, e));
                step.kind = plan::settled(&plan.table, step, same)?;
            }
        }
    }

    // what the program must hold, and the one-way changes it must have confirmed
    for plan in &plans {
        let needs = plan.needs();
        if needs.one_way && !c.one_way_confirmed {
            return Err(ClError::Validation(format!(
                "table '{}': this change loses a value for good (a hash, or a fingerprint that does not keep the value) and has to be confirmed with `confirm_one_way()`. Nothing was changed",
                plan.table
            )));
        }
        if needs.read || needs.search {
            let Some(keys) = &keys else {
                return Err(ClError::Validation(format!("table '{}': this change needs the keys of the fields; set them. Nothing was changed", plan.table)));
            };
            if needs.read && keys.is_search_only() {
                return Err(ClError::Validation(format!("table '{}': this change needs the read key, which this program does not hold. Nothing was changed", plan.table)));
            }
            if needs.search && !keys.has_search() {
                return Err(ClError::Validation(format!("table '{}': this change needs the search key, which this program does not hold. Nothing was changed", plan.table)));
            }
        }
    }

    // a unique constraint on a field that changes holds its value
    for plan in &plans {
        let changing: Vec<&str> = plan.steps.iter().filter(|s| s.kind != StepKind::Keep).map(|s| s.key.as_str()).collect();
        if changing.is_empty() {
            continue;
        }
        for path in unique_paths(&main, &plan.table)? {
            if let Some(crate::fields::Step::Key(first)) = path.steps.first()
                && changing.contains(&first.as_str())
            {
                return Err(ClError::Validation(format!(
                    "table '{}': a unique constraint is on field '{first}', which this change rewrites, and the constraint holds the value. Remove the constraint, make the change, then add it again on the fingerprint of the field. Nothing was changed",
                    plan.table
                )));
            }
        }
    }

    // the attachments of a table follow the keys of its fields: a table that gets its first protected
    // field has them sealed again, bound to the table, row and file, in `{db}.pblobs`; one that loses
    // its last has them taken back to the folder of the other attachments
    let blobs = sidecars::plan_blobs(&main)?;
    let moves: Vec<Move> = plans
        .iter()
        .filter(|p| (p.new_table_id || p.drop_table_id) && blobs.iter().any(|b| b.table == p.table))
        .map(|p| Move { table: p.table.clone(), to_protected: p.new_table_id })
        .collect();
    let moved_tables: Vec<String> = moves.iter().map(|m| m.table.clone()).collect();
    let attach_bytes = if moves.is_empty() { 0 } else { attachments::required_bytes(&main, Some(&moved_tables), &[])? };

    // count, and look at every row and every saved version the change rewrites
    let mut counts = Vec::new();
    let mut hash_values = 0u64;
    let mut without: Vec<(String, String, u64)> = Vec::new();
    for plan in &plans {
        let rows = main_plan.items.iter().find(|i| i.name == plan.table).map(|i| i.entries).unwrap_or(0);
        let mut count = Counts { rows, versions: 0 };
        let rewrites: Vec<_> = plan.steps.iter().filter(|s| s.kind != StepKind::Keep).collect();
        if !rewrites.is_empty() {
            let mut lacking = vec![0u64; rewrites.len()];
            let read = main.begin_read().map_err(io)?;
            let table = read.open_table(TableDefinition::<&str, &[u8]>::new(&plan.table)).map_err(io)?;
            for row in table.iter().map_err(io)? {
                let (_, value) = row.map_err(io)?;
                let parsed = Row::parse(value.value())?;
                for (i, step) in rewrites.iter().enumerate() {
                    if parsed.get(&step.key).is_none() {
                        lacking[i] += 1;
                    } else if step.kind == StepKind::Hash || step.kind == StepKind::OpenToHash {
                        hash_values += 1;
                    }
                }
            }
            if let Some(i) = lacking.iter().position(|n| *n > 0) {
                return Err(ClError::Validation(format!(
                    "table '{}': {} rows hold no value for field '{}', and a protected field has to hold one. Nothing was changed",
                    plan.table, lacking[i], rewrites[i].key
                )));
            }
            if let (Some(db), Some(history_plan)) = (&backup, &history_plan) {
                if history_plan.items.iter().any(|i| i.name == plan.table && i.kind == history::Kind::Versions) {
                    let read = db.begin_read().map_err(io)?;
                    let versions = read.open_table(TableDefinition::<&str, &[u8]>::new(&plan.table)).map_err(io)?;
                    let mut missing = vec![0u64; rewrites.len()];
                    for entry in versions.iter().map_err(io)? {
                        let (key, value) = entry.map_err(io)?;
                        if !is_v2(value.value())? {
                            return Err(bad(format!(
                                "table '{}': the history is not in the current form: open the database once to bring it to it. Nothing was changed",
                                plan.table
                            )));
                        }
                        let record = decode_record(&plan.table, key.value(), value.value())?;
                        let Some(data) = record.data else { continue };
                        count.versions += 1;
                        let parsed = Row::parse(&data)?;
                        for (i, step) in rewrites.iter().enumerate() {
                            if parsed.get(&step.key).is_none() {
                                missing[i] += 1;
                            } else if step.kind == StepKind::Hash || step.kind == StepKind::OpenToHash {
                                hash_values += 1;
                            }
                        }
                    }
                    for (i, step) in rewrites.iter().enumerate().filter(|(i, _)| missing[*i] > 0) {
                        let allowed = c.allow_without.iter().any(|f| f == &step.key) && !matches!(step.kind, StepKind::Hash | StepKind::OpenToHash);
                        if !allowed {
                            return Err(ClError::Validation(format!(
                                "table '{}': {} saved versions hold no value for field '{}' (an older layout). They can stay as they are with `allow_old_versions_without(\"{}\")`; a hash allows no exception. Nothing was changed",
                                plan.table, missing[i], step.key, step.key
                            )));
                        }
                        without.push((plan.table.clone(), step.key.clone(), missing[i]));
                    }
                }
            }
        }
        counts.push(count);
    }

    // the files and folders that get a new version
    let any_rows = plans.iter().any(|p| p.changes_rows());
    let db = &c.db_name;
    let mut targets = vec![Target::new(Root::Main, &format!("{db}.cldb"), true)];
    if backup.is_some() && any_rows {
        targets.push(Target::new(Root::Backup, &format!("{db}.cldb.bak"), true));
    }
    let after_sealed = meta.tables.iter().any(|t| match c.tables.iter().find(|(n, _)| n == &t.name) {
        Some((_, specs)) => !specs.is_empty(),
        None => !t.sealed.is_empty(),
    });
    let keys_file = paths.dir.join(format!("{db}.keys"));
    let keys_change = made_keys.is_some() || plans.iter().any(|p| p.new_table_id || p.drop_table_id);
    if keys_change && (after_sealed || keys_file.exists()) {
        targets.push(Target::new(Root::Main, &format!("{db}.keys"), after_sealed));
    }
    // the two attachment folders, when attachments change place
    if !moves.is_empty() {
        if crate::blob::blob_root(&paths.dir, db).is_dir() || moves.iter().any(|m| !m.to_protected) {
            targets.push(Target::new(Root::Main, &format!("{db}.blobs"), true));
        }
        if crate::blob::protected_blob_root(&paths.dir, db).is_dir() || moves.iter().any(|m| m.to_protected) {
            targets.push(Target::new(Root::Main, &format!("{db}.pblobs"), true));
        }
    }
    // the index file is built again from the catalog when the database opens
    let index = format!("{db}.inx");
    if paths.dir.join(&index).exists() {
        targets.push(Target::new(Root::Main, &index, false));
    }
    if let Ok(rd) = fs::read_dir(&paths.dir) {
        let mut stale: Vec<String> = rd
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(&format!("{index}.build-")))
            .collect();
        stale.sort();
        targets.extend(stale.iter().map(|n| Target::new(Root::Main, n, false)));
    }

    Ok(Analysis {
        paths,
        main,
        backup,
        main_plan,
        history_plan,
        meta,
        plans,
        old_ids,
        keys,
        locked: made_keys.clone().or(existing_locked),
        made_keys,
        counts,
        hash_values,
        allowed_versions_without: without,
        targets,
        moves,
        attach_bytes,
    })
}
