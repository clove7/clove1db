use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::durability::DurabilityMode;
use crate::handle::{DbHandle, FileOpen, RedbOptions};
use crate::metadata::inspect::{FileKind, inspect_database_with, inspect_open};
use crate::metadata::store::{create_meta_table, put_meta, read_meta};
use crate::metadata::types::TableStorageMode;
use crate::metadata::types::{BACKUP_FORMAT_V2, BackupFormat, CloveMeta, FileEra, TableMeta};
use crate::migration::chain::DbMigrationIndex;
use crate::migration::layout::FieldLayout;
use crate::migration::types::migration_dir_name;
use crate::upgrade::backup_normalize::eager_normalize;
use crate::upgrade::migration_refs::upgrade_migration_refs_with_durability;
use crate::units::{ClError, Result};

/// Test hook: make the first commit of a new encrypted database named `hooked` fail, after the file was created.
/// (Only that name, so tests running in parallel with other databases are never hit.)
#[cfg(test)]
pub(crate) static FAIL_AFTER_CREATE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub struct TableRegistration {
    pub name: String,
    pub layout: FieldLayout,
    pub storage: TableStorageMode,
    /// The protected fields the entity declares; empty for a table without any.
    pub sealed: &'static [crate::field_crypto::SealedSpec],
}

/// A new random identity for a table with protected fields: 16 bytes as lower-case hex.
fn new_table_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    crate::crypto::random_bytes(&mut bytes)
        .map_err(|_| ClError::Validation("the system could not provide random bytes".into()))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Compares the protected fields the code declares with those the table remembers, and records
/// them in `meta` for a table that is being created. Writes nothing: `meta` is stored later, in the
/// same commit that stores the rest of the description. A difference is an error before any file
/// is touched.
fn settle_sealed(
    meta: &mut CloveMeta,
    tables: &[TableRegistration],
    table_is_new: bool,
) -> Result<()> {
    use crate::field_crypto::{Plan, SealedField, check_layout};
    for reg in tables {
        let stored: Vec<SealedField> = meta
            .tables
            .iter()
            .find(|t| t.name == reg.name)
            .map(|t| t.sealed.clone())
            .unwrap_or_default();
        if let Plan::Create(fields) = check_layout(&reg.name, reg.sealed, &stored, table_is_new)? {
            let table_id = new_table_id()?;
            match meta.tables.iter_mut().find(|t| t.name == reg.name) {
                Some(tm) => {
                    tm.sealed = fields;
                    tm.table_id = Some(table_id);
                }
                None => meta.tables.push(TableMeta {
                    name: reg.name.clone(),
                    schema_id: reg.name.clone(),
                    schema_version: 1,
                    layout_hash: reg.layout.layout_hash.clone(),
                    storage: reg.storage,
                    table_id: Some(table_id),
                    sealed: fields,
                }),
            }
        }
    }
    Ok(())
}

/// Records, for a table being created, a keyed fingerprint of the settings of each verification
/// hash; for an existing table, compares it with the settings the code declares now. A change of
/// the settings is a migration, as a change of method is: every stored hash was made with the old
/// ones. Writes nothing; the fingerprint is stored by the same first commit as the description.
fn settle_hash_settings(
    meta: &mut CloveMeta,
    tables: &[TableRegistration],
    keys: &crate::field_crypto::FieldKeys,
    table_is_new: bool,
) -> Result<()> {
    use crate::field_crypto::Method;
    for reg in tables {
        let Some(table) = meta.tables.iter_mut().find(|t| t.name == reg.name) else {
            continue;
        };
        let Some(table_id) = table.table_id.clone() else {
            continue;
        };
        for spec in reg.sealed.iter().filter(|s| s.method == Method::Hash || s.method.has_full_print()) {
            // What the settings are fingerprinted with must be in the program's hands: the read
            // key for a hash, the search key for a fingerprint; otherwise it cannot compare.
            let (what, expected) = if spec.method == Method::Hash {
                let Some(algo) = spec.hash else { continue };
                if keys.is_search_only() {
                    continue;
                }
                ("hash", crate::field_crypto::settings_fingerprint(keys, &table_id, spec.id, algo)?)
            } else {
                if !keys.has_search() {
                    if table_is_new && spec.method.has_stored_print() {
                        return Err(ClError::Validation(format!(
                            "table '{}': a field with a fingerprint can only be created by a program that holds the search key; nothing was written",
                            reg.name
                        )));
                    }
                    continue;
                }
                ("fingerprint", crate::field_crypto::print_settings_fingerprint(keys, &table_id, spec.id, spec.normalize)?)
            };
            let Some(field) = table.sealed.iter_mut().find(|f| f.id == spec.id) else {
                continue;
            };
            match &field.check {
                Some(stored) if !crate::field_crypto::same_settings(stored, &expected) => {
                    return Err(ClError::Validation(format!(
                        "table '{}': the {what} settings of field '{}' differ from the ones it was created with. Changing how a {what} is made is a migration; nothing was written",
                        reg.name, field.name
                    )));
                }
                Some(_) => {}
                None if table_is_new => field.check = Some(expected),
                // Every table records the settings of these fields when it is created; a table
                // without them was not made by this library's open.
                None => {
                    return Err(ClError::Validation(format!(
                        "table '{}': the {what} settings of field '{}' were not recorded when it was created. Changing how a field is stored is a migration; nothing was written",
                        reg.name, field.name
                    )));
                }
            }
        }
    }
    Ok(())
}

pub struct UpgradeInput<'a> {
    pub dir_path: &'a Path,
    pub backup_dir_path: Option<&'a Path>,
    pub dir_name: &'a str,
    pub db_name: &'a str,
    pub tables: &'a [TableRegistration],
    pub backup_enabled: bool,
    pub blob_enabled: bool,
    pub has_cache: bool,
    pub durability: DurabilityMode,
    pub redb: RedbOptions,
    /// Where encryption events go (the storage's own sink). Empty when none is set.
    pub(crate) event_sink: crate::events::EventSink,
    /// The keys for protected fields of a database that is not encrypted as a whole.
    pub(crate) field_encryption: Option<std::sync::Arc<crate::encrypted_store::EncryptionConfig>>,
    /// Keep the locked data key in this file only, and none in the main file.
    pub(crate) field_keys_file: Option<std::path::PathBuf>,
}

pub struct UpgradeOutput {
    pub meta: CloveMeta,
    pub table_layouts: HashMap<String, FieldLayout>,
    /// The primary, still open. `Storage::build` serves from this handle
    /// rather than opening the file again.
    pub db: DbHandle,
    pub(crate) format_opens: Vec<FileOpen>,
    /// The keys of the protected fields of a database that is not encrypted as a whole.
    pub(crate) field_keys: Option<std::sync::Arc<crate::field_crypto::FieldKeys>>,
}

/// A keys file to write: the full content, where, and whether a file was there already.
struct KeyFilePlan {
    path: std::path::PathBuf,
    bytes: Vec<u8>,
    existed: bool,
}

pub struct OpenUpgradePipeline;

impl OpenUpgradePipeline {
    pub fn run(input: &UpgradeInput<'_>) -> Result<UpgradeOutput> {
        for table in input.tables {crate::journal::validate_table(&table.name)?;}
        let db_dir = input.dir_path.join(input.dir_name);
        fs::create_dir_all(&db_dir)?;
        if let Some(backup_root) = input.backup_dir_path {
            let backup_parent = backup_root.join(input.dir_name);
            fs::create_dir_all(&backup_parent)?;
        }

        let primary_path = db_dir.join(format!("{}.cldb", input.db_name));
        let backup_path = input.backup_dir_path.map(|bp| {
            bp.join(input.dir_name)
                .join(format!("{}.cldb.bak", input.db_name))
        });
        let migration_dir = db_dir.join(migration_dir_name(input.db_name));
        // A new encrypted database is made under this name and gets its final one only when it is complete.
        let pending_path = db_dir.join(format!("{}.cldb.new", input.db_name));
        // A change of the database's files that a crash cut short is settled before any file is opened:
        // finished if it had been decided, undone if not.
        {
            use crate::migration::encrypted::marker::{Migration, Places};
            let backup_folder = input.backup_dir_path.map(|bp| bp.join(input.dir_name));
            let places = Places { main: db_dir.as_path(), backup: backup_folder.as_deref().unwrap_or(db_dir.as_path()) };
            Migration::recover(places, input.db_name)?;
        }
        if input.redb.encryption.is_some() {
            clear_interrupted_creation(input, &db_dir, &primary_path, &pending_path, backup_path.as_deref(), &migration_dir)?;
        }
        // declared before `handle`, so the file is closed before this removes it
        let mut pending = PendingFile(None);

        // The primary is opened here and nowhere else: this handle is inspected,
        // gets the meta written through it, and is handed to `DatabaseManager`.
        // A missing file stays unopened until the end, so a build that fails
        // validation does not leave an empty `.cldb` behind; a directory is
        // left to `inspect_database`, which classifies it without opening it.
        let handle = if primary_path.is_file() {
            Some(DbHandle::open_with_events(&primary_path, input.durability, input.redb.clone(), "main", &input.event_sink)?)
        } else {
            None
        };

        let inspection = match &handle {
            Some(handle) => inspect_open(
                handle.get()?.raw(),
                &primary_path,
                backup_path.as_deref(),
                &migration_dir,
            )?,
            None => inspect_database_with(
                &primary_path,
                backup_path.as_deref(),
                &migration_dir,
                input.redb.encryption.as_ref(),
            )?,
        };

        match inspection.kind {
            FileKind::Invalid | FileKind::ExternalRedb => {
                return Err(ClError::NotCloveDatabase {
                    path: primary_path.display().to_string(),
                });
            }
            _ => {}
        }

        if inspection.kind != FileKind::New {
            validate_tables(
                &input.tables.iter().map(|t| t.name.clone()).collect::<Vec<_>>(),
                &inspection.tables,
            )?;
        }

        let file_era = resolve_file_era(&inspection);
        let mut meta = build_meta(input, file_era);
        if backup_path.as_ref().is_some_and(|p| p.exists()) {
            meta.backup_format = "unknown".to_string();
        }

        if inspection.kind == FileKind::Authenticated {
            if let Some(handle) = &handle {
                if let Ok(Some(existing)) = read_meta(handle.get()?.raw()) {
                    if existing.meta_version == crate::metadata::types::META_VERSION {
                        meta = existing;
                        meta.framework_version = env!("CARGO_PKG_VERSION").to_string();
                    }
                }
            }
        }

        // The protected fields must be the ones the table was created with. This only reads and
        // changes `meta` in memory: nothing is written here, and a difference returns before any
        // file is touched. (A table that already exists in the file is never "new".)
        settle_sealed(&mut meta, input.tables, inspection.kind == FileKind::New)?;

        // The keys of the protected fields of a database that is not encrypted as a whole: read
        // from the file when it exists, made now (and stored by the first commit below) when it
        // is new. Nothing is written here.
        let mut field_keys = None;
        let mut new_locked_key = None;
        // The keys file: written just before the first commit, and only when its content changes.
        let mut key_file: Option<KeyFilePlan> = None;
        if let Some(config) = &input.field_encryption
            && input.tables.iter().any(|t| !t.sealed.is_empty())
        {
            use crate::field_crypto::{keyfile, keystore};
            let is_new = inspection.kind == FileKind::New;
            let external = input.field_keys_file.is_some();
            let file_path = input
                .field_keys_file
                .clone()
                .unwrap_or_else(|| keyfile::default_path(&db_dir, input.db_name));
            // Read-only; a file that is not exactly the format is a tamper error, before anything is written.
            let file = if is_new && !external { None } else { keyfile::read_file(&file_path)? };
            let in_main = match (&handle, is_new) {
                (Some(handle), false) => keystore::read(handle.get()?.raw())?,
                _ => None,
            };
            let stored = if external {
                if in_main.is_some() {
                    return Err(ClError::Validation(
                        "this database keeps its keys inside the main file: open it without `field_keys_file`".into(),
                    ));
                }
                file.as_ref().map(|f| f.locked.clone())
            } else {
                in_main.clone()
            };
            match stored {
                Some(locked) => {
                    let keys = keystore::open(config, &locked)?;
                    // The copy next to the main file must be the same lock, whole and unchanged.
                    if let (false, Some(f)) = (external, &file)
                        && f.locked != locked
                    {
                        return Err(ClError::DataTampered);
                    }
                    field_keys = Some(keys);
                }
                None if is_new => {
                    let (locked, keys) = keystore::create(config)?;
                    new_locked_key = Some(locked);
                    field_keys = Some(keys);
                }
                None => {
                    return Err(ClError::Validation(
                        "the database has protected fields but holds no keys for them".into(),
                    ));
                }
            }
            // A program with only the search key neither checks nor writes the keys file.
            if let Some(keys) = field_keys.as_ref().filter(|k| !k.is_search_only()) {
                let locked = match (&new_locked_key, &in_main, &file) {
                    (Some(l), _, _) => l.clone(),
                    (None, Some(l), _) => l.clone(),
                    (None, None, Some(f)) => f.locked.clone(),
                    (None, None, None) => unreachable!("keys exist, so a lock exists"),
                };
                let wanted: Vec<(String, String)> = {
                    let mut ids: Vec<(String, String)> =
                        meta.tables.iter().filter_map(|t| t.table_id.clone().map(|id| (t.name.clone(), id))).collect();
                    ids.sort();
                    ids
                };
                let current = match &file {
                    Some(f) => Some(f.tables(keys)?),
                    None => None,
                };
                if external && let Some(current) = &current {
                    // A name in both must have the same identity, or the file belongs to another database.
                    for (name, id) in current {
                        if wanted.iter().any(|(n, i)| n == name && i != id) {
                            return Err(ClError::Validation(
                                "the keys file does not belong to this database (a table has another identity)".into(),
                            ));
                        }
                    }
                }
                if current.as_ref() != Some(&wanted) {
                    key_file = Some(KeyFilePlan {
                        path: file_path,
                        bytes: keyfile::encode(&locked, &wanted, keys)?,
                        existed: file.is_some(),
                    });
                }
            }
        }

        // An encrypted database needs its main file open before anything else is written, because
        // that is what unlocks the key for the side files. (A plain database keeps its order.)
        let mut handle = handle;
        if handle.is_none() && input.redb.encryption.is_some() {
            handle = Some(DbHandle::create_with_events(
                &pending_path,
                input.durability,
                input.redb.clone(),
                "main",
                &input.event_sink,
            )?);
            pending.0 = Some(pending_path.clone());
            crate::fsutil::maybe_crash("create_after_pending");
        }
        let handle = handle;

        // The settings of the verification hashes must be the ones the table was made with. They
        // are not stored, only a keyed fingerprint of them, which needs the field hash key: the
        // keys of the field-only encryption, or those of the whole-database encryption now that
        // its main file is open. A program with the search key alone cannot compare and skips this.
        let check_keys = match (&field_keys, input.redb.encryption.as_ref().and_then(|e| e.context().cloned())) {
            (Some(keys), _) => Some(keys.clone()),
            (None, Some(context)) => Some(std::sync::Arc::new(crate::field_crypto::FieldKeys::with_context(context)?)),
            (None, None) => None,
        };
        // Keys carried over from earlier roots (see `field_crypto::carried`) are put in place before any
        // setting is compared with them; a field whose carried key is missing fails the open like any other failed open.
        if let (Some(keys), Some(open)) = (&check_keys, &handle) {
            let carried = crate::field_crypto::carried::load(open.get()?.raw(), keys)?;
            let tables: Vec<_> = input.tables.iter().map(|t| (t.name.as_str(), t.sealed)).collect();
            crate::field_crypto::carried::explain_all(&meta, &tables, keys, &carried, &input.event_sink)?;
        }
        if let Some(keys) = &check_keys {
            settle_hash_settings(&mut meta, input.tables, keys, inspection.kind == FileKind::New)?;
        }

        // A database encrypted as a whole that has protected fields: its lock is in the file header,
        // and the keys file keeps a copy of it with the table list, so the protected values and the
        // attachments can still be opened if the main file is lost.
        if input.field_encryption.is_none()
            && input.tables.iter().any(|t| !t.sealed.is_empty())
            && let (Some(keys), Some(context)) =
                (&check_keys, input.redb.encryption.as_ref().and_then(|e| e.context().cloned()))
        {
            use crate::field_crypto::keyfile;
            let file_path = keyfile::default_path(&db_dir, input.db_name);
            let file = keyfile::read_file(&file_path)?;
            let locked = context.locked_data_key().clone();
            if let Some(f) = &file
                && f.locked != locked
            {
                return Err(ClError::DataTampered);
            }
            let wanted: Vec<(String, String)> = {
                let mut ids: Vec<(String, String)> =
                    meta.tables.iter().filter_map(|t| t.table_id.clone().map(|id| (t.name.clone(), id))).collect();
                ids.sort();
                ids
            };
            let current = match &file {
                Some(f) => Some(f.tables(keys)?),
                None => None,
            };
            if current.as_ref() != Some(&wanted) {
                key_file = Some(KeyFilePlan {
                    path: file_path,
                    bytes: keyfile::encode(&locked, &wanted, keys)?,
                    existed: file.is_some(),
                });
            }
        }

        let mut format_opens = Vec::new();
        if let Some(ref bp) = backup_path {
            if bp.exists() && input.backup_enabled && meta.backup_format != BACKUP_FORMAT_V2 {
                let table_names: Vec<String> =
                    input.tables.iter().map(|t| t.name.to_string()).collect();
                let result = eager_normalize(
                    bp,
                    &table_names,
                    input.has_cache,
                    input.durability,
                    &input.redb,
                )?;
                format_opens = result.opens;
                if let Some(reason) = result.failure {
                    meta.push_log("backup_conversion_failed", Some(reason));
                    meta.backup_upgraded = false;
                } else {
                    meta.push_log(
                        "backup_normalize",
                        Some(format!("converted={}", result.entries_converted)),
                    );
                    meta.backup_upgraded = true;
                    meta.backup_format = BACKUP_FORMAT_V2.to_string();
                    meta.backup_pre_upgrade_path = None;
                }
            }
        }

        let refs_upgraded = if input.redb.encryption.is_some() {
            0 // an encrypted database is never of the old format
        } else {
            upgrade_migration_refs_with_durability(&migration_dir, input.durability)?
        };
        if refs_upgraded > 0 {
            meta.push_log(
                "migration_refs_upgrade",
                Some(format!("files_updated={refs_upgraded}")),
            );
        }

        let table_names: Vec<String> = input.tables.iter().map(|t| t.name.clone()).collect();
        let side_context = input.redb.encryption.as_ref().and_then(|e| e.context().cloned());
        let mut migration_index = DbMigrationIndex::load_with_encryption(
            &db_dir,
            input.db_name,
            &table_names,
            input.durability,
            side_context,
            &input.event_sink,
        )?;

        let mut table_layouts = HashMap::new();
        for reg in input.tables {
            migration_index.ensure_table_unpersisted(&reg.name, &reg.layout)?;
            table_layouts.insert(reg.name.clone(), reg.layout.clone());

            let chain = migration_index.table_chain(&reg.name)?;
            if let Some(tm) = meta.tables.iter_mut().find(|t| t.name == reg.name) {
                tm.schema_id = reg.name.clone();
                tm.schema_version = chain.current_version();
                tm.layout_hash = reg.layout.layout_hash.clone();
            }

            if inspection.kind != FileKind::New {
                if let Some(on_disk) = chain.read_layout(chain.current_version())? {
                    if on_disk.layout_hash != reg.layout.layout_hash
                        && chain.manifests.is_empty()
                    {
                        return Err(ClError::LayoutMismatch {
                            table: reg.name.clone(),
                            registered: reg.layout.layout_hash.clone(),
                            chain_version: chain.current_version(),
                        });
                    }
                }
            }
        }

        // The root index is written only now: a layout mismatch above returns before any migration file is touched.
        migration_index.persist_root()?;

        let mut plain_created = false;
        let handle = match handle {
            Some(handle) => handle,
            None => {
                plain_created = true;
                DbHandle::create(&primary_path, input.durability, input.redb.clone(), "main")?
            }
        };
        if plain_created {
            crate::fsutil::maybe_crash("create_plain_before_first_commit");
        }

        meta.upgrade_complete = true;
        meta.framework_version = env!("CARGO_PKG_VERSION").to_string();
        meta.push_log("upgrade_complete", None);
        // Every check has passed and nothing was written yet: the keys file goes first, so the main
        // file never holds a protected table whose keys are nowhere else (a file left behind by a
        // crash here is a superset, or a file no database claims, and is reported clearly).
        let keys_file_written = match &key_file {
            Some(plan) => {
                crate::field_crypto::keyfile::write_file(&plan.path, &plan.bytes, input.durability)?;
                Some((plan.path.clone(), plan.existed))
            }
            None => None,
        };
        let first_commit = (|| -> Result<()> {
            #[cfg(test)]
            if input.redb.encryption.is_some() && input.db_name == "hooked" && FAIL_AFTER_CREATE.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(ClError::Validation("injected failure after the file was created".into()));
            }
            let db = handle.get()?;
            let write_txn = db.begin_write()?;
            crate::journal::initialize(&write_txn)?;
            create_meta_table(&write_txn)?;
            // In the file-only form the main file holds no lock at all.
            if let Some(locked) = &new_locked_key
                && input.field_keys_file.is_none()
            {
                crate::field_crypto::keystore::write(&write_txn, locked)?;
            }
            put_meta(&write_txn, &meta)?;
            write_txn.commit()?;
            Ok(())
        })();
        // A new encrypted database that fails here is removed again by `Storage::build`, together
        // with everything else this call created. A keys file this call made is removed too.
        if first_commit.is_err()
            && let Some((path, false)) = &keys_file_written
        {
            let _ = std::fs::remove_file(path);
        }
        first_commit?;

        // The new encrypted file is complete: close it, make sure it is on disk, give it its real name, and only then is there a database.
        let handle = if pending.0.is_some() {
            crate::fsutil::maybe_crash("create_before_place");
            handle.close();
            fs::OpenOptions::new().write(true).open(&pending_path).and_then(|f| f.sync_all())?;
            place_new_file(&pending_path, &primary_path)?;
            pending.0 = None;
            crate::fsutil::maybe_crash("create_after_place");
            // best effort: not every system lets a folder be flushed
            let _ = sync_folder(&db_dir);
            crate::fsutil::maybe_crash("create_after_folder_sync");
            DbHandle::open_with_events(&primary_path, input.durability, input.redb.clone(), "main", &input.event_sink)?
        } else {
            handle
        };

        Ok(UpgradeOutput {
            meta,
            table_layouts,
            db: handle,
            format_opens,
            // A database encrypted as a whole hands over the keys it built too, with the carried keys
            // loaded, so the storage does not build a second set without them.
            field_keys: field_keys.or_else(|| check_keys.filter(|_| input.tables.iter().any(|t| !t.sealed.is_empty()))),
        })
    }
}

/// The file of a new encrypted database while it is being made; removed again if the build fails before it is complete.
struct PendingFile(Option<PathBuf>);

impl Drop for PendingFile {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = fs::remove_file(path);
        }
    }
}

fn remove_any(path: &Path) -> std::io::Result<()> {
    let result = if path.is_dir() { fs::remove_dir_all(path) } else { fs::remove_file(path) };
    match result {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// A process that died while a new encrypted database was being made leaves its half-made file under the pending name. There is no
/// database yet in that case, so everything else that attempt wrote (index, backup, migration and attachment folders and the keys file of protected fields, all under keys
/// of a file that is gone) is removed too, and the next build makes the database again as if it had never been started. The pending
/// file goes last: if this is cut short, the next open finds it and does the rest.
fn clear_interrupted_creation(
    input: &UpgradeInput<'_>,
    db_dir: &Path,
    primary_path: &Path,
    pending_path: &Path,
    backup_path: Option<&Path>,
    migration_dir: &Path,
) -> Result<()> {
    let mut temp_name = pending_path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    temp_name.push(".creating");
    let creating = pending_path.with_file_name(temp_name);
    if !pending_path.exists() && !creating.exists() {
        return Ok(());
    }
    if !primary_path.exists() {
        if let Some(backup) = backup_path {
            remove_any(backup)?;
        }
        remove_any(&db_dir.join(format!("{}.inx", input.db_name)))?;
        remove_any(migration_dir)?;
        remove_any(&crate::blob::blob_root(db_dir, input.db_name))?;
        // the keys file of protected fields next to the main file is part of the same attempt
        remove_any(&crate::field_crypto::keyfile::default_path(db_dir, input.db_name))?;
    }
    remove_any(&creating)?;
    remove_any(pending_path)?;
    Ok(())
}

/// Give the finished file its real name without replacing a file that is there (a hard link fails if the name is taken; where links are
/// not available the check is made right before the rename).
fn place_new_file(pending: &Path, primary: &Path) -> Result<()> {
    let taken = || ClError::IoError(format!("{} appeared while the database was being made", primary.display()));
    match fs::hard_link(pending, primary) {
        Ok(()) => {
            let _ = fs::remove_file(pending);
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(taken()),
        Err(_) => {
            if primary.exists() {
                return Err(taken());
            }
            fs::rename(pending, primary)?;
            Ok(())
        }
    }
}

/// Flush a folder, so that a file just given its name there is not lost with the power.
pub(crate) fn sync_folder(dir: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_BACKUP_SEMANTICS: needed to open a folder
        fs::OpenOptions::new().write(true).custom_flags(0x0200_0000).open(dir)?.sync_all()
    }
    #[cfg(not(windows))]
    {
        fs::File::open(dir)?.sync_all()
    }
}

fn resolve_file_era(inspection: &crate::metadata::DatabaseInspection) -> FileEra {
    inspection.file_era.unwrap_or_else(|| {
        if inspection.migration_exists {
            FileEra::Clove049
        } else if inspection.primary_exists {
            FileEra::Legacy042
        } else {
            FileEra::Current
        }
    })
}

fn build_meta(input: &UpgradeInput<'_>, file_era: FileEra) -> CloveMeta {
    let tables: Vec<TableMeta> = input
        .tables
        .iter()
        .map(|reg| TableMeta {
            name: reg.name.clone(),
            schema_id: reg.name.clone(),
            schema_version: 1,
            layout_hash: reg.layout.layout_hash.clone(),
            storage: reg.storage,
            table_id: None,
            sealed: Vec::new(),
        })
        .collect();

    let mut meta = CloveMeta::new(
        input.db_name,
        file_era,
        input.backup_enabled,
        input.blob_enabled,
        tables,
    );

    if input.backup_enabled {
        meta.backup_format = BackupFormat::JsonWrappedV2.as_str().to_string();
        meta.backup_upgraded = true;
    }

    meta
}

fn validate_tables(expected: &[String], found: &[String]) -> Result<()> {
    if found.is_empty() {
        return Ok(());
    }
    let missing: Vec<String> = expected
        .iter()
        .filter(|t| !found.contains(t))
        .cloned()
        .collect();
    if !missing.is_empty() {
        return Err(ClError::TableMismatch {
            expected: expected.to_vec(),
            found: found.to_vec(),
        });
    }
    Ok(())
}
