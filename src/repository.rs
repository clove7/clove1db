use redb::TableHandle;
// use crate::emitter::LogEventEmitter;
use crate::{
    backup::{
        view::{BackupRecordView, HistoryDisplayMode, RecordData},
        BackupManager, BackupOperation, BackupRecord,
    },
    blob::{BlobReader, BlobStore},
    durability::{DurabilityMode, DEFAULT_MAX_COMMIT_BATCH_ENTRIES},
    fsutil::maybe_crash,
    handle::{DbHandle, DbRef, FileOpen, RedbOptions},
    metadata::types::{CloveMeta, TableStorageMode, META_TABLE},
    migration::chain::DbMigrationIndex,
    migration::layout::FieldLayout,
    migration::step_registry::MigrationStepRegistry,
    metadata::store::{put_meta, read_meta},
    migration::types::MigrationManifest,
    units::{ClError, Result},
};
// use crate::units::{CACHE_IDLE_SECONDS, CACHE_MAX_CAPACITY, CACHE_TTL_SECONDS};
use chrono::{Datelike, Local};
use itertools::Itertools;
use moka::sync::Cache;
use redb::{ReadableTable, ReadableTableMetadata, TableDefinition};
// use std::env;
use crate::entity::Entity;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct DatabaseManager {
    pub(crate) indexes:Arc<crate::indexes::Shared>,
    // L1: In-memory cache (moka) for fast access
    pub memory_cache: Cache<String, Vec<u8>>,
    pub(crate) query_runtime:crate::query::optimizer::Shared,
    pub(crate) event_sink:crate::events::EventSink,
    pub(crate) slow_query_threshold:Duration,

    // L2: Persistent database (redb) for long-term storage. Shared by every
    // clone, so `close` on one closes it for all of them.
    db: Arc<DbHandle>,

    // L3: Backup manager (backup.rs) (optional)
    pub backup_manager: Option<BackupManager>,

    // Date
    pub date: Date,

    // Directory
    pub dir: Arc<Dir>,

    // Database name
    pub db_name: String,

    // Tables names
    pub tables_names: Vec<String>,

    // Has cache
    pub(crate) has_cache: bool,

    // Durability policy (independent of cache)
    durability: DurabilityMode,
    pub(crate) journal_retention:crate::journal::Retention,

    // Max entries per commit_batch chunk
    max_commit_batch_entries: usize,
    pub(crate) format_opens: Vec<FileOpen>,

    // Blob sidecar storage
    blob_enabled: bool,
    table_storage: std::collections::HashMap<String, TableStorageMode>,
    blob_store: Option<BlobStore>,

    // Per-table migration index
    migration_index: Arc<RwLock<DbMigrationIndex>>,

    // Shared decoder registry for history resolution
    migration_registry: Arc<MigrationStepRegistry>,
    /// How this database's files are opened; the index worker opens `.inx` with it.
    pub(crate) redb: RedbOptions,
    /// Tables registered with protected fields: raw byte writes to them are refused.
    pub(crate) sealed_tables: Arc<std::collections::HashSet<String>>,
    /// The keys of the protected fields, forgotten when the database is closed.
    pub(crate) field_keys: Option<Arc<crate::field_crypto::FieldKeys>>,
}

impl DatabaseManager {
    /// Serve a primary that is already open — `Storage::build` opens each file
    /// once, in the upgrade pipeline, and hands that handle over here.
    pub fn open(
        db: DbHandle,
        dir_path: &PathBuf,
        backup_dir_path: Option<&PathBuf>,
        dir_name: &str,
        db_name: &str,
        tables: Vec<String>,
        cache_max_bytes: u64,
        cache_ttl_seconds: u64,
        cache_idle_seconds: u64,
        has_cache: bool,
        blob_enabled: bool,
        table_storage: std::collections::HashMap<String, TableStorageMode>,
        table_layouts: std::collections::HashMap<String, FieldLayout>,
        migration_registry: Arc<MigrationStepRegistry>,
        durability: DurabilityMode,
        max_commit_batch_entries: usize,
        redb: RedbOptions,
    ) -> Result<Self> {
        Self::open_with_attachments(
            db, dir_path, backup_dir_path, dir_name, db_name, tables, cache_max_bytes, cache_ttl_seconds,
            cache_idle_seconds, has_cache, blob_enabled, table_storage, table_layouts, migration_registry,
            durability, max_commit_batch_entries, redb, None,
        )
    }

    /// [`Self::open`], also giving the keys and the identities of the tables with protected fields,
    /// so that their attachments are sealed with the keys of those fields from the first moment
    /// (the attachments are checked when the database opens).
    pub(crate) fn open_with_attachments(
        db: DbHandle,
        dir_path: &PathBuf,
        backup_dir_path: Option<&PathBuf>,
        dir_name: &str,
        db_name: &str,
        tables: Vec<String>,
        cache_max_bytes: u64,
        cache_ttl_seconds: u64,
        cache_idle_seconds: u64,
        has_cache: bool,
        blob_enabled: bool,
        table_storage: std::collections::HashMap<String, TableStorageMode>,
        table_layouts: std::collections::HashMap<String, FieldLayout>,
        migration_registry: Arc<MigrationStepRegistry>,
        durability: DurabilityMode,
        max_commit_batch_entries: usize,
        redb: RedbOptions,
        protected_attachments: Option<(Arc<crate::field_crypto::FieldKeys>, Arc<std::collections::HashMap<String, String>>)>,
    ) -> Result<Self> {
        for table in &tables { crate::journal::validate_table(table)?; }
        let dir = dir_path.join(dir_name);
        let backup_dir = if let Some(backup_dir_path) = backup_dir_path {
            Some(backup_dir_path.join(dir_name))
        } else {
            None
        };

        let dir_local = Arc::new(Dir::new(&dir, backup_dir.as_ref())?);

        let backup_db_path = if let Some(backup_dir) = &dir_local.backup_dir {
            Some(backup_dir.join(format!("{}.cldb.bak", db_name)))
        } else {
            None
        };

        let db = Arc::new(db);

        let backup_manager = if let Some(backup_db_path) = backup_db_path {
            // Backup was asked for. A history file that cannot be opened is an error, whatever the reason:
            // opening without it would silently stop recording history.
            match BackupManager::new(&backup_db_path, has_cache, durability, &redb) {
                Ok(backup_manager) => Some(backup_manager),
                Err(e @ ClError::DatabaseInUse { .. }) => return Err(e),
                Err(e) => return Err(ClError::BackupOpenFailed { path: backup_db_path.display().to_string(), reason: e.to_string() }),
            }
        } else {
            None
        };

        let db_ref = db.get()?;
        let write_txn = db_ref.begin_write()?;
        crate::journal::initialize(&write_txn)?;
        {
            let meta_table: TableDefinition<&str, &[u8]> = TableDefinition::new(META_TABLE);
            write_txn.open_table(meta_table)?;

            for table in &tables {
                {
                    let table_definition: TableDefinition<&str, &[u8]> =
                        TableDefinition::new(table);
                    write_txn.open_table(table_definition)?;
                }

                if let Some(ref backup_manager_ref) = backup_manager {
                    backup_manager_ref.init_table(table)?;
                }
            }
        }
        write_txn.commit()?;
        drop(db_ref);

        // Capacity is **bytes**, not entries.
        //
        // An entry count cannot bound memory: the value is a `Vec<u8>` of
        // whatever the caller stored, so "10,000 entries" is 10,000 times an
        // unknown: rows of 10 KB each make it 100 MiB. The number the operator
        // wrote would be a count; the number that matters is a size, and
        // nothing connects the two.
        //
        // A weigher connects them. `max_capacity` then means what an operator
        // actually wants to control, and a row being large costs proportionally
        // more of the budget instead of exactly as much as an empty one.
        let memory_cache = Cache::builder()
            .max_capacity(cache_max_bytes)
            .weigher(|key: &String, value: &Vec<u8>| -> u32 {
                // Key included: a cache of tiny values under long keys is still
                // memory. Saturating, because the weight type is `u32` and a
                // single value may legitimately be larger than that — such an
                // entry simply costs the whole budget, which is the correct
                // outcome for something that big.
                key.len().saturating_add(value.len()).min(u32::MAX as usize) as u32
            })
            .time_to_live(Duration::from_secs(cache_ttl_seconds))
            .time_to_idle(Duration::from_secs(cache_idle_seconds))
            .build();

        let now = Local::now();
        let date = Date {
            day: now.day(),
            month: now.month(),
            year: now.year() as u32,
        };

        let mut migration_index = DbMigrationIndex::load_with_encryption(
            &dir_local.dir,
            db_name,
            &tables,
            durability,
            redb.encryption.as_ref().and_then(|e| e.context().cloned()),
            &crate::events::EventSink::default(),
        )?;
        for (table, layout) in &table_layouts {
            migration_index.ensure_table(table, layout)?;
        }

        let migration_index = Arc::new(RwLock::new(migration_index));

        let blob_store = if blob_enabled {
            let store = match redb.encryption.as_ref().and_then(|e| e.context()) {
                Some(context) => BlobStore::with_encryption(dir_local.dir.as_path(), db_name, context.clone()),
                None => BlobStore::new(dir_local.dir.as_path(), db_name),
            };
            let store = match protected_attachments {
                Some((keys, ids)) if !ids.is_empty() => {
                    store.with_protected(keys as Arc<dyn crate::encrypted_store::FileKeys>, ids)
                }
                _ => store,
            };
            store.ensure_root()?;
            for table in &tables {
                if table_storage.get(table).copied() == Some(TableStorageMode::BlobSidecar) && !store.is_unreadable(table) {
                    store.ensure_table(table)?;
                }
            }
            Some(store)
        } else {
            None
        };

        let manager=Self {
            indexes:Arc::new(Default::default()),
            memory_cache,
            query_runtime:Arc::new(std::sync::Mutex::new(Default::default())),
            event_sink:Default::default(),
            slow_query_threshold:Duration::from_millis(50),
            db: db,
            backup_manager,
            date,
            dir: dir_local,
            db_name: db_name.to_string(),
            tables_names: tables,
            has_cache,
            durability,
            journal_retention:crate::journal::Retention::Default,
            max_commit_batch_entries: max_commit_batch_entries.max(1),
            format_opens: Vec::new(),
            sealed_tables: Arc::new(std::collections::HashSet::new()),
            field_keys: None,
            blob_enabled,
            table_storage,
            blob_store,
            migration_index,
            migration_registry,
            redb,
        };
        manager.reconcile_blobs()?;
        Ok(manager)
    }

    #[deprecated(note = "use DatabaseManager::open")]
    pub fn new(
        dir_path: &PathBuf,
        backup_dir_path: Option<&PathBuf>,
        dir_name: &str,
        db_name: &str,
        tables: Vec<String>,
        cache_max_bytes: u64,
        cache_ttl_seconds: u64,
        cache_idle_seconds: u64,
        has_cache: bool,
        blob_enabled: bool,
        table_storage: std::collections::HashMap<String, TableStorageMode>,
        table_layouts: std::collections::HashMap<String, FieldLayout>,
        migration_registry: Arc<MigrationStepRegistry>,
    ) -> Result<Self> {
        for table in &tables { crate::journal::validate_table(table)?; }
        let dir = dir_path.join(dir_name);
        fs::create_dir_all(&dir)?;
        let db_path = dir.join(format!("{}.cldb", db_name));
        let redb = RedbOptions::default();
        let db = DbHandle::create(&db_path, DurabilityMode::Strict, redb.clone(), "main")?;
        Self::open(
            db,
            dir_path,
            backup_dir_path,
            dir_name,
            db_name,
            tables,
            cache_max_bytes,
            cache_ttl_seconds,
            cache_idle_seconds,
            has_cache,
            blob_enabled,
            table_storage,
            table_layouts,
            migration_registry,
            DurabilityMode::Strict,
            DEFAULT_MAX_COMMIT_BATCH_ENTRIES,
            redb,
        )
    }

    pub fn blob_enabled(&self) -> bool {
        self.blob_enabled
    }

    pub fn table_storage_mode(&self, table: &str) -> TableStorageMode {
        self.table_storage
            .get(table)
            .copied()
            .unwrap_or(TableStorageMode::InlineJson)
    }

    pub fn is_blob_table(&self, table: &str) -> bool {
        self.table_storage_mode(table) == TableStorageMode::BlobSidecar
    }

    pub(crate) fn blob_store(&self) -> Result<&BlobStore> {
        self.blob_store.as_ref().ok_or_else(|| {
            ClError::Validation("blob storage not enabled on this database".into())
        })
    }

    pub fn write_blob(&self, table: &str, id: &str, data: &[u8]) -> Result<()> {
        self.publish_blob(table,id,data,None)
    }

    pub fn durability(&self) -> DurabilityMode {
        self.durability
    }

    /// The open `.cldb`, or [`ClError::Closed`].
    ///
    /// Only snapshot reads are exposed. User writes use the journaled methods.
    /// Hold the handle for one operation; see
    /// [`DbHandle::get`].
    /// Query a registered raw table using an entity representation chosen by the caller.
    pub fn query<E:Entity>(&self,table:&str)->Result<crate::query::Query<E>> {
        if !self.tables_names.iter().any(|t|t==table){return Err(ClError::Validation("query table is not registered".into()))}
        Ok(crate::query::Query::new(self.clone(),table.into()))
    }
    pub fn db(&self) -> Result<DbRef<'_>> {
        self.db.get()
    }

    /// Read `_clove_meta`.
    pub fn read_meta(&self) -> Result<Option<CloveMeta>> {
        read_meta(self.db()?.raw())
    }

    /// Write `_clove_meta` with this database's commit policy.
    ///
    /// Use this rather than `metadata::write_meta(&db, ..)`: that one commits
    /// without quick repair, and redb judges the next open by the last commit.
    pub fn write_meta(&self, meta: &CloveMeta) -> Result<()> {
        let db = self.db()?;
        let write_txn = db.begin_write()?;
        put_meta(&write_txn, meta)?;
        write_txn.commit()?;
        Ok(())
    }

    /// Close this database: the `.cldb` and, when backup is enabled, its
    /// `.cldb.bak`. Every clone shares the files, so they are closed for all of
    /// them, and every later call returns [`ClError::Closed`].
    ///
    /// Waits for operations already running. Returns `false` if the primary
    /// was already closed.
    pub fn close(&self) -> bool {
        let was_open = self.db.close();
        if let Some(bm) = &self.backup_manager {
            bm.close();
        }
        if let Some(keys) = &self.field_keys {
            keys.clear();
        }
        was_open
    }

    pub fn is_closed(&self) -> bool {
        self.db.is_closed()
    }

    /// A checker of secrets against the verification hashes of this database (passwords, codes).
    /// It opens no value; every check is reported to the event sink.
    pub fn verifier(&self) -> Result<crate::field_crypto::Verifier> {
        drop(self.db()?);
        match &self.field_keys {
            Some(keys) => Ok(crate::field_crypto::Verifier::new(keys.clone(), self.event_sink.clone())),
            None => Err(ClError::Validation("this database has no protected fields".into())),
        }
    }

    /// A permission to open protected values of this database, for the request in hand. The
    /// application decides who may have one; every use is reported to the event sink.
    pub fn read_grant(&self) -> Result<crate::field_crypto::ReadGrant> {
        drop(self.db()?);
        match &self.field_keys {
            Some(keys) => Ok(crate::field_crypto::ReadGrant::new(keys.clone(), self.event_sink.clone())),
            None => Err(ClError::Validation("this database has no protected fields".into())),
        }
    }

    /// How this database's files opened: the `.cldb`, then its `.cldb.bak`
    /// when backup is enabled.
    pub(crate) fn opened_files(&self) -> Vec<&FileOpen> {
        std::iter::once(self.db.opened())
            .chain(self.backup_manager.as_ref().map(BackupManager::opened))
            .chain(self.format_opens.iter())
            .collect()
    }

    pub fn open_blob(&self, table: &str, id: &str) -> Result<BlobReader> {
        self.open_current_blob(table,id)
    }

    pub fn delete_blob(&self, table: &str, id: &str) -> Result<bool> {
        let removed=self.apply_changes(&[],&[(table.into(),id.into())])?;
        Ok(removed[0])
    }

    pub fn copy_blob(
        &self,
        table: &str,
        id: &str,
        dest: &DatabaseManager,
        dest_table: &str,
        dest_id: &str,
    ) -> Result<()> {
        self.copy_current_blob(table,id,dest,dest_table,dest_id)
    }

    pub fn blobs_root(&self) -> Option<PathBuf> {
        if self.blob_enabled {
            Some(crate::blob::blobs_root(&self.dir.dir, &self.db_name))
        } else {
            None
        }
    }

    pub fn migration_index(&self) -> Result<std::sync::RwLockReadGuard<'_, DbMigrationIndex>> {
        self.migration_index
            .read()
            .map_err(|_| ClError::MigrationError("migration index lock poisoned".into()))
    }


    /// Rows in the table, from redb's own count. It used to copy every key and
    /// value (`list_entries`) only to take the length.
    pub fn count_keys(&self, table: &str) -> Result<usize> {
        let definition: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(table);
        let db = self.db()?;
        let read_txn = db.begin_read()?;
        let table_ref = read_txn.open_table(definition)?;
        Ok(usize::try_from(table_ref.len()?).unwrap_or(usize::MAX))
    }

    pub fn table_layout(&self, table: &str) -> Result<FieldLayout> {
        let guard = self.migration_index()?;
        let chain = guard.table_chain(table)?;
        // Goes through the chain so a sealed layout file is read (and a changed one is an error).
        if let Some(layout) = chain.read_layout(chain.current_version())? {
            return Ok(layout);
        }
        Ok(FieldLayout::from_json_value(&serde_json::json!({})))
    }

    pub fn rewrite_backup_table(&self, from_table: &str, to_table: &str) -> Result<()> {
        let Some(ref bm) = self.backup_manager else {
            return Ok(());
        };
        bm.rewrite_table_name(from_table, to_table)
    }

    pub fn migration_registry(&self) -> &MigrationStepRegistry {
        &self.migration_registry
    }

    pub fn append_migration(
        &self,
        table: &str,
        manifest: MigrationManifest,
        snapshot: Option<&[(String, Vec<u8>)]>,
        new_layout: Option<&FieldLayout>,
    ) -> Result<()> {
        let mut index = self
            .migration_index
            .write()
            .map_err(|_| ClError::MigrationError("migration index lock poisoned".into()))?;
        index.append_manifest(table, manifest, snapshot, new_layout)?;

        if let Ok(Some(mut meta)) = self.read_meta() {
            if let Some(tm) = meta.tables.iter_mut().find(|t| t.name == table) {
                tm.schema_version = index.table_chain(table)?.current_version();
                if let Some(layout) = new_layout {
                    tm.layout_hash = layout.layout_hash.clone();
                }
            }
            meta.framework_version = env!("CARGO_PKG_VERSION").to_string();
            self.write_meta(&meta)?;
        }
        Ok(())
    }

    /// Every `(key, value)` in the table.
    ///
    /// A read error is returned, not skipped — see [`Self::list`] for why a
    /// silently short list is the worst of the available outcomes.
    pub fn list_entries(&self, table_name: &str) -> Result<Vec<(String, Vec<u8>)>> {
        let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(table_name);
        let db = self.db()?;
        let read_txn = db.begin_read()?;
        let table_ref = read_txn.open_table(table)?;
        table_ref
            .iter()?
            .map(|row| {
                let (k, v) = row?;
                Ok((k.value().to_string(), v.value().to_vec()))
            })
            .collect()
    }

    pub fn get_raw(&self, table_name: &str, key: &str) -> Result<Option<Vec<u8>>> {
        let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(table_name);
        self.get(table, table_name, key)
    }

    pub fn delete_raw(&self, table_name: &str, key: &str) -> Result<()> {
        let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(table_name);
        self.delete(table, table_name, key)?;
        Ok(())
    }

    /// Commit every write and delete in one transaction, regardless of the batch limit.
    /// Cache changes are applied only after the transaction commits. Like `commit_batch`,
    /// this raw API does not create backup history records.
    pub fn commit_batch_atomic(
        &self,
        writes: &[(String, String, Vec<u8>)],
        deletes: &[(String, String)],
    ) -> Result<()> {
        self.refuse_sealed(writes.iter().map(|r| r.0.as_str()))?;
        self.apply_changes(writes,deletes).map(|_|())
    }

    /// Fails when one of `tables` was registered with protected fields: raw bytes cannot be sealed,
    /// so such a table is written through its entity.
    /// A program that opened the database with the search key alone only reads: every write is
    /// refused, also the rewrite of a row with its protected values unchanged.
    fn ensure_writable(&self) -> Result<()> {
        if self.field_keys.as_ref().is_some_and(|keys| keys.is_search_only()) {
            return Err(ClError::Validation(
                "this program holds only the search key, so the database is read-only; open it with the read key to write".into(),
            ));
        }
        Ok(())
    }

    fn refuse_sealed<'a>(&self, tables: impl IntoIterator<Item = &'a str>) -> Result<()> {
        if self.sealed_tables.is_empty() {
            return Ok(());
        }
        for table in tables {
            if self.sealed_tables.contains(table) {
                return Err(ClError::Validation(
                    "a table with protected fields is written through its entity (`Repository::set` or `commit_entities`), not with raw bytes".into(),
                ));
            }
        }
        Ok(())
    }

    /// Commit raw changes in bounded transactions. Batches larger than the configured
    /// limit may leave a committed prefix on failure; writes precede deletes.
    /// This API does not create backup history records.
    pub fn commit_batch(
        &self,
        writes: &[(String, String, Vec<u8>)],
        deletes: &[(String, String)],
    ) -> Result<()> {
        self.refuse_sealed(writes.iter().map(|r| r.0.as_str()))?;
        self.commit_batch_prepared(writes, deletes)
    }

    /// `commit_batch` for bytes that are already in their stored form (rows sealed by their entity).
    pub(crate) fn commit_batch_prepared(
        &self,
        writes: &[(String, String, Vec<u8>)],
        deletes: &[(String, String)],
    ) -> Result<()> {
        let limit = self.max_commit_batch_entries;
        let total = writes.len() + deletes.len();
        if total > limit {
            let mut w_offset = 0usize;
            while w_offset < writes.len() {
                let end = (w_offset + limit).min(writes.len());
                self.commit_batch_chunk(&writes[w_offset..end], &[])?;
                w_offset = end;
            }
            let mut d_offset = 0usize;
            while d_offset < deletes.len() {
                let end = (d_offset + limit).min(deletes.len());
                self.commit_batch_chunk(&[], &deletes[d_offset..end])?;
                d_offset = end;
            }
            return Ok(());
        }
        self.commit_batch_chunk(writes, deletes)
    }

    fn commit_batch_chunk(
        &self,
        writes: &[(String, String, Vec<u8>)],
        deletes: &[(String, String)],
    ) -> Result<()> {
        self.apply_changes(writes,deletes).map(|_|())
    }

    pub(crate) fn journal_write<T>(&self,f:impl FnOnce(&redb::WriteTransaction,&mut Vec<crate::journal::ChangeKind>)->Result<T>)->Result<T> {crate::journal::write_with_sink(&self.db()?,self.journal_retention,&self.event_sink,f)}

    fn apply_changes(&self, writes:&[(String,String,Vec<u8>)], deletes:&[(String,String)])->Result<Vec<bool>> {
        for table in writes.iter().map(|r|r.0.as_str()).chain(deletes.iter().map(|r|r.0.as_str())) {crate::journal::validate_table(table)?;}
        let db=self.db()?;
        self.ensure_writable()?;
        let removed=crate::journal::write_with_sink(&db,self.journal_retention,&self.event_sink,|tx,changes| {
            maybe_crash("before_commit");
            // The journal row holds its own copy of every value: reserve all of it before the first write.
            crate::memory::reserve("write.change_rows",changes,writes.len()+deletes.len())?;
            for (table,key,value) in writes {
                if self.is_blob_table(table)&&crate::journal_blob::get(tx,table,key)?.is_none(){return Err(ClError::Validation("blob metadata requires set_with_blob or a previously written blob".into()))}
                let copy=crate::memory::copy_bytes("write.change_rows",value)?;
                tx.open_table(TableDefinition::<&str,&[u8]>::new(table))?.insert(key.as_str(),value.as_slice())?;
                changes.push(crate::journal::ChangeKind::Upsert{table:table.clone(),key:key.clone(),value:copy});
            }
            let mut removed=Vec::new();
            for (table,key) in deletes {
                let exists=tx.open_table(TableDefinition::<&str,&[u8]>::new(table))?.remove(key.as_str())?.is_some();
                if exists { changes.push(crate::journal::ChangeKind::Delete{table:table.clone(),key:key.clone()}); }
                let blob=if self.is_blob_table(table) {crate::journal_blob::remove(tx,table,key,changes)?} else {false};
                removed.push(exists||blob);
            }
            Ok(removed)
        })?;
        maybe_crash("after_commit");
        if self.has_cache {
            for (table,key,value) in writes {self.memory_cache.insert(format!("{table}:{key}"),value.clone());}
            for (table,key) in deletes {self.memory_cache.invalidate(&format!("{table}:{key}"));}
        }
        Ok(removed)
    }

    /// Atomically publish a full replacement and one immutable TableReset image.
    pub fn replace_table(&self,table:&str,entries:&[(String,Vec<u8>)])->Result<()> {
        self.refuse_sealed([table])?;
        self.ensure_writable()?;
        crate::journal::validate_table(table)?;
        let db=self.db()?;
        crate::journal::write_with_sink(&db,self.journal_retention,&self.event_sink,|tx,changes| {
            tx.delete_table(TableDefinition::<&str,&[u8]>::new(table))?;
            {let mut target=tx.open_table(TableDefinition::<&str,&[u8]>::new(table))?;for (k,v) in entries {target.insert(k.as_str(),v.as_slice())?;}}
            self.validate_blob_rows(tx,table,changes)?;
            Self::capture_reset(tx,table,changes)
        })?;self.clear_cache();Ok(())
    }

    fn capture_reset(tx:&redb::WriteTransaction,table:&str,changes:&mut Vec<crate::journal::ChangeKind>)->Result<()> {
        let generation=crate::journal::number(tx,"reset_generation")?.checked_add(1).ok_or_else(||ClError::Validation("reset generation exhausted".into()))?;
        crate::journal::put_number(tx,"reset_generation",generation)?;
        let snapshot=format!("__reset_{generation}");
        {let source=tx.open_table(TableDefinition::<&str,&[u8]>::new(table))?;let mut target=tx.open_table(TableDefinition::<&str,&[u8]>::new(&snapshot))?;for row in source.iter()? {let(k,v)=row?;target.insert(k.value(),v.value())?;}}
        maybe_crash("journal_during_reset");
        {let refs=tx.open_table(crate::journal_blob::REFS)?;let mut out=tx.open_table(TableDefinition::<&str,&[u8]>::new(&format!("{snapshot}_blobs")))?;for row in refs.iter()? {let(k,v)=row?;let(t,_):(String,String)=serde_json::from_str(k.value())?;if t==table {out.insert(k.value(),v.value())?;}}}
        changes.push(crate::journal::ChangeKind::TableReset{table:table.into(),snapshot});Ok(())
    }

    /// Migration delta: preserve unaffected rows, publish each changed table once.
    pub fn rewrite_tables(&self,writes:&[(String,String,Vec<u8>)],deletes:&[(String,String)])->Result<()> {
        self.refuse_sealed(writes.iter().map(|r| r.0.as_str()))?;
        self.rewrite_tables_with_blobs(writes,deletes,&[],&[])
    }
    pub(crate) fn rewrite_tables_with_blobs(&self,writes:&[(String,String,Vec<u8>)],deletes:&[(String,String)],blobs:&[(String,String,Vec<u8>)],copies:&[(String,String,DatabaseManager,String,String)])->Result<()> {
        self.ensure_writable()?;
        let mut prepared=Vec::new();for (t,k,v) in blobs {prepared.push((t,k,self.prepare_blob(t,k,v)?));}
        for (table,key,source,source_table,source_key) in copies {prepared.push((table,key,self.prepare_copy_from(source,source_table,source_key,table,key)?));}
        let tables=writes.iter().map(|r|r.0.as_str()).chain(deletes.iter().map(|r|r.0.as_str())).collect::<std::collections::BTreeSet<_>>();
        for table in &tables {crate::journal::validate_table(table)?;}
        let db=self.db()?;
        crate::journal::write_with_sink(&db,self.journal_retention,&self.event_sink,|tx,changes| {
            for (table,key) in deletes {tx.open_table(TableDefinition::<&str,&[u8]>::new(table))?.remove(key.as_str())?;if self.is_blob_table(table){crate::journal_blob::remove(tx,table,key,changes)?;}}
            for (table,key,reference) in &prepared {crate::journal_blob::put(tx,table,key,reference,changes)?;}
            for (table,key,value) in writes {tx.open_table(TableDefinition::<&str,&[u8]>::new(table))?.insert(key.as_str(),value.as_slice())?;}
            for table in &tables {self.validate_blob_rows(tx,table,changes)?;Self::capture_reset(tx,table,changes)?;}Ok(())
        })?;self.clear_cache();Ok(())
    }

    /// Write-Through: Write to both cache and DB. Raw bytes are refused for a table with
    /// protected fields.
    /// Write-Through: Write to both cache and DB
    pub fn set<'db>(
        &self,
        table: TableDefinition<'db, &str, &[u8]>,
        table_name: &str,
        key: &str,
        value: Vec<u8>,
    ) -> Result<()> {
        self.refuse_sealed([table_name])?;
        self.set_prepared(table, table_name, key, value)
    }

    /// `set` for bytes that are already in their stored form.
    pub(crate) fn set_prepared<'db>(
        &self,
        table: TableDefinition<'db, &str, &[u8]>,
        table_name: &str,
        key: &str,
        value: Vec<u8>,
    ) -> Result<()> {
        if table.name()!=table_name {return Err(ClError::Validation("table name mismatch".into()))}
        // The journal and the backup history each keep a copy of the row. The history copy is
        // reserved for before the commit, so that refusing it leaves the database as it was.
        if self.backup_manager.is_some() {
            crate::memory::probe("backup.encode_record", value.len().saturating_mul(2).saturating_add(1024))?;
        }
        let journal_copy=crate::memory::copy_bytes("write.single_row",&value)?;
        self.apply_changes(&[(table_name.into(),key.into(),journal_copy)],&[])?;

        if let Some(ref bm) = self.backup_manager {
            bm.record_set(table, table_name, key, value)?;
        }

        Ok(())
    }

    /// Read with Cache-Aside pattern
    pub fn get<'db>(
        &self,
        table: TableDefinition<'db, &str, &[u8]>,
        table_name: &str,
        key: &str,
    ) -> Result<Option<Vec<u8>>> {
        let cache_key = format!("{}:{}", table_name, key);

        // Taken before the cache, so a closed database is closed for cached
        // keys too rather than answering some reads and failing others.
        let db = self.db()?;

        // Step 1: Check memory cache first (L1)
        if self.has_cache
            && let Some(value) = self.memory_cache.get(&cache_key)
        {
            return Ok(Some(value));
        }

        // Step 2: Cache miss - read from database (L2)
        let read_txn = db.begin_read()?;
        let table_ref = read_txn.open_table(table)?;

        match table_ref.get(key)? {
            Some(value) => {
                let data: Vec<u8> = value.value().to_vec();

                // Step 3: Update cache for next time
                if self.has_cache {
                    self.memory_cache.insert(cache_key, data.clone());
                }

                Ok(Some(data))
            }
            None => Ok(None),
        }
    }

    /// Read one key **without touching the cache** — no lookup, no insert.
    ///
    /// For bulk reads: a range scan, a report, an export. Those walk many keys
    /// once and never read them again, so routing them through [`Self::get`]
    /// does two kinds of damage. It fills the cache with rows that will not be
    /// reused, and in doing so evicts the small hot rows that were the reason
    /// to have a cache at all — the scan pays nothing and the workload that
    /// follows pays for it.
    ///
    /// Use [`Self::get`] for a key you expect to read again, and this for a key
    /// you are walking past.
    pub fn get_uncached<'db>(
        &self,
        table: TableDefinition<'db, &str, &[u8]>,
        key: &str,
    ) -> Result<Option<Vec<u8>>> {
        let db = self.db()?;
        let read_txn = db.begin_read()?;
        let table_ref = read_txn.open_table(table)?;
        Ok(table_ref.get(key)?.map(|v| v.value().to_vec()))
    }

    /// Bytes currently held by the cache, and how many entries hold them.
    ///
    /// Returns `(bytes, entries)`, and `(0, 0)` when the database has no cache.
    /// Call [`Self::run_cache_maintenance`] first if you want the figure to
    /// exclude entries that have expired but not yet been reclaimed.
    pub fn cache_stats(&self) -> (u64, u64) {
        if !self.has_cache {
            return (0, 0);
        }
        (
            self.memory_cache.weighted_size(),
            self.memory_cache.entry_count(),
        )
    }

    /// Reclaim entries whose TTL or idle window has passed.
    ///
    /// `moka` expires entries on a clock but frees them during maintenance, and
    /// maintenance runs when the cache is *used*. A cache nobody touches
    /// therefore keeps every expired entry resident indefinitely — hours past
    /// its TTL, until the next read happens to run housekeeping.
    ///
    /// That is correct behaviour for a cache and surprising for an operator
    /// watching a memory graph, so this makes it something a caller can ask for
    /// — from a idle-time hook, a maintenance tick, or before reporting memory.
    pub fn run_cache_maintenance(&self) {
        if self.has_cache {
            self.memory_cache.run_pending_tasks();
        }
    }

    /// Drop every cached entry for this database.
    pub fn clear_cache(&self) {
        if self.has_cache {
            self.memory_cache.invalidate_all();
            self.memory_cache.run_pending_tasks();
        }
    }

    /// Every value in the table.
    ///
    /// # A read error is returned, never skipped
    ///
    /// This used to `filter_map` the iterator and drop any `Err`, so a row that
    /// could not be read simply was not in the result — a short list with no
    /// indication that it was short. For a caller listing rows to count them,
    /// display them, or decide what to migrate, that is silent data loss, and
    /// the shape of the bug guarantees nobody notices: the failure mode is
    /// *missing* data, not wrong data.
    ///
    /// It also interacted badly with redb. Before redb 4.3.0 an iterator that
    /// yielded `Err(Corrupted)` could go on yielding the rest of the table,
    /// skipping unreadable entries without erroring again; paired with a
    /// `filter_map` that swallowed the error, a corrupted page turned into a
    /// quietly incomplete list. redb now keeps returning the error, and so does
    /// this.
    pub fn list<'db>(&self, table: TableDefinition<'db, &str, &[u8]>) -> Result<Vec<Vec<u8>>> {
        // read from database (L2)
        let db = self.db()?;
        let read_txn = db.begin_read()?;
        let table_ref = read_txn.open_table(table)?;

        table_ref
            .iter()?
            .map(|row| {
                let (_key, value) = row?;
                Ok(value.value().to_vec())
            })
            .collect()
    }

    /// Delete from both cache and DB
    pub fn delete<'db>(
        &self,
        table: TableDefinition<'db, &str, &[u8]>,
        table_name: &str,
        key: &str,
    ) -> Result<bool> {
        if table.name()!=table_name {return Err(ClError::Validation("table name mismatch".into()))}
        let found=self.apply_changes(&[],&[(table_name.into(),key.into())])?[0];

        if found {
            if let Some(ref bm) = self.backup_manager {
                // Step 3: Record delete to backup (L3)
                bm.record_delete(table, table_name, key)?;
            }
        }

        Ok(found)
    }

    pub fn restore_by_version<'db>(
        &self,
        table: TableDefinition<'db, &str, &[u8]>,
        table_name: &str,
        key: &str,
        version: u64,
    ) -> Result<()> {
        let bm = self
            .backup_manager
            .as_ref()
            .ok_or_else(|| ClError::NotFound("backup not configured".into()))?;

        if let Ok(index) = self.migration_index() {
            if let Ok(chain) = index.table_chain(table_name) {
                BackupManager::assert_restorable(chain, version)?;
            }
        }

        // Read the specified record directly
        let backup_key = format!("{}:{}", key, version);
        let record = {
            let bdb = bm.db()?;
            let read_txn = bdb.begin_read()?;
            let tbl = read_txn.open_table(table)?;
            tbl.get(backup_key.as_str())?
                .map(|v| crate::backup::codec::decode_record(table.name(), &backup_key, v.value()))
                .transpose()?
                .ok_or_else(|| ClError::NotFound(format!("version {} not found", version)))?
        };

        match record.operation {
            // Set or Restore → Write data to Primary + Cache + Backup
            BackupOperation::Set | BackupOperation::Restore | BackupOperation::RestoreBulk => {
                let data = record.data;

                if data.is_some() {
                    let data = data.clone().ok_or_else(|| ClError::OptionNone)?;
                    self.apply_changes(&[(table_name.into(),key.into(),data.clone())],&[])?;

                    // Cache
                    if self.has_cache {
                        let cache_key = format!("{}:{}", table_name, key);
                        self.memory_cache.insert(cache_key, data.clone());
                    }
                }

                // A Restore/RestoreBulk with no data represents an absent row.
                if data.is_none() {
                    self.apply_changes(&[],&[(table_name.into(),key.into())])?;
                    if self.has_cache {self.memory_cache.invalidate(&format!("{table_name}:{key}"));}
                }

                // Backup record_restore
                bm.record_restore(table, table_name, key, version, data, record.bulk_id)?;
            }

            // Delete → Delete from Primary + Cache + log restore with None
            BackupOperation::Delete => {
                self.apply_changes(&[],&[(table_name.into(),key.into())])?;

                if self.has_cache {
                    let cache_key = format!("{}:{}", table_name, key);
                    self.memory_cache.invalidate(&cache_key);
                }

                bm.record_restore(table, table_name, key, version, None, None)?;
            }
        }

        Ok(())
    }

    pub fn get_by_version<'db>(
        &self,
        table: TableDefinition<'db, &str, &[u8]>,
        key: &str,
        version: u64,
    ) -> Result<BackupRecord> {
        let backup_key = format!("{}:{}", key, version);
        let bdb = self
            .backup_manager
            .as_ref()
            .ok_or_else(|| ClError::OptionNone)?
            .db()?;
        let read_txn = bdb.begin_read()?;
        let tbl = read_txn.open_table(table)?;

        let record = tbl
            .get(backup_key.as_str())?
            .map(|v| crate::backup::codec::decode_record(table.name(), &backup_key, v.value()))
            .transpose()?
            .ok_or_else(|| ClError::NotFound(format!("version {} not found", version)));

        drop(read_txn);

        record
    }

    pub fn restore_at<'db>(
        &self,
        table: TableDefinition<'db, &str, &[u8]>,
        table_name: &str,
        key: &str,
        timestamp: i64,
    ) -> Result<()> {
        let bm = self
            .backup_manager
            .as_ref()
            .ok_or_else(|| ClError::NotFound("backup not configured".into()))?;

        // Search for the last record before the timestamp
        let record = bm
            .history(table, key)?
            .into_iter()
            .filter(|r| r.timestamp <= timestamp)
            .last()
            .ok_or_else(|| ClError::NotFound("no record at this timestamp".into()))?;

        let target_version = record.version;

        // Same logic as restore_by_version
        self.restore_by_version(table, table_name, key, target_version)
    }

    pub fn get_version_by_at<'db>(
        &self,
        table: TableDefinition<'db, &str, &[u8]>,
        key: &str,
        timestamp: i64,
    ) -> Result<BackupRecord> {
        let bm = self
            .backup_manager
            .as_ref()
            .ok_or_else(|| ClError::NotFound("backup not configured".into()))?;

        // Search for the last record before the timestamp
        bm.history(table, key)?
            .into_iter()
            .filter(|r| r.timestamp <= timestamp)
            .last()
            .ok_or_else(|| ClError::NotFound("no record at this timestamp".into()))
    }

    pub fn set_bulk<'db>(&self, table_name: &str, entries: Vec<(String, u64)>) -> Result<String> {
        self.ensure_writable()?;
        let bm = self
            .backup_manager
            .as_ref()
            .ok_or_else(|| ClError::NotFound("backup not configured".into()))?;
        bm.write_bulk(table_name, entries)
    }

    pub fn restore_bulk<'db>(
        &self,
        table: TableDefinition<'db, &str, &[u8]>,
        table_name: &str,
        bulk_id: &str,
    ) -> Result<()> {
        let bm = self
            .backup_manager
            .as_ref()
            .ok_or_else(|| ClError::NotFound("backup not configured".into()))?;

        let bulk_entries = {
            let bulk_name = format!("{}_bulk", table_name);
            let bulk_table: TableDefinition<&str, &[u8]> = TableDefinition::new(bulk_name.as_str());
            let bdb = bm.db()?;
            let read_txn = bdb.begin_read()?;
            let btbl = read_txn.open_table(bulk_table)?;
            let bulk_data = btbl
                .get(bulk_id)?
                .ok_or_else(|| ClError::NotFound(format!("bulk_id {} not found", bulk_id)))?;
            let bulk: crate::backup::BulkRecord = serde_json::from_slice(bulk_data.value())?;
            bulk.entries
        };

        if let Ok(index) = self.migration_index() {
            if let Ok(chain) = index.table_chain(table_name) {
                for entry in &bulk_entries {
                    BackupManager::assert_restorable(chain, entry.version)?;
                }
            }
        }

        let results = bm.restore_bulk(table, table_name, bulk_id)?;

        for (key,data) in results {
            match data {
                Some(value)=>{self.apply_changes(&[(table_name.into(),key,value)],&[])?;},
                None=>{self.apply_changes(&[],&[(table_name.into(),key)])?;}
            }
        }

        Ok(())
    }

    pub fn current_version<'db>(&self, table_name: &str, id: &str) -> Result<u64> {
        let bm = self
            .backup_manager
            .as_ref()
            .ok_or_else(|| ClError::NotFound("backup not configured".into()))?;
        bm.current_version(table_name, id)
    }

    pub fn history<'db>(
        &self,
        table: TableDefinition<'db, &str, &[u8]>,
        key: &str,
    ) -> Result<Vec<BackupRecord>> {
        let bm = self
            .backup_manager
            .as_ref()
            .ok_or_else(|| ClError::NotFound("backup not configured".into()))?;

        bm.history(table, key)
    }

}

#[derive(Debug, Clone)]
pub struct Date {
    pub day: u32,
    pub month: u32,
    pub year: u32,
}

#[derive(Debug, Clone)]
pub struct Dir {
    pub dir: PathBuf,
    pub backup_dir: Option<PathBuf>,
}

impl Dir {
    pub fn new(dir: &PathBuf, backup_dir: Option<&PathBuf>) -> Result<Self> {
        if !dir.exists() {
            fs::create_dir_all(&dir)?;
        }

        let backup_dir_set = if let Some(backup) = backup_dir {
            if !backup.exists() {
                fs::create_dir_all(backup)?;
            }
            Some(backup.to_path_buf())
        } else {
            None
        };

        Ok(Self {
            dir: dir.to_path_buf(),
            backup_dir: backup_dir_set,
        })
    }
}

#[derive(Clone)]
pub struct Repository<T: DeserializeOwned + Serialize + Clone + 'static> {
    pub table: &'static str,
    pub database_manager: DatabaseManager,
    /// Set for an entity registered with `register_sealed`.
    pub(crate) sealed: Option<Arc<crate::field_crypto::SealedHooks<T>>>,
    _marker: std::marker::PhantomData<T>,
}

impl<T: DeserializeOwned + Serialize + Clone + Entity> Repository<T> {
    pub fn new(table: &'static str, database_manager: DatabaseManager) -> Self {
        Self {
            table,
            database_manager,
            sealed: None,
            _marker: std::marker::PhantomData,
        }
    }

    pub(crate) fn new_sealed(
        table: &'static str,
        database_manager: DatabaseManager,
        sealed: Arc<crate::field_crypto::SealedHooks<T>>,
    ) -> Self {
        Self { sealed: Some(sealed), ..Self::new(table, database_manager) }
    }

    /// The stored bytes of `value` as row `id`: the plain JSON, or, for an entity with protected
    /// fields, the JSON with each protected field sealed.
    fn encode(&self, id: &str, value: &T) -> Result<Vec<u8>> {
        match &self.sealed {
            Some(hooks) => hooks.encode(id, value),
            None => Ok(serde_json::to_vec(value)?),
        }
    }

    /// The entity of stored row `id`. Protected fields stay closed and are tied to this row.
    fn decode(&self, id: &str, bytes: &[u8]) -> Result<T> {
        let mut value: T = serde_json::from_slice(bytes)?;
        if let Some(hooks) = &self.sealed {
            hooks.bind(id, &mut value);
        }
        Ok(value)
    }

    /// Ties the protected fields of an entity built from a stored record of row `id` to that row.
    pub(crate) fn bind_entity(&self, id: &str, value: &mut T) {
        if let Some(hooks) = &self.sealed {
            hooks.bind(id, value);
        }
    }

    pub fn get(&self, id: &str) -> Result<T> {
        let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(self.table);
        let data = self.database_manager.get(table, self.table, id)?;
        if let Some(data) = data {
            let value = self.decode(id, &data)?;
            Ok(value)
        } else {
            Err(ClError::NotFound(format!("{} not found", self.table)).into())
        }
    }

    /// [`Self::get`], but the cache is neither read nor written.
    ///
    /// The read for a key you are walking past rather than coming back to —
    /// range scans, reports, exports. See
    /// [`DatabaseManager::get_uncached`] for why routing a bulk walk through
    /// the cache costs the workload that follows it.
    pub fn get_uncached(&self, id: &str) -> Result<T> {
        let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(self.table);
        let data = self.database_manager.get_uncached(table, id)?;
        if let Some(data) = data {
            let value = self.decode(id, &data)?;
            Ok(value)
        } else {
            Err(ClError::NotFound(format!("{} not found", self.table)).into())
        }
    }

    /// Bytes and entries currently cached for this repository's database.
    pub fn cache_stats(&self) -> (u64, u64) {
        self.database_manager.cache_stats()
    }

    /// Reclaim expired entries now. See
    /// [`DatabaseManager::run_cache_maintenance`].
    pub fn run_cache_maintenance(&self) {
        self.database_manager.run_cache_maintenance();
    }

    /// Drop every cached entry for this repository's database.
    pub fn clear_cache(&self) {
        self.database_manager.clear_cache();
    }

    /// Every row. [`Self::list_map`] with no map; see it for how the table is read.
    pub fn list(&self) -> Result<Vec<T>> {
        self.list_map(|row| row)
    }

    /// Every row, read one at a time and passed through `map` as it is read.
    ///
    /// # Why not copy the table first
    ///
    /// `list` used to copy every stored value into one `Vec<Vec<u8>>` and parse
    /// them only once the whole table was in memory. On a table of a few
    /// hundred megabytes that held it twice while it was read, and left much of
    /// that heap freed but still committed to the process. Here each
    /// value is parsed straight out of the read transaction, so nothing is held
    /// but what `map` returns: a field `map` drops never outlives its row, and
    /// the result is sized from the table instead of grown by doubling.
    ///
    /// A row that does not parse is an error. `list` used to `unwrap()` it,
    /// which took the process down.
    ///
    /// Reads the file, not the cache, as `list` always has.
    pub fn list_map<U>(&self, mut map: impl FnMut(T) -> U) -> Result<Vec<U>> {
        let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(self.table);
        let db = self.database_manager.db()?;
        let read_txn = db.begin_read()?;
        let table_ref = read_txn.open_table(table)?;
        let mut out = crate::memory::vec_with_capacity("repository.list_rows", usize::try_from(table_ref.len()?).unwrap_or(0))?;
        for row in table_ref.iter()? {
            let (key, value) = row?;
            crate::memory::push("repository.list_rows", &mut out, map(self.decode(key.value(), value.value())?))?;
        }
        Ok(out)
    }

    /// [`Self::get_uncached`], read as `U` instead of `T`.
    ///
    /// `U` is any type whose fields are a subset of the stored row's. serde
    /// passes over the stored fields `U` does not name without building them,
    /// and the value is parsed straight out of the read transaction rather than
    /// copied first. It is how a caller reads many large rows without their
    /// bulky fields.
    pub fn get_uncached_as<U: DeserializeOwned>(&self, id: &str) -> Result<U> {
        let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(self.table);
        let db = self.database_manager.db()?;
        let read_txn = db.begin_read()?;
        let table_ref = read_txn.open_table(table)?;
        match table_ref.get(id)? {
            Some(value) => Ok(serde_json::from_slice(value.value())?),
            None => Err(ClError::NotFound(format!("{} not found", self.table))),
        }
    }

    pub fn set(&self, id: &str, value: &T) -> Result<()> {
        let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(self.table);
        let data = self.encode(id, value)?;
        self.database_manager.set_prepared(table, self.table, id, data)?;
        Ok(())
    }

    /// Writes several entities (and deletes several rows) of this table in bounded transactions.
    /// Each entity is encoded as `set` does, so protected fields are sealed. This is the way to
    /// write in batches to a table that has protected fields: the raw batch calls refuse it.
    pub fn commit_entities(&self, writes: &[(&str, &T)], deletes: &[&str]) -> Result<()> {
        let mut rows = Vec::with_capacity(writes.len());
        for (id, value) in writes {
            let bytes = self.encode(id, value)?;
            rows.push((self.table.to_string(), (*id).to_string(), bytes));
        }
        let removed: Vec<(String, String)> =
            deletes.iter().map(|id| (self.table.to_string(), (*id).to_string())).collect();
        self.database_manager.commit_batch_prepared(&rows, &removed)
    }

    pub fn set_bulk(&self, entries: Vec<(String, u64)>) -> Result<String> {
        self.database_manager.set_bulk(self.table, entries)
    }

    pub fn delete(&self, id: &str) -> Result<()> {
        let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(self.table);
        self.database_manager.delete(table, self.table, id)?;
        Ok(())
    }

    pub fn set_with_blob(&self, id: &str, meta: &T, blob: &[u8]) -> Result<()> {
        if !self.database_manager.is_blob_table(self.table) {
            return Err(ClError::Validation(format!(
                "table '{}' is not registered as blob sidecar",
                self.table
            )));
        }
        // A row with protected fields is sealed first; the size is then added next to them.
        let mut meta_json: serde_json::Value = if self.database_manager.sealed_tables.contains(self.table) {
            serde_json::from_slice(&self.encode(id, meta)?)?
        } else {
            serde_json::to_value(meta)?
        };
        if let serde_json::Value::Object(ref mut obj) = meta_json {
            obj.insert("size_bytes".to_string(), serde_json::json!(blob.len()));
        }
        let data = serde_json::to_vec(&meta_json)?;
        let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(self.table);
        self.database_manager.publish_blob(self.table,id,blob,Some(data.clone()))?;
        if let Some(ref bm)=self.database_manager.backup_manager {bm.record_set(table,self.table,id,data)?;}
        Ok(())
    }

    pub fn create_with_blob(&self, meta: &T, blob: &[u8]) -> Result<()> {
        self.set_with_blob(meta.entity_id(), meta, blob)
    }

    pub fn open_blob(&self, id: &str) -> Result<BlobReader> {
        if !self.database_manager.is_blob_table(self.table) {
            return Err(ClError::Validation(format!(
                "table '{}' is not registered as blob sidecar",
                self.table
            )));
        }
        self.database_manager.open_blob(self.table, id)
    }

    pub fn is_blob_table(&self) -> bool {
        self.database_manager.is_blob_table(self.table)
    }

    pub fn restore_by_version(&self, id: &str, version: u64) -> Result<()> {
        let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(self.table);
        self.database_manager
            .restore_by_version(table, self.table, id, version)
    }

    pub fn get_by_version(
        &self,
        id: &str,
        version: u64,
        mode: HistoryDisplayMode,
    ) -> Result<BackupRecordRepository<T>> {
        let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(self.table);
        let record = self.database_manager.get_by_version(table, id, version)?;
        self.resolve_backup_record(record, mode)
    }

    pub fn get_version_by_at(
        &self,
        id: &str,
        timestamp: i64,
        mode: HistoryDisplayMode,
    ) -> Result<BackupRecordRepository<T>> {
        let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(self.table);
        let record = self
            .database_manager
            .get_version_by_at(table, id, timestamp)?;
        self.resolve_backup_record(record, mode)
    }

    fn resolve_backup_record(
        &self,
        record: BackupRecord,
        mode: HistoryDisplayMode,
    ) -> Result<BackupRecordRepository<T>> {
        let index = self.database_manager.migration_index().ok();
        let view = BackupManager::resolve_record(
            &record,
            index.as_deref().map(|g| &*g),
            self.database_manager.migration_registry(),
            mode,
        );
        Ok(view_into_repository(view))
    }

    pub fn restore_at(&self, id: &str, timestamp: i64) -> Result<()> {
        let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(self.table);
        self.database_manager
            .restore_at(table, self.table, id, timestamp)
    }

    pub fn restore_bulk(&self, bulk_id: &str) -> Result<()> {
        let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(self.table);
        self.database_manager
            .restore_bulk(table, self.table, bulk_id)
    }

    pub fn history(
        &self,
        id: &str,
        mode: HistoryDisplayMode,
    ) -> Result<Vec<BackupRecordRepository<T>>> {
        let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(self.table);
        let index = self.database_manager.migration_index().ok();
        let registry = self.database_manager.migration_registry();

        let history = self
            .database_manager
            .history(table, id)?
            .into_iter()
            .map(|record| {
                let view = BackupManager::resolve_record(
                    &record,
                    index.as_deref().map(|g| &*g),
                    registry,
                    mode,
                );
                view_into_repository(view)
            })
            .collect_vec();

        Ok(history)
    }

    pub fn current_version(&self, id: &str) -> Result<u64> {
        self.database_manager.current_version(self.table, id)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BackupRecordRepository<T> {
    pub version: u64,
    pub timestamp: i64,
    pub date: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub date_from_migration: bool,
    pub operation: BackupOperation,
    pub table: String,
    pub key: String,
    pub data: RecordData,
    pub bulk_id: Option<String>,
    pub restored_version: Option<u64>,
    pub schema_at_version: String,
    pub migration_id: Option<String>,
    pub readable: bool,
    pub restorable: bool,
    pub decode_path: Vec<String>,
    #[serde(skip)]
    pub _marker: std::marker::PhantomData<T>,
}

fn view_into_repository<T>(view: BackupRecordView) -> BackupRecordRepository<T> {
    BackupRecordRepository {
        version: view.version,
        timestamp: view.timestamp,
        date: view.date,
        date_from_migration: view.date_from_migration,
        operation: view.operation,
        table: view.table,
        key: view.key,
        data: view.data,
        bulk_id: view.bulk_id,
        restored_version: view.restored_version,
        schema_at_version: view.schema_at_version,
        migration_id: view.migration_id,
        readable: view.readable,
        restorable: view.restorable,
        decode_path: view.decode_path,
        _marker: std::marker::PhantomData,
    }
}
