// use crate::emitter::LogEventEmitter;
use crate::{
    backup::{
        view::{BackupRecordView, HistoryDisplayMode, RecordData},
        BackupManager, BackupOperation, BackupRecord,
    },
    blob::BlobStore,
    durability::{DurabilityMode, DEFAULT_MAX_COMMIT_BATCH_ENTRIES},
    fsutil::maybe_crash,
    handle::{DbHandle, DbRef, RedbOptions},
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
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
// use std::env;
use crate::entity::Entity;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fs::File;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct DatabaseManager {
    // L1: In-memory cache (moka) for fast access
    pub memory_cache: Cache<String, Vec<u8>>,

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
    has_cache: bool,

    // Durability policy (independent of cache)
    durability: DurabilityMode,

    // Max entries per commit_batch chunk
    max_commit_batch_entries: usize,

    // Blob sidecar storage
    blob_enabled: bool,
    table_storage: std::collections::HashMap<String, TableStorageMode>,
    blob_store: Option<BlobStore>,

    // Per-table migration index
    migration_index: Arc<RwLock<DbMigrationIndex>>,

    // Shared decoder registry for history resolution
    migration_registry: Arc<MigrationStepRegistry>,
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
            let backup_manager = BackupManager::new(&backup_db_path, has_cache, durability, redb);
            if backup_manager.is_ok() {
                Some(backup_manager.unwrap())
            } else {
                None
            }
        } else {
            None
        };

        let db_ref = db.get()?;
        let write_txn = db_ref.begin_write()?;
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
        // unknown. A production database of run logs carrying a serialized
        // snapshot per row filled a 10,000-entry cache with roughly 100 MiB and
        // held it for thirteen hours. The number the operator wrote was a count;
        // the number that mattered was a size, and nothing connected the two.
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

        let mut migration_index = DbMigrationIndex::load_with_durability(
            &dir_local.dir,
            db_name,
            &tables,
            durability,
        )?;
        for (table, layout) in &table_layouts {
            migration_index.ensure_table(table, layout)?;
        }

        let migration_index = Arc::new(RwLock::new(migration_index));

        let blob_store = if blob_enabled {
            let store = BlobStore::new(dir_local.dir.as_path(), db_name);
            store.ensure_root()?;
            for table in &tables {
                if table_storage.get(table).copied() == Some(TableStorageMode::BlobSidecar) {
                    store.ensure_table(table)?;
                }
            }
            Some(store)
        } else {
            None
        };

        Ok(Self {
            memory_cache,
            db: db,
            backup_manager,
            date,
            dir: dir_local,
            db_name: db_name.to_string(),
            tables_names: tables,
            has_cache,
            durability,
            max_commit_batch_entries: max_commit_batch_entries.max(1),
            blob_enabled,
            table_storage,
            blob_store,
            migration_index,
            migration_registry,
        })
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
        let dir = dir_path.join(dir_name);
        fs::create_dir_all(&dir)?;
        let db_path = dir.join(format!("{}.cldb", db_name));
        let redb = RedbOptions::default();
        let db = DbHandle::new(redb.create(&db_path)?, db_path, DurabilityMode::Strict, redb);
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

    pub fn blob_store(&self) -> Result<&BlobStore> {
        self.blob_store.as_ref().ok_or_else(|| {
            ClError::Validation("blob storage not enabled on this database".into())
        })
    }

    pub fn write_blob(&self, table: &str, id: &str, data: &[u8]) -> Result<()> {
        self.blob_store()?
            .write_atomic_with_mode(table, id, data, self.durability)
    }

    pub fn durability(&self) -> DurabilityMode {
        self.durability
    }

    /// The open `.cldb`, or [`ClError::Closed`].
    ///
    /// Reads go through the returned guard as a `&Database`. Writes go through
    /// its `begin_write`, which applies this database's durability and quick
    /// repair — see [`DbRef::begin_write`]. Hold it for one operation; see
    /// [`DbHandle::get`].
    pub fn db(&self) -> Result<DbRef<'_>> {
        self.db.get()
    }

    /// Read `_clove_meta`.
    pub fn read_meta(&self) -> Result<Option<CloveMeta>> {
        read_meta(&*self.db()?)
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
        was_open
    }

    pub fn is_closed(&self) -> bool {
        self.db.is_closed()
    }

    pub fn open_blob(&self, table: &str, id: &str) -> Result<File> {
        self.blob_store()?.open_read(table, id)
    }

    pub fn delete_blob(&self, table: &str, id: &str) -> Result<bool> {
        match &self.blob_store {
            Some(store) => store.delete(table, id),
            None => Ok(false),
        }
    }

    pub fn copy_blob(
        &self,
        table: &str,
        id: &str,
        dest: &DatabaseManager,
        dest_table: &str,
        dest_id: &str,
    ) -> Result<()> {
        let src = self.blob_store()?;
        let dest_store = dest.blob_store()?;
        src.copy(table, id, dest_store, dest_table, dest_id)
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


    pub fn count_keys(&self, table: &str) -> Result<usize> {
        Ok(self.list_entries(table)?.len())
    }

    pub fn table_layout(&self, table: &str) -> Result<FieldLayout> {
        let guard = self.migration_index()?;
        let chain = guard.table_chain(table)?;
        let version = chain.current_version();
        let path = crate::migration::types::layout_path(&chain.dir, version);
        if path.exists() {
            let data = fs::read_to_string(path)?;
            return Ok(serde_json::from_str(&data)?);
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
        if self.is_blob_table(table_name) {
            let _ = self.delete_blob(table_name, key);
        }
        let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(table_name);
        self.delete(table, table_name, key)?;
        Ok(())
    }

    pub fn commit_batch(
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
        let db = self.db()?;
        let write_txn = db.begin_write()?;
        maybe_crash("before_commit");

        for (table_name, key, value) in writes {
            let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(table_name.as_str());
            let mut table_ref = write_txn.open_table(table)?;
            if self.has_cache {
                table_ref.insert(key.as_str(), value.as_slice())?;
            } else {
                let mut slot = table_ref.insert_reserve(key.as_str(), value.len())?;
                slot.as_mut().copy_from_slice(value);
            }
        }

        for (table_name, key) in deletes {
            let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(table_name.as_str());
            let mut table_ref = write_txn.open_table(table)?;
            let _ = table_ref.remove(key.as_str());
        }

        write_txn.commit()?;
        maybe_crash("after_commit");

        if self.has_cache {
            for (table_name, key, value) in writes {
                let cache_key = format!("{}:{}", table_name, key);
                self.memory_cache.insert(cache_key, value.clone());
            }
            for (table_name, key) in deletes {
                let cache_key = format!("{}:{}", table_name, key);
                self.memory_cache.invalidate(&cache_key);
            }
        }

        Ok(())
    }

    /// Write-Through: Write to both cache and DB
    pub fn set<'db>(
        &self,
        table: TableDefinition<'db, &str, &[u8]>,
        table_name: &str,
        key: &str,
        value: Vec<u8>,
    ) -> Result<()> {
        // Disk first (write-through), then cache.
        {
            let db = self.db()?;
            let write_txn = db.begin_write()?;
            {
                let mut table_ref = write_txn.open_table(table)?;
                if self.has_cache {
                    table_ref.insert(key, value.as_slice())?;
                } else {
                    let mut slot = table_ref.insert_reserve(key, value.len())?;
                    slot.as_mut().copy_from_slice(&value);
                }
            }
            write_txn.commit()?;
        }

        if self.has_cache {
            let cache_key = format!("{}:{}", table_name, key);
            self.memory_cache.insert(cache_key, value.clone());
        }

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
    /// therefore keeps every expired entry resident indefinitely — in one
    /// production run, roughly 100 MiB survived a five-minute TTL for thirteen
    /// hours, until the next read happened to run housekeeping.
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
        let cache_key = format!("{}:{}", table_name, key);

        let db = self.db()?;

        // Check if exists
        let read_txn = db.begin_read()?;
        let table_ref = read_txn.open_table(table)?;
        let found = table_ref.get(key)?.is_some();
        drop(table_ref);
        drop(read_txn);

        if found {
            // Step 1: Delete from database (L2)
            let write_txn = db.begin_write()?;
            {
                let mut table_ref = write_txn.open_table(table)?;
                table_ref.remove(key)?;
            }
            write_txn.commit()?;
        }
        // Released before the backup takes its own file.
        drop(db);

        // Step 2: Delete from cache (L1)
        if self.has_cache {
            self.memory_cache.invalidate(&cache_key);
        }

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
                .and_then(|v| serde_json::from_slice::<BackupRecord>(v.value()).ok())
                .ok_or_else(|| ClError::NotFound(format!("version {} not found", version)))?
        };

        match record.operation {
            // Set or Restore → Write data to Primary + Cache + Backup
            BackupOperation::Set | BackupOperation::Restore | BackupOperation::RestoreBulk => {
                let data = record.data;

                if data.is_some() {
                    let data = data.clone().ok_or_else(|| ClError::OptionNone)?;
                    // Primary DB
                    let db = self.db()?;
                    let write_txn = db.begin_write()?;
                    {
                        let mut table_ref = write_txn.open_table(table)?;
                        if self.has_cache {
                            table_ref.insert(key, data.as_slice())?;
                        } else {
                            let mut slot = table_ref.insert_reserve(key, data.len())?;
                            slot.as_mut().copy_from_slice(&data);
                        }
                    }
                    write_txn.commit()?;
                    drop(db);

                    // Cache
                    if self.has_cache {
                        let cache_key = format!("{}:{}", table_name, key);
                        self.memory_cache.insert(cache_key, data.clone());
                    }
                }

                // Backup record_restore
                bm.record_restore(table, table_name, key, version, data, record.bulk_id)?;
            }

            // Delete → Delete from Primary + Cache + log restore with None
            BackupOperation::Delete => {
                {
                    let db = self.db()?;
                    let write_txn = db.begin_write()?;
                    {
                        write_txn.open_table(table)?.remove(key)?;
                    }
                    write_txn.commit()?;
                }

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
            .and_then(|v| serde_json::from_slice::<BackupRecord>(v.value()).ok())
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

        for (key, data) in results {
            let db = self.db()?;
            match data {
                Some(d) => {
                    let write_txn = db.begin_write()?;
                    {
                        let mut table_ref = write_txn.open_table(table)?;
                        if self.has_cache {
                            table_ref.insert(key.as_str(), d.as_slice())?;
                        } else {
                            let mut slot = table_ref.insert_reserve(key.as_str(), d.len())?;
                            slot.as_mut().copy_from_slice(&d);
                        }
                    }
                    write_txn.commit()?;
                    if self.has_cache {
                        let cache_key = format!("{}:{}", table_name, key);
                        self.memory_cache.insert(cache_key, d);
                    }
                }
                None => {
                    let write_txn = db.begin_write()?;
                    {
                        write_txn.open_table(table)?.remove(key.as_str())?;
                    }
                    write_txn.commit()?;
                    if self.has_cache {
                        let cache_key = format!("{}:{}", table_name, key);
                        self.memory_cache.invalidate(&cache_key);
                    }
                }
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
    _marker: std::marker::PhantomData<T>,
}

impl<T: DeserializeOwned + Serialize + Clone + Entity> Repository<T> {
    pub fn new(table: &'static str, database_manager: DatabaseManager) -> Self {
        Self {
            table,
            database_manager,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn get(&self, id: &str) -> Result<T> {
        let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(self.table);
        let data = self.database_manager.get(table, self.table, id)?;
        if let Some(data) = data {
            let value: T = serde_json::from_slice(&data)?;
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
            let value: T = serde_json::from_slice(&data)?;
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

    pub fn list(&self) -> Result<Vec<T>> {
        let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(self.table);
        let data = self.database_manager.list(table)?;

        Ok(data
            .iter()
            .map(|data| {
                serde_json::from_slice::<T>(&data)
                    .map_err(|e| ClError::Serialization(e))
                    .unwrap()
            })
            .collect_vec())
    }

    pub fn set(&self, id: &str, value: &T) -> Result<()> {
        let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(self.table);
        let data = serde_json::to_vec(value)?;
        self.database_manager.set(table, self.table, id, data)?;
        Ok(())
    }

    pub fn set_bulk(&self, entries: Vec<(String, u64)>) -> Result<String> {
        self.database_manager.set_bulk(self.table, entries)
    }

    pub fn delete(&self, id: &str) -> Result<()> {
        if self.database_manager.is_blob_table(self.table) {
            let _ = self.database_manager.delete_blob(self.table, id);
        }
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
        let mut meta_json = serde_json::to_value(meta)?;
        if let serde_json::Value::Object(ref mut obj) = meta_json {
            obj.insert("size_bytes".to_string(), serde_json::json!(blob.len()));
        }
        let data = serde_json::to_vec(&meta_json)?;
        let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(self.table);
        self.database_manager.set(table, self.table, id, data)?;
        self.database_manager.write_blob(self.table, id, blob)?;
        Ok(())
    }

    pub fn create_with_blob(&self, meta: &T, blob: &[u8]) -> Result<()> {
        self.set_with_blob(meta.entity_id(), meta, blob)
    }

    pub fn open_blob(&self, id: &str) -> Result<File> {
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
