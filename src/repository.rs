// use crate::emitter::LogEventEmitter;
use crate::{
    backup::{
        view::{BackupRecordView, HistoryDisplayMode, RecordData},
        BackupManager, BackupOperation, BackupRecord,
    },
    blob::BlobStore,
    metadata::types::{TableStorageMode, META_TABLE},
    migration::chain::DbMigrationIndex,
    migration::layout::FieldLayout,
    migration::step_registry::MigrationStepRegistry,
    metadata::store::{read_meta, write_meta},
    migration::types::MigrationManifest,
    units::{ClError, Result},
};
// use crate::units::{CACHE_IDLE_SECONDS, CACHE_MAX_CAPACITY, CACHE_TTL_SECONDS};
use chrono::{Datelike, Local};
use itertools::Itertools;
use moka::sync::Cache;
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
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

    // L2: Persistent database (redb) for long-term storage
    pub db: Arc<Database>,

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
    pub fn open(
        dir_path: &PathBuf,
        backup_dir_path: Option<&PathBuf>,
        dir_name: &str,
        db_name: &str,
        tables: Vec<String>,
        cache_max_capacity: u64,
        cache_ttl_seconds: u64,
        cache_idle_seconds: u64,
        has_cache: bool,
        blob_enabled: bool,
        table_storage: std::collections::HashMap<String, TableStorageMode>,
        table_layouts: std::collections::HashMap<String, FieldLayout>,
        migration_registry: Arc<MigrationStepRegistry>,
    ) -> Result<Self> {
        let dir = dir_path.join(dir_name);
        let backup_dir = if let Some(backup_dir_path) = backup_dir_path {
            Some(backup_dir_path.join(dir_name))
        } else {
            None
        };

        let dir_local = Arc::new(Dir::new(&dir, backup_dir.as_ref())?);

        let db_path = dir_local.dir.join(format!("{}.cldb", db_name));
        let backup_db_path = if let Some(backup_dir) = &dir_local.backup_dir {
            Some(backup_dir.join(format!("{}.cldb.bak", db_name)))
        } else {
            None
        };

        let db = Arc::new(if db_path.exists() {
            Database::open(&db_path).map_err(|e| ClError::Database(redb::Error::from(e)))?
        } else {
            Database::create(&db_path).map_err(|e| ClError::Database(redb::Error::from(e)))?
        });

        let backup_manager = if let Some(backup_db_path) = backup_db_path {
            let backup_manager = BackupManager::new(&backup_db_path, has_cache);
            if backup_manager.is_ok() {
                Some(backup_manager.unwrap())
            } else {
                None
            }
        } else {
            None
        };

        let write_txn = db.begin_write()?;
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

        let memory_cache = Cache::builder()
            .max_capacity(cache_max_capacity)
            .time_to_live(Duration::from_secs(cache_ttl_seconds))
            .time_to_idle(Duration::from_secs(cache_idle_seconds))
            .build();

        let now = Local::now();
        let date = Date {
            day: now.day(),
            month: now.month(),
            year: now.year() as u32,
        };

        let mut migration_index =
            DbMigrationIndex::load(&dir_local.dir, db_name, &tables)?;
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
        cache_max_capacity: u64,
        cache_ttl_seconds: u64,
        cache_idle_seconds: u64,
        has_cache: bool,
        blob_enabled: bool,
        table_storage: std::collections::HashMap<String, TableStorageMode>,
        table_layouts: std::collections::HashMap<String, FieldLayout>,
        migration_registry: Arc<MigrationStepRegistry>,
    ) -> Result<Self> {
        Self::open(
            dir_path,
            backup_dir_path,
            dir_name,
            db_name,
            tables,
            cache_max_capacity,
            cache_ttl_seconds,
            cache_idle_seconds,
            has_cache,
            blob_enabled,
            table_storage,
            table_layouts,
            migration_registry,
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
        self.blob_store()?.write_atomic(table, id, data)
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

        if let Ok(Some(mut meta)) = read_meta(&self.db) {
            if let Some(tm) = meta.tables.iter_mut().find(|t| t.name == table) {
                tm.schema_version = index.table_chain(table)?.current_version();
                if let Some(layout) = new_layout {
                    tm.layout_hash = layout.layout_hash.clone();
                }
            }
            meta.framework_version = env!("CARGO_PKG_VERSION").to_string();
            write_meta(&self.db, &meta)?;
        }
        Ok(())
    }

    pub fn list_entries(&self, table_name: &str) -> Result<Vec<(String, Vec<u8>)>> {
        let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(table_name);
        let read_txn = self.db.begin_read()?;
        let table_ref = read_txn.open_table(table)?;
        Ok(table_ref
            .iter()?
            .filter_map(|entry| {
                entry
                    .ok()
                    .map(|(k, v)| (k.value().to_string(), v.value().to_vec()))
            })
            .collect_vec())
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
        let mut write_txn = self.db.begin_write()?;
        if !self.has_cache {
            write_txn.set_durability(Durability::Immediate)?;
        }

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
        if self.has_cache {
            // Write to database (L2)
            let write_txn = self.db.begin_write()?;
            {
                let mut table_ref = write_txn.open_table(table)?;
                table_ref.insert(key, value.as_slice())?;
            }
            write_txn.commit()?;

            // Write to cache (L1) - only after DB success
            let cache_key = format!("{}:{}", table_name, key);
            self.memory_cache.insert(cache_key, value.clone());
        } else {
            // Write to database (L2)
            let mut write_txn = self.db.begin_write()?;
            write_txn.set_durability(Durability::Immediate)?;
            {
                let mut table_ref = write_txn.open_table(table)?;
                let mut slot = table_ref.insert_reserve(key, value.len())?;
                slot.as_mut().copy_from_slice(&value);
            }
            write_txn.commit()?;
        }

        if let Some(ref bm) = self.backup_manager {
            // Step 3: Record write to backup (L3)
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

        // Step 1: Check memory cache first (L1)
        if self.has_cache
            && let Some(value) = self.memory_cache.get(&cache_key)
        {
            return Ok(Some(value));
        }

        // Step 2: Cache miss - read from database (L2)
        let read_txn = self.db.begin_read()?;
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

    pub fn list<'db>(&self, table: TableDefinition<'db, &str, &[u8]>) -> Result<Vec<Vec<u8>>> {
        // read from database (L2)
        let read_txn = self.db.begin_read()?;
        let table_ref = read_txn.open_table(table)?;

        Ok(table_ref
            .iter()?
            .filter_map(|data| {
                if data.is_ok() {
                    Some(data.unwrap().1.value().to_vec())
                } else {
                    None
                }
            })
            .collect_vec())
    }

    /// Delete from both cache and DB
    pub fn delete<'db>(
        &self,
        table: TableDefinition<'db, &str, &[u8]>,
        table_name: &str,
        key: &str,
    ) -> Result<bool> {
        let cache_key = format!("{}:{}", table_name, key);

        // Check if exists
        let read_txn = self.db.begin_read()?;
        let table_ref = read_txn.open_table(table)?;
        let found = table_ref.get(key)?.is_some();
        drop(read_txn);

        if found {
            // Step 1: Delete from database (L2)
            let write_txn = self.db.begin_write()?;
            {
                let mut table_ref = write_txn.open_table(table)?;
                table_ref.remove(key)?;
            }
            write_txn.commit()?;
        }

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
        let read_txn = self
            .backup_manager
            .as_ref()
            .ok_or_else(|| ClError::OptionNone)?
            .db
            .begin_read()?;
        let tbl = read_txn.open_table(table)?;

        let record = tbl
            .get(backup_key.as_str())?
            .and_then(|v| serde_json::from_slice::<BackupRecord>(v.value()).ok())
            .ok_or_else(|| ClError::NotFound(format!("version {} not found", version)))?;

        drop(read_txn);

        match record.operation {
            // Set or Restore → Write data to Primary + Cache + Backup
            BackupOperation::Set | BackupOperation::Restore | BackupOperation::RestoreBulk => {
                let data = record.data;

                if data.is_some() {
                    let data = data.clone().ok_or_else(|| ClError::OptionNone)?;
                    // Primary DB
                    let mut write_txn = self.db.begin_write()?;
                    if self.has_cache {
                        write_txn.open_table(table)?.insert(key, data.as_slice())?;
                    } else {
                        write_txn.set_durability(Durability::Immediate)?;
                        {
                            let mut table_ref = write_txn.open_table(table)?;
                            let mut slot = table_ref.insert_reserve(key, data.len())?;
                            slot.as_mut().copy_from_slice(&data);
                        }
                    }
                    write_txn.commit()?;

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
                let write_txn = self.db.begin_write()?;
                {
                    write_txn.open_table(table)?.remove(key)?;
                }
                write_txn.commit()?;

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
        let read_txn = self
            .backup_manager
            .as_ref()
            .ok_or_else(|| ClError::OptionNone)?
            .db
            .begin_read()?;
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
            let read_txn = bm.db.begin_read()?;
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
            match data {
                Some(d) => {
                    let mut write_txn = self.db.begin_write()?;
                    if self.has_cache {
                        write_txn
                            .open_table(table)?
                            .insert(key.as_str(), d.as_slice())?;
                    } else {
                        write_txn.set_durability(Durability::Immediate)?;
                        {
                            let mut table_ref = write_txn.open_table(table)?;
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
                    let write_txn = self.db.begin_write()?;
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

    /// Get database reference (for repositories)
    pub fn db(&self) -> &Arc<Database> {
        &self.db
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
