// use crate::emitter::LogEventEmitter;
use crate::{
    backup::{BackupManager, BackupOperation, BackupRecord},
    units::{ClError, Result},
};
// use crate::units::{CACHE_IDLE_SECONDS, CACHE_MAX_CAPACITY, CACHE_TTL_SECONDS};
use chrono::{Datelike, Local};
use itertools::Itertools;
use moka::sync::Cache;
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
// use std::env;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
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
}

impl DatabaseManager {
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

        let db = Arc::new(
            Database::create(db_path).map_err(|e| ClError::Database(redb::Error::from(e)))?,
        );

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

        Ok(Self {
            memory_cache,
            db: db,
            backup_manager,
            date,
            dir: dir_local,
            db_name: db_name.to_string(),
            tables_names: tables,
            has_cache,
        })
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

impl<T: DeserializeOwned + Serialize + Clone> Repository<T> {
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
        let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(self.table);
        self.database_manager.delete(table, self.table, id)?;
        Ok(())
    }

    pub fn restore_by_version(&self, id: &str, version: u64) -> Result<()> {
        let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(self.table);
        self.database_manager
            .restore_by_version(table, self.table, id, version)
    }

    pub fn get_by_version(&self, id: &str, version: u64) -> Result<BackupRecordRepository<T>> {
        let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(self.table);
        let record = self.database_manager.get_by_version(table, id, version)?;

        let data = if let Some(data) = record.data {
            let value = serde_json::from_slice(&data)?;
            Some(value)
        } else {
            None
        };

        Ok(BackupRecordRepository::<T> {
            version: record.version,
            timestamp: record.timestamp,
            date: record.date,
            operation: record.operation,
            table: record.table,
            key: record.key,
            data: data,
            restored_version: record.restored_version,
            bulk_id: record.bulk_id,
        })
    }

    pub fn get_version_by_at(&self, id: &str, timestamp: i64) -> Result<BackupRecordRepository<T>> {
        let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(self.table);
        let record = self
            .database_manager
            .get_version_by_at(table, id, timestamp)?;

        let data = if let Some(data) = record.data {
            let value = serde_json::from_slice(&data)?;
            Some(value)
        } else {
            None
        };

        Ok(BackupRecordRepository::<T> {
            version: record.version,
            timestamp: record.timestamp,
            date: record.date,
            operation: record.operation,
            table: record.table,
            key: record.key,
            data: data,
            restored_version: record.restored_version,
            bulk_id: record.bulk_id,
        })
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

    pub fn history(&self, id: &str) -> Result<Vec<BackupRecordRepository<T>>> {
        let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new(self.table);
        let history = self
            .database_manager
            .history(table, id)?
            .into_iter()
            .map(|record| {
                let data = if let Some(data) = record.data {
                    let value = serde_json::from_slice(&data).unwrap();
                    Some(value)
                } else {
                    None
                };

                BackupRecordRepository::<T> {
                    version: record.version,
                    timestamp: record.timestamp,
                    date: record.date,
                    operation: record.operation,
                    table: record.table,
                    key: record.key,
                    data: data,
                    restored_version: record.restored_version,
                    bulk_id: record.bulk_id,
                }
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
    pub data: Option<T>,
    pub bulk_id: Option<String>,
    pub restored_version: Option<u64>,
}
