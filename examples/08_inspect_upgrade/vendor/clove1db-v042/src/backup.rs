// backup.rs
use crate::units::ClError;
use crate::units::Result;
use chrono::Local;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::path::PathBuf;
use std::sync::Arc;

fn version_table_name(table_name: &str) -> String {
    format!("{}_version", table_name)
}

fn bulk_table_name(table_name: &str) -> String {
    format!("{}_bulk", table_name)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum BackupOperation {
    Set,
    Delete,
    Restore,
    RestoreBulk,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BackupRecord {
    pub version: u64,
    pub timestamp: i64,
    pub date: String,
    pub operation: BackupOperation,
    pub table: String,
    pub key: String,
    pub data: Option<Vec<u8>>, // None on Delete
    pub bulk_id: Option<String>,
    pub restored_version: Option<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BulkEntry {
    pub key: String,
    pub version: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BulkRecord {
    pub bulk_id: String,
    pub timestamp: i64,
    pub date: String,
    pub table: String,
    pub entries: Vec<BulkEntry>,
}

#[derive(Clone, Debug)]
pub struct BackupManager {
    pub db: Arc<Database>,
    has_cache: bool,
}

impl BackupManager {
    pub fn new(path: &PathBuf, has_cache: bool) -> Result<Self> {
        // Last version in any table — we will search later when using
        // The tables are created in DatabaseManager::new() ✅
        let db =
            Arc::new(Database::create(path).map_err(|e| ClError::Database(redb::Error::from(e)))?);
        Ok(Self {
            db: db.clone(),
            has_cache,
        })
    }

    pub fn init_table(&self, table_name: &str) -> Result<()> {
        let ver_name = version_table_name(table_name);
        let bulk_name = bulk_table_name(table_name);

        let write_txn = self.db.begin_write()?;
        {
            let data_table: TableDefinition<&str, &[u8]> = TableDefinition::new(table_name);
            write_txn.open_table(data_table)?;

            let ver_table: TableDefinition<&str, u64> = TableDefinition::new(ver_name.as_str());
            write_txn.open_table(ver_table)?;

            let bulk_table: TableDefinition<&str, &[u8]> = TableDefinition::new(bulk_name.as_str());
            write_txn.open_table(bulk_table)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Called from DatabaseManager::set()
    pub fn record_set<'db>(
        &self,
        table: TableDefinition<'db, &str, &[u8]>, // ← The TableDefinition
        table_name: &str,
        key: &str,
        data: Vec<u8>,
    ) -> Result<()> {
        let version = self.next_version(table_name, key)?;
        let record = BackupRecord {
            version,
            timestamp: Local::now().timestamp_millis(),
            date: Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
            operation: BackupOperation::Set,
            table: table_name.to_string(),
            key: key.to_string(),
            data: Some(data),
            restored_version: None,
            bulk_id: None,
        };
        self.write(table, key, version, &record)
    }

    /// Called from DatabaseManager::delete()
    pub fn record_delete<'db>(
        &self,
        table: TableDefinition<'db, &str, &[u8]>, // ← The TableDefinition
        table_name: &str,
        key: &str,
    ) -> Result<()> {
        let version = self.next_version(table_name, key)?;

        let record = BackupRecord {
            version,
            timestamp: Local::now().timestamp_millis(),
            date: Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
            operation: BackupOperation::Delete,
            table: table_name.to_string(),
            key: key.to_string(),
            data: None,
            restored_version: None,
            bulk_id: None,
        };
        self.write(table, key, version, &record)
    }

    pub fn record_restore<'db>(
        &self,
        table: TableDefinition<'db, &str, &[u8]>,
        table_name: &str,
        key: &str,
        restored_version: u64,
        data: Option<Vec<u8>>,
        bulk_id: Option<String>,
    ) -> Result<()> {
        let version = self.next_version(table_name, key)?;

        let record = BackupRecord {
            version,
            timestamp: Local::now().timestamp_millis(),
            date: Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
            operation: BackupOperation::Restore,
            table: table_name.to_string(),
            key: key.to_string(),
            restored_version: Some(restored_version),
            data,
            bulk_id,
        };

        self.write(table, key, version, &record)
    }

    pub fn restore_bulk<'db>(
        &self,
        table: TableDefinition<'db, &str, &[u8]>,
        table_name: &str,
        bulk_id: &str,
    ) -> Result<Vec<(String, Option<Vec<u8>>)>> {
        let bulk = {
            let bulk_name = bulk_table_name(table_name);
            let bulk_table: TableDefinition<&str, &[u8]> = TableDefinition::new(bulk_name.as_str());

            let read_txn = self.db.begin_read()?;
            let btbl = read_txn.open_table(bulk_table)?;
            let bulk_data = btbl
                .get(bulk_id)?
                .ok_or_else(|| ClError::NotFound(format!("bulk_id {} not found", bulk_id)))?;
            let bulk = serde_json::from_slice::<BulkRecord>(bulk_data.value())?;
            drop(read_txn);
            bulk
        };

        let mut results = Vec::new();

        for entry in &bulk.entries {
            let backup_key = format!("{}:{}", entry.key, entry.version);
            let read_txn = self.db.begin_read()?;
            let tbl = read_txn.open_table(table)?;

            let record = tbl
                .get(backup_key.as_str())?
                .and_then(|v| serde_json::from_slice::<BackupRecord>(v.value()).ok());

            drop(read_txn);

            let data = record.as_ref().and_then(|r| match r.operation {
                BackupOperation::Set | BackupOperation::Restore | BackupOperation::RestoreBulk => {
                    r.data.clone()
                }
                BackupOperation::Delete => None,
            });

            let new_version = self.next_version(table_name, &entry.key)?;
            let restore_record = BackupRecord {
                version: new_version,
                timestamp: Local::now().timestamp_millis(),
                date: Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
                operation: BackupOperation::RestoreBulk,
                table: table_name.to_string(),
                key: entry.key.clone(),
                restored_version: Some(entry.version),
                bulk_id: Some(bulk_id.to_string()),
                data: data.clone(),
            };

            let rk = format!("{}:{}", entry.key, new_version);
            let rdata = serde_json::to_vec(&restore_record)?;
            let write_txn = self.db.begin_write()?;
            {
                if self.has_cache {
                    let mut tbl = write_txn.open_table(table)?;
                    tbl.insert(rk.as_str(), rdata.as_slice())?;
                } else {
                    let mut tbl = write_txn.open_table(table)?;
                    let mut slot = tbl.insert_reserve(rk.as_str(), rdata.len())?;
                    slot.as_mut().copy_from_slice(&rdata);
                }
            }
            write_txn.commit()?;

            results.push((entry.key.clone(), data));
        }

        Ok(results)
    }

    pub fn list_bulk(&self, table_name: &str) -> Result<Vec<BulkRecord>> {
        let bulk_name = bulk_table_name(table_name);
        let bulk_table: TableDefinition<&str, &[u8]> = TableDefinition::new(bulk_name.as_str());

        let read_txn = self.db.begin_read()?;
        let btbl = read_txn.open_table(bulk_table)?;

        let mut records: Vec<BulkRecord> = btbl
            .iter()?
            .filter_map(|e| e.ok())
            .filter_map(|(_, v)| serde_json::from_slice::<BulkRecord>(v.value()).ok())
            .collect();

        records.sort_by_key(|r| r.timestamp);
        Ok(records)
    }

    /// Retrieve history of a specific key — ordered from oldest to newest
    pub fn history<'db>(
        &self,
        table: TableDefinition<'db, &str, &[u8]>,
        key: &str,
    ) -> Result<Vec<BackupRecord>> {
        let read_txn = self.db.begin_read()?;
        let tbl = read_txn.open_table(table)?;
        let prefix = format!("{}:", key);

        let mut records: Vec<BackupRecord> = tbl
            .iter()?
            .filter_map(|e| e.ok())
            .filter(|(k, _)| k.value().starts_with(&prefix))
            .filter_map(|(_, v)| serde_json::from_slice::<BackupRecord>(v.value()).ok())
            .collect();

        records.sort_by_key(|r| r.version);
        Ok(records)
    }

    /// The last version of data before a specific timestamp
    pub fn view_at<'db>(
        &self,
        table: TableDefinition<'db, &str, &[u8]>,
        key: &str,
        timestamp: i64,
    ) -> Result<Option<Vec<u8>>> {
        Ok(self
            .history(table, key)?
            .into_iter()
            .filter(|r| r.timestamp <= timestamp)
            .last()
            .and_then(|r| match r.operation {
                BackupOperation::Set => r.data,
                BackupOperation::Restore => r.data,
                BackupOperation::RestoreBulk => r.data,
                BackupOperation::Delete => None,
            }))
    }

    pub fn view_by_version<'db>(
        &self,
        table: TableDefinition<'db, &str, &[u8]>,
        key: &str,
        version: u64,
    ) -> Result<Option<Vec<u8>>> {
        let backup_key = format!("{}:{}", key, version);
        let read_txn = self.db.begin_read()?;
        let tbl = read_txn.open_table(table)?;

        Ok(tbl
            .get(backup_key.as_str())?
            .and_then(|v| serde_json::from_slice::<BackupRecord>(v.value()).ok())
            .and_then(|r| match r.operation {
                BackupOperation::Set => r.data,
                BackupOperation::Restore => r.data,
                BackupOperation::RestoreBulk => r.data,
                BackupOperation::Delete => None,
            }))
    }

    pub fn current_version(&self, table_name: &str, key: &str) -> Result<u64> {
        let ver_name = version_table_name(table_name);
        let ver_table: TableDefinition<&str, u64> = TableDefinition::new(ver_name.as_str());

        let read_txn = self.db.begin_read()?;
        let tbl = read_txn.open_table(ver_table)?;

        Ok(tbl.get(key)?.map(|v| v.value()).unwrap_or(0))
    }

    // ── Internal ──────────────────────────────────────────────────────

    fn next_version(&self, table_name: &str, key: &str) -> Result<u64> {
        let ver_name = version_table_name(table_name);

        let ver_table: TableDefinition<&str, u64> = TableDefinition::new(ver_name.as_str());

        let write_txn = self.db.begin_write()?;
        let new_version = {
            let mut tbl = write_txn.open_table(ver_table)?;
            let current = tbl.get(key)?.map(|v| v.value()).unwrap_or(0);
            let next = current + 1;
            tbl.insert(key, next)?;
            next
        };
        write_txn.commit()?;

        Ok(new_version)
    }

    fn write<'db>(
        &self,
        table: TableDefinition<'db, &str, &[u8]>,
        key: &str,
        version: u64,
        record: &BackupRecord,
    ) -> Result<()> {
        // backup key = "entity_id:version" → append-only ✅
        let backup_key = format!("{}:{}", key, version);
        let data = serde_json::to_vec(record)?;

        let write_txn = self.db.begin_write()?;
        {
            if self.has_cache {
                let mut tbl = write_txn.open_table(table)?;
                tbl.insert(backup_key.as_str(), data.as_slice())?;
            } else {
                let mut tbl = write_txn.open_table(table)?;
                let mut slot = tbl.insert_reserve(backup_key.as_str(), data.len())?;
                slot.as_mut().copy_from_slice(&data);
            }
        }
        write_txn.commit()?;

        Ok(())
    }

    pub fn write_bulk<'db>(&self, table_name: &str, entries: Vec<(String, u64)>) -> Result<String> {
        let entries: Vec<BulkEntry> = entries
            .into_iter()
            .map(|(key, version)| BulkEntry { key, version })
            .collect();

        if entries.is_empty() {
            return Err(ClError::Validation("no valid ids provided".into()).into());
        }

        let bulk_id = uuid::Uuid::new_v4().to_string();

        {
            let record = BulkRecord {
                bulk_id: bulk_id.clone(),
                timestamp: Local::now().timestamp_millis(),
                date: Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
                table: table_name.to_string(),
                entries,
            };

            let bulk_name = bulk_table_name(table_name);
            let bulk_table: TableDefinition<&str, &[u8]> = TableDefinition::new(bulk_name.as_str());
            let data = serde_json::to_vec(&record)?;
            let write_txn = self.db.begin_write()?;
            {
                if self.has_cache {
                    let mut btbl = write_txn.open_table(bulk_table)?;
                    btbl.insert(bulk_id.as_str(), data.as_slice())?;
                } else {
                    let mut btbl = write_txn.open_table(bulk_table)?;
                    let mut slot = btbl.insert_reserve(bulk_id.as_str(), data.len())?;
                    slot.as_mut().copy_from_slice(&data);
                }
            }
            write_txn.commit()?;
            record
        };

        Ok(bulk_id)
    }
}
