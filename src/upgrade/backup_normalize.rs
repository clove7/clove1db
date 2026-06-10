use std::fs;
use std::path::Path;

use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};

use crate::backup::{BackupRecord, BulkRecord};
use crate::metadata::inspect::{pre_upgrade_path, upgrading_path};
use crate::upgrade::legacy_record::{canonical_bytes, parse_backup_value};
use crate::units::{ClError, Result};

const BATCH_SIZE: usize = 1000;

pub struct BackupNormalizeResult {
    pub upgraded: bool,
    pub entries_converted: usize,
    pub entries_skipped: usize,
    pub pre_upgrade_removed: bool,
}

pub fn eager_normalize(
    backup_path: &Path,
    data_tables: &[String],
    has_cache: bool,
) -> Result<BackupNormalizeResult> {
    if !backup_path.exists() {
        return Ok(BackupNormalizeResult {
            upgraded: false,
            entries_converted: 0,
            entries_skipped: 0,
            pre_upgrade_removed: false,
        });
    }

    if is_fully_normalized(backup_path, data_tables)? {
        return Ok(BackupNormalizeResult {
            upgraded: false,
            entries_converted: 0,
            entries_skipped: count_data_entries(backup_path, data_tables)?,
            pre_upgrade_removed: false,
        });
    }

    let pre_path = pre_upgrade_path(backup_path);
    if !pre_path.exists() {
        fs::copy(backup_path, &pre_path)?;
    }

    let upgrading = upgrading_path(backup_path);
    if upgrading.exists() {
        fs::remove_file(&upgrading)?;
    }
    fs::copy(backup_path, &upgrading)?;

    let (converted, skipped) = transform_database(&upgrading, data_tables, has_cache)?;

    verify_normalized(&upgrading, data_tables)?;

    drop_open_handles();

    fs::remove_file(backup_path).map_err(|e| ClError::BackupNormalizeFailed {
        reason: format!("remove original backup: {}", e),
    })?;
    fs::rename(&upgrading, backup_path).map_err(|e| ClError::BackupNormalizeFailed {
        reason: format!("swap upgrading backup: {}", e),
    })?;

    let pre_removed = if pre_path.exists() {
        fs::remove_file(&pre_path).is_ok()
    } else {
        false
    };

    Ok(BackupNormalizeResult {
        upgraded: true,
        entries_converted: converted,
        entries_skipped: skipped,
        pre_upgrade_removed: pre_removed,
    })
}

fn is_fully_normalized(backup_path: &Path, data_tables: &[String]) -> Result<bool> {
    let db = Database::open(backup_path).map_err(|e| ClError::Database(redb::Error::from(e)))?;
    let read_txn = db.begin_read()?;

    for table_name in data_tables {
        let table: TableDefinition<&str, &[u8]> = TableDefinition::new(table_name.as_str());
        let table_ref = match read_txn.open_table(table) {
            Ok(t) => t,
            Err(_) => continue,
        };
        for entry in table_ref.iter()? {
            let (_, value) = entry?;
            let bytes = value.value();
            if bytes.is_empty() {
                continue;
            }
            if serde_json::from_slice::<BackupRecord>(bytes).is_err() {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn count_data_entries(backup_path: &Path, data_tables: &[String]) -> Result<usize> {
    let db = Database::open(backup_path).map_err(|e| ClError::Database(redb::Error::from(e)))?;
    let read_txn = db.begin_read()?;
    let mut count = 0;
    for table_name in data_tables {
        let table: TableDefinition<&str, &[u8]> = TableDefinition::new(table_name.as_str());
        if let Ok(table_ref) = read_txn.open_table(table) {
            count += table_ref.iter()?.count();
        }
    }
    Ok(count)
}

fn transform_database(
    path: &Path,
    data_tables: &[String],
    has_cache: bool,
) -> Result<(usize, usize)> {
    let db = Database::open(path).map_err(|e| ClError::Database(redb::Error::from(e)))?;
    let mut converted = 0usize;
    let mut skipped = 0usize;

    for table_name in data_tables {
        let bulk_name = format!("{}_bulk", table_name);
        let ver_name = format!("{}_version", table_name);

        let entries = read_table_entries(&db, table_name)?;
        if entries.is_empty() {
            continue;
        }

        let mut batch: Vec<(String, Vec<u8>)> = Vec::new();
        for (key, value) in entries {
            if serde_json::from_slice::<BackupRecord>(&value).is_ok() {
                skipped += 1;
                batch.push((key, value));
            } else {
                let record = parse_backup_value(table_name, &key, &value)?;
                let bytes = canonical_bytes(&record)?;
                converted += 1;
                batch.push((key, bytes));
            }
            if batch.len() >= BATCH_SIZE {
                write_batch(&db, table_name, &batch, has_cache)?;
                batch.clear();
            }
        }
        if !batch.is_empty() {
            write_batch(&db, table_name, &batch, has_cache)?;
        }

        normalize_bulk_table(&db, &bulk_name, has_cache)?;
        let _ = ver_name;
    }

    Ok((converted, skipped))
}

fn read_table_entries(db: &Database, table_name: &str) -> Result<Vec<(String, Vec<u8>)>> {
    let read_txn = db.begin_read()?;
    let table: TableDefinition<&str, &[u8]> = TableDefinition::new(table_name);
    let table_ref = read_txn.open_table(table).map_err(|_| {
        ClError::BackupNormalizeFailed {
            reason: format!("table '{}' not found in backup", table_name),
        }
    })?;
    Ok(table_ref
        .iter()?
        .filter_map(|e| e.ok())
        .map(|(k, v)| (k.value().to_string(), v.value().to_vec()))
        .collect())
}

fn write_batch(
    db: &Database,
    table_name: &str,
    batch: &[(String, Vec<u8>)],
    has_cache: bool,
) -> Result<()> {
    let table: TableDefinition<&str, &[u8]> = TableDefinition::new(table_name);
    let mut write_txn = db.begin_write()?;
    if !has_cache {
        write_txn.set_durability(Durability::Immediate)?;
    }
    {
        let mut table_ref = write_txn.open_table(table)?;
        for (key, value) in batch {
            if has_cache {
                table_ref.insert(key.as_str(), value.as_slice())?;
            } else {
                let mut slot = table_ref.insert_reserve(key.as_str(), value.len())?;
                slot.as_mut().copy_from_slice(value);
            }
        }
    }
    write_txn.commit()?;
    Ok(())
}

fn normalize_bulk_table(db: &Database, bulk_table_name: &str, has_cache: bool) -> Result<()> {
    let read_txn = db.begin_read()?;
    let table: TableDefinition<&str, &[u8]> = TableDefinition::new(bulk_table_name);
    let Ok(table_ref) = read_txn.open_table(table) else {
        return Ok(());
    };

    let entries: Vec<(String, Vec<u8>)> = table_ref
        .iter()?
        .filter_map(|e| e.ok())
        .map(|(k, v)| (k.value().to_string(), v.value().to_vec()))
        .collect();
    drop(read_txn);

    if entries.is_empty() {
        return Ok(());
    }

    let mut batch = Vec::new();
    for (key, value) in entries {
        if serde_json::from_slice::<BulkRecord>(&value).is_ok() {
            batch.push((key, value));
        } else {
            return Err(ClError::BackupNormalizeFailed {
                reason: format!("bulk entry '{}' is not valid BulkRecord JSON", key),
            });
        }
    }
    write_batch(db, bulk_table_name, &batch, has_cache)
}

fn verify_normalized(backup_path: &Path, data_tables: &[String]) -> Result<()> {
    let before = count_data_entries(backup_path, data_tables)?;
    if !is_fully_normalized(backup_path, data_tables)? {
        return Err(ClError::BackupNormalizeFailed {
            reason: "verify failed: not all entries parse as BackupRecord".into(),
        });
    }
    let after = count_data_entries(backup_path, data_tables)?;
    if before != after {
        return Err(ClError::BackupNormalizeFailed {
            reason: format!("entry count mismatch: before {} after {}", before, after),
        });
    }
    Ok(())
}

fn drop_open_handles() {
    // redb Database drops when out of scope; explicit hook for future use
}
