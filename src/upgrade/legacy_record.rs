use chrono::Local;

use crate::backup::{BackupOperation, BackupRecord};
use crate::units::{ClError, Result};

/// Flexible JSON shape for BackupRecord versions that predate optional fields.
#[derive(Debug, serde::Deserialize)]
struct LegacyBackupJson {
    version: u64,
    timestamp: i64,
    date: String,
    operation: BackupOperation,
    table: String,
    key: String,
    #[serde(default)]
    data: Option<Vec<u8>>,
    #[serde(default)]
    bulk_id: Option<String>,
    #[serde(default)]
    restored_version: Option<u64>,
}

pub fn parse_backup_value(
    table_name: &str,
    backup_key: &str,
    value: &[u8],
) -> Result<BackupRecord> {
    if value.is_empty() {
        return from_raw_entity(backup_key, table_name, value);
    }

    if let Ok(record) = serde_json::from_slice::<BackupRecord>(value) {
        return Ok(canonicalize_record(record));
    }

    if let Ok(legacy) = serde_json::from_slice::<LegacyBackupJson>(value) {
        return Ok(canonicalize_record(BackupRecord {
            version: legacy.version,
            timestamp: legacy.timestamp,
            date: legacy.date,
            operation: legacy.operation,
            table: legacy.table,
            key: legacy.key,
            data: legacy.data,
            bulk_id: legacy.bulk_id,
            restored_version: legacy.restored_version,
        }));
    }

    from_raw_entity(backup_key, table_name, value)
}

pub fn from_raw_entity(backup_key: &str, table_name: &str, value: &[u8]) -> Result<BackupRecord> {
    let (entity_key, version) = parse_versioned_key(backup_key)?;
    let operation = if value.is_empty() {
        BackupOperation::Delete
    } else {
        BackupOperation::Set
    };
    let data = if value.is_empty() {
        None
    } else {
        Some(value.to_vec())
    };

    Ok(BackupRecord {
        version,
        timestamp: 0,
        date: Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
        operation,
        table: table_name.to_string(),
        key: entity_key,
        data,
        bulk_id: None,
        restored_version: None,
    })
}

pub fn canonicalize_record(mut record: BackupRecord) -> BackupRecord {
    if record.table.is_empty() {
        record.table = "unknown".into();
    }
    record
}

pub fn canonical_bytes(record: &BackupRecord) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(record)?)
}

fn parse_versioned_key(backup_key: &str) -> Result<(String, u64)> {
    let Some((entity_key, version_str)) = backup_key.rsplit_once(':') else {
        return Err(ClError::BackupNormalizeFailed {
            reason: format!("key '{}' is not versioned", backup_key),
        });
    };
    let version: u64 = version_str.parse().map_err(|_| ClError::BackupNormalizeFailed {
        reason: format!("invalid version suffix in '{}'", backup_key),
    })?;
    Ok((entity_key.to_string(), version))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_current_backup_record() {
        let record = BackupRecord {
            version: 1,
            timestamp: 1,
            date: "d".into(),
            operation: BackupOperation::Set,
            table: "t".into(),
            key: "k".into(),
            data: Some(b"{\"id\":\"k\"}".to_vec()),
            bulk_id: None,
            restored_version: None,
        };
        let bytes = serde_json::to_vec(&record).unwrap();
        let parsed = parse_backup_value("t", "k:1", &bytes).unwrap();
        assert_eq!(parsed.version, 1);
        assert!(parsed.data.is_some());
    }

    #[test]
    fn fallback_raw_entity() {
        let bytes = br#"{"id":"a","v":1}"#;
        let parsed = parse_backup_value("products", "a:2", bytes).unwrap();
        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.key, "a");
        assert!(matches!(parsed.operation, BackupOperation::Set));
    }

    #[test]
    fn delete_raw_empty_value() {
        let parsed = parse_backup_value("products", "a:3", &[]).unwrap();
        assert!(matches!(parsed.operation, BackupOperation::Delete));
        assert!(parsed.data.is_none());
    }
}
