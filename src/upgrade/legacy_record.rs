use crate::backup::{BackupRecord, codec};
use crate::units::Result;
pub fn parse_backup_value(
    table_name: &str,
    backup_key: &str,
    value: &[u8],
) -> Result<BackupRecord> {
    codec::decode_record(table_name, backup_key, value)
}
pub fn from_raw_entity(backup_key: &str, table_name: &str, value: &[u8]) -> Result<BackupRecord> {
    codec::raw_record(table_name, backup_key, value)
}
pub fn canonicalize_record(record: BackupRecord) -> BackupRecord {
    record
}
pub fn canonical_bytes(record: &BackupRecord) -> Result<Vec<u8>> {
    codec::encode_record(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::BackupOperation;

    #[test]
    fn parses_current_backup_record() {
        let record = BackupRecord {
            date_from_migration: false,
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
