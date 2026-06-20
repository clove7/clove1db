use crate::migration::types::TableStorageMode;
use crate::units::Result;

#[derive(Debug, Clone, Default)]
pub struct MigrationScanReport {
    pub source_table: String,
    pub target_table: String,
    pub from_storage: TableStorageMode,
    pub to_storage: TableStorageMode,
    pub record_count: usize,
    pub estimated_metadata_bytes: u64,
    pub estimated_blob_bytes: u64,
    pub blob_sidecar_sources: usize,
    pub inline_with_payload_hint: usize,
}

impl MigrationScanReport {
    pub fn new(source_table: impl Into<String>, target_table: impl Into<String>) -> Self {
        Self {
            source_table: source_table.into(),
            target_table: target_table.into(),
            ..Default::default()
        }
    }
}

pub fn scan_record(
    report: &mut MigrationScanReport,
    key: &str,
    bytes: &[u8],
    from_storage: TableStorageMode,
    to_storage: TableStorageMode,
) -> Result<()> {
    report.record_count += 1;
    report.from_storage = from_storage;
    report.to_storage = to_storage;

    match from_storage {
        TableStorageMode::BlobSidecar => {
            report.blob_sidecar_sources += 1;
            report.estimated_metadata_bytes += bytes.len() as u64;
            if to_storage == TableStorageMode::BlobSidecar {
                report.estimated_blob_bytes += 1;
            }
        }
        TableStorageMode::InlineJson => {
            report.estimated_metadata_bytes += bytes.len() as u64;
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) {
                if v.get("data").is_some() {
                    report.inline_with_payload_hint += 1;
                }
            }
            let _ = key;
        }
    }
    Ok(())
}
