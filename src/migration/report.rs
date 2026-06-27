use serde::{Deserialize, Serialize};

use crate::migration::types::TargetConflictPolicy;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictEntry {
    pub table: String,
    pub key: String,
    pub policy: TargetConflictPolicy,
}

/// A source row skipped inside [`MigrateTo::migrate_json`] / [`MigrateTo::migrate_blob`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedEntry {
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationReport {
    pub dry_run: bool,
    pub migration_id: String,
    pub source_count: usize,
    pub would_insert: usize,
    pub would_overwrite: usize,
    /// Rows skipped because the target key already exists (`TargetConflictPolicy::Skip`).
    pub would_skip: usize,
    /// Rows skipped by the migration transform (`MigrateOutcome::Skip`).
    #[serde(default)]
    pub source_skipped: usize,
    #[serde(default)]
    pub skipped_entries: Vec<SkippedEntry>,
    pub conflicts: Vec<ConflictEntry>,
    pub would_delete_old_db: bool,
    pub errors: Vec<String>,
    #[serde(default)]
    pub blobs_written: usize,
    #[serde(default)]
    pub blobs_copied: usize,
    #[serde(default)]
    pub blobs_deleted: usize,
    #[serde(default)]
    pub metadata_only_rows: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_storage: Option<crate::metadata::types::TableStorageMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_storage: Option<crate::metadata::types::TableStorageMode>,
}

impl MigrationReport {
    pub fn new(migration_id: String, dry_run: bool) -> Self {
        Self {
            dry_run,
            migration_id,
            source_count: 0,
            would_insert: 0,
            would_overwrite: 0,
            would_skip: 0,
            source_skipped: 0,
            skipped_entries: Vec::new(),
            conflicts: Vec::new(),
            would_delete_old_db: false,
            errors: Vec::new(),
            blobs_written: 0,
            blobs_copied: 0,
            blobs_deleted: 0,
            metadata_only_rows: 0,
            from_storage: None,
            to_storage: None,
        }
    }

    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty() || !self.conflicts.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct MigrationResult {
    pub migration_id: String,
    pub records_migrated: usize,
    pub report: MigrationReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalScanSummary {
    pub table: String,
    pub row_count: usize,
    pub total_value_bytes: u64,
}
