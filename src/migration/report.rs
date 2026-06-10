use serde::{Deserialize, Serialize};

use crate::migration::types::KeyConflictPolicy;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictEntry {
    pub table: String,
    pub key: String,
    pub policy: KeyConflictPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationReport {
    pub dry_run: bool,
    pub migration_id: String,
    pub source_count: usize,
    pub would_insert: usize,
    pub would_overwrite: usize,
    pub would_skip: usize,
    pub conflicts: Vec<ConflictEntry>,
    pub would_delete_old_db: bool,
    pub errors: Vec<String>,
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
            conflicts: Vec::new(),
            would_delete_old_db: false,
            errors: Vec::new(),
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
