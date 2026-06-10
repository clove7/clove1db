use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationKind {
    SameDbRemapTable,
    CrossDbMove,
    ExternalImport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyConflictPolicy {
    Fail,
    Overwrite,
    Skip,
}

impl Default for KeyConflictPolicy {
    fn default() -> Self {
        Self::Fail
    }
}

#[derive(Debug, Clone)]
pub enum MigrationSourceRef {
    CloveDb {
        path: PathBuf,
        table: String,
    },
    Explicit {
        db_name: String,
        table: String,
    },
    ExternalRedb {
        path: PathBuf,
        spec: RedbTableSpec,
    },
}

#[derive(Debug, Clone)]
pub enum MigrationTargetRef {
    Explicit {
        db_name: String,
        table: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyDecoder {
    Utf8String,
    U64AsString,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueDecoder {
    RawPassthrough,
    JsonValidate,
}

#[derive(Debug, Clone)]
pub struct RedbTableSpec {
    pub source_table: String,
    pub key_decoder: KeyDecoder,
    pub value_decoder: ValueDecoder,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaRef {
    pub db: String,
    pub table: String,
    pub schema: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionScope {
    pub backup_versions_from: u64,
    pub backup_versions_to: u64,
    pub primary_snapshot_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationManifest {
    pub migration_id: String,
    pub parent_migration_id: Option<String>,
    pub timestamp: i64,
    pub kind: MigrationKind,
    pub from: SchemaRef,
    pub to: SchemaRef,
    pub version_scope: VersionScope,
    pub decoder: String,
    pub key_conflict_policy: KeyConflictPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationIndexEntry {
    pub migration_id: String,
    pub order: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationIndex {
    pub db_name: String,
    pub current_schema: String,
    pub initial_schema: String,
    pub chain: Vec<MigrationIndexEntry>,
}

pub fn migration_dir_name(db_name: &str) -> String {
    format!("{}.migration", db_name)
}
