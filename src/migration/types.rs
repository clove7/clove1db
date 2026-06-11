use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

pub const MIGRATION_INDEX_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationKind {
    InPlaceEvolve,
    DataTransfer,
    ExternalImport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetConflictPolicy {
    Fail,
    Skip,
    OverwriteIfCompatible,
    Overwrite,
}

impl Default for TargetConflictPolicy {
    fn default() -> Self {
        Self::Fail
    }
}

/// Legacy alias kept for manifest serialization compatibility in reports.
pub type KeyConflictPolicy = TargetConflictPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyDecoder {
    Utf8String,
    U64AsString,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueDecoder {
    RawPassthrough,
    JsonValidate,
    /// `u64` keys with JSON stored in redb's `String` column (legacy API style).
    JsonString,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaRef {
    pub db: String,
    pub table: String,
    pub schema_id: String,
    pub schema_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionScope {
    pub backup_versions_from: u64,
    pub backup_versions_to: u64,
    pub scope_table: String,
    pub primary_snapshot_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableRenameInfo {
    pub from_table: String,
    pub to_table: String,
    pub backup_rewrite: bool,
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
    pub from_layout_hash: String,
    pub to_layout_hash: String,
    pub target_conflict_policy: TargetConflictPolicy,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table_rename: Option<TableRenameInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_diff: Option<Vec<FieldDiffEntry>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDiffEntry {
    pub op: String,
    pub field: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_field: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationIndexEntry {
    pub migration_id: String,
    pub order: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableChainSummary {
    pub schema_id: String,
    pub current_version: u32,
    pub initial_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableChainIndex {
    pub schema_id: String,
    pub current_version: u32,
    pub initial_version: u32,
    pub chain: Vec<MigrationIndexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbMigrationRootIndex {
    pub index_version: u32,
    pub db_name: String,
    pub tables: HashMap<String, TableChainSummary>,
}

// ── API types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MigrationFrom {
    pub db: String,
    pub table: String,
}

#[derive(Debug, Clone)]
pub struct MigrationTo {
    pub db: String,
    pub table: Option<String>,
    pub delete_source: bool,
}

impl MigrationTo {
    pub fn new(db: impl Into<String>) -> Self {
        Self {
            db: db.into(),
            table: None,
            delete_source: false,
        }
    }

    pub fn table(mut self, table: impl Into<String>) -> Self {
        self.table = Some(table.into());
        self
    }

    pub fn delete_source(mut self, delete: bool) -> Self {
        self.delete_source = delete;
        self
    }
}

#[derive(Debug, Clone)]
pub struct ExternalFrom {
    pub path: PathBuf,
    pub table: String,
    pub key_decoder: KeyDecoder,
    pub value_decoder: ValueDecoder,
}

pub fn migration_dir_name(db_name: &str) -> String {
    format!("{}.migration", db_name)
}

pub fn table_chain_dir(migration_dir: &std::path::Path, table: &str) -> std::path::PathBuf {
    migration_dir.join("tables").join(table)
}

pub fn layout_path(table_dir: &std::path::Path, version: u32) -> std::path::PathBuf {
    table_dir.join("layouts").join(format!("v{version}.json"))
}

#[derive(Debug, Clone)]
pub struct RedbTableSpec {
    pub source_table: String,
    pub key_decoder: KeyDecoder,
    pub value_decoder: ValueDecoder,
}
