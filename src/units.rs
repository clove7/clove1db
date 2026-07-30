use redb::{SetDurabilityError, StorageError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClError {
    #[error("IO error: {0}")]
    IoError(String),
    #[error("Validation error: {0}")]
    ValidationError(String),
    #[error("Search error: {0}")]
    SearchError(String),
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("Execution error: {0}")]
    ExecutionError(String),
    #[error("Image not found: {0}")]
    ImageNotFound(String),
    #[error("Invalid coordinates: {0}")]
    InvalidCoordinates(String),
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Directory not found: {0}")]
    DirectoryNotFound(String),
    #[error("Database error: {0}")]
    Database(#[from] redb::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("corrupt migration index at '{path}': {detail}")]
    CorruptMigrationIndex { path: String, detail: String },

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Cache error: {0}")]
    Cache(String),

    #[error("UTF-8 error: {0}")]
    Utf8Error(String),

    #[error("Option None error")]
    OptionNone,

    #[error("Migration error: {0}")]
    MigrationError(String),

    #[error(
        "Version {version} ({schema_at_version}) is not restorable; current is {current_schema_version} (migration {migration_id})"
    )]
    NotRestorable {
        version: u64,
        schema_at_version: String,
        current_schema_version: String,
        migration_id: String,
    },

    #[error("Migration key conflict on table '{table}' key '{key}' with policy {policy:?}")]
    MigrationConflict {
        table: String,
        key: String,
        policy: String,
    },

    #[error("Migration decoder not found for layout {from_layout_hash} -> {to_layout_hash} (migration {migration_id})")]
    DecoderNotFound {
        from_layout_hash: String,
        to_layout_hash: String,
        migration_id: String,
    },

    #[error("layout mismatch on table '{table}': registered hash '{registered}' but chain has version {chain_version}")]
    LayoutMismatch {
        table: String,
        registered: String,
        chain_version: u32,
    },

    #[error("legacy migration format at '{path}' — re-seed or remove old migration directory")]
    LegacyMigrationFormat { path: String },

    #[error("target table '{table}' on db '{db}' already has {existing_keys} keys")]
    TargetTableOccupied {
        db: String,
        table: String,
        existing_keys: usize,
    },

    #[error("external import requires migrate::<Source, Target>() with MigrateTo impl for table '{table}'")]
    ExternalMappingRequired { table: String },

    #[error("incompatible overwrite on table '{table}' key '{key}'")]
    IncompatibleOverwrite { table: String, key: String },

    #[error("table mismatch: expected {expected:?}, found {found:?}")]
    TableMismatch {
        expected: Vec<String>,
        found: Vec<String>,
    },

    #[error("backup normalize failed: {reason}")]
    BackupNormalizeFailed { reason: String },

    #[error("not a clove1db database: {path}")]
    NotCloveDatabase { path: String },

    #[error("upgrade incomplete for database '{db_name}'")]
    UpgradeIncomplete { db_name: String },
}

impl From<std::io::Error> for ClError {
    fn from(e: std::io::Error) -> Self {
        ClError::IoError(e.to_string())
    }
}

impl From<std::path::PathBuf> for ClError {
    fn from(e: std::path::PathBuf) -> Self {
        ClError::DirectoryNotFound(e.display().to_string())
    }
}
// Implement From for redb error types
impl From<redb::TransactionError> for ClError {
    fn from(e: redb::TransactionError) -> Self {
        ClError::Database(redb::Error::from(e))
    }
}

impl From<redb::TableError> for ClError {
    fn from(e: redb::TableError) -> Self {
        ClError::Database(redb::Error::from(e))
    }
}

impl From<StorageError> for ClError {
    fn from(e: StorageError) -> Self {
        ClError::Database(redb::Error::from(e))
    }
}

impl From<redb::CommitError> for ClError {
    fn from(e: redb::CommitError) -> Self {
        ClError::Database(redb::Error::from(e))
    }
}

impl From<SetDurabilityError> for ClError {
    fn from(e: SetDurabilityError) -> Self {
        ClError::Database(redb::Error::from(e))
    }
}

impl From<std::str::Utf8Error> for ClError {
    fn from(e: std::str::Utf8Error) -> Self {
        ClError::Utf8Error(e.to_string())
    }
}

impl From<std::string::FromUtf8Error> for ClError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        ClError::Utf8Error(e.to_string())
    }
}

impl From<std::string::String> for ClError {
    fn from(e: std::string::String) -> Self {
        ClError::Utf8Error(e)
    }
}

pub type Result<T> = std::result::Result<T, ClError>;
