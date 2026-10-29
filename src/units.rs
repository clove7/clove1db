use redb::{SetDurabilityError, StorageError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClError {
    #[error("serialized id_field must equal the row key")]
    IdFieldMismatch,
    #[error("query matched {count} rows where at most one was required")]
    NonUnique { count:u64 },
    #[error("cursor does not match this query or database")]
    InvalidCursor,
    #[error("sum requires numeric JSON values")]
    UnsupportedSum,
    #[error("decimal sum exceeds the supported 4096 coefficient digits or exponent magnitude") ]
    DecimalSumLimit,
    #[error("integer sum overflow")]
    SumOverflow,
    #[error("unique constraint violation")]
    UniqueViolation,
    #[error("unique constraint cannot be enabled: {groups} duplicate groups")]
    DuplicateGroups {groups:u64},
    #[error("journal consumer expired; register again and copy a full ReadView")]
    ConsumerExpired,
    #[error("internal journal consumer requires a full rebuild")]
    ConsumerNeedsRebuild,
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

    /// A database file (`.cldb`, `.cldb.bak` or `.inx`) is locked by another
    /// program, or is already open through another handle. Returned at once:
    /// nothing was opened, so the files are exactly as they were. Not damage and
    /// not a disk error: close the other user of the file and open again.
    #[error("database is in use by another program: {path}")]
    DatabaseInUse { path: String },

    /// Backup history was asked for, but its file (`.cldb.bak`) could not be opened or created, for a
    /// reason other than another program using it (that is [`ClError::DatabaseInUse`]). The database is
    /// not opened: it would otherwise run without recording history, silently.
    #[error("cannot open the backup history {path}: {reason}")]
    BackupOpenFailed { path: String, reason: String },

    /// The system refused memory the library needed for the caller's data, at `site` (see
    /// [`crate::memory::ALLOC_SITES`]). Returned before anything was committed: the database is
    /// as it was, and the call can be retried when memory is available. Allocations the library
    /// cannot reserve for (small ones, and those inside redb, serde_json and Rust itself) still
    /// stop the process, which loses nothing.
    #[error("out of memory: could not reserve {bytes} bytes for {site}")]
    OutOfMemory { site: &'static str, bytes: u64 },

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

    /// The database was closed by `Storage::close` (or `DatabaseManager::close`)
    /// and cannot be used again. Build a new `Storage` to reopen it.
    #[error("database is closed: {path}")]
    Closed { path: String },

    /// The database could not be opened: a wrong key, a wrong cipher or hash choice, wrong password
    /// settings, no key, an unencrypted file, or a file that is damaged or cut. One error for all of
    /// them; the cause goes to the diagnostic sink only.
    #[error("the database could not be opened")]
    EncryptedOpenFailed,

    /// Data failed authentication after the database was opened: the file was changed or damaged.
    #[error("the database file was changed or damaged")]
    DataTampered,
}

impl From<crate::encrypted_store::StoreError> for ClError {
    fn from(e: crate::encrypted_store::StoreError) -> Self {
        use crate::encrypted_store::StoreError;
        match e {
            StoreError::OpenFailed => ClError::EncryptedOpenFailed,
            StoreError::Tampered => ClError::DataTampered,
            StoreError::InvalidParams(why) => ClError::Validation(why.to_string()),
            // The path is filled in by the caller that knows it, before the error leaves the library.
            StoreError::InUse => ClError::DatabaseInUse { path: String::new() },
            StoreError::NeedsRepair => ClError::Database(redb::Error::RepairAborted),
            StoreError::Io(e) => ClError::from(e),
        }
    }
}

impl From<std::io::Error> for ClError {
    fn from(e: std::io::Error) -> Self {
        if crate::encrypted_store::is_tamper(&e) {
            return ClError::DataTampered;
        }
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
        if let StorageError::Io(io) = &e {
            if crate::encrypted_store::is_tamper(io) {
                return ClError::DataTampered;
            }
        }
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
