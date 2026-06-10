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
