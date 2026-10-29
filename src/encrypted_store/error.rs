//! Errors of the encrypted store. Opening has one failure; the cause goes to a diagnostic sink.
use std::fmt;
use std::io;

/// What a caller can learn from a failed call.
#[derive(Debug)]
pub enum StoreError {
    /// Every way an open can fail on the key side: wrong key, wrong cipher or hash choice, wrong
    /// password settings, no key, a plain database, a damaged or cut file. The cause is only in
    /// the diagnostic.
    OpenFailed,
    /// After a successful open: data failed authentication, so it was changed or damaged.
    Tampered,
    /// The settings given are not acceptable (nothing to do with the file's content).
    InvalidParams(&'static str),
    /// Another handle or program has the database open.
    InUse,
    /// A file opened for reading only needs repair first, which cannot be done without writing.
    NeedsRepair,
    /// An operating system error that says nothing about keys.
    Io(io::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::OpenFailed => f.write_str("the database could not be opened"),
            StoreError::Tampered => f.write_str("the database file was changed or damaged"),
            StoreError::InvalidParams(why) => write!(f, "invalid settings: {why}"),
            StoreError::InUse => f.write_str("the database is open elsewhere"),
            StoreError::NeedsRepair => f.write_str("the database needs repair before it can be read"),
            StoreError::Io(e) => write!(f, "file error: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

pub type Result<T> = std::result::Result<T, StoreError>;

/// The cause of an open failure, for the programmer. Holds no key, no password, no file content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreDiagnostic {
    /// No key was given for the part of the data key this open needs.
    KeyMissing,
    /// The lock did not open: wrong key, wrong cipher or hash choice, or wrong password settings.
    LockRejected,
    /// The file is too short or the header is not shaped like one of ours.
    HeaderMalformed,
    /// The file starts like an unencrypted redb database.
    LooksLikeUnencrypted,
    /// The key is right but the database inside could not be started (damaged or cut).
    DatabaseUnreadable,
}

impl StoreDiagnostic {
    /// The fixed event name for this cause. Nothing variable, so it can be logged freely.
    pub fn event_name(self) -> &'static str {
        match self {
            StoreDiagnostic::KeyMissing => "encryption/open_failed/key_missing",
            StoreDiagnostic::LockRejected => "encryption/open_failed/lock_rejected",
            StoreDiagnostic::HeaderMalformed => "encryption/open_failed/header_malformed",
            StoreDiagnostic::LooksLikeUnencrypted => "encryption/open_failed/looks_like_unencrypted",
            StoreDiagnostic::DatabaseUnreadable => "encryption/open_failed/database_unreadable",
        }
    }
}

/// The marker inside the I/O error the file layer returns when data fails authentication.
#[derive(Debug)]
pub(crate) struct TamperMarker {
    pub chunk: Option<u64>,
}

impl fmt::Display for TamperMarker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.chunk {
            Some(i) => write!(f, "data block {i} failed authentication"),
            None => f.write_str("data failed authentication"),
        }
    }
}

impl std::error::Error for TamperMarker {}

pub(crate) fn tamper_io(chunk: Option<u64>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, TamperMarker { chunk })
}

/// True when an I/O error came from data failing authentication (as opposed to the disk).
pub fn is_tamper(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<TamperMarker>())
}
