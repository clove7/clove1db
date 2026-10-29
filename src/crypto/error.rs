//! One error for every failed open, and the non-secret detail kept for the developer.
use thiserror::Error;

/// Failure of the crypto layer.
///
/// A failed open is always [`CryptoError::OpenFailed`], whatever the cause: wrong key, wrong
/// cipher kind, damaged lock, or no key at all. Telling these apart would help someone guessing.
/// The cause goes to the developer through [`OpenDiagnostic`], never through the error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CryptoError {
    #[error("cannot open: wrong key or damaged data")]
    OpenFailed,
    #[error("system random source unavailable")]
    Random,
    /// A configuration value is outside what the algorithm accepts. The text is fixed and
    /// never carries a key, password or salt.
    #[error("invalid crypto parameters: {0}")]
    InvalidParams(&'static str),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

/// Why an open failed. For the developer's diagnostic event only; it holds no secret value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenDiagnostic {
    /// No key was supplied for something that needs one.
    KeyMissing,
    /// The locked key has a length or layout no cipher kind produces.
    MalformedInput,
    /// Authentication failed: wrong key, wrong cipher kind, or modified bytes.
    AuthenticationFailed,
}
