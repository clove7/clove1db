//! Whole-database encryption: every byte of a database file is sealed, the file shows no
//! signature, and any change to the bytes the database reads is an error, never wrong data.
//!
//! The file layer sits under redb ([`BlockBackend`]); [`EncryptedDatabase`] creates and opens
//! files with a data key that is itself locked by the programmer's keys. Nothing about the cipher
//! or its settings is written to the file: a wrong choice fails like a wrong key.
//!
//! Limits, stated plainly:
//! - A block put back at its own place from an older copy of the file has a valid seal. It is
//!   found by [`EncryptedDatabase::verify_all`] (or `verify_on_open`), not by ordinary reads.
//! - The whole file put back to an older state cannot be told from the file alone.
//! - Space redb has freed but not reused is not read, so a change there is not noticed.
//! - The number of files and their sizes are visible; so are the file names the programmer chose.
//! - Nothing converts a plain database in place: an existing plain database is moved to an
//!   encrypted one by a migration, and opening a plain file with a key is the single open error.
//! - [`verify_encrypted_files`] checks every block of closed files; an open database relies on
//!   `encryption_verify_on_open` at its next open.
#[cfg(test)]
mod database_tests;
#[cfg(test)]
mod stale_probe_tests;
#[cfg(test)]
mod write_cost_tests;
#[cfg(test)]
mod storage_cost_tests;
#[cfg(test)]
mod layer_tests;
pub mod backend;
pub mod blobs;
pub mod error;
pub mod file_header;
pub mod layout;
pub mod sealed;
pub mod sidecar;
pub mod store;
pub mod tuning;

pub use backend::BlockBackend;
pub use blobs::SealedBlobStore;
pub use tuning::EncryptionTuning;
pub use sidecar::SidecarFiles;
pub use sealed::{BLOCK as SEALED_BLOCK, FileKeys, SealedReader, SealedWriter, read_sealed_file, write_sealed_file};
pub use error::{Result, StoreDiagnostic, StoreError, is_tamper};
pub use store::{
    Credentials, EncryptedDatabase, EncryptionConfig, EncryptionContext, EncryptionHandle, KeySource,
    OpenOptionsExt, cipher_allowed, open_database_over, verify_encrypted_files,
    open_database_over_mode, open_database_over_tuned, write_file_header,
};
#[cfg(clove_test_encrypt_all)]
pub(crate) use store::test_encrypt_all_config;
