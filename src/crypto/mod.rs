//! Encryption foundation: keys, key locking, subkey derivation, ciphers, fingerprints.
//!
//! Nothing here touches storage. Every algorithm comes from an established, published library; this module
//! only joins them and enforces the key rules. The public shape is provisional until
//! field encryption is built on top of it.
mod cipher;
mod error;
mod kdf;
mod keys;
mod mac;
mod secret;

#[cfg(test)]
mod kat_tests;
#[cfg(test)]
mod kat_vectors;
#[cfg(test)]
mod kdf_tests;
#[cfg(test)]
mod key_tests;

pub use cipher::{Aead, CipherKind, TAG_LEN};
pub use error::{CryptoError, OpenDiagnostic, Result};
pub use kdf::{HkdfHash, PasswordKdf};
pub use keys::{
    Access, DataKey, KeySuite, LockedDataKey, LockedKey, ProgrammerKey, ReadRoot, SALT_LEN, Scope,
    SearchRoot,
};
pub use mac::{MacKind, MacTag};
pub use secret::{KEY_LEN, Key32, SecretBytes, ct_eq, random_bytes};
