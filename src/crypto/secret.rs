//! Secret byte holders: wiped on drop, constant-time equality, redacted output.
//!
//! Limit of the language: a value returned by value is copied by the compiler, and the old
//! stack slot is not under our control. Keys therefore stay inside their holder and are
//! lent out as slices.
use super::error::{CryptoError, Result};
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEY_LEN: usize = 32;
pub(crate) const REDACTED: &str = "[redacted]";

/// Constant-time equality for secret values. The length is not secret.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Fill `buf` from the operating system's random source.
pub(crate) fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| CryptoError::Random)
}

/// Fill `buf` from the operating system's random source (for padding and filler that must look
/// random; keys come from [`Key32::generate`]).
pub fn random_bytes(buf: &mut [u8]) -> Result<()> {
    fill_random(buf)
}

/// A 256-bit key. No `Clone`, wiped on drop, compared in constant time.
pub struct Key32([u8; KEY_LEN]);

impl Key32 {
    /// A fresh random key from the system.
    pub fn generate() -> Result<Self> {
        let mut key = Key32([0; KEY_LEN]);
        fill_random(&mut key.0)?;
        Ok(key)
    }
    pub fn from_bytes(bytes: &[u8; KEY_LEN]) -> Self {
        Key32(*bytes)
    }
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let bytes: &[u8; KEY_LEN] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidParams("key must be 32 bytes"))?;
        Ok(Self::from_bytes(bytes))
    }
    pub(crate) fn zeroed() -> Self {
        Key32([0; KEY_LEN])
    }
    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
    pub(crate) fn as_bytes_mut(&mut self) -> &mut [u8; KEY_LEN] {
        &mut self.0
    }
}

impl Zeroize for Key32 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl Drop for Key32 {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for Key32 {}

impl PartialEq for Key32 {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(&self.0, &other.0)
    }
}
impl Eq for Key32 {}

impl fmt::Debug for Key32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key32({REDACTED})")
    }
}
impl fmt::Display for Key32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

/// Secret bytes of any length: a password, or a decrypted value. Wiped on drop.
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        SecretBytes(bytes)
    }
    pub fn from_slice(bytes: &[u8]) -> Self {
        SecretBytes(bytes.to_vec())
    }
    /// A zero-filled buffer of `len` bytes, allocated once so nothing is left behind by growth.
    pub(crate) fn zeroed(len: usize) -> Self {
        SecretBytes(vec![0; len])
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub(crate) fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Zeroize for SecretBytes {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for SecretBytes {}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(&self.0, &other.0)
    }
}
impl Eq for SecretBytes {}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes({REDACTED})")
    }
}
impl fmt::Display for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}
