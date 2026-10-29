//! Keyed fingerprints: the same value and key always give the same tag, and nothing else does.
use super::{
    error::{CryptoError, Result},
    secret::{Key32, ct_eq},
};
use hmac::{Hmac, KeyInit, Mac, SimpleHmac};
use sha2::{Sha256, Sha512};
use sha3::Sha3_256;

const MAX_TAG_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacKind {
    HmacSha256,
    HmacSha512,
    HmacSha3_256,
    Blake3Keyed,
}

/// A fingerprint. It is stored and searched, so it is not a secret; comparison is still
/// constant-time because the value it came from may be.
#[derive(Clone, Copy)]
pub struct MacTag {
    bytes: [u8; MAX_TAG_LEN],
    len: usize,
}

impl MacTag {
    fn from_slice(tag: &[u8]) -> Self {
        let mut bytes = [0; MAX_TAG_LEN];
        bytes[..tag.len()].copy_from_slice(tag);
        Self {
            bytes,
            len: tag.len(),
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl PartialEq for MacTag {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(self.as_bytes(), other.as_bytes())
    }
}
impl Eq for MacTag {}

impl std::fmt::Debug for MacTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MacTag({} bytes)", self.len)
    }
}

impl MacKind {
    pub const ALL: [MacKind; 4] = [
        MacKind::HmacSha256,
        MacKind::HmacSha512,
        MacKind::HmacSha3_256,
        MacKind::Blake3Keyed,
    ];

    pub fn output_len(self) -> usize {
        match self {
            MacKind::HmacSha512 => 64,
            _ => 32,
        }
    }

    pub fn mac(self, key: &Key32, data: &[u8]) -> Result<MacTag> {
        self.mac_with_key(key.as_bytes(), data)
    }

    pub(crate) fn mac_with_key(self, key: &[u8], data: &[u8]) -> Result<MacTag> {
        match self {
            MacKind::HmacSha256 => hmac_tag::<Hmac<Sha256>>(key, data),
            MacKind::HmacSha512 => hmac_tag::<Hmac<Sha512>>(key, data),
            MacKind::HmacSha3_256 => hmac_tag::<SimpleHmac<Sha3_256>>(key, data),
            MacKind::Blake3Keyed => {
                let key: &[u8; 32] = key
                    .try_into()
                    .map_err(|_| CryptoError::InvalidParams("BLAKE3 key must be 32 bytes"))?;
                Ok(MacTag::from_slice(blake3::keyed_hash(key, data).as_bytes()))
            }
        }
    }

    /// Recompute the tag for `data` and compare with `expected` in constant time.
    pub fn verify(self, key: &Key32, data: &[u8], expected: &[u8]) -> Result<bool> {
        Ok(ct_eq(self.mac(key, data)?.as_bytes(), expected))
    }
}

fn hmac_tag<M: Mac + KeyInit>(key: &[u8], data: &[u8]) -> Result<MacTag> {
    let mut mac = <M as KeyInit>::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidParams("HMAC key rejected"))?;
    mac.update(data);
    Ok(MacTag::from_slice(&mac.finalize().into_bytes()))
}
