//! The first 2048 bytes of an encrypted database file.
//!
//! Slot A holds the locked data key (the read lock then the search lock). Slot B is reserved for
//! changing the programmer key safely later; nothing reads it yet. Everything else is random.
//! No name, version, size or setting is written: the bytes are random-looking sealed values and
//! random filler, so nothing marks the file as ours.
use super::error::StoreDiagnostic;
use super::layout::{FILE_HEADER_LEN, SLOT_LEN};
use crate::crypto::{KEY_LEN, KeySuite, LockedDataKey, LockedKey, SALT_LEN, random_bytes};
use std::io;

/// Bytes of one locked root for this cipher.
pub fn lock_len(suite: &KeySuite) -> usize {
    SALT_LEN + suite.cipher.overhead() + KEY_LEN
}

pub fn encode(suite: &KeySuite, locked: &LockedDataKey) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0u8; FILE_HEADER_LEN as usize];
    random_bytes(&mut bytes).map_err(|_| io::Error::other("no random source"))?;
    let n = lock_len(suite);
    if locked.read.as_bytes().len() != n || locked.search.as_bytes().len() != n {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "locked key does not match the cipher"));
    }
    bytes[..n].copy_from_slice(locked.read.as_bytes());
    bytes[n..2 * n].copy_from_slice(locked.search.as_bytes());
    debug_assert!(2 * n <= SLOT_LEN);
    Ok(bytes)
}

/// redb's own file signature, public in its documentation.
const PLAIN_SIGNATURE: [u8; 9] = [b'r', b'e', b'd', b'b', 0x1A, 0x0A, 0xA9, 0x0D, 0x0A];

pub fn decode(suite: &KeySuite, bytes: &[u8]) -> Result<LockedDataKey, StoreDiagnostic> {
    if bytes.starts_with(&PLAIN_SIGNATURE) {
        return Err(StoreDiagnostic::LooksLikeUnencrypted);
    }
    let n = lock_len(suite);
    if bytes.len() < FILE_HEADER_LEN as usize {
        return Err(StoreDiagnostic::HeaderMalformed);
    }
    Ok(LockedDataKey {
        read: LockedKey::from_bytes(bytes[..n].to_vec()),
        search: LockedKey::from_bytes(bytes[n..2 * n].to_vec()),
    })
}
