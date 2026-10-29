//! The small keys file `{db}.keys`: the locked data key and the identity of each table with
//! protected fields, so the protected values (and the attachments) can still be opened if the main
//! file is lost.
//!
//! ```text
//! "CLVK" | version | len(lock read) u16 | lock read | len(lock search) u16 | lock search |
//! len(sealed) u32 | sealed table list
//! ```
//! The two locks are the data key sealed under the programmer's read key and search key, exactly as
//! they are stored in the main file. The table list (names and identities) is sealed with a key made
//! from the data key, so no table name is readable; everything before it is the associated data of
//! that seal, so changing any byte of the header or of the list is an error. A byte changed inside a
//! lock makes the lock fail to open, which is the same error as a wrong key.
use super::keys::FieldKeys;
use crate::{
    crypto::{LockedDataKey, LockedKey},
    durability::DurabilityMode,
    units::{ClError, Result},
};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 4] = b"CLVK";
const VERSION: u8 = 1;

/// The default place of the file: next to the main file.
pub(crate) fn default_path(db_dir: &Path, db_name: &str) -> PathBuf {
    db_dir.join(format!("{db_name}.keys"))
}

/// A parsed file: the two locks, and the sealed list still sealed.
pub(crate) struct KeyFile {
    pub(crate) locked: LockedDataKey,
    /// Everything before the sealed list: the associated data of its seal.
    header: Vec<u8>,
    sealed: Vec<u8>,
}

fn tampered() -> ClError {
    ClError::DataTampered
}

/// The file for `locked` and the tables `ids` (name, identity), sealed with `keys`.
pub(crate) fn encode(locked: &LockedDataKey, ids: &[(String, String)], keys: &FieldKeys) -> Result<Vec<u8>> {
    let mut sorted: Vec<&(String, String)> = ids.iter().collect();
    sorted.sort();
    let list = serde_json::to_vec(&sorted)?;
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    for lock in [&locked.read, &locked.search] {
        let bytes = lock.as_bytes();
        out.extend_from_slice(&u16::try_from(bytes.len()).map_err(|_| tampered())?.to_le_bytes());
        out.extend_from_slice(bytes);
    }
    let sealed = keys
        .key_file_cipher()?
        .seal(&out, &list)
        .map_err(|_| ClError::Validation("the keys file could not be sealed".into()))?;
    out.extend_from_slice(&u32::try_from(sealed.len()).map_err(|_| tampered())?.to_le_bytes());
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Splits a file into its parts. Anything that is not exactly the format is a tamper error.
pub(crate) fn parse(bytes: &[u8]) -> Result<KeyFile> {
    struct Cursor<'a> {
        bytes: &'a [u8],
        at: usize,
    }
    impl<'a> Cursor<'a> {
        fn take(&mut self, n: usize) -> Result<&'a [u8]> {
            let end = self.at.checked_add(n).filter(|end| *end <= self.bytes.len()).ok_or_else(tampered)?;
            let part = &self.bytes[self.at..end];
            self.at = end;
            Ok(part)
        }
    }
    let mut cursor = Cursor { bytes, at: 0 };
    if cursor.take(4)? != MAGIC || cursor.take(1)? != [VERSION] {
        return Err(tampered());
    }
    let mut locks = Vec::new();
    for _ in 0..2 {
        let len = u16::from_le_bytes(cursor.take(2)?.try_into().map_err(|_| tampered())?) as usize;
        locks.push(LockedKey::from_bytes(cursor.take(len)?.to_vec()));
    }
    let header_end = cursor.at;
    let len = u32::from_le_bytes(cursor.take(4)?.try_into().map_err(|_| tampered())?) as usize;
    let sealed = cursor.take(len)?.to_vec();
    if cursor.at != bytes.len() {
        return Err(tampered());
    }
    let search = locks.pop().ok_or_else(tampered)?;
    let read = locks.pop().ok_or_else(tampered)?;
    Ok(KeyFile { locked: LockedDataKey { read, search }, header: bytes[..header_end].to_vec(), sealed })
}

impl KeyFile {
    /// The tables (name, identity), sorted by name. Needs the read key.
    pub(crate) fn tables(&self, keys: &FieldKeys) -> Result<Vec<(String, String)>> {
        let plain = keys.key_file_cipher()?.open(&self.header, &self.sealed).map_err(|_| tampered())?;
        let mut list: Vec<(String, String)> = serde_json::from_slice(plain.as_bytes()).map_err(|_| tampered())?;
        list.sort();
        Ok(list)
    }
}

/// The file at `path`, or `None` when there is none.
pub(crate) fn read_file(path: &Path) -> Result<Option<KeyFile>> {
    match std::fs::read(path) {
        Ok(bytes) => parse(&bytes).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Writes the file through a temporary file and a rename (and a sync in strict mode).
pub(crate) fn write_file(path: &Path, bytes: &[u8], mode: DurabilityMode) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    crate::fsutil::write_atomic(path, bytes, mode)
}
