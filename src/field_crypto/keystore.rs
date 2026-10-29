//! The keys of a database that is not encrypted as a whole but has protected fields.
//!
//! The data key is made when the database is created and stored locked (sealed under the
//! programmer's read and search keys) in an internal table of the main file. The table name starts
//! with `__`, which is reserved, and the table is written without any journal effect, so it is in
//! neither the change log nor the backup history. Nothing about the cipher is stored. A copy of the
//! lock, with the table identities, lives in the small keys file next to the database (`keyfile`).
use super::keys::FieldKeys;
use crate::{
    crypto::{DataKey, LockedDataKey, LockedKey, ProgrammerKey},
    encrypted_store::{EncryptionConfig, KeySource},
    units::{ClError, Result},
};
use redb::{ReadableDatabase, ReadableTable, TableDefinition, WriteTransaction};
use std::sync::Arc;

pub(crate) const TABLE: TableDefinition<'static, &str, &[u8]> = TableDefinition::new("__field_keys");

fn programmer(source: &KeySource) -> ProgrammerKey<'_> {
    match source {
        KeySource::Raw(key) => ProgrammerKey::Raw(key),
        KeySource::Password { password, kdf } => ProgrammerKey::Password { password, kdf },
    }
}

/// Makes the keys of a new database: the locked form to store, and the unlocked keys to use.
/// A new database needs both the read key and the search key.
pub(crate) fn create(config: &EncryptionConfig) -> Result<(LockedDataKey, Arc<FieldKeys>)> {
    let (Some(read), Some(search)) = (&config.read, &config.search) else {
        return Err(ClError::Validation(
            "a new database with protected fields needs both a read key and a search key".into(),
        ));
    };
    let (read, search) = (programmer(read), programmer(search));
    let data = DataKey::generate()
        .map_err(|_| ClError::Validation("the system could not provide random bytes".into()))?;
    let locked = data
        .lock(&config.suite, &read, &search)
        .map_err(|_| ClError::Validation("the keys given are not usable".into()))?;
    let access = locked
        .unlock(&config.suite, Some(&read), Some(&search))
        .map_err(|_| ClError::Validation("the keys given are not usable".into()))?;
    Ok((locked, Arc::new(FieldKeys::with_access(config.suite, access)?)))
}

/// Opens the keys of an existing database with the keys the program holds. A wrong key, a missing
/// key and a damaged lock are all the same error, as for a database encrypted as a whole.
pub(crate) fn open(config: &EncryptionConfig, locked: &LockedDataKey) -> Result<Arc<FieldKeys>> {
    let read = config.read.as_ref().map(programmer);
    let search = config.search.as_ref().map(programmer);
    let access = locked
        .unlock(&config.suite, read.as_ref(), search.as_ref())
        .map_err(|_| ClError::EncryptedOpenFailed)?;
    Ok(Arc::new(FieldKeys::with_access(config.suite, access)?))
}

/// Stores the locked data key. Called inside the transaction that stores the table description.
pub(crate) fn write(tx: &WriteTransaction, locked: &LockedDataKey) -> Result<()> {
    let mut table = tx.open_table(TABLE)?;
    table.insert("read", locked.read.as_bytes())?;
    table.insert("search", locked.search.as_bytes())?;
    Ok(())
}

/// The stored locked data key, or `None` when the database has none.
pub(crate) fn read(db: &redb::Database) -> Result<Option<LockedDataKey>> {
    let tx = db.begin_read()?;
    let table = match tx.open_table(TABLE) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(other) => return Err(other.into()),
    };
    let (Some(read), Some(search)) = (table.get("read")?, table.get("search")?) else {
        return Ok(None);
    };
    Ok(Some(LockedDataKey {
        read: LockedKey::from_bytes(read.value().to_vec()),
        search: LockedKey::from_bytes(search.value().to_vec()),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CipherKind, HkdfHash, Key32, KeySuite};

    fn config(read: Option<u8>, search: Option<u8>) -> EncryptionConfig {
        EncryptionConfig {
            suite: KeySuite { cipher: CipherKind::XChaCha20Poly1305, hkdf: HkdfHash::Sha256 },
            read: read.map(|b| KeySource::Raw(Key32::from_bytes(&[b; 32]))),
            search: search.map(|b| KeySource::Raw(Key32::from_bytes(&[b; 32]))),
        }
    }

    #[test]
    fn a_new_database_needs_both_keys() {
        for c in [config(Some(1), None), config(None, Some(2)), config(None, None)] {
            let err = create(&c).err().expect("must be refused").to_string();
            assert!(err.contains("both a read key and a search key"), "{err}");
        }
    }

    #[test]
    fn the_stored_lock_opens_with_the_right_keys_only() {
        let (locked, made) = create(&config(Some(1), Some(2))).unwrap();
        let place = ("t", 1u32);
        let sealed = made.cipher(place.0, place.1).unwrap().seal(b"x", b"value").unwrap();
        // Same keys: the same field cipher, so it opens what the first one sealed.
        let again = open(&config(Some(1), Some(2)), &locked).unwrap();
        assert!(again.cipher(place.0, place.1).unwrap().open(b"x", &sealed).is_ok());
        // A wrong key of either kind, or none: the one open error.
        for wrong in [config(Some(9), Some(2)), config(Some(1), Some(9)), config(None, None)] {
            assert!(matches!(open(&wrong, &locked), Err(ClError::EncryptedOpenFailed)));
        }
    }

    #[test]
    fn the_search_key_alone_opens_but_cannot_seal() {
        let (locked, _) = create(&config(Some(1), Some(2))).unwrap();
        let search_only = open(&config(None, Some(2)), &locked).unwrap();
        let err = search_only.cipher("t", 1).err().expect("must fail").to_string();
        assert!(err.contains("no read key"), "{err}");
    }

    #[test]
    fn the_stored_bytes_name_no_cipher_and_two_locks_differ() {
        let (a, _) = create(&config(Some(1), Some(2))).unwrap();
        let (b, _) = create(&config(Some(1), Some(2))).unwrap();
        assert_ne!(a, b);
        assert_eq!(a.read.as_bytes().len(), b.read.as_bytes().len());
    }
}
