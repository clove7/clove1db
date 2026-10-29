//! The keys of protected fields: one cipher per table and field, derived from the read root.
use super::carried::CarriedKind;
use crate::{
    crypto::{Access, Aead, Key32, KeySuite, Scope},
    encrypted_store::{EncryptionContext, cipher_allowed},
    units::{ClError, Result},
};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

enum Source {
    /// The database is encrypted as a whole: its unlocked keys are shared.
    Context(EncryptionContext),
    /// Keys opened for the protected fields of an otherwise plain database.
    Own(Access),
}

impl Source {
    fn access(&self) -> &Access {
        match self {
            Source::Context(context) => context.access(),
            Source::Own(access) => access,
        }
    }
}

fn unavailable() -> ClError {
    ClError::Validation("protected-field keys are unavailable".into())
}

/// Derives and remembers the cipher of each protected field. Cheap to share. [`FieldKeys::clear`]
/// drops the cached ciphers and the roots at once (when the database is closed); what is left is
/// wiped when the last holder is dropped, since the key and cipher types wipe themselves.
pub(crate) struct FieldKeys {
    suite: KeySuite,
    source: RwLock<Option<Source>>,
    ciphers: RwLock<HashMap<(String, u32), Arc<Aead>>>,
    /// Keys carried over from earlier roots (see `carried`): used for their field instead of deriving.
    carried: RwLock<HashMap<(String, u32, CarriedKind), Key32>>,
}

impl FieldKeys {
    fn new(suite: KeySuite, source: Source) -> Result<Self> {
        if !cipher_allowed(suite.cipher) {
            return Err(ClError::Validation(
                "this cipher is not allowed for protected fields".into(),
            ));
        }
        Ok(Self {
            suite,
            source: RwLock::new(Some(source)),
            ciphers: RwLock::new(HashMap::new()),
            carried: RwLock::new(HashMap::new()),
        })
    }

    pub(crate) fn with_access(suite: KeySuite, access: Access) -> Result<Self> {
        Self::new(suite, Source::Own(access))
    }

    pub(crate) fn with_context(context: EncryptionContext) -> Result<Self> {
        Self::new(context.suite(), Source::Context(context))
    }

    /// Forget every key now. Later calls fail with a clear error instead of using a stale key.
    pub(crate) fn clear(&self) {
        if let Ok(mut carried) = self.carried.write() {
            carried.clear();
        }
        if let Ok(mut ciphers) = self.ciphers.write() {
            ciphers.clear();
        }
        if let Ok(mut source) = self.source.write() {
            *source = None;
        }
    }

    /// True when the search root was opened, so fingerprints can be made and matched. False once cleared.
    pub(crate) fn has_search(&self) -> bool {
        self.source
            .read()
            .ok()
            .and_then(|source| source.as_ref().map(|s| s.access().search().is_some()))
            .unwrap_or(false)
    }

    /// True when the keys were opened with the search key alone: such a program can read rows but
    /// holds no read key, so it can neither write nor open a protected value. False once cleared.
    pub(crate) fn is_search_only(&self) -> bool {
        self.source
            .read()
            .ok()
            .and_then(|source| source.as_ref().map(|s| s.access().read().is_none()))
            .unwrap_or(false)
    }

    /// How many ciphers are held (for tests).
    #[cfg(test)]
    pub(crate) fn cached(&self) -> usize {
        self.ciphers.read().map(|c| c.len()).unwrap_or(0)
    }

    /// The suite (cipher and key derivation) these keys use.
    pub(crate) fn suite(&self) -> KeySuite {
        self.suite
    }

    /// The key carried over for this field, if there is one (see `carried`).
    fn carried_key(&self, kind: CarriedKind, table_id: &str, field_id: u32) -> Option<Key32> {
        let carried = self.carried.read().ok()?;
        carried.get(&(table_id.to_string(), field_id, kind)).map(|key| Key32::from_bytes(key.as_bytes()))
    }

    /// Use `key` for this field from now on instead of deriving one.
    pub(crate) fn install_carried(&self, kind: CarriedKind, table_id: &str, field_id: u32, key: Key32) {
        if let Ok(mut carried) = self.carried.write() {
            carried.insert((table_id.to_string(), field_id, kind), key);
        }
    }

    /// The key that seals the carried key of one field: from the read root for a hash, from the
    /// search root for a fingerprint, under a scope that is no field's scope. `None` when this
    /// program does not hold that root.
    pub(crate) fn carried_seal_key(&self, kind: CarriedKind, table_id: &str, field_id: u32) -> Result<Option<Key32>> {
        let field = super::carried::entry_name(table_id, field_id);
        let scope = Scope { table: super::carried::SCOPE, field: &field };
        let source = self.source.read().map_err(|_| unavailable())?;
        let source = source.as_ref().ok_or_else(unavailable)?;
        let derived = match kind {
            CarriedKind::Hash => source.access().read().map(|root| root.encryption_key(self.suite.hkdf, &scope)),
            CarriedKind::Print => source.access().search().map(|root| root.full_fingerprint_key(self.suite.hkdf, &scope)),
        };
        derived
            .transpose()
            .map_err(|_| ClError::Validation("a field key could not be derived".into()))
    }

    /// The key of the fingerprints of one field of one table, from the search root. A program that
    /// holds the search key can make and match fingerprints without the read key.
    pub(crate) fn print_key(&self, table_id: &str, field_id: u32) -> Result<crate::crypto::Key32> {
        if let Some(key) = self.carried_key(CarriedKind::Print, table_id, field_id) {
            return Ok(key);
        }
        let table = format!("t:{table_id}");
        let field = format!("f:{field_id}");
        let source = self.source.read().map_err(|_| unavailable())?;
        let source = source.as_ref().ok_or_else(unavailable)?;
        let search = source.access().search().ok_or_else(|| {
            ClError::Validation("this program holds no search key; fingerprints can be neither written nor matched".into())
        })?;
        search
            .full_fingerprint_key(self.suite.hkdf, &Scope { table: &table, field: &field })
            .map_err(|_| ClError::Validation("a field key could not be derived".into()))
    }

    /// The key of the fingerprints of the parts of the values of one field of one table, from the
    /// search root.
    pub(crate) fn part_key(&self, table_id: &str, field_id: u32) -> Result<crate::crypto::Key32> {
        let table = format!("t:{table_id}");
        let field = format!("f:{field_id}");
        let source = self.source.read().map_err(|_| unavailable())?;
        let source = source.as_ref().ok_or_else(unavailable)?;
        let search = source.access().search().ok_or_else(|| {
            ClError::Validation("this program holds no search key; fingerprints can be neither written nor matched".into())
        })?;
        search
            .part_fingerprint_key(self.suite.hkdf, &Scope { table: &table, field: &field })
            .map_err(|_| ClError::Validation("a field key could not be derived".into()))
    }

    /// The key that mixes into the verification hash of one field of one table (a secret the file
    /// does not hold). Needs the read root, like [`FieldKeys::cipher`].
    pub(crate) fn hash_key(&self, table_id: &str, field_id: u32) -> Result<crate::crypto::Key32> {
        if let Some(key) = self.carried_key(CarriedKind::Hash, table_id, field_id) {
            return Ok(key);
        }
        let table = format!("t:{table_id}");
        let field = format!("f:{field_id}");
        let source = self.source.read().map_err(|_| unavailable())?;
        let source = source.as_ref().ok_or_else(unavailable)?;
        let read = source.access().read().ok_or_else(|| {
            ClError::Validation(
                "this program holds no read key; protected fields can be neither written nor opened".into(),
            )
        })?;
        read.hash_key(self.suite.hkdf, &Scope { table: &table, field: &field })
            .map_err(|_| ClError::Validation("a field key could not be derived".into()))
    }

    /// The cipher that seals the table list in the keys file. Needs the read root.
    pub(crate) fn key_file_cipher(&self) -> Result<Aead> {
        let source = self.source.read().map_err(|_| unavailable())?;
        let source = source.as_ref().ok_or_else(unavailable)?;
        let read = source.access().read().ok_or_else(|| {
            ClError::Validation(
                "this program holds no read key; the table list of the keys file can be neither written nor opened".into(),
            )
        })?;
        let key = read
            .encryption_key(self.suite.hkdf, &Scope { table: "keys-file", field: "tables" })
            .map_err(|_| ClError::Validation("a field key could not be derived".into()))?;
        Aead::new(self.suite.cipher, &key).map_err(|_| ClError::Validation("a field cipher could not be built".into()))
    }

    /// The cipher of one field of one table. Needs the read root: a program that holds only the
    /// search key can neither seal nor open a protected value.
    pub(crate) fn cipher(&self, table_id: &str, field_id: u32) -> Result<Arc<Aead>> {
        let cache_key = (table_id.to_string(), field_id);
        if let Some(found) = self.ciphers.read().map_err(|_| unavailable())?.get(&cache_key) {
            return Ok(found.clone());
        }
        let table = format!("t:{table_id}");
        let field = format!("f:{field_id}");
        let cipher = {
            let source = self.source.read().map_err(|_| unavailable())?;
            let source = source.as_ref().ok_or_else(unavailable)?;
            let read = source.access().read().ok_or_else(|| {
                ClError::Validation(
                    "this program holds no read key; protected fields can be neither written nor opened".into(),
                )
            })?;
            let key = read
                .encryption_key(self.suite.hkdf, &Scope { table: &table, field: &field })
                .map_err(|_| ClError::Validation("a field key could not be derived".into()))?;
            Arc::new(
                Aead::new(self.suite.cipher, &key)
                    .map_err(|_| ClError::Validation("a field cipher could not be built".into()))?,
            )
            // `key` is wiped here, when it goes out of scope.
        };
        self.ciphers
            .write()
            .map_err(|_| unavailable())?
            .insert(cache_key, cipher.clone());
        Ok(cipher)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn denied() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "this program holds no read key; protected attachments can be neither written nor opened",
    )
}

/// Attachments of tables with protected fields are sealed with these keys, whatever the database
/// itself is encrypted with (or not). A file's key depends on its own salt and on its binding (table
/// identity, place, row and file), so a file moved anywhere else does not open.
impl crate::encrypted_store::FileKeys for FieldKeys {
    fn sealed_aead(&self, label: &str, binding: &str, salt: &[u8]) -> std::io::Result<Aead> {
        let source = self.source.read().map_err(|_| std::io::Error::other("keys unavailable"))?;
        let source = source.as_ref().ok_or_else(|| std::io::Error::other("keys unavailable"))?;
        let read = source.access().read().ok_or_else(denied)?;
        let field = format!("{label}:{}:{}:{binding}", binding.len(), hex(salt));
        let key = read
            .encryption_key(self.suite.hkdf, &Scope { table: "attachment", field: &field })
            .map_err(|_| std::io::Error::other("key derivation failed"))?;
        Aead::new(self.suite.cipher, &key).map_err(|_| std::io::Error::other("cipher setup failed"))
    }

    fn can_open(&self) -> bool {
        !self.is_search_only()
    }

    fn name_fingerprint(&self, domain: &str, name: &str) -> std::io::Result<String> {
        let source = self.source.read().map_err(|_| std::io::Error::other("keys unavailable"))?;
        let source = source.as_ref().ok_or_else(|| std::io::Error::other("keys unavailable"))?;
        let read = source.access().read().ok_or_else(denied)?;
        let key = read
            .hash_key(self.suite.hkdf, &Scope { table: "attachment-names", field: domain })
            .map_err(|_| std::io::Error::other("key derivation failed"))?;
        let tag = crate::crypto::MacKind::HmacSha256
            .mac(&key, name.as_bytes())
            .map_err(|_| std::io::Error::other("mac failed"))?;
        Ok(hex(&tag.as_bytes()[..16]))
    }
}

impl std::fmt::Debug for FieldKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FieldKeys([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CipherKind, DataKey, HkdfHash, Key32, ProgrammerKey};

    fn keys() -> FieldKeys {
        let suite = KeySuite { cipher: CipherKind::Aes256GcmSiv, hkdf: HkdfHash::Sha256 };
        let data = DataKey::generate().unwrap();
        let read = Key32::from_bytes(&[1; 32]);
        let search = Key32::from_bytes(&[2; 32]);
        let locked = data.lock(&suite, &ProgrammerKey::Raw(&read), &ProgrammerKey::Raw(&search)).unwrap();
        let access = locked
            .unlock(&suite, Some(&ProgrammerKey::Raw(&read)), Some(&ProgrammerKey::Raw(&search)))
            .unwrap();
        FieldKeys::with_access(suite, access).unwrap()
    }

    #[test]
    fn a_cipher_is_made_once_per_table_and_field() {
        let k = keys();
        let a = k.cipher("t1", 1).unwrap();
        let b = k.cipher("t1", 1).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        k.cipher("t1", 2).unwrap();
        k.cipher("t2", 1).unwrap();
        assert_eq!(k.cached(), 3);
    }

    #[test]
    fn different_places_give_different_keys() {
        let k = keys();
        let sealed = |t: &str, f: u32| k.cipher(t, f).unwrap().seal(b"x", b"same").unwrap();
        // A value sealed for one place does not open under another place's cipher.
        let text = sealed("t1", 1);
        assert!(k.cipher("t1", 1).unwrap().open(b"x", &text).is_ok());
        assert!(k.cipher("t1", 2).unwrap().open(b"x", &text).is_err());
        assert!(k.cipher("t2", 1).unwrap().open(b"x", &text).is_err());
    }

    #[test]
    fn clearing_forgets_every_key_and_later_calls_fail_clearly() {
        let k = keys();
        let held = k.cipher("t1", 1).unwrap();
        assert_eq!(k.cached(), 1);
        k.clear();
        assert_eq!(k.cached(), 0);
        let err = k.cipher("t1", 1).err().expect("must fail").to_string();
        assert!(err.contains("unavailable"), "{err}");
        // A cipher handed out before is the holder's own; it is wiped when the holder drops it.
        assert!(held.seal(b"x", b"still usable by its holder").is_ok());
    }
}
