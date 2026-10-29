//! The two-key system: random roots locked by the programmer's key, subkeys derived from them.
//!
//! - The data key is two independent random roots: a read root and a search root.
//! - Each root is locked on its own by a programmer key (a raw key or a password), so a
//!   program can hold the search root without being able to decrypt anything.
//! - Only the read root derives encryption keys. Only the search root derives fingerprint
//!   keys. The types enforce it: there is no call that crosses.
//! - The locked form is `salt || nonce || sealed root || tag`. It names no cipher kind and
//!   holds no settings.
use super::{
    cipher::{Aead, CipherKind},
    error::{CryptoError, OpenDiagnostic, Result},
    kdf::{HkdfHash, PasswordKdf},
    secret::{KEY_LEN, Key32, SecretBytes, fill_random},
};

pub const SALT_LEN: usize = 32;
const LOCK_LABEL: &[u8] = b"clove1db/lock/v1";
const SUBKEY_LABEL: &[u8] = b"clove1db/subkey/v1";

/// The algorithm choices that must match between lock and unlock. Never written to a file:
/// a wrong choice fails like a wrong key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeySuite {
    pub cipher: CipherKind,
    pub hkdf: HkdfHash,
}

/// AES-256-GCM-SIV with HKDF-SHA-256: what whole-database encryption uses unless a suite is chosen. AES is the faster
/// of the two allowed ciphers on processors with hardware AES (most today); XChaCha20-Poly1305 stays a choice, and is
/// the faster one where there is no such hardware.
impl Default for KeySuite {
    fn default() -> Self {
        KeySuite { cipher: CipherKind::Aes256GcmSiv, hkdf: HkdfHash::Sha256 }
    }
}

/// What the programmer holds to open a locked root.
#[derive(Debug, Clone, Copy)]
pub enum ProgrammerKey<'a> {
    Raw(&'a Key32),
    Password {
        password: &'a SecretBytes,
        kdf: &'a PasswordKdf,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Read = 1,
    Search = 2,
}

/// A root key sealed under a programmer key. Safe to store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedKey(Vec<u8>);

impl LockedKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Wrap stored bytes. Nothing is checked here; opening checks everything.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

fn lock_aad(role: Role, salt: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(LOCK_LABEL.len() + 1 + salt.len());
    aad.extend_from_slice(LOCK_LABEL);
    aad.push(role as u8);
    aad.extend_from_slice(salt);
    aad
}

/// The key that seals a root: the programmer key (stretched first when it is a password),
/// then HKDF with the salt and the role, so the two roots never share a wrapping key.
fn wrap_key(suite: &KeySuite, role: Role, key: &ProgrammerKey, salt: &[u8]) -> Result<Key32> {
    let mut stretched = Key32::zeroed();
    let ikm: &[u8] = match key {
        ProgrammerKey::Raw(raw) => raw.as_bytes(),
        ProgrammerKey::Password { password, kdf } => {
            kdf.derive(password.as_bytes(), salt, stretched.as_bytes_mut())?;
            stretched.as_bytes()
        }
    };
    let mut info = Vec::with_capacity(LOCK_LABEL.len() + 1);
    info.extend_from_slice(LOCK_LABEL);
    info.push(role as u8);
    let mut wrap = Key32::zeroed();
    suite
        .hkdf
        .derive(Some(salt), ikm, &info, wrap.as_bytes_mut())?;
    Ok(wrap)
}

fn lock_root(suite: &KeySuite, role: Role, root: &Key32, key: &ProgrammerKey) -> Result<LockedKey> {
    let mut salt = [0u8; SALT_LEN];
    fill_random(&mut salt)?;
    let wrap = wrap_key(suite, role, key, &salt)?;
    let sealed = Aead::new(suite.cipher, &wrap)?.seal(&lock_aad(role, &salt), root.as_bytes())?;
    let mut bytes = Vec::with_capacity(SALT_LEN + sealed.len());
    bytes.extend_from_slice(&salt);
    bytes.extend_from_slice(&sealed);
    Ok(LockedKey(bytes))
}

fn unlock_root(
    suite: &KeySuite,
    role: Role,
    locked: &LockedKey,
    key: Option<&ProgrammerKey>,
    sink: &mut dyn FnMut(OpenDiagnostic),
) -> Result<Key32> {
    let Some(key) = key else {
        sink(OpenDiagnostic::KeyMissing);
        return Err(CryptoError::OpenFailed);
    };
    if locked.0.len() != SALT_LEN + suite.cipher.overhead() + KEY_LEN {
        sink(OpenDiagnostic::MalformedInput);
        return Err(CryptoError::OpenFailed);
    }
    let (salt, sealed) = locked.0.split_at(SALT_LEN);
    let wrap = wrap_key(suite, role, key, salt)?;
    let root = Aead::new(suite.cipher, &wrap)?.open_reporting(&lock_aad(role, salt), sealed, sink)?;
    Key32::from_slice(root.as_bytes()).map_err(|_| CryptoError::OpenFailed)
}

/// Where a subkey is used. Two scopes that differ in any byte give different keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scope<'a> {
    pub table: &'a str,
    pub field: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Purpose {
    Encryption = 1,
    FullFingerprint = 2,
    PartFingerprint = 3,
    Hash = 4,
}

/// Length-prefixed, so ("ab", "c") and ("a", "bc") can never produce the same info.
fn subkey_info(role: Role, purpose: Purpose, scope: &Scope) -> Result<Vec<u8>> {
    let mut info = Vec::with_capacity(SUBKEY_LABEL.len() + 2 + 8 + scope.table.len() + scope.field.len());
    info.extend_from_slice(SUBKEY_LABEL);
    info.push(role as u8);
    info.push(purpose as u8);
    for part in [scope.table, scope.field] {
        let len = u32::try_from(part.len())
            .map_err(|_| CryptoError::InvalidParams("scope name too long"))?;
        info.extend_from_slice(&len.to_be_bytes());
        info.extend_from_slice(part.as_bytes());
    }
    Ok(info)
}

fn derive_subkey(
    root: &Key32,
    hkdf: HkdfHash,
    role: Role,
    purpose: Purpose,
    scope: &Scope,
) -> Result<Key32> {
    let info = subkey_info(role, purpose, scope)?;
    let mut key = Key32::zeroed();
    hkdf.derive(None, root.as_bytes(), &info, key.as_bytes_mut())?;
    Ok(key)
}

macro_rules! root_type {
    ($(#[$doc:meta])* $name:ident, $role:expr) => {
        $(#[$doc])*
        pub struct $name(Key32);

        impl $name {
            pub fn generate() -> Result<Self> {
                Ok(Self(Key32::generate()?))
            }

            pub fn lock(&self, suite: &KeySuite, key: &ProgrammerKey) -> Result<LockedKey> {
                lock_root(suite, $role, &self.0, key)
            }

            /// Open a locked root. A wrong key, a wrong suite, a damaged lock and a missing key
            /// all return [`CryptoError::OpenFailed`].
            pub fn unlock(
                locked: &LockedKey,
                suite: &KeySuite,
                key: Option<&ProgrammerKey>,
            ) -> Result<Self> {
                Self::unlock_reporting(locked, suite, key, &mut |_| {})
            }

            /// Like [`Self::unlock`], and hands the cause of a failure to `sink` first.
            pub fn unlock_reporting(
                locked: &LockedKey,
                suite: &KeySuite,
                key: Option<&ProgrammerKey>,
                sink: &mut dyn FnMut(OpenDiagnostic),
            ) -> Result<Self> {
                Ok(Self(unlock_root(suite, $role, locked, key, sink)?))
            }

            /// Change the programmer key: the same root, locked again under `new`.
            pub fn relock(
                locked: &LockedKey,
                suite: &KeySuite,
                old: &ProgrammerKey,
                new: &ProgrammerKey,
            ) -> Result<LockedKey> {
                Self::unlock(locked, suite, Some(old))?.lock(suite, new)
            }

            #[cfg(test)]
            pub(crate) fn from_key(key: Key32) -> Self {
                Self(key)
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}({})", stringify!($name), super::secret::REDACTED)
            }
        }
    };
}

root_type!(
    /// The root of everything that decrypts. Held by programs that may read values.
    ReadRoot,
    Role::Read
);
root_type!(
    /// The root of every fingerprint. Held by programs that may search. It cannot decrypt:
    /// it has no call that derives an encryption key, and this does not compile.
    ///
    /// ```compile_fail
    /// use clove1db::crypto::{HkdfHash, Scope, SearchRoot};
    /// let root = SearchRoot::generate().unwrap();
    /// let scope = Scope { table: "t", field: "f" };
    /// let _ = root.encryption_key(HkdfHash::Sha256, &scope);
    /// ```
    ///
    /// The same code asking for a fingerprint key does compile:
    ///
    /// ```
    /// use clove1db::crypto::{HkdfHash, Scope, SearchRoot};
    /// let root = SearchRoot::generate().unwrap();
    /// let scope = Scope { table: "t", field: "f" };
    /// let _ = root.full_fingerprint_key(HkdfHash::Sha256, &scope).unwrap();
    /// ```
    SearchRoot,
    Role::Search
);

impl ReadRoot {
    /// The key that seals and opens the values of one field.
    pub fn encryption_key(&self, hkdf: HkdfHash, scope: &Scope) -> Result<Key32> {
        derive_subkey(&self.0, hkdf, Role::Read, Purpose::Encryption, scope)
    }
    /// The key for verification hashes of one field (passwords, codes).
    pub fn hash_key(&self, hkdf: HkdfHash, scope: &Scope) -> Result<Key32> {
        derive_subkey(&self.0, hkdf, Role::Read, Purpose::Hash, scope)
    }
}

impl SearchRoot {
    /// The key for whole-value fingerprints of one field.
    pub fn full_fingerprint_key(&self, hkdf: HkdfHash, scope: &Scope) -> Result<Key32> {
        derive_subkey(&self.0, hkdf, Role::Search, Purpose::FullFingerprint, scope)
    }
    /// The key for fingerprints of value parts of one field.
    pub fn part_fingerprint_key(&self, hkdf: HkdfHash, scope: &Scope) -> Result<Key32> {
        derive_subkey(&self.0, hkdf, Role::Search, Purpose::PartFingerprint, scope)
    }
}

/// Both roots, as created with a database.
#[derive(Debug)]
pub struct DataKey {
    pub read: ReadRoot,
    pub search: SearchRoot,
}

impl DataKey {
    pub fn generate() -> Result<Self> {
        Ok(Self {
            read: ReadRoot::generate()?,
            search: SearchRoot::generate()?,
        })
    }

    pub fn lock(
        &self,
        suite: &KeySuite,
        read_key: &ProgrammerKey,
        search_key: &ProgrammerKey,
    ) -> Result<LockedDataKey> {
        Ok(LockedDataKey {
            read: self.read.lock(suite, read_key)?,
            search: self.search.lock(suite, search_key)?,
        })
    }
}

/// Both locked roots, as stored in a database header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedDataKey {
    pub read: LockedKey,
    pub search: LockedKey,
}

/// What a program can do after opening: only the roots it held a key for.
#[derive(Debug)]
pub struct Access {
    read: Option<ReadRoot>,
    search: Option<SearchRoot>,
}

impl Access {
    pub fn read(&self) -> Option<&ReadRoot> {
        self.read.as_ref()
    }
    pub fn search(&self) -> Option<&SearchRoot> {
        self.search.as_ref()
    }
}

impl LockedDataKey {
    /// Open with the keys the program holds. A key given for a root must be right. With no
    /// key at all there is nothing to open.
    pub fn unlock(
        &self,
        suite: &KeySuite,
        read_key: Option<&ProgrammerKey>,
        search_key: Option<&ProgrammerKey>,
    ) -> Result<Access> {
        self.unlock_reporting(suite, read_key, search_key, &mut |_| {})
    }

    pub fn unlock_reporting(
        &self,
        suite: &KeySuite,
        read_key: Option<&ProgrammerKey>,
        search_key: Option<&ProgrammerKey>,
        sink: &mut dyn FnMut(OpenDiagnostic),
    ) -> Result<Access> {
        if read_key.is_none() && search_key.is_none() {
            sink(OpenDiagnostic::KeyMissing);
            return Err(CryptoError::OpenFailed);
        }
        let read = read_key
            .map(|k| ReadRoot::unlock_reporting(&self.read, suite, Some(k), sink))
            .transpose()?;
        let search = search_key
            .map(|k| SearchRoot::unlock_reporting(&self.search, suite, Some(k), sink))
            .transpose()?;
        Ok(Access { read, search })
    }
}
