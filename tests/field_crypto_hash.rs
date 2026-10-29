//! Verification hashes of passwords and codes: stored salted and slow, never readable, checked
//! with a verifier, tied to their row.
use clove1db::{
    CloveFields, EncryptionConfig, KeySource, LibraryEvent,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    entity::Entity,
    field_crypto::Hashed,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use redb::TableDefinition;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize, CloveFields)]
struct Account {
    id: String,
    name: String,
    #[clove(hash = "argon2id", id = 1)]
    password: Hashed,
    #[clove(hash = "scrypt", id = 2)]
    code: Hashed,
}
impl Entity for Account {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn account(id: &str, password: &str, code: &str) -> Account {
    Account { id: id.into(), name: "visible".into(), password: Hashed::new(password), code: Hashed::new(code) }
}

fn keys(read: Option<u8>, search: Option<u8>) -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite { cipher: CipherKind::Aes256GcmSiv, hkdf: HkdfHash::Sha256 },
        read: read.map(|b| KeySource::Raw(Key32::from_bytes(&[b; 32]))),
        search: search.map(|b| KeySource::Raw(Key32::from_bytes(&[b; 32]))),
    }
}

fn temp_dir() -> PathBuf {
    std::env::temp_dir().join(uuid::Uuid::new_v4().to_string())
}

type Seen = Arc<Mutex<Vec<(String, String, bool)>>>;

fn open(dir: &Path, config: EncryptionConfig, seen: &Seen) -> Storage {
    open_on(with_keys(base(dir), config), seen)
}

/// The same, in an ordinary database with field keys under every cfg.
fn open_field_mode(dir: &Path, config: EncryptionConfig, seen: &Seen) -> Storage {
    open_on(field_db(dir, config), seen)
}

fn open_on(db: DatabaseConfig, seen: &Seen) -> Storage {
    let seen = seen.clone();
    let storage = StorageConfig::default().event_sink(move |e| {
        if let LibraryEvent::HashVerify { field, row, matched, .. } = e {
            let text = format!("{e:?}");
            assert!(!text.contains("hunter2") && !text.contains("123456"), "{text}");
            seen.lock().unwrap().push((field.clone(), row.clone(), *matched));
        }
    });
    Storage::builder(storage)
        .add_database(db.register_sealed::<Account>("accounts"))
        .build()
        .unwrap()
}

fn raw_json(s: &Storage, id: &str) -> serde_json::Value {
    let bytes = s
        .db_manager("store")
        .get_uncached(TableDefinition::<&str, &[u8]>::new("accounts"), id)
        .unwrap()
        .expect("row exists");
    serde_json::from_slice(&bytes).unwrap()
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(walk(&path));
            } else {
                out.push(path);
            }
        }
    }
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// The same table and fields as `Account`, but the password hash is declared with scrypt.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize, CloveFields)]
struct AccountScrypt {
    id: String,
    name: String,
    #[clove(hash = "scrypt", id = 1)]
    password: Hashed,
    #[clove(hash = "scrypt", id = 2)]
    code: Hashed,
}
impl Entity for AccountScrypt {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// Under `--cfg clove_test_encrypt_all` every database starts encrypted as a whole.
fn base(dir: &Path) -> DatabaseConfig {
    DatabaseConfig::new("records", "store").dir_path(dir.to_path_buf()).has_cache(false).backup_enabled(true)
}

/// The keys for the protected fields: their own keys in an ordinary database, the keys of the
/// encryption of the whole database under the test cfg.
fn with_keys(db: DatabaseConfig, config: EncryptionConfig) -> DatabaseConfig {
    #[cfg(clove_test_encrypt_all)]
    {
        db.encryption(config)
    }
    #[cfg(not(clove_test_encrypt_all))]
    {
        db.field_encryption(config)
    }
}

/// An ordinary database with field keys, also under the test cfg: a program with only the search
/// key and a scan of readable files exist only there (listed in 7-5-plain-only.md).
fn field_db(dir: &Path, config: EncryptionConfig) -> DatabaseConfig {
    let db = base(dir);
    #[cfg(clove_test_encrypt_all)]
    let db = db.plain();
    db.field_encryption(config)
}

fn open_scrypt(dir: &Path, config: EncryptionConfig, whole: bool) -> clove1db::units::Result<Storage> {
    let db = if whole { base(dir).encryption(config) } else { with_keys(base(dir), config) };
    Storage::builder(StorageConfig::default()).add_database(db.register_sealed::<AccountScrypt>("accounts")).build()
}

fn open_argon(dir: &Path, config: EncryptionConfig, whole: bool) -> clove1db::units::Result<Storage> {
    let db = if whole { base(dir).encryption(config) } else { with_keys(base(dir), config) };
    Storage::builder(StorageConfig::default()).add_database(db.register_sealed::<Account>("accounts")).build()
}

/// Every file except the main one (whose size redb changes at every open), by relative path.
fn others(dir: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    walk(dir)
        .into_iter()
        .filter(|p| p.extension().is_none_or(|e| e != "cldb"))
        .map(|p| (p.strip_prefix(dir).unwrap().display().to_string(), std::fs::read(&p).unwrap()))
        .collect()
}

fn description(s: &Storage) -> Vec<(u32, Option<String>)> {
    let meta = s.db_manager("store").read_meta().unwrap().unwrap();
    let table = meta.tables.into_iter().find(|t| t.name == "accounts").unwrap();
    table.sealed.into_iter().map(|f| (f.id, f.check)).collect()
}

fn changing_the_settings_is_refused(whole: bool) {
    let dir = temp_dir();
    {
        let s = open_argon(&dir, keys(Some(1), Some(2)), whole).unwrap();
        s.domain::<Account>().repo().set("a1", &account("a1", "hunter2", "123456")).unwrap();
        s.close();
    }
    let described = {
        let s = open_argon(&dir, keys(Some(1), Some(2)), whole).unwrap();
        let d = description(&s);
        s.close();
        d
    };
    assert_eq!(described.len(), 2);
    assert!(described.iter().all(|(_, check)| check.as_ref().is_some_and(|c| c.len() == 43)), "{described:?}");
    let before = others(&dir);

    let err = open_scrypt(&dir, keys(Some(1), Some(2)), whole).err().expect("must be refused");
    match &err {
        ClError::Validation(t) => {
            assert!(t.contains("hash settings") && t.contains("migration") && t.contains("nothing was written"), "{t}");
            assert!(!t.to_lowercase().contains("argon") && !t.to_lowercase().contains("scrypt"), "{t}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
    let after = others(&dir);
    assert_eq!(before.keys().collect::<Vec<_>>(), after.keys().collect::<Vec<_>>());
    for (name, bytes) in &before {
        assert!(after[name] == *bytes, "{name} was changed by a refused open");
    }

    // The same settings open as before, with the same description, and the old hash still verifies.
    let s = open_argon(&dir, keys(Some(1), Some(2)), whole).unwrap();
    assert_eq!(description(&s), described);
    let read = s.domain::<Account>().repo().get("a1").unwrap();
    assert!(read.password.verify("hunter2", &s.domain::<Account>().verifier().unwrap()).unwrap());
}

#[test]
fn changing_the_hash_settings_is_a_migration_and_writes_nothing() {
    changing_the_settings_is_refused(false);
}

#[test]
fn the_same_holds_for_a_database_encrypted_as_a_whole() {
    changing_the_settings_is_refused(true);
}

#[test]
fn a_program_with_only_the_search_key_cannot_compare_the_settings_and_skips_the_check() {
    let dir = temp_dir();
    {
        let s = Storage::builder(StorageConfig::default())
            .add_database(field_db(&dir, keys(Some(1), Some(2))).register_sealed::<Account>("accounts"))
            .build()
            .unwrap();
        s.domain::<Account>().repo().set("a1", &account("a1", "hunter2", "123456")).unwrap();
        s.close();
    }
    // It opens (read-only) even though the code declares other settings: it holds no key to compare with.
    let s = Storage::builder(StorageConfig::default())
        .add_database(field_db(&dir, keys(None, Some(2))).register_sealed::<AccountScrypt>("accounts"))
        .build()
        .unwrap();
    assert!(s.domain::<AccountScrypt>().repo().get("a1").is_ok());
}

#[test]
fn only_hash_fields_carry_a_settings_fingerprint() {
    let dir = temp_dir();
    let s = open_argon(&dir, keys(Some(1), Some(2)), false).unwrap();
    // Both fields of `Account` are hashes, so both carry one; a fingerprint is not a hash of anything stored.
    let d = description(&s);
    assert_ne!(d[0].1, d[1].1, "two fields, two fingerprints");
    let text = serde_json::to_string(&s.db_manager("store").read_meta().unwrap().unwrap().tables).unwrap().to_lowercase();
    for word in ["argon", "scrypt", "memory", "iteration"] {
        assert!(!text.contains(word), "{text}");
    }
}

#[test]
fn a_secret_is_stored_as_a_salted_hash_and_verifies_only_when_right() {
    let dir = temp_dir();
    let seen: Seen = Arc::default();
    let s = open(&dir, keys(Some(1), Some(2)), &seen);
    let domain = s.domain::<Account>();
    domain.repo().set("a1", &account("a1", "hunter2", "123456")).unwrap();
    domain.repo().set("a2", &account("a2", "hunter2", "123456")).unwrap();
    let (j1, j2) = (raw_json(&s, "a1"), raw_json(&s, "a2"));
    for key in ["password", "code"] {
        assert_eq!(j1[key].as_str().unwrap().len(), 66, "{key}");
        // The same secret in two rows, and the same secret written twice, give different text.
        assert_ne!(j1[key], j2[key], "{key}");
    }
    let verifier = domain.verifier().unwrap();
    let read = domain.repo().get("a1").unwrap();
    assert!(read.password.verify("hunter2", &verifier).unwrap());
    assert!(!read.password.verify("hunter3", &verifier).unwrap());
    assert!(read.code.verify("123456", &verifier).unwrap());
    assert!(!read.code.verify("123457", &verifier).unwrap());
    // The password does not open the code field and the other way round.
    assert!(!read.password.verify("123456", &verifier).unwrap());
    let seen = seen.lock().unwrap();
    assert_eq!(
        *seen,
        [
            ("password".to_string(), "a1".to_string(), true),
            ("password".to_string(), "a1".to_string(), false),
            ("code".to_string(), "a1".to_string(), true),
            ("code".to_string(), "a1".to_string(), false),
            ("password".to_string(), "a1".to_string(), false),
        ]
    );
}

#[test]
fn no_secret_appears_in_any_file() {
    let dir = temp_dir();
    let seen: Seen = Arc::default();
    {
        let s = open_field_mode(&dir, keys(Some(1), Some(2)), &seen);
        let domain = s.domain::<Account>();
        domain.repo().set("a1", &account("a1", "hunter2", "123456")).unwrap();
        let mut again = domain.repo().get("a1").unwrap();
        again.password = Hashed::new("hunter2-changed");
        domain.repo().set("a1", &again).unwrap();
        s.close();
    }
    let mut ordinary = false;
    for path in walk(&dir) {
        let bytes = std::fs::read(&path).unwrap();
        for secret in ["hunter2", "123456"] {
            assert!(!contains(&bytes, secret.as_bytes()), "{secret} found in {}", path.display());
        }
        ordinary |= contains(&bytes, b"visible");
    }
    assert!(ordinary, "the scan itself is blind");
}

#[test]
fn a_changed_secret_replaces_the_hash_and_an_unchanged_one_keeps_its_text() {
    let dir = temp_dir();
    let seen: Seen = Arc::default();
    let s = open(&dir, keys(Some(1), Some(2)), &seen);
    let domain = s.domain::<Account>();
    domain.repo().set("a1", &account("a1", "hunter2", "123456")).unwrap();
    let first = raw_json(&s, "a1");
    // Written back as read: the same text.
    let read = domain.repo().get("a1").unwrap();
    domain.repo().set("a1", &read).unwrap();
    assert_eq!(raw_json(&s, "a1")["password"], first["password"]);
    // A new password: new text, and only the new password verifies.
    let mut changed = domain.repo().get("a1").unwrap();
    changed.password = Hashed::new("new-secret");
    domain.repo().set("a1", &changed).unwrap();
    let after = raw_json(&s, "a1");
    assert_ne!(after["password"], first["password"]);
    assert_eq!(after["code"], first["code"], "the code was not touched");
    let verifier = domain.verifier().unwrap();
    let now = domain.repo().get("a1").unwrap();
    assert!(now.password.verify("new-secret", &verifier).unwrap());
    assert!(!now.password.verify("hunter2", &verifier).unwrap());
}

#[test]
fn a_hash_cannot_be_moved_to_another_row() {
    let dir = temp_dir();
    let seen: Seen = Arc::default();
    let s = open(&dir, keys(Some(1), Some(2)), &seen);
    let domain = s.domain::<Account>();
    domain.repo().set("a1", &account("a1", "mine", "111111")).unwrap();
    domain.repo().set("a2", &account("a2", "victim", "222222")).unwrap();
    // The attacker's own hash, read from row a1, offered for row a2.
    let mut moved = domain.repo().get("a2").unwrap();
    moved.password = domain.repo().get("a1").unwrap().password;
    let err = domain.repo().set("a2", &moved).unwrap_err();
    assert!(matches!(&err, ClError::Validation(t) if t.contains("can only be written back")), "{err:?}");
    let verifier = domain.verifier().unwrap();
    let a2 = domain.repo().get("a2").unwrap();
    assert!(!a2.password.verify("mine", &verifier).unwrap());
    assert!(a2.password.verify("victim", &verifier).unwrap());
}

#[test]
fn what_cannot_be_checked_says_why() {
    let dir = temp_dir();
    let seen: Seen = Arc::default();
    {
        let s = open_field_mode(&dir, keys(Some(1), Some(2)), &seen);
        s.domain::<Account>().repo().set("a1", &account("a1", "hunter2", "123456")).unwrap();
        s.close();
    }
    // A value that was never written, and one that came from outside the storage.
    let s = open_field_mode(&dir, keys(Some(1), Some(2)), &seen);
    let domain = s.domain::<Account>();
    let verifier = domain.verifier().unwrap();
    let err = Hashed::new("x").verify("x", &verifier).unwrap_err();
    assert!(matches!(&err, ClError::Validation(t) if t.contains("not been written")), "{err:?}");
    let read = domain.repo().get("a1").unwrap();
    let outside: Account = serde_json::from_str(&serde_json::to_string(&read).unwrap()).unwrap();
    let err = outside.password.verify("hunter2", &verifier).unwrap_err();
    assert!(matches!(&err, ClError::Validation(t) if t.contains("not read from a storage")), "{err:?}");
    s.close();
    // With the search key alone nothing can be checked.
    let s = open_field_mode(&dir, keys(None, Some(2)), &seen);
    let domain = s.domain::<Account>();
    let read = domain.repo().get("a1").unwrap();
    let verifier = domain.verifier().unwrap();
    let err = read.password.verify("hunter2", &verifier).unwrap_err();
    assert!(matches!(&err, ClError::Validation(t) if t.contains("no read key")), "{err:?}");
}

#[test]
fn a_different_database_does_not_verify_the_same_hash() {
    let seen: Seen = Arc::default();
    let (dir_a, dir_b) = (temp_dir(), temp_dir());
    let a = open(&dir_a, keys(Some(1), Some(2)), &seen);
    let b = open(&dir_b, keys(Some(1), Some(2)), &seen);
    // Same programmer keys, two databases: each has its own data key, so a hash is bound to its file.
    a.domain::<Account>().repo().set("a1", &account("a1", "hunter2", "123456")).unwrap();
    let text_in_a = raw_json(&a, "a1");
    let read_a = a.domain::<Account>().repo().get("a1").unwrap();
    let verifier_b = b.domain::<Account>().verifier().unwrap();
    // The value read from `a` is bound to a place in `a`; checked with b's keys it does not match.
    assert!(!read_a.password.verify("hunter2", &verifier_b).unwrap());
    assert!(read_a.password.verify("hunter2", &a.domain::<Account>().verifier().unwrap()).unwrap());
    assert_eq!(text_in_a["password"].as_str().unwrap().len(), 66);
}
