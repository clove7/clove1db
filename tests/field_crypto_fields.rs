//! A database that is not encrypted as a whole, with keys for its protected fields; opening a
//! protected value with a read grant; the report of each use.
use clove1db::{
    CloveFields, EncryptionConfig, KeySource, LibraryEvent,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    entity::Entity,
    field_crypto::Sealed,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use redb::TableDefinition;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const PHONE: &str = "+155500000001";

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize, CloveFields)]
struct Person {
    id: String,
    name: String,
    #[clove(encrypt, id = 1)]
    phone: Sealed<String>,
    #[clove(encrypt, id = 2)]
    tags: Sealed<Vec<String>>,
}
impl Entity for Person {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn person(id: &str, phone: &str) -> Person {
    Person {
        id: id.into(),
        name: "visible".into(),
        phone: Sealed::new(phone.into()),
        tags: Sealed::new(vec!["vip".into(), "late".into()]),
    }
}

fn keys(read: Option<u8>, search: Option<u8>) -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite { cipher: CipherKind::XChaCha20Poly1305, hkdf: HkdfHash::Sha256 },
        read: read.map(|b| KeySource::Raw(Key32::from_bytes(&[b; 32]))),
        search: search.map(|b| KeySource::Raw(Key32::from_bytes(&[b; 32]))),
    }
}

fn temp_dir() -> PathBuf {
    std::env::temp_dir().join(uuid::Uuid::new_v4().to_string())
}

/// Under `--cfg clove_test_encrypt_all` every database starts encrypted as a whole.
fn base(dir: &Path) -> DatabaseConfig {
    DatabaseConfig::new("records", "store").dir_path(dir.to_path_buf()).has_cache(false).backup_enabled(true)
}

/// A database that is not encrypted as a whole, also under the test cfg (listed in 7-5-plain-only.md).
fn plain_base(dir: &Path) -> DatabaseConfig {
    let db = base(dir);
    #[cfg(clove_test_encrypt_all)]
    let db = db.plain();
    db
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

type Seen = Arc<Mutex<Vec<(String, String, u32, String)>>>;

fn open_fields(dir: &Path, config: EncryptionConfig) -> clove1db::units::Result<Storage> {
    Storage::builder(StorageConfig::default())
        .add_database(with_keys(base(dir), config).register_sealed::<Person>("people"))
        .build()
}

/// Field keys in an ordinary database, under every cfg.
fn open_field_mode(dir: &Path, config: EncryptionConfig) -> clove1db::units::Result<Storage> {
    Storage::builder(StorageConfig::default())
        .add_database(plain_base(dir).field_encryption(config).register_sealed::<Person>("people"))
        .build()
}

fn open_fields_watched(dir: &Path, config: EncryptionConfig, seen: &Seen) -> clove1db::units::Result<Storage> {
    let seen = seen.clone();
    let storage = StorageConfig::default().event_sink(move |e| {
        if let LibraryEvent::FieldRead { table, field, field_id, row, .. } = e {
            // The event is printed too: it must not hold a value.
            assert!(!format!("{e:?}").contains("155500000001"));
            seen.lock().unwrap().push((table.clone(), field.clone(), *field_id, row.clone()));
        }
    });
    Storage::builder(storage)
        .add_database(with_keys(base(dir), config).register_sealed::<Person>("people"))
        .build()
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

fn raw(s: &Storage, id: &str) -> Option<Vec<u8>> {
    s.db_manager("store")
        .get_uncached(TableDefinition::<&str, &[u8]>::new("people"), id)
        .unwrap()
}

#[test]
fn a_plain_database_with_field_keys_holds_no_protected_text_in_any_file() {
    let dir = temp_dir();
    {
        let s = open_field_mode(&dir, keys(Some(1), Some(2))).unwrap();
        let repo = s.domain::<Person>().repo();
        repo.set("p1", &person("p1", PHONE)).unwrap();
        repo.set("p2", &person("p2", "+155500000009")).unwrap();
        s.close();
    }
    let files = walk(&dir);
    assert!(!files.is_empty());
    let mut visible = false;
    for path in &files {
        let bytes = std::fs::read(path).unwrap();
        for secret in ["155500000001", "155500000009", "vip", "late"] {
            assert!(!contains(&bytes, secret.as_bytes()), "{secret} found in {}", path.display());
        }
        visible |= contains(&bytes, b"visible");
        assert!(!path.to_string_lossy().contains("155500000001"));
    }
    assert!(visible, "the scan itself is blind: an ordinary field was not found");
}

#[test]
fn field_keys_survive_close_and_the_value_opens_with_a_grant_and_reports_its_use() {
    let dir = temp_dir();
    {
        let s = open_fields(&dir, keys(Some(1), Some(2))).unwrap();
        s.domain::<Person>().repo().set("p1", &person("p1", PHONE)).unwrap();
        s.close();
    }
    let seen: Seen = Arc::default();
    let s = open_fields_watched(&dir, keys(Some(1), Some(2)), &seen).unwrap();
    let read = s.domain::<Person>().repo().get("p1").unwrap();
    assert!(seen.lock().unwrap().is_empty(), "reading a row is not opening a value");
    let grant = s.domain::<Person>().read_grant().unwrap();
    assert_eq!(read.phone.open(&grant).unwrap(), PHONE);
    assert_eq!(read.tags.open(&grant).unwrap(), vec!["vip".to_string(), "late".to_string()]);
    let seen = seen.lock().unwrap();
    assert_eq!(
        *seen,
        [
            ("people".to_string(), "phone".to_string(), 1, "p1".to_string()),
            ("people".to_string(), "tags".to_string(), 2, "p1".to_string()),
        ]
    );
}

#[test]
fn it_works_with_whole_database_encryption_too() {
    let dir = temp_dir();
    let s = Storage::builder(StorageConfig::default())
        .add_database(base(&dir).encryption(keys(Some(1), Some(2))).register_sealed::<Person>("people"))
        .build()
        .unwrap();
    s.domain::<Person>().repo().set("p1", &person("p1", PHONE)).unwrap();
    let grant = s.domain::<Person>().read_grant().unwrap();
    let read = s.domain::<Person>().repo().get("p1").unwrap();
    assert_eq!(read.phone.open(&grant).unwrap(), PHONE);
}

#[test]
fn a_value_that_cannot_be_opened_says_why() {
    let dir = temp_dir();
    let s = open_fields(&dir, keys(Some(1), Some(2))).unwrap();
    let domain = s.domain::<Person>();
    domain.repo().set("p1", &person("p1", PHONE)).unwrap();
    let grant = domain.read_grant().unwrap();
    // Not written yet.
    let err = Sealed::new("x".to_string()).open(&grant).unwrap_err();
    assert!(matches!(&err, ClError::Validation(t) if t.contains("not been written")), "{err:?}");
    // Read from outside the storage.
    let read = domain.repo().get("p1").unwrap();
    let outside: Person = serde_json::from_str(&serde_json::to_string(&read).unwrap()).unwrap();
    let err = outside.phone.open(&grant).unwrap_err();
    assert!(matches!(&err, ClError::Validation(t) if t.contains("not read from a storage")), "{err:?}");
    // A value carried to another entity still says where it was read from, so it opens as its
    // own value and cannot be passed off as the value of another row.
    domain.repo().set("p2", &person("p2", "+155500000009")).unwrap();
    let mut moved = domain.repo().get("p2").unwrap();
    moved.phone = domain.repo().get("p1").unwrap().phone;
    assert_eq!(moved.phone.open(&grant).unwrap(), PHONE);
    let err = domain.repo().set("p2", &moved).unwrap_err();
    assert!(matches!(&err, ClError::Validation(t) if t.contains("can only be written back")), "{err:?}");
}

#[test]
fn a_program_with_only_the_search_key_reads_rows_but_neither_writes_nor_opens() {
    let dir = temp_dir();
    {
        let s = open_field_mode(&dir, keys(Some(1), Some(2))).unwrap();
        s.domain::<Person>().repo().set("p1", &person("p1", PHONE)).unwrap();
        s.close();
    }
    let s = open_field_mode(&dir, keys(None, Some(2))).unwrap();
    let domain = s.domain::<Person>();
    let read = domain.repo().get("p1").unwrap();
    assert_eq!(read.name, "visible");
    let grant = domain.read_grant().unwrap();
    let err = read.phone.open(&grant).unwrap_err();
    assert!(matches!(&err, ClError::Validation(t) if t.contains("no read key")), "{err:?}");
    let err = domain.repo().set("p3", &person("p3", PHONE)).unwrap_err();
    assert!(matches!(&err, ClError::Validation(t) if t.contains("no read key")), "{err:?}");
    assert!(raw(&s, "p3").is_none());
}

#[test]
fn a_program_with_only_the_search_key_cannot_write_at_all() {
    let dir = temp_dir();
    {
        let s = open_field_mode(&dir, keys(Some(1), Some(2))).unwrap();
        s.domain::<Person>().repo().set("p1", &person("p1", PHONE)).unwrap();
        s.close();
    }
    let s = open_field_mode(&dir, keys(None, Some(2))).unwrap();
    let domain = s.domain::<Person>();
    let repo = domain.repo();
    let before = raw(&s, "p1").unwrap();
    let read = repo.get("p1").unwrap();
    let read_only = |r: clove1db::units::Result<()>, what: &str| match r {
        Err(ClError::Validation(t)) => assert!(t.contains("read-only") || t.contains("protected fields"), "{what}: {t}"),
        other => panic!("{what}: not refused: {other:?}"),
    };
    // Rewriting the row with its protected values exactly as read is a write too.
    read_only(repo.set("p1", &read), "set of a closed row");
    read_only(repo.set("p1", &person("p1", PHONE)), "set of a new value");
    read_only(repo.commit_entities(&[("p1", &read)], &[]), "commit_entities");
    read_only(repo.commit_entities(&[], &["p1"]), "commit_entities delete");
    read_only(repo.delete("p1"), "delete");
    read_only(domain.update("p1", NewPerson).map(|_: Person| ()), "update");
    let dm = s.db_manager("store");
    read_only(
        dm.commit_batch(&[("people".to_string(), "p1".to_string(), b"{}".to_vec())], &[]),
        "commit_batch",
    );
    read_only(dm.commit_batch_atomic(&[], &[("people".to_string(), "p1".to_string())]), "commit_batch_atomic delete");
    assert_eq!(raw(&s, "p1").unwrap(), before, "a refused write changed the row");
    s.close();
    // With the read key the row is intact and opens.
    let s = open_field_mode(&dir, keys(Some(1), Some(2))).unwrap();
    let read = s.domain::<Person>().repo().get("p1").unwrap();
    let grant = s.domain::<Person>().read_grant().unwrap();
    assert_eq!(read.phone.open(&grant).unwrap(), PHONE);
}

impl clove1db::dto::OutputDto<Person> for Person {
    fn from_entity(entity: Person) -> Self {
        entity
    }
}

/// An input for `Domain::update`.
#[derive(Deserialize)]
struct NewPerson;
impl clove1db::dto::InputDto<Person> for NewPerson {
    fn into_entity(self) -> clove1db::units::Result<Person> {
        Ok(person("p1", PHONE))
    }
}

#[test]
fn a_wrong_or_missing_key_is_the_single_open_error() {
    let dir = temp_dir();
    drop(open_field_mode(&dir, keys(Some(1), Some(2))).unwrap());
    for wrong in [keys(Some(9), Some(2)), keys(Some(1), Some(9)), keys(None, None)] {
        let err = open_field_mode(&dir, wrong).err().expect("must be refused");
        assert!(matches!(err, ClError::EncryptedOpenFailed), "{err:?}");
    }
    drop(open_field_mode(&dir, keys(Some(1), Some(2))).unwrap());
}

#[test]
fn a_new_database_with_field_keys_needs_both_keys_and_leaves_no_file() {
    let dir = temp_dir();
    let err = open_fields(&dir, keys(Some(1), None)).err().expect("must be refused");
    assert!(matches!(&err, ClError::Validation(t) if t.contains("both a read key and a search key")), "{err:?}");
    assert!(walk(&dir).is_empty(), "files left behind");
}

#[test]
fn whole_database_encryption_and_field_keys_are_not_combined() {
    let dir = temp_dir();
    let err = Storage::builder(StorageConfig::default())
        .add_database(
            base(&dir)
                .encryption(keys(Some(1), Some(2)))
                .field_encryption(keys(Some(1), Some(2)))
                .register_sealed::<Person>("people"),
        )
        .build()
        .err()
        .expect("must be refused");
    assert!(matches!(&err, ClError::Validation(t) if t.contains("not both")), "{err:?}");
    assert!(walk(&dir).is_empty());
}

#[test]
fn closing_the_database_forgets_the_keys() {
    let dir = temp_dir();
    let s = open_fields(&dir, keys(Some(1), Some(2))).unwrap();
    let domain = s.domain::<Person>();
    domain.repo().set("p1", &person("p1", PHONE)).unwrap();
    let read = domain.repo().get("p1").unwrap();
    let grant = domain.read_grant().unwrap();
    assert_eq!(read.phone.open(&grant).unwrap(), PHONE);
    s.close();
    let err = read.phone.open(&grant).unwrap_err();
    assert!(matches!(&err, ClError::Validation(t) if t.contains("unavailable")), "{err:?}");
    assert!(domain.read_grant().is_err(), "a grant was made for a closed database");
}
