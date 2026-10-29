//! Rows of an entity with protected fields: written sealed, read back closed and tied to their row.
use clove1db::{
    CloveFields, EncryptionConfig, KeySource,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    dto::OutputDto,
    entity::Entity,
    field_crypto::Sealed,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use redb::TableDefinition;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

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
impl OutputDto<Person> for Person {
    fn from_entity(entity: Person) -> Self {
        entity
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

fn enc() -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite { cipher: CipherKind::Aes256GcmSiv, hkdf: HkdfHash::Sha256 },
        read: Some(KeySource::Raw(Key32::from_bytes(&[1; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[2; 32]))),
    }
}

fn temp_dir() -> PathBuf {
    std::env::temp_dir().join(uuid::Uuid::new_v4().to_string())
}

/// Under `--cfg clove_test_encrypt_all` every database starts encrypted as a whole.
fn base(dir: &Path) -> DatabaseConfig {
    DatabaseConfig::new("records", "store").dir_path(dir.to_path_buf()).has_cache(false).backup_enabled(true)
}

/// A database with no keys at all, also under the test cfg (listed in 7-5-plain-only.md).
fn plain_base(dir: &Path) -> DatabaseConfig {
    let db = base(dir);
    #[cfg(clove_test_encrypt_all)]
    let db = db.plain();
    db
}

fn open(dir: &Path) -> Storage {
    Storage::builder(StorageConfig::default())
        .add_database(base(dir).encryption(enc()).register_sealed::<Person>("people"))
        .build()
        .unwrap()
}

fn raw(s: &Storage, id: &str) -> Option<Vec<u8>> {
    s.db_manager("store")
        .get_uncached(TableDefinition::<&str, &[u8]>::new("people"), id)
        .unwrap()
}

fn raw_json(s: &Storage, id: &str) -> serde_json::Value {
    serde_json::from_slice(&raw(s, id).expect("row exists")).unwrap()
}

#[test]
fn a_row_is_stored_sealed() {
    let s = open(&temp_dir());
    s.domain::<Person>().repo().set("p1", &person("p1", PHONE)).unwrap();
    let bytes = raw(&s, "p1").unwrap();
    let text = String::from_utf8(bytes).unwrap();
    for secret in ["966500000001", "vip", "late"] {
        assert!(!text.contains(secret), "{text}");
    }
    let json = raw_json(&s, "p1");
    assert_eq!(json["name"], "visible");
    assert!(json["phone"].as_str().is_some_and(|t| t.len() > 20));
    assert!(json["tags"].as_str().is_some_and(|t| t.len() > 20));
}

#[test]
fn every_read_path_gives_closed_values_tied_to_the_row() {
    let s = open(&temp_dir());
    let domain = s.domain::<Person>();
    domain.repo().set("p1", &person("p1", PHONE)).unwrap();
    let check = |p: &Person| {
        assert_eq!(p.name, "visible");
        assert!(!p.phone.is_new() && p.phone.is_bound(), "phone");
        assert!(!p.tags.is_new() && p.tags.is_bound(), "tags");
    };
    check(&domain.repo().get("p1").unwrap());
    check(&domain.repo().get_uncached("p1").unwrap());
    let listed = domain.repo().list().unwrap();
    assert_eq!(listed.len(), 1);
    check(&listed[0]);
    check(&domain.query().collect().unwrap()[0]);
    check(&domain.query().one().unwrap().unwrap());
    let history: Vec<Person> = domain.history_typed("p1").unwrap();
    assert!(!history.is_empty());
    history.iter().for_each(check);
}

#[test]
fn writing_the_same_value_again_stores_new_text() {
    let s = open(&temp_dir());
    let repo = s.domain::<Person>().repo();
    repo.set("p1", &person("p1", PHONE)).unwrap();
    let first = raw_json(&s, "p1");
    repo.set("p1", &person("p1", PHONE)).unwrap();
    let second = raw_json(&s, "p1");
    assert_ne!(first["phone"], second["phone"]);
    assert_ne!(first["tags"], second["tags"]);
}

#[test]
fn a_row_read_back_is_written_to_its_own_place_with_its_text_unchanged() {
    let s = open(&temp_dir());
    let repo = s.domain::<Person>().repo();
    repo.set("p1", &person("p1", PHONE)).unwrap();
    let before = raw(&s, "p1").unwrap();
    let mut read = repo.get("p1").unwrap();
    read.name = "renamed".into();
    repo.set("p1", &read).unwrap();
    let after = raw_json(&s, "p1");
    let before: serde_json::Value = serde_json::from_slice(&before).unwrap();
    assert_eq!(after["name"], "renamed");
    assert_eq!(after["phone"], before["phone"]);
    assert_eq!(after["tags"], before["tags"]);
}

#[test]
fn a_closed_value_is_refused_anywhere_but_its_own_place() {
    let s = open(&temp_dir());
    let repo = s.domain::<Person>().repo();
    repo.set("p1", &person("p1", PHONE)).unwrap();
    let read = repo.get("p1").unwrap();
    let err = repo.set("p2", &read).unwrap_err();
    assert!(matches!(&err, ClError::Validation(t) if t.contains("can only be written back")), "{err:?}");
    assert!(raw(&s, "p2").is_none(), "a refused write left a row");
    // Text that came from outside the storage (a request body, say) is never bound.
    let outside: Person = serde_json::from_str(&serde_json::to_string(&read).unwrap()).unwrap();
    let err = repo.set("p1", &outside).unwrap_err();
    assert!(matches!(&err, ClError::Validation(t) if t.contains("can only be written back")), "{err:?}");
}

#[test]
fn raw_writes_to_a_protected_table_are_refused_and_change_nothing() {
    let s = open(&temp_dir());
    let repo = s.domain::<Person>().repo();
    repo.set("p1", &person("p1", PHONE)).unwrap();
    let before = raw(&s, "p1").unwrap();
    let dm = s.db_manager("store");
    let row = || vec![("people".to_string(), "p9".to_string(), br#"{"id":"p9","name":"x","phone":"clear","tags":"clear"}"#.to_vec())];
    let refused = |r: clove1db::units::Result<()>| match r {
        Err(ClError::Validation(t)) => assert!(t.contains("protected fields"), "{t}"),
        other => panic!("not refused: {other:?}"),
    };
    refused(dm.commit_batch(&row(), &[]));
    refused(dm.commit_batch_atomic(&row(), &[]));
    refused(dm.rewrite_tables(&row(), &[]));
    refused(dm.replace_table("people", &[("p9".to_string(), b"{}".to_vec())]));
    refused(dm.set(TableDefinition::<&str, &[u8]>::new("people"), "people", "p9", b"{}".to_vec()));
    assert!(raw(&s, "p9").is_none());
    assert_eq!(raw(&s, "p1").unwrap(), before);
}

#[test]
fn a_batch_by_entity_seals_every_row() {
    let s = open(&temp_dir());
    let repo = s.domain::<Person>().repo();
    repo.set("gone", &person("gone", PHONE)).unwrap();
    let (a, b) = (person("a", "+155500000002"), person("b", "+155500000003"));
    repo.commit_entities(&[("a", &a), ("b", &b)], &["gone"]).unwrap();
    assert!(raw(&s, "gone").is_none());
    for id in ["a", "b"] {
        let text = String::from_utf8(raw(&s, id).unwrap()).unwrap();
        assert!(!text.contains("96650000000"), "{text}");
        assert!(repo.get(id).unwrap().phone.is_bound());
    }
    // A closed value from row `a` cannot go into row `b` through a batch either.
    let from_a = repo.get("a").unwrap();
    assert!(repo.commit_entities(&[("b", &from_a)], &[]).is_err());
}

#[test]
fn a_protected_table_without_keys_is_not_built_and_writes_nothing() {
    let dir = temp_dir();
    let err = Storage::builder(StorageConfig::default())
        .add_database(plain_base(&dir).register_sealed::<Person>("people"))
        .build()
        .err()
        .expect("must be refused");
    assert!(matches!(&err, ClError::Validation(t) if t.contains("needs encryption keys")), "{err:?}");
    let files = walk(&dir);
    assert!(files.is_empty(), "files left behind: {files:?}");
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

#[test]
fn a_row_survives_closing_and_opening_again() {
    let dir = temp_dir();
    {
        let s = open(&dir);
        s.domain::<Person>().repo().set("p1", &person("p1", PHONE)).unwrap();
        s.close();
    }
    let s = open(&dir);
    let read = s.domain::<Person>().repo().get("p1").unwrap();
    assert!(read.phone.is_bound() && read.tags.is_bound());
    s.domain::<Person>().repo().set("p1", &read).unwrap();
}
