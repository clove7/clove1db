//! One write over several tables, one of them with protected fields: `Repository::prepare` seals
//! the row, `DatabaseManager::commit_atomic` writes it with plain rows and deletes in one operation.
use clove1db::{
    CloveFields, EncryptionConfig, KeySource, Unique,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    entity::Entity,
    field_crypto::Sealed,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const PHONE: &str = "+155500000077";

#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Customer {
    id: String,
    name: String,
    #[clove(encrypt, id = 1)]
    phone: Sealed<String>,
}
impl Entity for Customer {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Activity {
    id: String,
    label: String,
}
impl Entity for Activity {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Session {
    id: String,
}
impl Entity for Session {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Scan {
    id: String,
}
impl Entity for Scan {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn keys() -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite { cipher: CipherKind::XChaCha20Poly1305, hkdf: HkdfHash::Sha256 },
        read: Some(KeySource::Raw(Key32::from_bytes(&[1; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[2; 32]))),
    }
}

fn temp_dir() -> PathBuf {
    std::env::temp_dir().join(uuid::Uuid::new_v4().to_string())
}

fn config(dir: &Path, name: &str, limit: usize) -> DatabaseConfig {
    DatabaseConfig::new("records", name)
        .dir_path(dir.to_path_buf())
        .has_cache(false)
        .blob_enabled(true)
        .max_commit_batch_entries(limit)
        .field_encryption(keys())
        .unique(Unique::on(Activity::label))
        .register_sealed::<Customer>("customers")
        .register::<Activity>("activity")
        .register::<Session>("sessions")
        .register_blob::<Scan>("scans")
}

fn open(dir: &Path) -> Storage {
    Storage::builder(StorageConfig::default()).add_database(config(dir, "store", 3)).build().unwrap()
}

fn customer(id: &str, phone: &str) -> Customer {
    Customer { id: id.into(), name: "visible".into(), phone: Sealed::new(phone.into()) }
}

fn activity(id: &str, label: &str) -> Activity {
    Activity { id: id.into(), label: label.into() }
}

fn raw_activity(id: &str, label: &str) -> (String, String, Vec<u8>) {
    ("activity".into(), id.into(), serde_json::to_vec(&activity(id, label)).unwrap())
}

fn phone_of(s: &Storage, id: &str) -> String {
    let d = s.domain::<Customer>();
    d.repo().get(id).unwrap().phone.open(&d.read_grant().unwrap()).unwrap()
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

fn is_validation(r: clove1db::units::Result<()>, part: &str) {
    match r {
        Err(ClError::Validation(t)) => assert!(t.contains(part), "{t}"),
        other => panic!("expected a refusal containing {part:?}, got {other:?}"),
    }
}

#[test]
fn a_protected_row_a_plain_row_and_a_delete_land_together() {
    let dir = temp_dir();
    let s = open(&dir);
    let db = s.db_manager("store");
    s.domain::<Session>().repo().set("s1", &Session { id: "s1".into() }).unwrap();
    s.domain::<Session>().repo().set("s2", &Session { id: "s2".into() }).unwrap();

    let prepared = [s.domain::<Customer>().repo().prepare("c1", &customer("c1", PHONE)).unwrap()];
    db.commit_atomic(
        &prepared,
        &[raw_activity("a1", "phone changed")],
        &[("sessions".into(), "s1".into()), ("sessions".into(), "s2".into())],
    )
    .unwrap();
    s.close();

    // After a reopen: all three changes are there.
    let s = open(&dir);
    assert_eq!(phone_of(&s, "c1"), PHONE);
    assert_eq!(s.domain::<Activity>().repo().get("a1").unwrap().label, "phone changed");
    assert!(s.domain::<Session>().repo().get("s1").is_err());
    assert!(s.domain::<Session>().repo().get("s2").is_err());
    s.close();

    // The protected value is in no file of the folder.
    for file in walk(&dir) {
        let bytes = std::fs::read(&file).unwrap();
        assert!(!bytes.windows(PHONE.len()).any(|w| w == PHONE.as_bytes()), "the phone is readable in {file:?}");
    }
}

#[test]
fn a_prepared_row_of_a_plain_table_is_written_too() {
    let dir = temp_dir();
    let s = open(&dir);
    let row = s.domain::<Activity>().repo().prepare("a1", &activity("a1", "one")).unwrap();
    assert_eq!((row.table(), row.key()), ("activity", "a1"));
    s.db_manager("store").commit_atomic(&[row], &[], &[]).unwrap();
    assert_eq!(s.domain::<Activity>().repo().get("a1").unwrap().label, "one");
}

#[test]
fn raw_bytes_for_a_protected_table_are_refused_and_nothing_is_written() {
    let dir = temp_dir();
    let s = open(&dir);
    let fake = ("customers".to_string(), "c9".to_string(), br#"{"id":"c9","name":"x","phone":"p"}"#.to_vec());
    is_validation(
        s.db_manager("store").commit_atomic(&[], &[raw_activity("a1", "never"), fake], &[]),
        "protected fields",
    );
    assert!(s.domain::<Activity>().repo().get("a1").is_err(), "the plain row was written");
    assert!(s.domain::<Customer>().repo().get("c9").is_err());
}

#[test]
fn a_row_prepared_for_another_database_is_refused() {
    let dir = temp_dir();
    let other = temp_dir();
    let s = open(&dir);
    let t = Storage::builder(StorageConfig::default()).add_database(config(&other, "store", 3)).build().unwrap();
    let foreign = t.domain::<Customer>().repo().prepare("c1", &customer("c1", PHONE)).unwrap();
    is_validation(s.db_manager("store").commit_atomic(&[foreign], &[raw_activity("a1", "never")], &[]), "another database");
    assert!(s.domain::<Customer>().repo().get("c1").is_err());
    assert!(s.domain::<Activity>().repo().get("a1").is_err());
}

#[test]
fn a_row_for_an_attachments_table_is_refused() {
    let dir = temp_dir();
    let s = open(&dir);
    let err = s.domain::<Scan>().repo().prepare("f1", &Scan { id: "f1".into() }).unwrap_err();
    assert!(matches!(&err, ClError::Validation(t) if t.contains("set_with_blob")), "{err:?}");
}

#[test]
fn one_violation_of_uniqueness_writes_nothing() {
    let dir = temp_dir();
    let s = open(&dir);
    s.domain::<Activity>().repo().set("a0", &activity("a0", "taken")).unwrap();
    let prepared = [s.domain::<Customer>().repo().prepare("c1", &customer("c1", PHONE)).unwrap()];
    let r = s.db_manager("store").commit_atomic(&prepared, &[raw_activity("a1", "taken")], &[]);
    assert!(r.is_err(), "the duplicate label was accepted");
    assert!(s.domain::<Customer>().repo().get("c1").is_err(), "the protected row was written");
    assert!(s.domain::<Activity>().repo().get("a1").is_err());
}

#[test]
fn more_rows_than_the_batch_limit_are_still_one_operation() {
    // The limit is 3. Ten rows, the last one a duplicate: split in chunks, the first rows would stay.
    let dir = temp_dir();
    let s = open(&dir);
    let repo = s.domain::<Activity>().repo();
    repo.set("a0", &activity("a0", "taken")).unwrap();
    let mut prepared = Vec::new();
    for i in 1..=9 {
        prepared.push(repo.prepare(&format!("a{i}"), &activity(&format!("a{i}"), &format!("l{i}"))).unwrap());
    }
    prepared.push(repo.prepare("a10", &activity("a10", "taken")).unwrap());
    assert!(s.db_manager("store").commit_atomic(&prepared, &[], &[]).is_err());
    for i in 1..=10 {
        assert!(repo.get(&format!("a{i}")).is_err(), "row a{i} was written by a split call");
    }
    // Without the duplicate, all ten land.
    prepared.pop();
    prepared.push(repo.prepare("a10", &activity("a10", "l10")).unwrap());
    s.db_manager("store").commit_atomic(&prepared, &[], &[]).unwrap();
    for i in 1..=10 {
        assert!(repo.get(&format!("a{i}")).is_ok());
    }
}

#[test]
fn a_program_with_only_the_search_key_cannot_write() {
    let dir = temp_dir();
    let s = open(&dir);
    s.close();
    let search_only = EncryptionConfig {
        suite: KeySuite { cipher: CipherKind::XChaCha20Poly1305, hkdf: HkdfHash::Sha256 },
        read: None,
        search: Some(KeySource::Raw(Key32::from_bytes(&[2; 32]))),
    };
    let s = Storage::builder(StorageConfig::default())
        .add_database(config(&dir, "store", 3).field_encryption(search_only))
        .build()
        .unwrap();
    let prepared = s.domain::<Customer>().repo().prepare("c1", &customer("c1", PHONE));
    let written = prepared.and_then(|p| s.db_manager("store").commit_atomic(&[p], &[raw_activity("a1", "never")], &[]));
    assert!(written.is_err());
    assert!(s.domain::<Activity>().repo().get("a1").is_err());
}
