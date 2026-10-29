//! The small keys file `{db}.keys`: made next to the database, written only when it changes,
//! sealed so no table name or key shows, checked at open, and (as an option) the only place the
//! sealed data key is kept.
use super::{
    envelope::{Place, open_envelope},
    keyfile, keystore,
};
use crate::{
    CloveFields,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    encrypted_store::{EncryptionConfig, FileKeys, KeySource, SealedBlobStore},
    entity::Entity,
    field_crypto::Sealed,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const PHONE: &str = "+155500000001";

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize, CloveFields)]
struct Person {
    id: String,
    name: String,
    #[clove(encrypt, id = 1)]
    phone: Sealed<String>,
}
impl Entity for Person {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// The same table with another field: a different layout, so opening it is refused.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize, CloveFields)]
struct PersonMore {
    id: String,
    name: String,
    #[clove(encrypt, id = 1)]
    phone: Sealed<String>,
    extra: String,
}
impl Entity for PersonMore {
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

fn config(dir: &Path) -> DatabaseConfig {
    let db = DatabaseConfig::new("records", "store").dir_path(dir.to_path_buf()).has_cache(false).blob_enabled(true);
    #[cfg(clove_test_encrypt_all)]
    let db = db.plain();
    db
}

fn open(dir: &Path, external: Option<&Path>) -> crate::units::Result<Storage> {
    let mut db = config(dir).field_encryption(keys());
    if let Some(path) = external {
        db = db.field_keys_file(path.to_path_buf());
    }
    Storage::builder(StorageConfig::default()).add_database(db.register_sealed_blob::<Person>("files")).build()
}

fn open_more(dir: &Path) -> crate::units::Result<Storage> {
    Storage::builder(StorageConfig::default())
        .add_database(config(dir).field_encryption(keys()).register_sealed_blob::<PersonMore>("files"))
        .build()
}

fn temp_dir() -> PathBuf {
    std::env::temp_dir().join(uuid::Uuid::new_v4().to_string())
}

fn db_dir(dir: &Path) -> PathBuf {
    dir.join("records")
}

fn keys_path(dir: &Path) -> PathBuf {
    db_dir(dir).join("store.keys")
}

fn main_path(dir: &Path) -> PathBuf {
    db_dir(dir).join("store.cldb")
}

fn has(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
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
    out.sort();
    out
}

/// Every file except the main one (redb itself rewrites that at every open), with its bytes.
fn others(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    walk(dir)
        .into_iter()
        .filter(|p| p.extension().is_none_or(|e| e != "cldb"))
        .map(|p| {
            let bytes = std::fs::read(&p).unwrap();
            (p, bytes)
        })
        .collect()
}

fn person(id: &str) -> Person {
    Person { id: id.into(), name: "visible".into(), phone: Sealed::new(PHONE.into()) }
}

/// A database encrypted as a whole (the keys of the protected fields are its keys).
fn open_whole(dir: &Path) -> crate::units::Result<Storage> {
    Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("records", "store")
                .dir_path(dir.to_path_buf())
                .has_cache(false)
                .blob_enabled(true)
                .encryption(keys())
                .register_sealed_blob::<Person>("files"),
        )
        .build()
}

/// A database with one row and one attachment, closed.
fn prepared(dir: &Path, external: Option<&Path>) -> (String, String, Vec<u8>) {
    prepared_in(open(dir, external).unwrap())
}

fn prepared_in(s: Storage) -> (String, String, Vec<u8>) {
    let token = s.db_manager("store").register_consumer("keys-test").unwrap();
    let bytes: Vec<u8> = (0..150_000u32).map(|i| (i % 251) as u8).collect();
    s.domain::<Person>().repo().set_with_blob("d1", &person("d1"), &bytes).unwrap();
    let raw = s
        .db_manager("store")
        .get_uncached(redb::TableDefinition::<&str, &[u8]>::new("files"), "d1")
        .unwrap()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    let blob_id = s
        .db_manager("store")
        .read_changes(&token, 0, 20)
        .unwrap()
        .into_iter()
        .find_map(|c| match c.kind {
            crate::ChangeKind::BlobPut { blob_id, .. } => Some(blob_id),
            _ => None,
        })
        .expect("a blob put");
    s.close();
    (json["phone"].as_str().unwrap().to_string(), blob_id, bytes)
}

#[test]
fn the_default_makes_the_file_and_it_recovers_values_and_attachments_without_the_main_file() {
    let dir = temp_dir();
    let (sealed_phone, blob_id, bytes) = prepared(&dir, None);
    assert!(keys_path(&dir).is_file(), "no keys file was made");
    assert!(std::fs::metadata(keys_path(&dir)).unwrap().len() < 1024);

    // The main file is lost. The keys file and the programmer's keys are all that is left.
    std::fs::remove_file(main_path(&dir)).unwrap();
    let file = keyfile::read_file(&keys_path(&dir)).unwrap().expect("the keys file");
    let field_keys = keystore::open(&keys(), &file.locked).unwrap();
    let tables = file.tables(&field_keys).unwrap();
    let table_id = tables.iter().find(|(name, _)| name == "files").map(|(_, id)| id.clone()).expect("the table");

    let cipher = field_keys.cipher(&table_id, 1).unwrap();
    let place = Place { table_id: &table_id, field_id: 1, row_key: "d1" };
    let opened = open_envelope(&cipher, &place, &sealed_phone).unwrap();
    assert_eq!(opened.as_bytes(), format!("\"{PHONE}\"").as_bytes());

    // The attachment opens too: its sealed file is named by the table, the row and the file.
    let store = SealedBlobStore::with_keys(&db_dir(&dir).join("store.pblobs"), field_keys.clone() as Arc<dyn FileKeys>);
    let mut reader = store.open_read(&format!("{table_id}/0"), &format!("{}:d1{blob_id}", "d1".len())).unwrap();
    let mut out = Vec::new();
    reader.read_to_end(&mut out).unwrap();
    assert_eq!(out, bytes);
}

#[test]
fn the_file_shows_no_table_name_and_no_key() {
    let dir = temp_dir();
    prepared(&dir, None);
    let content = std::fs::read(keys_path(&dir)).unwrap();
    assert!(!has(&content, b"files"), "a table name is readable");
    assert!(!has(&content, b"store"), "the database name is readable");
    assert!(!has(&content, &[1u8; 32]) && !has(&content, &[2u8; 32]), "a programmer key is in the file");
    assert!(!has(&content, PHONE.as_bytes()));
    // Both locks are in it, as stored in the main file.
    let main = keystore::read(redb::Database::open(main_path(&dir)).as_ref().unwrap()).unwrap().unwrap();
    assert!(has(&content, main.read.as_bytes()) && has(&content, main.search.as_bytes()));
}

#[test]
fn opens_do_not_change_the_file_and_a_failed_open_does_not_write_it() {
    let dir = temp_dir();
    prepared(&dir, None);
    let before = std::fs::read(keys_path(&dir)).unwrap();
    let stamp = std::fs::metadata(keys_path(&dir)).unwrap().modified().unwrap();
    for _ in 0..2 {
        open(&dir, None).unwrap().close();
    }
    assert_eq!(std::fs::read(keys_path(&dir)).unwrap(), before, "a good open changed the keys file");
    assert_eq!(std::fs::metadata(keys_path(&dir)).unwrap().modified().unwrap(), stamp, "a good open rewrote the keys file");

    // A refused open (another layout) writes nothing, not even the file that is missing.
    std::fs::remove_file(keys_path(&dir)).unwrap();
    assert!(matches!(open_more(&dir), Err(ClError::LayoutMismatch { .. })));
    assert!(!keys_path(&dir).exists(), "a failed open wrote the keys file");
    // A good open makes it again, with the same content.
    open(&dir, None).unwrap().close();
    assert!(keys_path(&dir).is_file());
    let again = keyfile::read_file(&keys_path(&dir)).unwrap().unwrap();
    assert_eq!(again.locked, keystore::read(redb::Database::open(main_path(&dir)).as_ref().unwrap()).unwrap().unwrap());
}

#[test]
fn a_changed_byte_is_a_tamper_error() {
    let dir = temp_dir();
    prepared(&dir, None);
    let original = std::fs::read(keys_path(&dir)).unwrap();
    // The magic, the middle of a lock, the sealed list, and the last byte.
    for at in [0, 20, original.len() / 2 + 90, original.len() - 1] {
        let mut changed = original.clone();
        changed[at] ^= 1;
        std::fs::write(keys_path(&dir), &changed).unwrap();
        let err = open(&dir, None).err().unwrap_or_else(|| panic!("byte {at}: opened"));
        assert!(matches!(err, ClError::DataTampered), "byte {at}: {err:?}");
    }
    // A shortened file too.
    std::fs::write(keys_path(&dir), &original[..original.len() - 3]).unwrap();
    assert!(matches!(open(&dir, None).err(), Some(ClError::DataTampered)));
    // The original opens again, and was not rewritten by the failed tries.
    std::fs::write(keys_path(&dir), &original).unwrap();
    open(&dir, None).unwrap().close();
    assert_eq!(std::fs::read(keys_path(&dir)).unwrap(), original);
}

#[test]
fn the_file_only_form_keeps_no_lock_in_the_main_file_and_refuses_a_missing_or_wrong_file() {
    let dir = temp_dir();
    let apart = temp_dir().join("elsewhere").join("keys.bin");
    prepared(&dir, Some(&apart));
    assert!(apart.is_file());
    assert!(!keys_path(&dir).exists(), "a keys file was also made next to the database");

    // The main file holds no lock: no row in the key table, and the lock's bytes are nowhere in it.
    let file = keyfile::read_file(&apart).unwrap().unwrap();
    assert!(keystore::read(redb::Database::open(main_path(&dir)).as_ref().unwrap()).unwrap().is_none());
    let main = std::fs::read(main_path(&dir)).unwrap();
    assert!(!has(&main, file.locked.read.as_bytes()) && !has(&main, file.locked.search.as_bytes()));

    // The right file opens and the value is there.
    {
        let s = open(&dir, Some(&apart)).unwrap();
        let grant = s.domain::<Person>().read_grant().unwrap();
        assert_eq!(s.domain::<Person>().repo().get("d1").unwrap().phone.open(&grant).unwrap(), PHONE);
        s.close();
    }

    // Without the file: refused with a clear message, before any file is touched.
    let before = walk(&dir).into_iter().map(|p| (p.clone(), std::fs::read(&p).unwrap())).collect::<Vec<_>>();
    let hidden = apart.with_extension("moved");
    std::fs::rename(&apart, &hidden).unwrap();
    let err = open(&dir, Some(&apart)).err().expect("must be refused");
    assert!(matches!(&err, ClError::Validation(t) if t.contains("keys file") && t.contains("missing")), "{err:?}");
    let after = walk(&dir).into_iter().map(|p| (p.clone(), std::fs::read(&p).unwrap())).collect::<Vec<_>>();
    assert!(before == after, "a refused open touched a file");

    // Another database's file: refused, and nothing but the main file's own noise changes.
    let other_dir = temp_dir();
    let other_apart = temp_dir().join("keys.bin");
    prepared(&other_dir, Some(&other_apart));
    let before = others(&dir);
    let err = open(&dir, Some(&other_apart)).err().expect("must be refused");
    assert!(matches!(&err, ClError::Validation(t) if t.contains("does not belong")), "{err:?}");
    assert!(before == others(&dir), "a refused open changed a file");
    assert!(!keys_path(&dir).exists());

    // Put the right one back: it opens.
    std::fs::rename(&hidden, &apart).unwrap();
    open(&dir, Some(&apart)).unwrap().close();

    // A database that is made in the file-only form needs the file to be absent at creation.
    let fresh = temp_dir();
    let leftover = temp_dir().join("leftover.bin");
    std::fs::create_dir_all(leftover.parent().unwrap()).unwrap();
    std::fs::write(&leftover, b"something").unwrap();
    let err = open(&fresh, Some(&leftover)).err().expect("must be refused");
    assert!(matches!(&err, ClError::Validation(t) if t.contains("exists but the database does not")), "{err:?}");
    assert!(!db_dir(&fresh).exists(), "a refused open made a folder");
}

#[test]
fn a_program_with_only_the_search_key_neither_checks_nor_writes_the_file() {
    let dir = temp_dir();
    prepared(&dir, None);
    let before = std::fs::read(keys_path(&dir)).unwrap();
    // Even a damaged file does not matter to a program that cannot read the table list.
    let mut damaged = before.clone();
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    std::fs::write(keys_path(&dir), &damaged).unwrap();
    let search_only = EncryptionConfig {
        suite: KeySuite { cipher: CipherKind::XChaCha20Poly1305, hkdf: HkdfHash::Sha256 },
        read: None,
        search: Some(KeySource::Raw(Key32::from_bytes(&[2; 32]))),
    };
    let s = Storage::builder(StorageConfig::default())
        .add_database(config(&dir).field_encryption(search_only).register_sealed_blob::<Person>("files"))
        .build()
        .unwrap();
    s.close();
    assert_eq!(std::fs::read(keys_path(&dir)).unwrap(), damaged, "a read-only program wrote the keys file");
}

#[test]
fn a_table_added_to_an_existing_database_is_refused_and_the_file_stays_as_it_was() {
    // The set of tables is fixed when the database is made, so the file's table list is too.
    let dir = temp_dir();
    prepared(&dir, None);
    let before = std::fs::read(keys_path(&dir)).unwrap();
    let err = Storage::builder(StorageConfig::default())
        .add_database(
            config(&dir)
                .field_encryption(keys())
                .register_sealed_blob::<Person>("files")
                .register_sealed::<PersonOther>("others"),
        )
        .build()
        .err()
        .expect("must be refused");
    assert!(matches!(err, ClError::TableMismatch { .. }), "{err:?}");
    assert_eq!(std::fs::read(keys_path(&dir)).unwrap(), before);
}

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize, CloveFields)]
struct PersonOther {
    id: String,
    #[clove(encrypt, id = 1)]
    phone: Sealed<String>,
}
impl Entity for PersonOther {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[test]
fn a_database_encrypted_as_a_whole_gets_the_file_and_it_recovers_without_the_main_file() {
    let dir = temp_dir();
    let (sealed_phone, blob_id, bytes) = prepared_in(open_whole(&dir).unwrap());
    assert!(keys_path(&dir).is_file(), "no keys file was made");
    let content = std::fs::read(keys_path(&dir)).unwrap();
    assert!(!has(&content, b"files") && !has(&content, &[1u8; 32]) && !has(&content, &[2u8; 32]));

    // Two more opens leave it as it was.
    let stamp = std::fs::metadata(keys_path(&dir)).unwrap().modified().unwrap();
    for _ in 0..2 {
        open_whole(&dir).unwrap().close();
    }
    assert_eq!(std::fs::read(keys_path(&dir)).unwrap(), content);
    assert_eq!(std::fs::metadata(keys_path(&dir)).unwrap().modified().unwrap(), stamp);

    // The main file is lost: the copy of the lock in the keys file is what is left.
    std::fs::remove_file(main_path(&dir)).unwrap();
    let file = keyfile::read_file(&keys_path(&dir)).unwrap().expect("the keys file");
    let field_keys = keystore::open(&keys(), &file.locked).unwrap();
    let tables = file.tables(&field_keys).unwrap();
    let table_id = tables.iter().find(|(name, _)| name == "files").map(|(_, id)| id.clone()).expect("the table");
    let cipher = field_keys.cipher(&table_id, 1).unwrap();
    let place = Place { table_id: &table_id, field_id: 1, row_key: "d1" };
    assert_eq!(
        open_envelope(&cipher, &place, &sealed_phone).unwrap().as_bytes(),
        format!("\"{PHONE}\"").as_bytes()
    );
    let store = SealedBlobStore::with_keys(&db_dir(&dir).join("store.pblobs"), field_keys.clone() as Arc<dyn FileKeys>);
    let mut reader = store.open_read(&format!("{table_id}/0"), &format!("{}:d1{blob_id}", "d1".len())).unwrap();
    let mut out = Vec::new();
    reader.read_to_end(&mut out).unwrap();
    assert_eq!(out, bytes);
}

#[test]
fn a_changed_byte_in_the_file_of_a_database_encrypted_as_a_whole_is_a_tamper_error() {
    let dir = temp_dir();
    prepared_in(open_whole(&dir).unwrap());
    let original = std::fs::read(keys_path(&dir)).unwrap();
    for at in [0, 20, original.len() / 2 + 90, original.len() - 1] {
        let mut changed = original.clone();
        changed[at] ^= 1;
        std::fs::write(keys_path(&dir), &changed).unwrap();
        let err = open_whole(&dir).err().unwrap_or_else(|| panic!("byte {at}: opened"));
        assert!(matches!(err, ClError::DataTampered), "byte {at}: {err:?}");
    }
    std::fs::write(keys_path(&dir), &original).unwrap();
    open_whole(&dir).unwrap().close();
}

#[test]
fn the_file_only_form_is_refused_for_a_database_encrypted_as_a_whole() {
    let dir = temp_dir();
    let apart = temp_dir().join("keys.bin");
    let err = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("records", "store")
                .dir_path(dir.clone())
                .has_cache(false)
                .blob_enabled(true)
                .encryption(keys())
                .field_keys_file(apart.clone())
                .register_sealed_blob::<Person>("files"),
        )
        .build()
        .err()
        .expect("must be refused");
    assert!(matches!(&err, ClError::Validation(t) if t.contains("not available for a database encrypted as a whole")), "{err:?}");
    assert!(!dir.exists() && !apart.exists(), "a refused build touched a file");
}
