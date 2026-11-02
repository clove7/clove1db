//! A database that already exists gets a table with protected fields: "new" is judged for each
//! table, and the keys are made when the file holds no protected table yet.
use clove1db::{
    CloveFields, EncryptionConfig, KeySource,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    entity::Entity,
    field_crypto::{Hashed, Sealed, SealedFields},
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A table with nothing protected.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize, CloveFields)]
struct Item {
    id: String,
    name: String,
    phone: String,
    password: String,
}
impl Entity for Item {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// The same table once its phone is protected.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize, CloveFields)]
struct Customer {
    id: String,
    name: String,
    #[clove(encrypt, id = 1)]
    phone: Sealed<String>,
    #[clove(hash = "argon2id", id = 2)]
    password: Hashed,
}
impl Entity for Customer {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// A second table with protected fields.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize, CloveFields)]
struct Secret {
    id: String,
    #[clove(encrypt, id = 1)]
    value: Sealed<String>,
}
impl Entity for Secret {
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

fn search_only() -> EncryptionConfig {
    EncryptionConfig { read: None, ..keys() }
}

fn base(dir: &Path) -> DatabaseConfig {
    DatabaseConfig::new("records", "store").dir_path(dir.to_path_buf()).has_cache(false).backup_enabled(true)
}

fn build(config: DatabaseConfig) -> clove1db::units::Result<Storage> {
    Storage::builder(StorageConfig::default()).add_database(config).build()
}

fn temp_dir() -> PathBuf {
    std::env::temp_dir().join(uuid::Uuid::new_v4().to_string())
}

/// Every file under `dir` joined, to look for text that must not be there.
fn all_bytes(dir: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    fn walk(dir: &Path, out: &mut Vec<u8>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.extend(std::fs::read(&path).unwrap());
            }
        }
    }
    walk(dir, &mut out);
    out
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle.as_bytes())
}

/// Plain database with one table, holding `rows` rows, closed.
fn make_plain(dir: &Path, rows: usize) {
    let s = build(base(dir).register::<Item>("customers")).unwrap();
    for i in 0..rows {
        s.domain::<Item>().repo().set(&format!("i{i}"), &Item { id: format!("i{i}"), name: "n".into(), ..Default::default() }).unwrap();
    }
    s.close();
}

fn customer(id: &str, phone: &str) -> Customer {
    Customer { id: id.into(), name: "visible".into(), phone: Sealed::new(phone.into()), password: Hashed::new("pw-one") }
}

fn read_phone(s: &Storage, id: &str) -> String {
    let domain = s.domain::<Customer>();
    let row = domain.repo().get(id).unwrap();
    row.phone.open(&domain.read_grant().unwrap()).unwrap()
}

fn open_sealed<E: Entity + Serialize + Default + SealedFields>(
    dir: &Path,
    enc: EncryptionConfig,
    table: &'static str,
) -> clove1db::units::Result<Storage> {
    build(base(dir).field_encryption(enc).register_sealed::<E>(table))
}

#[test]
fn first_protected_table_of_a_plain_database() {
    let dir = temp_dir();
    make_plain(&dir, 0);
    assert!(!contains(&all_bytes(&dir), "__field_keys"));

    // the table exists, is empty, and has no stored description of protected fields: it is new
    let s = open_sealed::<Customer>(&dir, keys(), "customers").unwrap();
    s.domain::<Customer>().repo().set("c1", &customer("c1", "+15550000001")).unwrap();
    s.close();

    let s = open_sealed::<Customer>(&dir, keys(), "customers").unwrap();
    assert_eq!(read_phone(&s, "c1"), "+15550000001");
    let row = s.domain::<Customer>().repo().get("c1").unwrap();
    assert!(row.password.verify("pw-one", &s.domain::<Customer>().verifier().unwrap()).unwrap());
    s.close();
    assert!(!contains(&all_bytes(&dir), "+15550000001"), "the value is on disk in clear");
}

#[test]
fn a_table_with_rows_is_still_refused_and_nothing_is_written() {
    let dir = temp_dir();
    make_plain(&dir, 3);
    let before = std::fs::read_dir(dir.join("records")).unwrap().count();

    let err = open_sealed::<Customer>(&dir, keys(), "customers").err().expect("must be refused");
    assert!(err.to_string().contains("already exists"), "{err}");
    assert_eq!(std::fs::read_dir(dir.join("records")).unwrap().count(), before, "a file was created");
    assert!(!contains(&all_bytes(&dir), "__field_keys"), "keys were written");

    // still a plain database with its rows
    let s = build(base(&dir).register::<Item>("customers")).unwrap();
    assert_eq!(s.domain::<Item>().repo().get("i2").unwrap().name, "n");
}


#[test]
fn only_the_search_key_cannot_create_a_protected_table() {
    let dir = temp_dir();
    make_plain(&dir, 0);
    let err = open_sealed::<Customer>(&dir, search_only(), "customers").err().expect("must be refused");
    assert!(err.to_string().contains("read key"), "{err}");
    assert!(!contains(&all_bytes(&dir), "__field_keys"), "keys were written");
    // the database is as it was
    assert!(build(base(&dir).register::<Item>("customers")).is_ok());
}

#[test]
fn a_leftover_keys_file_is_replaced_when_the_database_holds_no_protected_table() {
    // a keys file from an attempt that stopped before its first write
    let other = temp_dir();
    open_sealed::<Customer>(&other, keys(), "customers").unwrap().close();
    let stale = std::fs::read(other.join("records").join("store.keys")).unwrap();

    let dir = temp_dir();
    make_plain(&dir, 0);
    std::fs::write(dir.join("records").join("store.keys"), &stale).unwrap();

    let s = open_sealed::<Customer>(&dir, keys(), "customers").unwrap();
    s.domain::<Customer>().repo().set("c1", &customer("c1", "+15550000002")).unwrap();
    s.close();
    let s = open_sealed::<Customer>(&dir, keys(), "customers").unwrap();
    assert_eq!(read_phone(&s, "c1"), "+15550000002");
    assert_ne!(std::fs::read(dir.join("records").join("store.keys")).unwrap(), stale);
}

#[test]
fn an_external_keys_file_with_a_new_protected_table() {
    let dir = temp_dir();
    let keys_file = temp_dir().join("outside.keys");
    make_plain(&dir, 0);

    let s = build(base(&dir).field_encryption(keys()).field_keys_file(&keys_file).register_sealed::<Customer>("customers")).unwrap();
    s.domain::<Customer>().repo().set("c1", &customer("c1", "+15550000003")).unwrap();
    s.close();
    assert!(keys_file.is_file());
    let s = build(base(&dir).field_encryption(keys()).field_keys_file(&keys_file).register_sealed::<Customer>("customers")).unwrap();
    assert_eq!(read_phone(&s, "c1"), "+15550000003");
}

#[test]
fn the_whole_database_encrypted_gets_a_protected_table() {
    let dir = temp_dir();
    let s = build(base(&dir).encryption(keys()).register::<Item>("customers")).unwrap();
    s.close();
    let s = build(base(&dir).encryption(keys()).register_sealed::<Customer>("customers")).unwrap();
    s.domain::<Customer>().repo().set("c1", &customer("c1", "+15550000004")).unwrap();
    s.close();
    let s = build(base(&dir).encryption(keys()).register_sealed::<Customer>("customers")).unwrap();
    assert_eq!(read_phone(&s, "c1"), "+15550000004");
}
/// A table that is added later, nothing protected in it.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize, CloveFields)]
struct Note {
    id: String,
    text: String,
}
impl Entity for Note {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn watched(config: DatabaseConfig) -> (clove1db::units::Result<Storage>, std::sync::Arc<std::sync::Mutex<Vec<(String, Vec<String>)>>>) {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = seen.clone();
    let cfg = StorageConfig::default().event_sink(move |e| {
        if let clove1db::LibraryEvent::TablesCreated { database, tables } = e {
            sink.lock().unwrap().push((database.clone(), tables.clone()));
        }
    });
    (Storage::builder(cfg).add_database(config).build(), seen)
}

#[test]
fn a_missing_table_is_refused_unless_asked_for() {
    let dir = temp_dir();
    make_plain(&dir, 1);
    let err = build(base(&dir).register::<Item>("customers").register::<Note>("notes")).err().expect("refused");
    assert!(matches!(err, ClError::TableMismatch { .. }), "{err:?}");
    assert!(err.to_string().contains("create_missing_tables"), "{err}");
    // the explicit `false` is the same
    assert!(build(base(&dir).create_missing_tables(false).register::<Item>("customers").register::<Note>("notes")).is_err());
}

#[test]
fn a_missing_table_is_created_with_the_option_and_reported() {
    for whole in [false, true] {
        let dir = temp_dir();
        let first = if whole { base(&dir).encryption(keys()) } else { base(&dir) };
        let s = build(first.register::<Item>("customers")).unwrap();
        s.domain::<Item>().repo().set("i1", &Item { id: "i1".into(), name: "kept".into(), ..Default::default() }).unwrap();
        s.close();

        let again = if whole { base(&dir).encryption(keys()) } else { base(&dir) };
        let (s, seen) = watched(again.create_missing_tables(true).register::<Item>("customers").register::<Note>("notes"));
        let s = s.unwrap();
        assert_eq!(*seen.lock().unwrap(), vec![("store".to_string(), vec!["notes".to_string()])], "whole={whole}");
        s.domain::<Note>().repo().set("n1", &Note { id: "n1".into(), text: "hello".into() }).unwrap();
        s.domain::<Note>().repo().set("n1", &Note { id: "n1".into(), text: "hello again".into() }).unwrap();
        s.close();

        let again = if whole { base(&dir).encryption(keys()) } else { base(&dir) };
        let (s, seen) = watched(again.create_missing_tables(true).register::<Item>("customers").register::<Note>("notes"));
        let s = s.unwrap();
        assert!(seen.lock().unwrap().is_empty(), "nothing is created the second time");
        assert_eq!(s.domain::<Note>().repo().get("n1").unwrap().text, "hello again");
        assert_eq!(s.domain::<Item>().repo().get("i1").unwrap().name, "kept");
        // the history of the new table works: the older version is there
        assert!(s.domain::<Note>().history("n1").map(|v| !v.is_empty()).unwrap_or(false), "whole={whole}");
    }
}

#[test]
fn a_new_protected_table_in_a_database_that_has_none_of_it_yet() {
    for whole in [false, true] {
        let dir = temp_dir();
        let first = if whole { base(&dir).encryption(keys()) } else { base(&dir) };
        build(first.register::<Note>("notes")).unwrap().close();

        let open = |dir: &Path| {
            let c = base(dir).create_missing_tables(true).register::<Note>("notes").register_sealed::<Secret>("secrets");
            build(if whole { c.encryption(keys()) } else { c.field_encryption(keys()) })
        };
        let s = open(&dir).unwrap();
        s.domain::<Secret>().repo().set("s1", &Secret { id: "s1".into(), value: Sealed::new("top-value-77".into()) }).unwrap();
        s.close();
        let s = open(&dir).unwrap();
        let domain = s.domain::<Secret>();
        let row = domain.repo().get("s1").unwrap();
        assert_eq!(row.value.open(&domain.read_grant().unwrap()).unwrap(), "top-value-77");
        s.close();
        assert!(!contains(&all_bytes(&dir), "top-value-77"), "the value is on disk in clear (whole={whole})");
    }
}
