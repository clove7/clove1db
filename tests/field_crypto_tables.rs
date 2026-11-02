//! A table remembers its protected fields; opening it with a different declaration is refused
//! and writes nothing.
use clove1db::{
    CloveFields, EncryptionConfig, KeySource,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    entity::Entity,
    field_crypto::{Hashed, Sealed, SealedFields, SearchPrint},
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize, CloveFields)]
struct Customer {
    id: String,
    name: String,
    #[clove(encrypt, id = 1)]
    phone: Sealed<String>,
    #[clove(hash = "argon2id", id = 2)]
    password: Hashed,
    #[clove(search_print, id = 3)]
    token: SearchPrint,
}
impl Entity for Customer {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// The same table with the phone declared with a full fingerprint.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize, CloveFields)]
struct CustomerPrinted {
    id: String,
    name: String,
    #[clove(encrypt, id = 1, print = "full")]
    phone: Sealed<String>,
    #[clove(hash = "argon2id", id = 2)]
    password: Hashed,
    #[clove(search_print, id = 3)]
    token: SearchPrint,
}
impl Entity for CustomerPrinted {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// The same table with nothing protected.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize, CloveFields)]
struct CustomerPlain {
    id: String,
    name: String,
    phone: String,
    password: String,
    token: String,
}
impl Entity for CustomerPlain {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// Under `--cfg clove_test_encrypt_all` every database starts encrypted as a whole.
fn config(dir: &Path) -> DatabaseConfig {
    DatabaseConfig::new("records", "store").dir_path(dir.to_path_buf()).has_cache(false)
}

/// Protected fields need the keys of an encrypted database.
fn enc() -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite { cipher: CipherKind::XChaCha20Poly1305, hkdf: HkdfHash::Sha256 },
        read: Some(KeySource::Raw(Key32::from_bytes(&[1; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[2; 32]))),
    }
}

fn open_sealed<E>(dir: &Path) -> clove1db::units::Result<Storage>
where
    E: Entity + Serialize + Default + SealedFields,
{
    Storage::builder(StorageConfig::default())
        .add_database(config(dir).encryption(enc()).register_sealed::<E>("customers"))
        .build()
}

/// The same encrypted database, with the table registered without protected fields.
fn open_plain_encrypted<E: Entity + Serialize + Default>(dir: &Path) -> clove1db::units::Result<Storage> {
    Storage::builder(StorageConfig::default())
        .add_database(config(dir).encryption(enc()).register::<E>("customers"))
        .build()
}

fn open_plain<E: Entity + Serialize + Default>(dir: &Path) -> clove1db::units::Result<Storage> {
    Storage::builder(StorageConfig::default())
        .add_database(config(dir).register::<E>("customers"))
        .build()
}

fn temp_dir() -> PathBuf {
    std::env::temp_dir().join(uuid::Uuid::new_v4().to_string())
}

fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn walk(dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push((path.clone(), std::fs::read(&path).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, &mut out);
    out
}

/// A refused open leaves every file as it was, except the main file, which redb itself changes on
/// every open (its size varies even when an open succeeds, with or without protected fields). The
/// main file's content is checked through the table description instead (`same_description`).
fn assert_untouched(before: &[(PathBuf, Vec<u8>)], after: &[(PathBuf, Vec<u8>)]) {
    assert_eq!(before.len(), after.len(), "files appeared or vanished");
    for ((path_a, a), (path_b, b)) in before.iter().zip(after) {
        assert_eq!(path_a, path_b);
        if path_a.extension().is_some_and(|e| e == "cldb") {
            continue;
        }
        assert!(a == b, "{} changed", path_a.display());
    }
}

/// The description of the table, as stored: identity, protected fields and layout.
fn description(s: &Storage) -> (Option<String>, Vec<clove1db::field_crypto::SealedField>, String) {
    let meta = table_meta(s);
    (meta.table_id, meta.sealed, meta.layout_hash)
}

fn table_meta(s: &Storage) -> clove1db::metadata::TableMeta {
    s.db_manager("store")
        .read_meta()
        .unwrap()
        .unwrap()
        .tables
        .into_iter()
        .find(|t| t.name == "customers")
        .unwrap()
}

#[test]
fn a_new_table_records_its_protected_fields_and_an_identity() {
    let dir = temp_dir();
    let meta = table_meta(&open_sealed::<Customer>(&dir).unwrap());
    let fields: Vec<_> = meta.sealed.iter().map(|f| (f.id, f.name.as_str(), f.method)).collect();
    assert_eq!(fields, [(1, "phone", 1), (2, "password", 4), (3, "token", 5)]);
    let id = meta.table_id.unwrap();
    assert_eq!(id.len(), 32);
    assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
}

#[test]
fn reopening_with_the_same_declaration_keeps_the_identity() {
    let dir = temp_dir();
    let first = table_meta(&open_sealed::<Customer>(&dir).unwrap());
    let second = table_meta(&open_sealed::<Customer>(&dir).unwrap());
    assert_eq!(first.table_id, second.table_id);
    assert_eq!(first.sealed, second.sealed);
}

#[test]
fn a_different_method_is_refused_and_nothing_is_written() {
    let dir = temp_dir();
    let described = description(&open_sealed::<Customer>(&dir).unwrap());
    let before = snapshot(&dir);
    let err = open_sealed::<CustomerPrinted>(&dir).err().expect("must be refused");
    match err {
        ClError::Validation(text) => {
            assert!(text.contains("migration") && text.contains("nothing was written"), "{text}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
    assert_untouched(&before, &snapshot(&dir));
    // The original declaration still opens, and the description is exactly what it was.
    assert_eq!(described, description(&open_sealed::<Customer>(&dir).unwrap()));
}

#[test]
fn removing_the_protection_of_a_table_is_refused() {
    let dir = temp_dir();
    let described = description(&open_sealed::<Customer>(&dir).unwrap());
    let before = snapshot(&dir);
    let err = open_plain_encrypted::<CustomerPlain>(&dir).err().expect("must be refused");
    assert!(matches!(err, ClError::Validation(ref t) if t.contains("migration")), "{err:?}");
    assert_untouched(&before, &snapshot(&dir));
    assert_eq!(described, description(&open_sealed::<Customer>(&dir).unwrap()));
}

#[test]
fn protecting_an_existing_table_that_holds_rows_is_refused() {
    let dir = temp_dir();
    {
        let storage = open_plain_encrypted::<CustomerPlain>(&dir).unwrap();
        let row = CustomerPlain { id: "c1".into(), name: "n".into(), phone: "p".into(), password: "w".into(), token: "t".into() };
        storage.domain::<CustomerPlain>().repo().set("c1", &row).unwrap();
        storage.close();
    }
    let described = description(&open_plain_encrypted::<CustomerPlain>(&dir).unwrap());
    let before = snapshot(&dir);
    let err = open_sealed::<Customer>(&dir).err().expect("must be refused");
    assert!(matches!(err, ClError::Validation(ref t) if t.contains("migration")), "{err:?}");
    assert_untouched(&before, &snapshot(&dir));
    // Still a table without protected fields, with no identity recorded.
    let after = description(&open_plain_encrypted::<CustomerPlain>(&dir).unwrap());
    assert_eq!(described, after);
    assert!(after.0.is_none() && after.1.is_empty());
}

#[test]
fn protecting_an_existing_table_that_is_empty_is_accepted_and_a_protected_value_survives_a_reopen() {
    let dir = temp_dir();
    // The table exists in the file, without rows and without protected fields.
    let plain = open_plain_encrypted::<CustomerPlain>(&dir).unwrap();
    assert!(description(&plain).1.is_empty());
    plain.close();
    {
        let storage = open_sealed::<Customer>(&dir).unwrap();
        let meta = table_meta(&storage);
        assert_eq!(meta.sealed.len(), 3);
        assert!(meta.table_id.is_some());
        let row = Customer { id: "c1".into(), name: "n".into(), phone: Sealed::new("+155500000001".into()), password: Hashed::new("pw"), ..Default::default() };
        storage.domain::<Customer>().repo().set("c1", &row).unwrap();
        storage.close();
    }
    let storage = open_sealed::<Customer>(&dir).unwrap();
    let domain = storage.domain::<Customer>();
    let row = domain.repo().get("c1").unwrap();
    assert_eq!(row.phone.open(&domain.read_grant().unwrap()).unwrap(), "+155500000001");
}

#[test]
fn protecting_an_emptied_table_whose_backup_still_holds_old_versions_is_refused() {
    let dir = temp_dir();
    let with_backup = || config(&dir).backup_enabled(true).encryption(enc());
    {
        let storage = Storage::builder(StorageConfig::default()).add_database(with_backup().register::<CustomerPlain>("customers")).build().unwrap();
        let row = CustomerPlain { id: "r1".into(), name: "n".into(), phone: "+155-PLAIN-PHONE".into(), password: "pw".into(), token: "t".into() };
        storage.domain::<CustomerPlain>().repo().set("r1", &row).unwrap();
        // The table is empty now, but its backup file still holds the plain versions.
        storage.domain::<CustomerPlain>().repo().delete("r1").unwrap();
        storage.close();
    }
    let reopen = |plain: bool| {
        let config = if plain { with_backup().register::<CustomerPlain>("customers") } else { with_backup().register_sealed::<Customer>("customers") };
        Storage::builder(StorageConfig::default()).add_database(config).build()
    };
    let described = description(&reopen(true).unwrap());
    let before = snapshot(&dir);
    let err = reopen(false).err().expect("must be refused");
    assert!(matches!(err, ClError::Validation(ref t) if t.contains("migration")), "{err:?}");
    assert_untouched(&before, &snapshot(&dir));
    let after = description(&reopen(true).unwrap());
    assert_eq!(described, after);
    assert!(after.0.is_none() && after.1.is_empty());
}

#[test]
fn a_migration_step_over_an_entity_with_protected_fields_is_a_clear_error_not_a_panic() {
    use clove1db::migration::MigrationStepRegistry;
    // The step registry captures the layout of each side from a default value; a default value of
    // an entity with protected fields cannot be serialized outside the storage, and says so.
    for err in [
        MigrationStepRegistry::layout_pair::<Customer, CustomerPlain>().unwrap_err(),
        MigrationStepRegistry::layout_pair::<CustomerPlain, Customer>().unwrap_err(),
        MigrationStepRegistry::layout_pair::<Customer, CustomerPrinted>().unwrap_err(),
    ] {
        let text = err.to_string();
        assert!(text.contains("can only be serialized by the storage"), "{text}");
    }
    // Two entities without protected fields still work.
    assert!(MigrationStepRegistry::layout_pair::<CustomerPlain, CustomerPlain>().is_ok());
}

#[test]
fn a_table_without_protected_fields_is_described_exactly_as_before() {
    let dir = temp_dir();
    let meta = table_meta(&open_plain::<CustomerPlain>(&dir).unwrap());
    assert!(meta.sealed.is_empty() && meta.table_id.is_none());
    let text = serde_json::to_string(&meta).unwrap();
    assert!(!text.contains("sealed") && !text.contains("table_id"), "{text}");
}

#[test]
fn a_new_protected_value_is_never_written_by_a_plain_registration() {
    let dir = temp_dir();
    let storage = open_plain::<Customer>(&dir).unwrap();
    let customer = Customer { id: "c1".into(), name: "n".into(), phone: Sealed::new("+155500000001".into()), ..Default::default() };
    // `Customer` was registered without `register_sealed`: the write is refused, not stored as text.
    let err = storage.domain::<Customer>().repo().set("c1", &customer).unwrap_err();
    assert!(err.to_string().contains("can only be serialized by the storage"), "{err}");
    assert!(storage.domain::<Customer>().repo().get("c1").is_err());
    drop(storage);
    for (path, bytes) in snapshot(&dir) {
        let hay = String::from_utf8_lossy(&bytes);
        assert!(!hay.contains("155500000001"), "{}", path.display());
    }
}
