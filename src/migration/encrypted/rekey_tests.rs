//! Changing the keys of a database that has protected fields: another cipher, other keys, and both,
//! with the verification hash and the search fingerprint still working afterwards.
use super::run::ChangeProtection;
use crate::{
    CloveFields,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    encrypted_store::{EncryptionConfig, KeySource},
    entity::Entity,
    field_crypto::{Hashed, Sealed, SearchPrint},
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const PHONE: &str = "+155-REKEY-PHONE-";
const PASSWORD: &str = "REKEY-SECRET-PASSWORD";
const EMAIL: &str = "rekey.mail@example.test";
const ORDINARY: &str = "REKEY-VISIBLE-";

#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Account {
    id: String,
    name: String,
    #[clove(encrypt, id = 1)]
    phone: Sealed<String>,
    #[clove(hash = "argon2id", id = 2)]
    password: Hashed,
    #[clove(search_print, id = 3)]
    email: SearchPrint,
}
impl Entity for Account {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn account(i: usize, version: usize) -> Account {
    Account {
        id: format!("a{i:02}"),
        name: format!("{ORDINARY}{i}"),
        phone: Sealed::new(format!("{PHONE}{i}-v{version}")),
        password: Hashed::new(PASSWORD),
        email: SearchPrint::new(EMAIL),
    }
}

fn keys(read: u8, cipher: CipherKind) -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite { cipher, hkdf: HkdfHash::Sha256 },
        read: Some(KeySource::Raw(Key32::from_bytes(&[read; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[read.wrapping_add(1); 32]))),
    }
}

fn aes(read: u8) -> EncryptionConfig {
    keys(read, CipherKind::Aes256GcmSiv)
}

fn xchacha(read: u8) -> EncryptionConfig {
    keys(read, CipherKind::XChaCha20Poly1305)
}

fn open(root: &Path, protection: EncryptionConfig) -> crate::units::Result<Storage> {
    Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("records", "store")
                .dir_path(root.to_path_buf())
                .has_cache(false)
                .backup_enabled(true)
                .encryption(protection)
                .register_sealed::<Account>("accounts"),
        )
        .build()
}

/// A database with `rows` accounts, each written twice (so the history holds both versions).
fn make(protection: EncryptionConfig, rows: usize) -> PathBuf {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = open(&root, protection).unwrap();
    let repo = s.domain::<Account>().repo();
    for i in 0..rows {
        repo.set(&format!("a{i:02}"), &account(i, 1)).unwrap();
        repo.set(&format!("a{i:02}"), &account(i, 2)).unwrap();
    }
    drop(repo);
    s.close();
    root
}

fn change(root: &Path, from: EncryptionConfig, to: EncryptionConfig) -> crate::units::Result<super::run::ChangeDone> {
    ChangeProtection::new(root, "records", "store")
        .from_whole_database(from)
        .to_whole_database(to)
        .protected_table::<Account>("accounts")
        .execute()
}

/// Everything the database holds reads back as it was: the sealed value, the hash, the fingerprint.
fn check(root: &Path, protection: EncryptionConfig, rows: usize, version: usize) {
    let s = open(root, protection).unwrap();
    let domain = s.domain::<Account>();
    let grant = domain.read_grant().unwrap();
    let verifier = domain.verifier().unwrap();
    assert_eq!(domain.repo().list().unwrap().len(), rows);
    for i in 0..rows {
        let row = domain.repo().get(&format!("a{i:02}")).unwrap();
        assert_eq!(row.name, format!("{ORDINARY}{i}"));
        assert_eq!(row.phone.open(&grant).unwrap(), format!("{PHONE}{i}-v{version}"));
        assert!(row.password.verify(PASSWORD, &verifier).unwrap(), "the old password no longer verifies");
        assert!(!row.password.verify("not the password", &verifier).unwrap());
        assert!(row.email.matches(EMAIL, &verifier).unwrap(), "the fingerprint no longer matches");
        assert!(!row.email.matches("someone.else@example.test", &verifier).unwrap());
    }
    drop(domain);
    s.close();
}

#[test]
fn another_cipher_keeps_the_values_the_hash_and_the_fingerprint() {
    let root = make(aes(1), 12);
    let done = change(&root, aes(1), xchacha(1)).unwrap();
    assert!(done.rows > 0);
    check(&root, xchacha(1), 12, 2);
    // the old keys no longer open it
    assert!(matches!(open(&root, aes(1)).err(), Some(ClError::EncryptedOpenFailed)));
}

#[test]
fn other_keys_carry_the_hash_and_the_fingerprint_over_and_a_second_change_carries_them_again() {
    let root = make(aes(1), 8);
    change(&root, aes(1), aes(5)).unwrap();
    check(&root, aes(5), 8, 2);
    assert!(matches!(open(&root, aes(1)).err(), Some(ClError::EncryptedOpenFailed)));
    // a second change: the carried keys move on to the third roots
    change(&root, aes(5), xchacha(9)).unwrap();
    check(&root, xchacha(9), 8, 2);
    // and a write after the changes is verified and found like the rest
    let s = open(&root, xchacha(9)).unwrap();
    let repo = s.domain::<Account>().repo();
    repo.set("late", &account(99, 3)).unwrap();
    let domain = s.domain::<Account>();
    let verifier = domain.verifier().unwrap();
    let row = domain.repo().get("late").unwrap();
    assert!(row.password.verify(PASSWORD, &verifier).unwrap());
    assert!(row.email.matches(EMAIL, &verifier).unwrap());
    drop(domain);
    drop(repo);
    s.close();
}

/// The same fields, in a table whose rows carry an attachment.
#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Dossier {
    id: String,
    name: String,
    #[clove(encrypt, id = 1)]
    phone: Sealed<String>,
    #[clove(search_print, id = 3)]
    email: SearchPrint,
}
impl Entity for Dossier {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn open_files(root: &Path, protection: EncryptionConfig) -> crate::units::Result<Storage> {
    Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("records", "store")
                .dir_path(root.to_path_buf())
                .has_cache(false)
                .blob_enabled(true)
                .encryption(protection)
                .register_sealed_blob::<Dossier>("dossiers"),
        )
        .build()
}

fn attachment(i: usize) -> Vec<u8> {
    let mut v = b"REKEY-ATTACHMENT-MARKER-".to_vec();
    v.extend((0..(20_000 * (i + 1))).map(|k| (k % 251) as u8));
    v
}

#[test]
fn the_attachments_of_protected_tables_are_sealed_again_under_new_names() {
    use std::io::Read;
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = open_files(&root, aes(1)).unwrap();
    let repo = s.domain::<Dossier>().repo();
    for i in 0..3 {
        let d = Dossier {
            id: format!("d{i}"),
            name: format!("{ORDINARY}{i}"),
            phone: Sealed::new(format!("{PHONE}{i}")),
            email: SearchPrint::new(EMAIL),
        };
        repo.set_with_blob(&d.id, &d, &attachment(i)).unwrap();
    }
    drop(repo);
    s.close();
    drop(s);
    let names = |root: &Path| {
        let mut all = Vec::new();
        files(root, &mut all);
        let mut n: Vec<String> = all
            .iter()
            .filter(|p| p.to_string_lossy().contains(".pblobs"))
            .map(|p| p.strip_prefix(root).unwrap().to_string_lossy().into_owned())
            .collect();
        n.sort();
        n
    };
    let before = names(&root);
    assert_eq!(before.len(), 3, "{before:?}");
    ChangeProtection::new(&root, "records", "store")
        .from_whole_database(aes(1))
        .to_whole_database(xchacha(7))
        .protected_table::<Dossier>("dossiers")
        .execute()
        .unwrap();
    let after = names(&root);
    assert_eq!(after.len(), 3, "{after:?}");
    assert!(before.iter().all(|b| !after.contains(b)), "a file kept its old name: {before:?} {after:?}");
    let s = open_files(&root, xchacha(7)).unwrap();
    let repo = s.domain::<Dossier>().repo();
    for i in 0..3 {
        let mut out = Vec::new();
        repo.open_blob(&format!("d{i}")).unwrap().read_to_end(&mut out).unwrap();
        assert_eq!(out, attachment(i));
    }
    drop(repo);
    s.close();
}

/// A database that is not encrypted as a whole and whose protected fields have keys of their own.
fn open_fields(root: &Path, protection: EncryptionConfig, keys_file: Option<&Path>) -> crate::units::Result<Storage> {
    let db = DatabaseConfig::new("records", "store").dir_path(root.to_path_buf()).has_cache(false).backup_enabled(true);
    // under the test build that encrypts every database as a whole, this one asks to stay plain
    #[cfg(clove_test_encrypt_all)]
    let db = db.plain();
    let mut db = db.field_encryption(protection).register_sealed::<Account>("accounts");
    if let Some(file) = keys_file {
        db = db.field_keys_file(file);
    }
    Storage::builder(StorageConfig::default()).add_database(db).build()
}

fn make_fields(protection: EncryptionConfig, rows: usize, keys_file: Option<&Path>) -> PathBuf {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = open_fields(&root, protection, keys_file).unwrap();
    let repo = s.domain::<Account>().repo();
    for i in 0..rows {
        repo.set(&format!("a{i:02}"), &account(i, 1)).unwrap();
        repo.set(&format!("a{i:02}"), &account(i, 2)).unwrap();
    }
    drop(repo);
    s.close();
    root
}

fn check_fields(root: &Path, protection: EncryptionConfig, keys_file: Option<&Path>, rows: usize) {
    let s = open_fields(root, protection, keys_file).unwrap();
    let domain = s.domain::<Account>();
    let grant = domain.read_grant().unwrap();
    let verifier = domain.verifier().unwrap();
    assert_eq!(domain.repo().list().unwrap().len(), rows);
    for i in 0..rows {
        let row = domain.repo().get(&format!("a{i:02}")).unwrap();
        assert_eq!(row.phone.open(&grant).unwrap(), format!("{PHONE}{i}-v2"));
        assert!(row.password.verify(PASSWORD, &verifier).unwrap());
        assert!(row.email.matches(EMAIL, &verifier).unwrap());
    }
    drop(domain);
    s.close();
}

#[test]
fn field_keys_of_a_plain_database_change_and_the_hash_and_the_fingerprint_go_with_them() {
    let root = make_fields(aes(1), 6, None);
    ChangeProtection::new(&root, "records", "store")
        .from_field_keys(aes(1))
        .to_field_keys(xchacha(7))
        .protected_table::<Account>("accounts")
        .execute()
        .unwrap();
    check_fields(&root, xchacha(7), None, 6);
    assert!(matches!(open_fields(&root, aes(1), None).err(), Some(ClError::EncryptedOpenFailed)));
    // a second change carries the keys on
    ChangeProtection::new(&root, "records", "store")
        .from_field_keys(xchacha(7))
        .to_field_keys(aes(11))
        .protected_table::<Account>("accounts")
        .execute()
        .unwrap();
    check_fields(&root, aes(11), None, 6);
}

#[test]
fn a_wrong_old_field_key_is_refused_and_the_files_are_untouched() {
    let root = make_fields(aes(1), 3, None);
    let read_all = |root: &Path| {
        let mut all = Vec::new();
        files(root, &mut all);
        all.sort();
        all.iter().map(|p| std::fs::read(p).unwrap()).collect::<Vec<_>>()
    };
    let before = read_all(&root);
    let err = ChangeProtection::new(&root, "records", "store")
        .from_field_keys(aes(9))
        .to_field_keys(xchacha(7))
        .protected_table::<Account>("accounts")
        .execute()
        .err()
        .expect("must be refused");
    assert!(matches!(err, ClError::EncryptedOpenFailed), "{err:?}");
    assert!(before == read_all(&root), "a refused change touched a file");
    check_fields(&root, aes(1), None, 3);
}

#[test]
fn a_database_that_keeps_its_lock_in_a_keys_file_elsewhere_is_refused_and_untouched() {
    // made with `field_keys_file`: its main file has no lock of the data key, and a new data key made
    // for it would not open its fields
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let file = root.join("outside.keys");
    {
        let s = open_fields(&root, aes(1), Some(&file)).unwrap();
        let repo = s.domain::<Account>().repo();
        for i in 0..4 {
            repo.set(&format!("a{i:02}"), &account(i, 2)).unwrap();
        }
        drop(repo);
        s.close();
    }
    let read_all = |root: &Path| {
        let mut all = Vec::new();
        files(root, &mut all);
        all.sort();
        all.iter().map(|p| std::fs::read(p).unwrap()).collect::<Vec<_>>()
    };
    let before = read_all(&root);
    let err = ChangeProtection::new(&root, "records", "store")
        .from_field_keys(aes(1))
        .to_field_keys(xchacha(7))
        .protected_table::<Account>("accounts")
        .execute()
        .err()
        .expect("must be refused");
    assert!(matches!(&err, ClError::Validation(t) if t.contains("outside the main file")), "{err:?}");
    assert!(before == read_all(&root), "a refused change touched a file");
    check_fields(&root, aes(1), Some(&file), 4);
}

#[test]
fn from_whole_database_to_field_keys_and_back() {
    let root = make(aes(1), 5);
    ChangeProtection::new(&root, "records", "store")
        .from_whole_database(aes(1))
        .to_field_keys(xchacha(7))
        .protected_table::<Account>("accounts")
        .execute()
        .unwrap();
    check_fields(&root, xchacha(7), None, 5);
    ChangeProtection::new(&root, "records", "store")
        .from_field_keys(xchacha(7))
        .to_whole_database(aes(3))
        .protected_table::<Account>("accounts")
        .execute()
        .unwrap();
    check(&root, aes(3), 5, 2);
}

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().filter_map(|e| e.ok()) {
        if e.path().is_dir() {
            files(&e.path(), out);
        } else {
            out.push(e.path());
        }
    }
}

fn has(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

#[test]
fn the_history_is_moved_too_and_a_restored_version_opens_and_verifies() {
    let root = make(aes(1), 4);
    change(&root, aes(1), xchacha(7)).unwrap();
    let s = open(&root, xchacha(7)).unwrap();
    let domain = s.domain::<Account>();
    domain.restore_by_version("a02", 1).unwrap();
    let grant = domain.read_grant().unwrap();
    let verifier = domain.verifier().unwrap();
    let row = domain.repo().get("a02").unwrap();
    assert_eq!(row.phone.open(&grant).unwrap(), format!("{PHONE}2-v1"));
    assert!(row.password.verify(PASSWORD, &verifier).unwrap());
    assert!(row.email.matches(EMAIL, &verifier).unwrap());
    drop(domain);
    s.close();
}

#[test]
fn no_clear_value_and_no_old_file_stays_in_the_folder() {
    let root = make(aes(1), 6);
    change(&root, aes(1), xchacha(7)).unwrap();
    let mut all = Vec::new();
    files(&root, &mut all);
    assert!(all.iter().any(|p| p.to_string_lossy().ends_with(".keys")), "{all:?}");
    for path in &all {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        assert!(!name.contains(".mig-"), "a file of the change is left: {name}");
        let bytes = std::fs::read(path).unwrap();
        for secret in [PHONE, PASSWORD, EMAIL, ORDINARY, "REKEY-"] {
            assert!(!has(&bytes, secret), "{name} holds {secret}");
        }
    }
}

#[test]
fn a_wrong_old_key_is_refused_and_the_files_are_untouched() {
    let root = make(aes(1), 3);
    let before: Vec<Vec<u8>> = {
        let mut all = Vec::new();
        files(&root, &mut all);
        all.sort();
        all.iter().map(|p| std::fs::read(p).unwrap()).collect()
    };
    let err = change(&root, aes(9), xchacha(7)).err().expect("must be refused");
    assert!(matches!(err, ClError::EncryptedOpenFailed), "{err:?}");
    let after: Vec<Vec<u8>> = {
        let mut all = Vec::new();
        files(&root, &mut all);
        all.sort();
        all.iter().map(|p| std::fs::read(p).unwrap()).collect()
    };
    assert!(before == after, "a refused change touched a file");
    check(&root, aes(1), 3, 2);
}

#[test]
fn a_database_with_protected_fields_is_not_taken_to_or_from_plain_files() {
    let root = make(aes(1), 2);
    let err = ChangeProtection::new(&root, "records", "store")
        .from_whole_database(aes(1))
        .to_plain()
        .protected_table::<Account>("accounts")
        .execute()
        .err()
        .expect("must be refused");
    assert!(matches!(&err, ClError::MigrationError(t) if t.contains("protected fields")), "{err:?}");
    check(&root, aes(1), 2, 2);
}

#[test]
fn a_carried_key_that_was_changed_in_the_new_file_fails_the_open() {
    use crate::{encrypted_store::EncryptionHandle, field_crypto::carried, handle::RedbOptions};
    use redb::ReadableTable;
    let root = make(aes(1), 3);
    change(&root, aes(1), xchacha(7)).unwrap();
    let main = root.join("records").join("store.cldb");
    {
        let opener = RedbOptions { encryption: Some(EncryptionHandle::new(xchacha(7))), ..RedbOptions::default() };
        let (db, _) = opener.open_timed(&main, false, "main").unwrap();
        let tx = db.begin_write().unwrap();
        {
            let mut table = tx.open_table(carried::TABLE).unwrap();
            let (name, mut stored) = {
                let first = table.iter().unwrap().next().expect("an entry").unwrap();
                (first.0.value().to_string(), first.1.value().to_vec())
            };
            let last = stored.len() - 1;
            stored[last] ^= 0x01;
            table.insert(name.as_str(), stored.as_slice()).unwrap();
        }
        tx.commit().unwrap();
    }
    let err = open(&root, xchacha(7)).err().expect("a changed carried key must fail the open");
    assert!(matches!(err, ClError::DataTampered), "{err:?}");
}

#[test]
fn a_table_with_protected_fields_that_is_not_named_is_refused_and_nothing_changes() {
    let root = make(aes(1), 3);
    let err = ChangeProtection::new(&root, "records", "store")
        .from_whole_database(aes(1))
        .to_whole_database(aes(5))
        .execute()
        .err()
        .expect("must be refused");
    assert!(matches!(&err, ClError::MigrationError(t) if t.contains("did not declare")), "{err:?}");
    check(&root, aes(1), 3, 2);
}
