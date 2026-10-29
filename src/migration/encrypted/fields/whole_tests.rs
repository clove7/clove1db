//! Changing how the fields of a table are protected in a database that is encrypted as a whole: the
//! new files are made with the same data key as the old ones (the one handle opens the old main file
//! and makes the new files), so what the change does not touch stays the very bytes it was and the
//! keys of every hash and fingerprint are still the ones they were made with.
use super::api::ChangeFields;
use crate::{
    CloveFields,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite, LockedDataKey},
    encrypted_store::{EncryptionConfig, EncryptionHandle, KeySource},
    entity::Entity,
    field_crypto::{Hashed, Sealed},
    handle::RedbOptions,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use redb::TableDefinition;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Plain {
    id: String,
    name: String,
    phone: String,
    password: String,
}
impl Entity for Plain {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

macro_rules! entity {
    ($name:ident { $($body:tt)* }) => {
        #[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
        struct $name {
            id: String,
            name: String,
            $($body)*
        }
        impl Entity for $name {
            fn entity_id(&self) -> &str {
                &self.id
            }
        }
    };
}

entity!(Sealed1 {
    #[clove(encrypt, id = 1)]
    phone: Sealed<String>,
    password: String,
});
entity!(Printed1 {
    #[clove(encrypt, id = 1, print = "full")]
    phone: Sealed<String>,
    password: String,
});
entity!(Hashed2 {
    #[clove(encrypt, id = 1, print = "full")]
    phone: Sealed<String>,
    #[clove(hash = "argon2id", id = 2)]
    password: Hashed,
});

const SECRET: &str = "swordfish-marker-7731";
const PHONE_MARK: &[u8] = b"+1555000000";

fn keys(read: u8) -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite {
            cipher: if read % 2 == 0 { CipherKind::Aes256GcmSiv } else { CipherKind::XChaCha20Poly1305 },
            hkdf: HkdfHash::Sha256,
        },
        read: Some(KeySource::Raw(Key32::from_bytes(&[read; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[read.wrapping_add(1); 32]))),
    }
}

fn whole_db(root: &Path, protection: EncryptionConfig) -> DatabaseConfig {
    DatabaseConfig::new("records", "store")
        .dir_path(root.to_path_buf())
        .has_cache(false)
        .backup_enabled(true)
        .encryption(protection)
}

/// A database encrypted as a whole, of `rows` people, each written twice (so there is a history).
fn make(rows: usize, protection: EncryptionConfig) -> PathBuf {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = Storage::builder(StorageConfig::default()).add_database(whole_db(&root, protection).register::<Plain>("people")).build().unwrap();
    let m = s.db_manager("store");
    for i in 0..rows {
        for round in 0..2 {
            let row = serde_json::json!({
                "id": format!("p{i}"), "name": format!("{SECRET}-{i}"),
                "phone": format!("+1555000000{i:02}"), "password": format!("pw-{i}-{round}"),
            });
            m.set(TableDefinition::new("people"), "people", &format!("p{i}"), serde_json::to_vec(&row).unwrap()).unwrap();
        }
    }
    drop(m);
    s.close();
    root
}

fn open_with<E: Entity + Serialize + Default + crate::field_crypto::SealedFields>(root: &Path, protection: EncryptionConfig) -> crate::units::Result<Storage> {
    Storage::builder(StorageConfig::default()).add_database(whole_db(root, protection).register_sealed::<E>("people")).build()
}

fn change(root: &Path) -> ChangeFields {
    ChangeFields::new(root, "records", "store")
}

/// The lock of the data key the main file holds, as the one handle that opens it reads it.
fn lock_of(root: &Path, protection: EncryptionConfig) -> LockedDataKey {
    let handle = EncryptionHandle::new(protection);
    let options = RedbOptions { encryption: Some(handle.clone()), ..RedbOptions::default() };
    let main = root.join("records").join("store.cldb");
    let _db = options.open_read_only_timed(&main, "main").0.unwrap();
    handle.context().expect("the main file unlocked the data key").locked_data_key().clone()
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().filter_map(|e| e.ok()) {
        if e.path().is_dir() {
            walk(&e.path(), out);
        } else {
            out.push(e.path());
        }
    }
}

fn listing(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    walk(root, &mut files);
    let mut v: Vec<_> = files.iter().map(|p| (p.strip_prefix(root).unwrap().display().to_string(), std::fs::read(p).unwrap())).collect();
    v.sort();
    v
}

fn in_files(root: &Path, needle: &[u8]) -> Vec<String> {
    listing(root).into_iter().filter(|(_, b)| b.windows(needle.len()).any(|w| w == needle)).map(|(n, _)| n).collect()
}

fn nothing_left_over(root: &Path) {
    for (name, _) in listing(root) {
        assert!(!name.contains(".mig-") && !name.contains(".migrating") && !name.contains(".creating"), "left behind: {name}");
    }
}

#[test]
fn a_field_is_sealed_in_a_database_encrypted_as_a_whole_and_the_data_key_is_the_same() {
    let root = make(5, keys(5));
    let before = lock_of(&root, keys(5));
    let done = change(&root).whole_database_keys(keys(5)).table::<Sealed1>("people").execute().unwrap();
    assert!(done.rows > 0 && done.versions >= 5, "{done:?}");
    nothing_left_over(&root);
    // the lock in the header of the new main file is the old one, byte for byte, and the old password opens it
    assert!(lock_of(&root, keys(5)) == before, "the data key was changed");
    let s = open_with::<Sealed1>(&root, keys(5)).unwrap();
    let domain = s.domain::<Sealed1>();
    let grant = domain.read_grant().unwrap();
    for i in 0..5 {
        let person = domain.repo().get(&format!("p{i}")).unwrap();
        assert_eq!(person.phone.open(&grant).unwrap(), format!("+1555000000{i:02}"));
        assert_eq!(person.password, format!("pw-{i}-1"));
    }
    drop(domain);
    s.close();
    // no clear value in any file of the folder (the whole-database layer and the field layer both)
    assert!(in_files(&root, PHONE_MARK).is_empty());
    assert!(in_files(&root, SECRET.as_bytes()).is_empty());
    // another key is refused, as for any open
    assert!(matches!(open_with::<Sealed1>(&root, keys(7)).err(), Some(ClError::EncryptedOpenFailed)));
}

#[test]
fn fingerprints_and_a_hash_are_added_one_after_the_other_and_both_still_work() {
    let root = make(4, keys(4));
    let before = lock_of(&root, keys(4));
    change(&root).whole_database_keys(keys(4)).table::<Sealed1>("people").execute().unwrap();
    change(&root).whole_database_keys(keys(4)).table::<Printed1>("people").execute().unwrap();
    change(&root).whole_database_keys(keys(4)).table::<Hashed2>("people").confirm_one_way().execute().unwrap();
    nothing_left_over(&root);
    assert!(lock_of(&root, keys(4)) == before, "the data key was changed");
    let s = open_with::<Hashed2>(&root, keys(4)).unwrap();
    let domain = s.domain::<Hashed2>();
    let (grant, verifier) = (domain.read_grant().unwrap(), domain.verifier().unwrap());
    for i in 0..4 {
        let person = domain.repo().get(&format!("p{i}")).unwrap();
        assert_eq!(person.phone.open(&grant).unwrap(), format!("+1555000000{i:02}"));
        // the password the row had is accepted, another is not
        assert!(person.password.verify(&format!("pw-{i}-1"), &verifier).unwrap());
        assert!(!person.password.verify("not the password", &verifier).unwrap());
    }
    drop(domain);
    s.close();
    assert!(in_files(&root, b"pw-1-1").is_empty());
}

/// Attachments: a table gets its first protected field (its attachments are sealed again, bound to
/// the table, the row and the file, in `{db}.pblobs`) and loses its last (they are taken back).
mod attachments_follow_the_keys {
    use super::*;
    use std::io::Read;

    fn blob_db(root: &Path, whole: bool) -> DatabaseConfig {
        let db = DatabaseConfig::new("records", "store").dir_path(root.to_path_buf()).has_cache(false).blob_enabled(true);
        if whole {
            db.encryption(keys(5))
        } else {
            #[cfg(clove_test_encrypt_all)]
            let db = db.plain();
            db.field_encryption(keys(5))
        }
    }

    fn bytes(i: usize) -> Vec<u8> {
        let mut v = b"ATTACHMENT-MARKER-".to_vec();
        v.extend((0..(15_000 * (i + 1))).map(|k| (k % 251) as u8));
        v
    }

    /// Plain fields and an attachment for each row; the keys are the database's (whole) or none yet.
    fn make(whole: bool) -> PathBuf {
        let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let db = if whole {
            blob_db(&root, true)
        } else {
            let db = DatabaseConfig::new("records", "store").dir_path(root.clone()).has_cache(false).blob_enabled(true);
            #[cfg(clove_test_encrypt_all)]
            let db = db.plain();
            db
        };
        let s = Storage::builder(StorageConfig::default()).add_database(db.register_blob::<Plain>("people")).build().unwrap();
        let repo = s.domain::<Plain>().repo();
        for i in 0..3 {
            let row = Plain { id: format!("p{i}"), name: format!("{SECRET}-{i}"), phone: format!("+1555000000{i:02}"), password: format!("pw-{i}") };
            repo.set_with_blob(&row.id, &row, &bytes(i)).unwrap();
        }
        drop(repo);
        s.close();
        root
    }

    fn read_all<E: Entity + Serialize + Default + crate::field_crypto::SealedFields>(root: &Path, whole: bool, sealed: bool) {
        let db = blob_db(root, whole);
        let s = if sealed {
            Storage::builder(StorageConfig::default()).add_database(db.register_sealed_blob::<E>("people")).build().unwrap()
        } else {
            Storage::builder(StorageConfig::default()).add_database(db.register_blob::<Plain>("people")).build().unwrap()
        };
        if sealed {
            let repo = s.domain::<E>().repo();
            for i in 0..3 {
                let mut out = Vec::new();
                repo.open_blob(&format!("p{i}")).unwrap().read_to_end(&mut out).unwrap();
                assert!(out == bytes(i), "an attachment is not what it was");
            }
        } else {
            let repo = s.domain::<Plain>().repo();
            for i in 0..3 {
                let mut out = Vec::new();
                repo.open_blob(&format!("p{i}")).unwrap().read_to_end(&mut out).unwrap();
                assert!(out == bytes(i), "an attachment is not what it was");
            }
        }
        s.close();
    }

    fn names(root: &Path, folder: &str) -> Vec<String> {
        let mut files = Vec::new();
        let dir = root.join("records").join(folder);
        if dir.is_dir() {
            walk(&dir, &mut files);
        }
        let mut v: Vec<String> = files.iter().map(|p| p.strip_prefix(root).unwrap().display().to_string()).collect();
        v.sort();
        v
    }

    fn run(whole: bool) {
        let root = make(whole);
        let config = |c: ChangeFields| if whole { c.whole_database_keys(keys(5)) } else { c.field_keys(keys(5)) };
        let before = names(&root, "store.blobs");
        assert_eq!(before.len(), 3, "{before:?}");
        // the first protected field: the attachments move to `store.pblobs`, sealed for the table, row and file
        let done = config(change(&root)).table::<Sealed1>("people").execute().unwrap();
        assert_eq!(done.attachments_moved, 3, "{done:?}");
        nothing_left_over(&root);
        let (blobs, pblobs) = (names(&root, "store.blobs"), names(&root, "store.pblobs"));
        assert_eq!(pblobs.len(), 3, "{pblobs:?}");
        assert!(blobs.iter().all(|n| !before.contains(n)) && blobs.len() <= 3, "{blobs:?}");
        read_all::<Sealed1>(&root, whole, true);
        assert!(in_files(&root, b"ATTACHMENT-MARKER").is_empty(), "an attachment shows in {:?}", in_files(&root, b"ATTACHMENT-MARKER"));
        // and the last: they come back
        let done = config(change(&root)).table_without_protected_fields("people").execute().unwrap();
        assert_eq!(done.attachments_moved, 3, "{done:?}");
        nothing_left_over(&root);
        assert!(names(&root, "store.pblobs").is_empty());
        assert_eq!(names(&root, "store.blobs").len(), 3);
        read_all::<Sealed1>(&root, whole, false);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn in_a_plain_database_with_keys_for_its_fields() {
        run(false);
    }

    #[test]
    fn in_a_database_encrypted_as_a_whole() {
        run(true);
    }
}

#[test]
fn a_wrong_key_is_refused_before_anything_is_written() {
    let root = make(3, keys(5));
    let before = listing(&root);
    let err = change(&root).whole_database_keys(keys(9)).table::<Sealed1>("people").execute().err().expect("must be refused");
    assert!(matches!(err, ClError::EncryptedOpenFailed), "{err:?}");
    assert!(before == listing(&root), "a refused change touched a file");
}
