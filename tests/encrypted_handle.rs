//! The shared handle a library keeps in its options: the main file unlocks the key, the backup
//! and the index reuse it, and the order and the failure cases behave.
mod encrypted_support;

use clove1db::crypto::{CipherKind, HkdfHash, Key32, KeySuite, PasswordKdf, SecretBytes};
use clove1db::encrypted_store::{
    EncryptionConfig, EncryptionHandle, KeySource, OpenOptionsExt, StoreDiagnostic, StoreError,
};
use encrypted_support::*;

const OPTS: OpenOptionsExt = OpenOptionsExt { cache_bytes: Some(1 << 20), verify_on_open: false, read_only: false, repair_seen: None, tuning: clove1db::EncryptionTuning::DEFAULT };

fn suite() -> KeySuite {
    KeySuite { cipher: CipherKind::Aes256GcmSiv, hkdf: HkdfHash::Sha256 }
}

fn config(read: &Key32, search: &Key32) -> EncryptionConfig {
    EncryptionConfig {
        suite: suite(),
        read: Some(KeySource::Raw(Key32::from_slice(&raw(read)).unwrap())),
        search: Some(KeySource::Raw(Key32::from_slice(&raw(search)).unwrap())),
    }
}

// Key32 has no accessor for its bytes; the test keeps its own copies instead.
fn raw(k: &Key32) -> Vec<u8> {
    KEYS.with(|m| m.borrow().iter().find(|(key, _)| key == k).unwrap().1.clone())
}

thread_local! {
    static KEYS: std::cell::RefCell<Vec<(Key32, Vec<u8>)>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn make_key(seed: u8) -> Key32 {
    let bytes = vec![seed; 32];
    let k = Key32::from_slice(&bytes).unwrap();
    KEYS.with(|m| m.borrow_mut().push((Key32::from_slice(&bytes).unwrap(), bytes)));
    k
}

#[test]
fn the_main_file_unlocks_and_the_others_follow() {
    let dir = TempDir::new("handle");
    let (r, s) = (make_key(1), make_key(2));
    let handle = EncryptionHandle::new(config(&r, &s));
    assert!(handle.context().is_none());
    let main = handle.open_file(&dir.path("a.cldb"), "main", true, &OPTS, &mut |_| {}).unwrap();
    assert!(handle.context().is_some());
    let w = main.begin_write().unwrap();
    insert_rows(&w, &rows(0, 50, 1));
    w.commit().unwrap();
    let bak = handle.open_file(&dir.path("a.cldb.bak"), "bak", true, &OPTS, &mut |_| {}).unwrap();
    let inx = handle.open_file(&dir.path("a.inx"), "index", true, &OPTS, &mut |_| {}).unwrap();
    drop((main, bak, inx));

    // a second handle with the same keys, opening in the library's order
    let again = EncryptionHandle::new(config(&r, &s));
    let main = again.open_file(&dir.path("a.cldb"), "main", false, &OPTS, &mut |_| {}).unwrap();
    assert_eq!(read_all(main.database()).unwrap(), rows(0, 50, 1));
    let bak = again.open_file(&dir.path("a.cldb.bak"), "bak", false, &OPTS, &mut |_| {}).unwrap();
    let inx = again.open_file(&dir.path("a.inx"), "index", false, &OPTS, &mut |_| {}).unwrap();
    drop((main, bak, inx));

    // a clone shares the unlocked key
    let shared = again.clone();
    assert!(shared.context().is_some());
}

#[test]
fn any_file_of_the_database_can_be_the_first_one_opened() {
    let dir = TempDir::new("handle-order");
    let (r, s) = (make_key(3), make_key(4));
    let first = EncryptionHandle::new(config(&r, &s));
    drop(first.open_file(&dir.path("a.cldb"), "main", true, &OPTS, &mut |_| {}).unwrap());
    drop(first.open_file(&dir.path("a.inx"), "index", true, &OPTS, &mut |_| {}).unwrap());
    // every file carries the same locked data key, so a new handle can unlock from any of them
    let fresh = EncryptionHandle::new(config(&r, &s));
    let mut why = Vec::new();
    let res = fresh.open_file(&dir.path("a.inx"), "index", false, &OPTS, &mut |d| why.push(d));
    assert!(res.is_ok(), "{:?}", res.err());
    assert!(fresh.context().is_some());
}

#[test]
fn the_wrong_keys_give_the_one_error_and_a_missing_file_is_not_found() {
    let dir = TempDir::new("handle-wrong");
    let (r, s, other) = (make_key(5), make_key(6), make_key(7));
    let handle = EncryptionHandle::new(config(&r, &s));
    drop(handle.open_file(&dir.path("a.cldb"), "main", true, &OPTS, &mut |_| {}).unwrap());
    let wrong = EncryptionHandle::new(config(&other, &s));
    let mut why = Vec::new();
    let e = wrong.open_file(&dir.path("a.cldb"), "main", false, &OPTS, &mut |d| why.push(d)).unwrap_err();
    assert!(matches!(e, StoreError::OpenFailed));
    assert!(why.contains(&StoreDiagnostic::LockRejected));
    assert!(wrong.context().is_none(), "a failed open must not leave a key behind");
    let missing = handle.open_file(&dir.path("none.cldb"), "main", false, &OPTS, &mut |_| {}).unwrap_err();
    assert!(matches!(missing, StoreError::Io(ref io) if io.kind() == std::io::ErrorKind::NotFound));
}

#[test]
fn an_empty_file_counts_as_not_there_when_creating() {
    let dir = TempDir::new("handle-empty");
    let (r, s) = (make_key(8), make_key(9));
    std::fs::write(dir.path("a.cldb"), b"").unwrap();
    let handle = EncryptionHandle::new(config(&r, &s));
    let db = handle.open_file(&dir.path("a.cldb"), "main", true, &OPTS, &mut |_| {}).unwrap();
    let w = db.begin_write().unwrap();
    insert_rows(&w, &rows(0, 5, 1));
    w.commit().unwrap();
    drop(db);
    // but a file with something in it that is not ours is never overwritten
    std::fs::write(dir.path("b.cldb"), b"not a database").unwrap();
    let e = handle.open_file(&dir.path("b.cldb"), "main", true, &OPTS, &mut |_| {});
    assert!(e.is_err());
    assert_eq!(std::fs::read(dir.path("b.cldb")).unwrap(), b"not a database");
}

#[test]
fn passwords_work_through_the_handle_and_nothing_prints() {
    let dir = TempDir::new("handle-pw");
    let kdf = PasswordKdf::Argon2id { memory_kib: 19_456, iterations: 2, lanes: 1 };
    let cfg = || EncryptionConfig {
        suite: suite(),
        read: Some(KeySource::Password { password: SecretBytes::from_slice(b"a pass phrase long enough"), kdf }),
        search: Some(KeySource::Raw(Key32::from_slice(&[7u8; 32]).unwrap())),
    };
    let handle = EncryptionHandle::new(cfg());
    let text = format!("{handle:?} {:?}", handle.suite());
    assert!(!text.contains("pass phrase") && !text.contains('7'), "{text}");
    drop(handle.open_file(&dir.path("a.cldb"), "main", true, &OPTS, &mut |_| {}).unwrap());
    assert!(EncryptionHandle::new(cfg()).open_file(&dir.path("a.cldb"), "main", false, &OPTS, &mut |_| {}).is_ok());
}
