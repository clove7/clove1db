//! An encrypted database through the whole library: the `.cldb`, its `.cldb.bak` and its `.inx` hold
//! nothing readable, wrong keys give one error, a damaged `.inx` is rebuilt, and a changed `.cldb`
//! never gives wrong rows.
use clove1db::{
    CloveFields, EncryptionConfig, KeySource, LibraryEvent,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    encrypted_store::{EncryptionHandle, verify_encrypted_files},
    entity::Entity,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const TABLE: &str = "secret_notes_table";
const MARKER: &str = "MARKER-5d2e91c0-ffe1";

#[derive(Clone, Default, Serialize, Deserialize, CloveFields)]
struct Note {
    id: String,
    n: i64,
}

impl Entity for Note {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn config(read: u8) -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite { cipher: CipherKind::XChaCha20Poly1305, hkdf: HkdfHash::Sha256 },
        read: Some(KeySource::Raw(Key32::from_bytes(&[read; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[200; 32]))),
    }
}

/// Under `--cfg clove_test_encrypt_all` every database starts encrypted; a test that wants a plain one says so.
fn plain(db: DatabaseConfig) -> DatabaseConfig {
    #[cfg(clove_test_encrypt_all)]
    {
        db.plain()
    }
    #[cfg(not(clove_test_encrypt_all))]
    {
        db
    }
}

fn build(root: &Path, encryption: Option<EncryptionConfig>) -> Result<Storage, ClError> {
    let mut db = DatabaseConfig::new("records", "store")
        .dir_path(root.to_path_buf())
        .backup_enabled(true)
        .has_cache(false)
        .register::<Note>(TABLE);
    db = match encryption {
        Some(e) => db.encryption(e),
        None => plain(db),
    };
    Storage::builder(StorageConfig::default()).add_database(db).build()
}

fn fresh_root() -> PathBuf {
    std::env::temp_dir().join(uuid::Uuid::new_v4().to_string())
}

fn rows(count: usize) -> Vec<(String, String, Vec<u8>)> {
    (0..count)
        .map(|i| {
            let id = format!("{MARKER}-{i:04}");
            let bytes = serde_json::to_vec(&Note { id: id.clone(), n: i as i64 }).unwrap();
            (TABLE.to_string(), id, bytes)
        })
        .collect()
}

fn read_rows(s: &Storage) -> Vec<(String, Vec<u8>)> {
    s.db_manager("store").read_view_at_head().unwrap().table_entries(TABLE).unwrap()
}

fn make(count: usize) -> PathBuf {
    let root = fresh_root();
    let s = build(&root, Some(config(1))).unwrap();
    s.db_manager("store").commit_batch_atomic(&rows(count), &[]).unwrap();
    // a second batch, so the backup history and the index have more than one state
    s.db_manager("store").commit_batch_atomic(&rows(count / 2), &[]).unwrap();
    s.close();
    root
}

fn has(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn the_three_database_files_hold_nothing_readable() {
    let root = make(300);
    let dir = root.join("records");
    for name in ["store.cldb", "store.cldb.bak", "store.inx"] {
        let bytes = std::fs::read(dir.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(bytes.len() > 4096, "{name} is too small to mean anything");
        for needle in [MARKER.as_bytes(), TABLE.as_bytes(), b"redb".as_slice(), &[0x1A, 0x0A, 0xA9, 0x0D, 0x0A], b"clove".as_slice(), b"notes"] {
            assert!(!has(&bytes, needle), "{name} contains {:?}", String::from_utf8_lossy(needle));
        }
        let (mut run, mut longest) = (0usize, 0usize);
        for b in &bytes {
            run = if *b == 0 { run + 1 } else { 0 };
            longest = longest.max(run);
        }
        assert!(longest < 16, "{name} has {longest} zero bytes in a row");
    }
    // and it reopens with the same keys, with every row
    let s = build(&root, Some(config(1))).unwrap();
    assert_eq!(read_rows(&s).len(), 300);
    s.close();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn every_wrong_way_of_opening_is_the_one_error() {
    let root = make(60);
    // wrong key
    assert!(matches!(build(&root, Some(config(2))), Err(ClError::EncryptedOpenFailed)));
    // no key at all
    let no_key = build(&root, None);
    assert!(no_key.is_err());
    assert!(!matches!(no_key, Err(ClError::DatabaseInUse { .. })));
    // right key still works afterwards
    build(&root, Some(config(1))).unwrap().close();
    // a plain database opened with a key
    let plain_root = fresh_root();
    build(&plain_root, None).unwrap().close();
    assert!(matches!(build(&plain_root, Some(config(1))), Err(ClError::EncryptedOpenFailed)));
    // text of the error says nothing about why
    let text = format!("{}", build(&root, Some(config(3))).err().unwrap());
    assert_eq!(text, "the database could not be opened");
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&plain_root);
}

#[test]
fn a_damaged_index_file_is_rebuilt_and_the_rows_are_untouched() {
    for damage in ["flip", "cut", "garbage"] {
        let root = make(120);
        let dir = root.join("records");
        let inx = dir.join("store.inx");
        let mut bytes = std::fs::read(&inx).unwrap();
        match damage {
            "flip" => {
                for pos in (8192..bytes.len()).step_by(4096) {
                    bytes[pos] ^= 0x40;
                }
            }
            "cut" => bytes.truncate(bytes.len() / 3),
            _ => bytes = (0..bytes.len()).map(|i| (i * 131 % 251) as u8).collect(),
        }
        std::fs::write(&inx, &bytes).unwrap();
        let s = build(&root, Some(config(1))).unwrap_or_else(|e| panic!("{damage}: {e:?}"));
        assert_eq!(read_rows(&s).len(), 120, "{damage}");
        s.close();
        let names: Vec<String> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        assert!(names.iter().any(|n| n.starts_with("store.inx.invalid-")), "{damage}: the damaged index was not set aside: {names:?}");
        assert!(dir.join("store.inx").is_file(), "{damage}: no new index");
        // the new index file is encrypted too
        let fresh = std::fs::read(dir.join("store.inx")).unwrap();
        assert!(!has(&fresh, MARKER.as_bytes()) && !has(&fresh, b"redb"));
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[test]
fn a_changed_main_file_gives_an_error_and_never_wrong_rows() {
    let root = make(200);
    let dir = root.join("records");
    let original = std::fs::read(dir.join("store.cldb")).unwrap();
    let expected = {
        let s = build(&root, Some(config(1))).unwrap();
        let r = read_rows(&s);
        s.close();
        r
    };
    let stride = 4096 + 40;
    let blocks = (original.len() - 4096) / stride;
    let (mut detected, mut same) = (0, 0);
    for i in (0..blocks).step_by(blocks.div_ceil(40).max(1)) {
        let mut m = original.clone();
        m[4096 + i * stride + 100] ^= 0x01;
        std::fs::write(dir.join("store.cldb"), &m).unwrap();
        match std::panic::catch_unwind(|| build(&root, Some(config(1)))) {
            Err(_) => detected += 1,
            Ok(Err(_)) => detected += 1,
            Ok(Ok(s)) => {
                let got = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| read_rows(&s)));
                match got {
                    Ok(rows) => {
                        assert_eq!(rows, expected, "block {i}: wrong rows without an error");
                        same += 1;
                    }
                    Err(_) => detected += 1,
                }
                s.close();
            }
        }
    }
    assert!(detected > 0, "no change was ever noticed ({same} unnoticed)");
    std::fs::write(dir.join("store.cldb"), &original).unwrap();
    build(&root, Some(config(1))).unwrap().close();
    let _ = std::fs::remove_dir_all(&root);
}

// ---- 7-4: the plain-file case, early refusals of wrong settings, and the full check of closed files

type Events = Arc<Mutex<Vec<String>>>;

fn build_events(root: &Path, encryption: Option<EncryptionConfig>, events: &Events) -> Result<Storage, ClError> {
    let sink = events.clone();
    let storage = StorageConfig::default().event_sink(move |e| {
        if let LibraryEvent::Encryption { event, file } = e {
            sink.lock().unwrap().push(format!("{event}@{file}"));
        }
    });
    let mut db = DatabaseConfig::new("records", "store")
        .dir_path(root.to_path_buf())
        .backup_enabled(true)
        .has_cache(false)
        .register::<Note>(TABLE);
    db = match encryption {
        Some(e) => db.encryption(e),
        None => plain(db),
    };
    Storage::builder(storage).add_database(db).build()
}

/// Every file under `root` with its bytes, and every folder (as `None`).
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn walk(dir: &Path, out: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                out.insert(path.clone(), None);
                walk(&path, out);
            } else {
                out.insert(path.clone(), Some(std::fs::read(&path).unwrap()));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, &mut out);
    out
}

fn custom(cipher: CipherKind, read: Option<u8>, search: Option<u8>) -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite { cipher, hkdf: HkdfHash::Sha256 },
        read: read.map(|b| KeySource::Raw(Key32::from_bytes(&[b; 32]))),
        search: search.map(|b| KeySource::Raw(Key32::from_bytes(&[b; 32]))),
    }
}

fn validation_text(result: Result<Storage, ClError>) -> String {
    match result.err().expect("the build should have been refused") {
        ClError::Validation(text) => text,
        other => panic!("expected a Validation error, got {other:?}"),
    }
}

#[test]
fn a_plain_file_opened_with_keys_is_one_event_and_nothing_changes() {
    let root = fresh_root();
    let s = build(&root, None).unwrap();
    s.db_manager("store").commit_batch_atomic(&rows(30), &[]).unwrap();
    s.close();
    let before = snapshot(&root);
    let events: Events = Arc::default();
    let result = build_events(&root, Some(config(1)), &events);
    assert!(matches!(result, Err(ClError::EncryptedOpenFailed)));
    assert_eq!(*events.lock().unwrap(), vec!["encryption/open_failed/looks_like_unencrypted@main".to_string()]);
    assert!(snapshot(&root) == before, "the plain files, or the list of files, changed");
    // the same database still opens plain, with its rows
    let s = build(&root, None).unwrap();
    assert_eq!(read_rows(&s).len(), 30);
    s.close();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn an_encrypted_file_opened_without_keys_changes_nothing() {
    let root = make(40);
    let before = snapshot(&root);
    let result = build(&root, None);
    assert!(result.is_err());
    assert!(!matches!(result, Err(ClError::DatabaseInUse { .. })));
    assert!(snapshot(&root) == before, "the encrypted files, or the list of files, changed");
    build(&root, Some(config(1))).unwrap().close();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_cipher_that_is_not_allowed_is_refused_before_any_file_is_touched() {
    for cipher in [CipherKind::Aes256Gcm, CipherKind::ChaCha20Poly1305] {
        let root = fresh_root();
        let text = validation_text(build(&root, Some(custom(cipher, Some(1), Some(2)))));
        assert_eq!(text, "this cipher is not allowed for a whole database");
        assert!(!root.exists(), "{cipher:?}: the root was made");
        // the same on an existing database, whose files stay as they were
        let made = make(20);
        let before = snapshot(&made);
        assert!(matches!(build(&made, Some(custom(cipher, Some(1), Some(200)))), Err(ClError::Validation(_))));
        assert!(snapshot(&made) == before);
        let _ = std::fs::remove_dir_all(&made);
    }
}

#[test]
fn missing_keys_are_refused_at_once_and_say_which() {
    let a = CipherKind::XChaCha20Poly1305;
    // a new database: no read key, and a read key without the search key
    let root = fresh_root();
    assert_eq!(validation_text(build(&root, Some(custom(a, None, Some(2))))), "whole-database encryption needs a read key");
    assert!(!root.exists(), "the root was made for a missing read key");
    assert_eq!(
        validation_text(build(&root, Some(custom(a, Some(1), None)))),
        "a new encrypted database needs both a read key and a search key"
    );
    assert!(!root.exists(), "the root was made for a missing search key");
    // an existing database: only a search key is the read-key message, and nothing changes
    let made = make(20);
    let before = snapshot(&made);
    assert_eq!(validation_text(build(&made, Some(custom(a, None, Some(200))))), "whole-database encryption needs a read key");
    assert_eq!(validation_text(build(&made, Some(custom(a, None, None)))), "whole-database encryption needs a read key");
    assert!(snapshot(&made) == before, "an existing database changed");
    // the read key alone opens an existing database (the search key stays optional there)
    build(&made, Some(custom(a, Some(1), None))).unwrap().close();
    let _ = std::fs::remove_dir_all(&made);
}

#[test]
fn an_empty_main_file_counts_as_a_new_database_for_the_early_key_check() {
    let root = fresh_root();
    let dir = root.join("records");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("store.cldb"), b"").unwrap();
    let before = snapshot(&root);
    assert_eq!(
        validation_text(build(&root, Some(custom(CipherKind::XChaCha20Poly1305, Some(1), None)))),
        "a new encrypted database needs both a read key and a search key"
    );
    assert!(snapshot(&root) == before, "the empty file or the folder changed");
    assert_eq!(std::fs::metadata(dir.join("store.cldb")).unwrap().len(), 0);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_closed_encrypted_database_holds_no_file_and_reopens_at_once_without_repair() {
    let root = fresh_root();
    let s = build(&root, Some(config(1))).unwrap();
    s.db_manager("store").commit_batch_atomic(&rows(80), &[]).unwrap();
    s.close();
    drop(s);
    // nothing holds the files any more: a read-only open of each succeeds (it is refused while any
    // handle of the database is open), which is the check that no operation is still open
    verify_encrypted_files(&root, "records", "store", &handle(1)).unwrap();
    // reopened at once: no file needed a repair, and every row is there
    let s = build(&root, Some(config(1))).unwrap();
    let report = s.open_report();
    assert!(!report.is_empty());
    assert!(report.iter().all(|r| !r.repaired), "a file was repaired after a clean close: {report:?}");
    assert_eq!(read_rows(&s).len(), 80);
    s.close();
    let _ = std::fs::remove_dir_all(&root);
}

fn handle(read: u8) -> EncryptionHandle {
    EncryptionHandle::new(config(read))
}

#[test]
fn closed_files_are_checked_in_full_and_a_changed_block_is_found() {
    let root = make(150);
    // intact: every file passes; the wrong key is the open error, not a tamper
    verify_encrypted_files(&root, "records", "store", &handle(1)).unwrap();
    assert!(matches!(
        ClError::from(verify_encrypted_files(&root, "records", "store", &handle(9)).unwrap_err()),
        ClError::EncryptedOpenFailed
    ));
    let dir = root.join("records");
    for name in ["store.cldb", "store.inx"] {
        let original = std::fs::read(dir.join(name)).unwrap();
        let stride = 4096 + 40;
        let blocks = (original.len() - 4096) / stride;
        let mut found = 0;
        for i in 0..blocks {
            let mut m = original.clone();
            m[4096 + i * stride + 100] ^= 0x01;
            std::fs::write(dir.join(name), &m).unwrap();
            match verify_encrypted_files(&root, "records", "store", &handle(1)) {
                Ok(()) => panic!("{name} block {i}: a changed block was not found"),
                Err(e) => {
                    assert!(matches!(ClError::from(e), ClError::DataTampered), "{name} block {i}");
                    found += 1;
                }
            }
        }
        println!("{name}: {blocks} blocks, a bit changed in each, {found} found");
        assert_eq!(found, blocks, "{name}: some changed blocks were not found");
        std::fs::write(dir.join(name), &original).unwrap();
        verify_encrypted_files(&root, "records", "store", &handle(1)).unwrap();
    }
    // a database open elsewhere is "in use", not "ok"
    let open = build(&root, Some(config(1))).unwrap();
    assert!(verify_encrypted_files(&root, "records", "store", &handle(1)).is_err());
    open.close();
    let _ = std::fs::remove_dir_all(&root);
}

fn salted(count: usize, salt: i64) -> Vec<(String, String, Vec<u8>)> {
    (0..count)
        .map(|i| {
            let id = format!("{MARKER}-{i:04}");
            let bytes = serde_json::to_vec(&Note { id: id.clone(), n: i as i64 + salt }).unwrap();
            (TABLE.to_string(), id, bytes)
        })
        .collect()
}

#[test]
fn a_block_put_back_from_an_older_copy_is_found_by_the_full_check_and_never_gives_wrong_rows() {
    let root = fresh_root();
    let dir = root.join("records");
    let main = dir.join("store.cldb");
    let s = build(&root, Some(config(1))).unwrap();
    s.db_manager("store").commit_batch_atomic(&salted(200, 0), &[]).unwrap();
    s.close();
    let old = std::fs::read(&main).unwrap();
    let s = build(&root, Some(config(1))).unwrap();
    s.db_manager("store").commit_batch_atomic(&salted(200, 1000), &[]).unwrap();
    s.close();
    let now = std::fs::read(&main).unwrap();
    let expected = {
        let s = build(&root, Some(config(1))).unwrap();
        let r = read_rows(&s);
        s.close();
        r
    };
    verify_encrypted_files(&root, "records", "store", &handle(1)).unwrap();
    let stride = 4096 + 40;
    let blocks = (old.len().min(now.len()) - 4096) / stride;
    let (mut changed, mut found, mut wrong_after_ok) = (0, 0, 0);
    for i in 0..blocks {
        let (a, b) = (4096 + i * stride, 4096 + (i + 1) * stride);
        if old[a..b] == now[a..b] {
            continue;
        }
        changed += 1;
        let mut m = now.clone();
        m[a..b].copy_from_slice(&old[a..b]);
        std::fs::write(&main, &m).unwrap();
        match verify_encrypted_files(&root, "records", "store", &handle(1)) {
            Err(e) => {
                assert!(matches!(ClError::from(e), ClError::DataTampered), "block {i}");
                found += 1;
            }
            Ok(()) => {
                let got = std::panic::catch_unwind(|| {
                    let s = build(&root, Some(config(1))).ok()?;
                    let r = read_rows(&s);
                    s.close();
                    Some(r)
                });
                if let Ok(Some(rows)) = got {
                    if rows != expected {
                        wrong_after_ok += 1;
                    }
                }
            }
        }
    }
    assert!(changed > 3, "the test changed nothing");
    assert!(found > 0, "no old block was found by the full check");
    assert_eq!(wrong_after_ok, 0, "the full check passed a file that gave wrong rows");
    println!("{changed} old blocks put back, {found} found by the full check");
    std::fs::write(&main, &now).unwrap();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_plain_database_is_unchanged_by_all_of_this() {
    let root = fresh_root();
    let s = build(&root, None).unwrap();
    s.db_manager("store").commit_batch_atomic(&rows(20), &[]).unwrap();
    s.close();
    let bytes = std::fs::read(root.join("records").join("store.cldb")).unwrap();
    assert!(has(&bytes, b"redb"), "a plain database still starts as redb");
    let s = build(&root, None).unwrap();
    assert_eq!(read_rows(&s).len(), 20);
    s.close();
    let _ = std::fs::remove_dir_all(&root);
}
