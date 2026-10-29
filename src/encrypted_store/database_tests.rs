//! A new encrypted database that fails after its file was created leaves nothing behind, and an
//! existing file is never removed.
use super::{EncryptionConfig, KeySource};
use crate::crypto::{CipherKind, HkdfHash, Key32, KeySuite};
use crate::entity::Entity;
use crate::storage::{DatabaseConfig, Storage, StorageConfig};
use crate::units::ClError;
use crate::storage::FAIL_AFTER_OPEN;
use crate::upgrade::pipeline::FAIL_AFTER_CREATE;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Mutex;

/// The failure hook is process-wide, so the tests that use it run one at a time.
static HOOK: Mutex<()> = Mutex::new(());

#[derive(Clone, Default, Serialize, Deserialize)]
struct Note {
    id: String,
    n: i64,
}

impl Entity for Note {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn config(read: u8, search: u8) -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite { cipher: CipherKind::Aes256GcmSiv, hkdf: HkdfHash::Sha256 },
        read: Some(KeySource::Raw(Key32::from_bytes(&[read; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[search; 32]))),
    }
}

fn build(root: &PathBuf, read: u8) -> Result<Storage, ClError> {
    Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("records", "hooked")
                .dir_path(root.clone())
                .backup_enabled(true)
                .has_cache(false)
                .encryption(config(read, 2))
                .register::<Note>("notes"),
        )
        .build()
}

fn files(dir: &std::path::Path) -> Vec<String> {
    let mut v: Vec<String> = match std::fs::read_dir(dir) {
        Ok(rd) => rd.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect(),
        Err(_) => Vec::new(),
    };
    v.sort();
    v
}

#[test]
fn a_failure_after_creation_removes_the_new_file_and_a_second_try_with_other_keys_works() {
    let _one_at_a_time = HOOK.lock().unwrap_or_else(|e| e.into_inner());
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    FAIL_AFTER_CREATE.store(true, Ordering::SeqCst);
    let first = build(&root, 1);
    FAIL_AFTER_CREATE.store(false, Ordering::SeqCst);
    assert!(matches!(first, Err(ClError::Validation(_))), "the injected error comes back, not another");
    let dir = root.join("records");
    assert!(!dir.join("hooked.cldb").exists(), "the new database file was left: {:?}", files(&dir));
    assert!(!files(&dir).iter().any(|n| n.ends_with(".creating")), "{:?}", files(&dir));
    // a new try with a different key for the same name succeeds (nothing of the first try is left to refuse it)
    let s = build(&root, 9).unwrap();
    s.close();
    assert!(dir.join("hooked.cldb").is_file());
    // the key of the second try opens it; the first one is refused with the single error
    assert!(build(&root, 9).map(|s| s.close()).is_ok());
    assert!(matches!(build(&root, 1), Err(ClError::EncryptedOpenFailed)));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_failure_never_removes_a_database_that_was_there_before() {
    let _one_at_a_time = HOOK.lock().unwrap_or_else(|e| e.into_inner());
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let rows: Vec<(String, String, Vec<u8>)> = (0..60)
        .map(|i| {
            let n = Note { id: format!("row-{i:03}"), n: i * 7 };
            ("notes".to_string(), n.id.clone(), serde_json::to_vec(&n).unwrap())
        })
        .collect();
    let s = build(&root, 1).unwrap();
    s.db_manager("hooked").commit_batch_atomic(&rows, &[]).unwrap();
    s.close();
    drop(s);
    let dir = root.join("records");
    FAIL_AFTER_CREATE.store(true, Ordering::SeqCst);
    let again = build(&root, 1);
    FAIL_AFTER_CREATE.store(false, Ordering::SeqCst);
    // the existing file is opened (not created), so the hook, which is for new files, does not fire
    assert!(again.is_ok() || matches!(again, Err(ClError::Validation(_))));
    drop(again);
    assert!(dir.join("hooked.cldb").is_file(), "an existing database was removed");
    // what was written is all still there, with its values, and the closed files check out block by block
    let s = build(&root, 1).unwrap();
    let got = s.db_manager("hooked").read_view_at_head().unwrap().table_entries("notes").unwrap();
    assert_eq!(got.len(), rows.len(), "the rows after the failed build");
    for (table, id, bytes) in &rows {
        let _ = table;
        let found = got.iter().find(|(k, _)| k == id).unwrap_or_else(|| panic!("row {id} is gone"));
        assert_eq!(&found.1, bytes, "row {id} changed");
    }
    s.close();
    drop(s);
    super::verify_encrypted_files(&root, "records", "hooked", &super::EncryptionHandle::new(config(1, 2))).unwrap();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_failure_after_the_database_opened_removes_every_file_this_call_made() {
    let _one_at_a_time = HOOK.lock().unwrap_or_else(|e| e.into_inner());
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    FAIL_AFTER_OPEN.store(true, Ordering::SeqCst);
    let first = build(&root, 1);
    FAIL_AFTER_OPEN.store(false, Ordering::SeqCst);
    assert!(matches!(first, Err(ClError::Validation(_))), "the injected error comes back");
    let dir = root.join("records");
    assert!(files(&dir).is_empty(), "left behind: {:?}", files(&dir));
    assert!(!dir.exists(), "the empty folder this call made was left");
    // a new try with another key works from nothing
    build(&root, 9).unwrap().close();
    assert!(dir.join("hooked.cldb").is_file());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn nothing_that_existed_before_is_removed_by_a_failed_build() {
    let _one_at_a_time = HOOK.lock().unwrap_or_else(|e| e.into_inner());
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    build(&root, 1).unwrap().close();
    let dir = root.join("records");
    let before = files(&dir);
    FAIL_AFTER_OPEN.store(true, Ordering::SeqCst);
    let again = build(&root, 1);
    FAIL_AFTER_OPEN.store(false, Ordering::SeqCst);
    assert!(matches!(again, Err(ClError::Validation(_))));
    assert_eq!(files(&dir), before, "a failed build changed files that were already there");
    build(&root, 1).unwrap().close();
    let _ = std::fs::remove_dir_all(&root);
}
