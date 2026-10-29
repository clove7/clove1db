//! A database file held by another program: opening returns `ClError::DatabaseInUse` at once,
//! for the `.cldb`, the `.cldb.bak` and the `.inx`, and the database is intact once the lock is released.
//! The lock is taken through a separate handle with the operating system's own file locking, which is
//! what another program does to the file; redb itself would otherwise wait for it without end.
use clove1db::{CloveFields, entity::Entity, storage::{DatabaseConfig, Storage, StorageConfig}, units::ClError};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Clone, Default, Serialize, Deserialize, CloveFields)]
struct Note { id: String, n: i64 }
impl Entity for Note { fn entity_id(&self) -> &str { &self.id } }

fn build(root: &Path) -> Result<Storage, ClError> {
    Storage::builder(StorageConfig::default())
        .add_database(DatabaseConfig::new("records", "store").dir_path(root.to_path_buf()).backup_enabled(true).has_cache(false).register::<Note>("notes"))
        .build()
}

/// How the other program holds the file.
#[derive(Clone, Copy, Debug)]
enum Hold {
    /// An exclusive lock on the whole file.
    Lock,
    /// Opened without sharing (Windows): nobody else can open it at all.
    NoSharing,
}

fn hold(path: &Path, how: Hold) -> File {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true);
    #[cfg(windows)]
    if matches!(how, Hold::NoSharing) {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0);
    }
    let file = options.open(path).expect("the other program opens the file");
    if matches!(how, Hold::Lock) {
        file.lock().expect("the other program locks the file");
    }
    file
}

fn check(which: &str, how: Hold) {
    let root: PathBuf = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    {
        let s = build(&root).unwrap();
        let rows = (0..50).map(|i| ("notes".to_string(), format!("{i:03}"), serde_json::to_vec(&Note { id: format!("{i:03}"), n: i }).unwrap())).collect::<Vec<_>>();
        s.db_manager("store").commit_batch_atomic(&rows, &[]).unwrap();
        s.close();
    }
    let dir = root.join("records");
    let target = match which { "cldb" => dir.join("store.cldb"), "bak" => dir.join("store.cldb.bak"), "inx" => dir.join("store.inx"), _ => unreachable!() };
    assert!(target.is_file(), "{which} file must exist");
    let names = |d: &Path| { let mut v = std::fs::read_dir(d).unwrap().map(|e| e.unwrap().file_name()).collect::<Vec<_>>(); v.sort(); v };
    let before = names(&dir);
    let target_len = std::fs::metadata(&target).unwrap().len();

    let held = hold(&target, how);
    let started = Instant::now();
    let opened = build(&root);
    let elapsed = started.elapsed();
    match opened {
        Err(ClError::DatabaseInUse { path }) => assert!(path.ends_with(target.file_name().unwrap().to_str().unwrap()), "error names the locked file, got {path}"),
        Err(other) => panic!("{which}/{how:?}: expected DatabaseInUse, got {other:?}"),
        Ok(_) => panic!("{which}/{how:?}: a locked database opened"),
    }
    assert!(elapsed < Duration::from_secs(5), "{which}/{how:?}: the error must come back at once, took {elapsed:?}");
    assert_eq!(names(&dir), before, "{which}/{how:?}: the failed open renames and creates nothing");
    assert_eq!(std::fs::metadata(&target).unwrap().len(), target_len, "{which}/{how:?}: the locked file is untouched");

    drop(held);

    let s = build(&root).unwrap_or_else(|e| panic!("{which}/{how:?}: reopen after release failed: {e:?}"));
    let rows = s.db_manager("store").read_view_at_head().unwrap().table_entries("notes").unwrap();
    assert_eq!(rows.len(), 50, "{which}/{how:?}: all rows are there after the lock is released");
    for (key, bytes) in rows {
        let row: Note = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(row.id, key);
    }
    s.close();
    let _ = std::fs::remove_dir_all(&root);
}

#[test] fn locked_cldb_returns_in_use() { check("cldb", Hold::Lock); }
#[test] fn locked_cldb_bak_returns_in_use() { check("bak", Hold::Lock); }
#[test] fn locked_inx_returns_in_use() { check("inx", Hold::Lock); }

#[cfg(windows)]
#[test] fn cldb_opened_without_sharing_returns_in_use() { check("cldb", Hold::NoSharing); }
#[cfg(windows)]
#[test] fn cldb_bak_opened_without_sharing_returns_in_use() { check("bak", Hold::NoSharing); }
#[cfg(windows)]
#[test] fn inx_opened_without_sharing_returns_in_use() { check("inx", Hold::NoSharing); }

/// The same files opened twice in one process are also "in use", not a generic database error.
#[test]
fn second_open_of_a_live_database_returns_in_use() {
    let root: PathBuf = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = build(&root).unwrap();
    match build(&root) {
        Err(ClError::DatabaseInUse { .. }) => {}
        Err(other) => panic!("expected DatabaseInUse, got {other:?}"),
        Ok(_) => panic!("a live database opened twice"),
    }
    s.close();
    let _ = std::fs::remove_dir_all(&root);
}
