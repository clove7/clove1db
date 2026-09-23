//! Opening, closing and crash recovery, checked against redb itself.
//!
//! Recovery is judged the way redb judges it: the probe reopens a file with a
//! repair callback, and redb calls it exactly when the file needs a full repair
//! — when the last commit before the process ended did not save the allocator
//! state, and nothing closed the file.
//!
//! An unclean exit needs a real process to end, so those tests re-run this test
//! binary as a child ([`quick_repair_child`]) that writes and then calls
//! `process::exit` — no destructor runs, which is what a kill, a crash, or a
//! `Storage` held in a `static` all come to.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use redb::ReadableDatabase;
use serde::{Deserialize, Serialize};

use crate::entity::Entity;
use crate::handle::opens;
use crate::storage::{DatabaseConfig, Storage, StorageConfig};
use crate::units::ClError;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Row {
    id: String,
    body: String,
}

impl Entity for Row {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn row(id: &str, body_bytes: usize) -> Row {
    Row {
        id: id.to_string(),
        body: "x".repeat(body_bytes),
    }
}

fn fresh_dir(tag: &str) -> PathBuf {
    let dir = PathBuf::from("./target/test_handle").join(tag);
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// One database, `rows`, with backup on — so both files are exercised.
fn build(dir: &Path, options: impl FnOnce(DatabaseConfig) -> DatabaseConfig) -> Storage {
    Storage::builder(StorageConfig::default().change_dir_path(dir.to_path_buf()))
        .add_database(
            options(DatabaseConfig::new("rows", "rows"))
                .backup_enabled(true)
                .register::<Row>("rows"),
        )
        .build()
        .unwrap()
}

fn primary(dir: &Path) -> PathBuf {
    dir.join("rows").join("rows.cldb")
}

fn backup(dir: &Path) -> PathBuf {
    dir.join("rows").join("rows.cldb.bak")
}

/// Would opening this file run a full repair? Opens it with a repair callback
/// and closes it again — which leaves it clean, so ask once per exit.
fn needs_full_repair(path: &Path) -> bool {
    let repaired = Arc::new(AtomicBool::new(false));
    let seen = repaired.clone();
    let db = redb::Database::builder()
        .set_repair_callback(move |_| seen.store(true, Ordering::SeqCst))
        .open(path)
        .unwrap();
    drop(db);
    repaired.load(Ordering::SeqCst)
}

fn is_closed<T: std::fmt::Debug>(result: crate::units::Result<T>) -> bool {
    matches!(result, Err(ClError::Closed { .. }))
}

// ─── close ──────────────────────────────────────────────────────────────

#[test]
fn close_releases_both_files_clean_while_storage_is_alive() {
    let dir = fresh_dir("close");
    let storage = build(&dir, |c| c);
    let repo = storage.domain::<Row>().repo();
    repo.set("a", &row("a", 16)).unwrap();
    repo.get("a").unwrap(); // now cached

    // Open means locked: nothing else can open the file.
    assert!(redb::Database::open(primary(&dir)).is_err());

    let clone = storage.clone();
    storage.close();

    // Closed for every clone, for writes and for reads — cached ones included.
    assert!(is_closed(clone.domain::<Row>().repo().get("a")));
    assert!(is_closed(repo.set("b", &row("b", 16))));
    assert!(is_closed(repo.list()));
    assert!(is_closed(repo.delete("a")));
    assert!(is_closed(repo.history("a", Default::default())));
    assert!(storage.db_manager("rows").is_closed());
    storage.close(); // twice is harmless

    // Released and clean, although `storage` has not been dropped.
    assert!(!needs_full_repair(&primary(&dir)));
    assert!(!needs_full_repair(&backup(&dir)));

    // And the data is there for the next build.
    drop(storage);
    let reopened = build(&dir, |c| c);
    assert_eq!(reopened.domain::<Row>().repo().get("a").unwrap().id, "a");
}

// ─── one open per build ─────────────────────────────────────────────────

#[test]
fn build_opens_each_file_once() {
    let dir = fresh_dir("single_open");

    let before = (opens::count(&primary(&dir)), opens::count(&backup(&dir)));
    let storage = build(&dir, |c| c);
    storage.domain::<Row>().repo().set("a", &row("a", 16)).unwrap();
    storage.close();
    drop(storage);
    let created = (opens::count(&primary(&dir)), opens::count(&backup(&dir)));
    assert_eq!(created, (before.0 + 1, before.1 + 1), "new database");

    // An existing, authenticated database: inspect, upgrade and serve used to
    // open the primary three to four times.
    let storage = build(&dir, |c| c);
    storage.close();
    drop(storage);
    let second = (opens::count(&primary(&dir)), opens::count(&backup(&dir)));
    assert_eq!(second.0, created.0 + 1, "existing database, primary");

    // The backup is the exception once: a `.bak` created by the first build is
    // not yet marked `backup_upgraded`, so the second build runs the one-time
    // format check on it (two more opens) and records the mark. From then on,
    // one open each.
    let storage = build(&dir, |c| c);
    let steady = (opens::count(&primary(&dir)), opens::count(&backup(&dir)));
    assert_eq!(steady, (second.0 + 1, second.1 + 1), "steady state");
    assert_eq!(storage.domain::<Row>().repo().get("a").unwrap().id, "a");
}

// ─── redb cache cap ─────────────────────────────────────────────────────

/// Writes ~4 MiB through `set` (so the backup gets it too), then reads all of
/// both files. Returns the redb cache held by `(primary, backup)` afterwards.
fn cache_after_full_read(dir: &Path, options: impl FnOnce(DatabaseConfig) -> DatabaseConfig) -> (usize, usize) {
    let storage = build(dir, options);
    let repo = storage.domain::<Row>().repo();
    for i in 0..64 {
        repo.set(&format!("r{i:03}"), &row(&format!("r{i:03}"), 64 * 1024)).unwrap();
    }
    assert_eq!(repo.list().unwrap().len(), 64);
    repo.history("r000", Default::default()).unwrap(); // walks the whole backup table

    let dbm = storage.db_manager("rows");
    let primary_used = dbm.db().unwrap().cache_stats().used_bytes();
    let backup_used = dbm
        .backup_manager
        .as_ref()
        .unwrap()
        .db()
        .unwrap()
        .cache_stats()
        .used_bytes();
    (primary_used, backup_used)
}

#[test]
fn redb_cache_bytes_caps_both_files() {
    const CAP: usize = 512 * 1024;

    // Without a cap the same reads keep far more than CAP — otherwise the
    // capped run below would prove nothing.
    let (p, b) = cache_after_full_read(&fresh_dir("cache_uncapped"), |c| c);
    assert!(p > 4 * CAP && b > 4 * CAP, "uncapped: primary {p}, backup {b}");

    let (p, b) = cache_after_full_read(&fresh_dir("cache_capped"), |c| c.redb_cache_bytes(CAP));
    assert!(p <= CAP, "primary holds {p} bytes over a {CAP} cap");
    assert!(b <= CAP, "backup holds {b} bytes over a {CAP} cap");
}

// ─── quick repair ───────────────────────────────────────────────────────

/// Every way clove1db commits. redb decides from the *last* commit whether the
/// next open needs a repair, so each one is tried as the last thing a process
/// does before it dies.
const WRITE_PATHS: &[&str] = &[
    "build",
    "set",
    "delete",
    "commit_batch",
    "restore",
    "set_bulk",
    "restore_bulk",
    "meta",
];

fn run_child(dir: &Path, write_path: &str, quick_repair: bool) {
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "handle_tests::quick_repair_child",
            "--exact",
            "--ignored",
            "--test-threads=1",
        ])
        .env("CLOVE_QR_DIR", dir)
        .env("CLOVE_QR_PATH", write_path)
        .env("CLOVE_QR_ON", if quick_repair { "1" } else { "0" })
        .status()
        .unwrap();
    assert!(status.success(), "child '{write_path}' failed: {status}");
}

/// Builds, writes through one path, and exits without closing anything.
#[test]
#[ignore = "child process of the quick_repair tests; does nothing when run directly"]
fn quick_repair_child() {
    let Ok(dir) = std::env::var("CLOVE_QR_DIR") else {
        return;
    };
    let write_path = std::env::var("CLOVE_QR_PATH").unwrap();
    let quick_repair = std::env::var("CLOVE_QR_ON").unwrap() == "1";

    let storage = build(Path::new(&dir), |c| c.quick_repair(quick_repair));
    let repo = storage.domain::<Row>().repo();
    let dbm = storage.db_manager("rows");
    if write_path != "build" {
        repo.set("a", &row("a", 16)).unwrap();
        repo.set("b", &row("b", 16)).unwrap();
    }

    match write_path.as_str() {
        "build" | "set" => {}
        "delete" => repo.delete("a").unwrap(),
        "commit_batch" => {
            let value = serde_json::to_vec(&row("c", 16)).unwrap();
            dbm.commit_batch(&[("rows".into(), "c".into(), value)], &[("rows".into(), "b".into())])
                .unwrap();
        }
        "restore" => repo.restore_by_version("a", 1).unwrap(),
        "set_bulk" => {
            repo.set_bulk(vec![("a".into(), 1)]).unwrap();
        }
        "restore_bulk" => {
            let bulk = repo.set_bulk(vec![("a".into(), 1), ("b".into(), 1)]).unwrap();
            repo.restore_bulk(&bulk).unwrap();
        }
        "meta" => {
            let meta = dbm.read_meta().unwrap().unwrap();
            dbm.write_meta(&meta).unwrap();
        }
        other => panic!("unknown write path '{other}'"),
    }

    // As a kill or a crash would: no destructor, no close.
    std::process::exit(0);
}

#[test]
fn quick_repair_leaves_nothing_to_repair_after_any_write_path() {
    for write_path in WRITE_PATHS {
        let dir = fresh_dir(&format!("qr_on_{write_path}"));
        run_child(&dir, write_path, true);
        assert!(!needs_full_repair(&primary(&dir)), "primary after '{write_path}'");
        assert!(!needs_full_repair(&backup(&dir)), "backup after '{write_path}'");
    }
}

/// The control: the same exit without quick repair does need a repair, so the
/// probe above can tell the two apart.
#[test]
fn without_quick_repair_an_unclean_exit_needs_a_full_repair() {
    let dir = fresh_dir("qr_off");
    run_child(&dir, "set", false);
    assert!(needs_full_repair(&primary(&dir)));
    assert!(needs_full_repair(&backup(&dir)));
}
