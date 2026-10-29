//! A process killed at the point where a journal backlog is given up on and the index is rebuilt (`index_replay_budget_rebuild`) leaves a database that
//! opens clean: the next open finishes the work, the contains index answers like a full scan, and nothing loops through repair.
//! The child sets the replay budget to 0 (`CLOVE_REPLAY_BUDGET_MS`) so that any backlog is over it, and `CLOVE_CRASH_POINT` makes it exit at the point.
#![cfg(feature = "crash-inject")]
use clove1db::{
    CloveFields, LibraryEvent,
    entity::Entity,
    query::optimizer::Plan,
    storage::{DatabaseConfig, Storage, StorageConfig},
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const TABLE: &str = "docs";
const ROWS: u64 = 6000;

#[derive(Clone, Default, Serialize, Deserialize, CloveFields)]
struct Doc {
    id: String,
    text: String,
}
impl Entity for Doc {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn text(i: u64, variant: u64) -> String {
    format!("row {i} variant {variant} alpha beta gamma delta {} {}", i * 7 % 13, "filler text to make the row longer ".repeat(5))
}

fn rows(variant: u64) -> Vec<(String, String, Vec<u8>)> {
    (0..ROWS)
        .map(|i| (TABLE.to_string(), format!("{i:05}"), serde_json::to_vec(&Doc { id: format!("{i:05}"), text: text(i, variant) }).unwrap()))
        .collect()
}

fn open(root: &Path, seen: &Arc<Mutex<Vec<&'static str>>>) -> Storage {
    let sink = seen.clone();
    let config = StorageConfig::default().event_sink(move |e| {
        if let LibraryEvent::Index { event, .. } = e {
            sink.lock().unwrap().push(*event);
        }
    });
    let db = DatabaseConfig::new("records", "store");
    #[cfg(clove_test_encrypt_all)]
    let db = db.plain();
    Storage::builder(config).add_database(db.dir_path(root.to_path_buf()).has_cache(false).register::<Doc>(TABLE)).build().unwrap()
}

/// (the contains index's answer when it is ready, a full scan's answer)
fn answers(s: &Storage, needle: &str) -> (Option<u64>, u64) {
    let q = s.domain::<Doc>().query().filter(Doc::text.contains(needle));
    let hints = q.test_plans(true).unwrap();
    let indexed = hints.iter().find(|h| h.plan == Plan::IndexContains).map(|h| q.clone().test_force_plan(h.clone()).count().unwrap());
    let scan = hints.iter().find(|h| h.plan == Plan::FullScan).map(|h| q.clone().test_force_plan(h.clone()).count().unwrap()).unwrap();
    (indexed, scan)
}

fn until_indexed(s: &Storage, needle: &str) -> (u64, u64) {
    let start = Instant::now();
    loop {
        let (i, scan) = answers(s, needle);
        if let Some(i) = i {
            return (i, scan);
        }
        assert!(start.elapsed() < Duration::from_secs(60), "the contains index never became ready");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// An index current for variant 0, then every row rewritten and the storage closed at once, so most of the rewrites are still in the journal.
fn with_backlog() -> PathBuf {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let seen = Arc::new(Mutex::new(vec![]));
    let s = open(&root, &seen);
    s.db_manager("store").commit_batch_atomic(&rows(0), &[]).unwrap();
    s.domain::<Doc>().query().filter(Doc::text.contains("alpha")).test_build_indexes().unwrap();
    until_indexed(&s, "alpha");
    s.db_manager("store").commit_batch_atomic(&rows(1), &[]).unwrap();
    s.close();
    root
}

/// The child: opens the database under the 0 budget and the crash point, and so never returns from `open`.
#[test]
#[ignore]
fn child_opens_the_backlog_and_is_killed_at_the_conversion_point() {
    let root = PathBuf::from(std::env::var("CLOVE_KILL_ROOT").unwrap());
    let seen = Arc::new(Mutex::new(vec![]));
    let _s = open(&root, &seen);
}

#[test]
fn a_kill_at_the_conversion_point_leaves_a_database_that_opens_clean() {
    let exe = std::env::current_exe().unwrap();
    let mut root = with_backlog();
    let mut status = None;
    // the backlog is made by closing at once; if the worker still got all of it done (it should not), make another database
    for _ in 0..3 {
        let out = Command::new(&exe)
            .args(["--include-ignored", "--exact", "child_opens_the_backlog_and_is_killed_at_the_conversion_point"])
            .env("CLOVE_KILL_ROOT", &root)
            .env("CLOVE_REPLAY_BUDGET_MS", "0")
            .env("CLOVE_CRASH_POINT", "index_replay_budget_rebuild")
            .output()
            .unwrap();
        status = out.status.code();
        if status == Some(99) {
            break;
        }
        std::fs::remove_dir_all(&root).ok();
        root = with_backlog();
    }
    assert_eq!(status, Some(99), "the child was killed at the conversion point");

    // the next open (normal budget) finishes the work and does not loop through repair
    let seen = Arc::new(Mutex::new(vec![]));
    let s = open(&root, &seen);
    for needle in ["alpha", "variant 1 ", "variant 0 ", "row 77 ", "zzzzz"] {
        let (indexed, scan) = until_indexed(&s, needle);
        assert_eq!(indexed, scan, "the index answers like a scan for {needle:?}");
    }
    assert_eq!(answers(&s, "variant 1 ").1, ROWS, "every row is the rewritten one");
    assert_eq!(answers(&s, "variant 0 ").1, 0);
    let events = seen.lock().unwrap().clone();
    assert!(events.iter().filter(|e| e.starts_with("index/rebuild/replay_budget")).count() <= 1, "no repair loop: {events:?}");
    s.close();
    std::fs::remove_dir_all(&root).ok();
}
