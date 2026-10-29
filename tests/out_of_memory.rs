//! Every allocation site the library reserves for (`clove1db::memory::ALLOC_SITES`) returns
//! `ClError::OutOfMemory` when the reservation is refused, before anything is committed,
//! and the database opens intact afterwards. Refusal is injected per site (`crash-inject`).
//! The injection is process-wide, so this file holds one test and runs the sites one after another.
#![cfg(feature = "crash-inject")]
use clove1db::{
    CloveFields, entity::Entity, memory::ALLOC_SITES, repository::Repository,
    storage::{DatabaseConfig, Storage, StorageConfig}, test_fail_allocation, units::ClError, LibraryEvent,
};
use serde::{Deserialize, Serialize};
use std::{path::{Path, PathBuf}, sync::atomic::{AtomicUsize, Ordering}, thread, time::Duration};

#[derive(Clone, Debug, Default, Serialize, Deserialize, CloveFields)]
struct Note { id: String, n: i64, title: String }
impl Entity for Note { fn entity_id(&self) -> &str { &self.id } }

const SEEDED: usize = 300;

/// How many times the index worker told the programmer it was refused memory.
static WORKER_OOM_EVENTS: AtomicUsize = AtomicUsize::new(0);

fn open(root: &Path) -> Storage {
    let config = StorageConfig::default().event_sink(|event| {
        if matches!(event, LibraryEvent::Index { event: "index/out_of_memory", .. }) {
            WORKER_OOM_EVENTS.fetch_add(1, Ordering::SeqCst);
        }
    });
    Storage::builder(config)
        .add_database(DatabaseConfig::new("records", "store").dir_path(root.to_path_buf()).backup_enabled(true).has_cache(false).register::<Note>("notes"))
        .build()
        .unwrap()
}

fn row(i: usize) -> (String, String, Vec<u8>) {
    let id = format!("{i:05}");
    ("notes".into(), id.clone(), serde_json::to_vec(&Note { id, n: (i % 7) as i64, title: format!("alpha note number {i}") }).unwrap())
}

fn seeded() -> (PathBuf, Storage) {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = open(&root);
    let rows = (0..SEEDED).map(row).collect::<Vec<_>>();
    s.db_manager("store").commit_batch_atomic(&rows, &[]).unwrap();
    (root, s)
}

/// The refusal came from `site`, and carries the site's name.
fn expect_oom<T: std::fmt::Debug>(result: Result<T, ClError>, site: &str) {
    match result {
        Err(ClError::OutOfMemory { site: got, .. }) => assert_eq!(got, site, "the error names the site that refused"),
        other => panic!("{site}: expected OutOfMemory, got {other:?}"),
    }
}

fn head(s: &Storage) -> u64 { s.db_manager("store").journal_head().unwrap() }
fn rows_in(s: &Storage) -> usize { s.db_manager("store").read_view_at_head().unwrap().table_entries("notes").unwrap().len() }

/// Close, reopen, and check that every seeded row is there, parses, and matches its key.
fn reopen_intact(root: &Path, s: Storage, what: &str) {
    s.close();
    let s = open(root);
    let rows = s.db_manager("store").read_view_at_head().unwrap().table_entries("notes").unwrap();
    assert_eq!(rows.len(), SEEDED, "{what}: the reopened database has exactly the seeded rows");
    for (key, bytes) in rows {
        let note: Note = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(note.id, key, "{what}: row integrity");
    }
    s.close();
}

#[test]
fn every_site_returns_out_of_memory_and_leaves_the_database_intact() {
    assert_eq!(ALLOC_SITES.len(), 10, "a new site needs a case below");
    for &site in ALLOC_SITES {
        let (root, s) = seeded();
        let db = s.db_manager("store");
        let repo = Repository::<Note>::new("notes", db.clone());
        let mut head_before = head(&s);
        let extra = row(SEEDED + 1);

        match site {
            "write.change_rows" | "journal.encode_row" => {
                test_fail_allocation(Some(site));
                expect_oom(db.commit_batch_atomic(std::slice::from_ref(&extra), &[]), site);
                test_fail_allocation(None);
            }
            "write.single_row" | "backup.encode_record" => {
                test_fail_allocation(Some(site));
                let note = Note { id: extra.1.clone(), n: 1, title: "x".into() };
                expect_oom(repo.set(&note.id, &note), site);
                test_fail_allocation(None);
            }
            "journal.read_rows" => {
                // Two retained changes for the consumer to read: a row written and removed again.
                let token = db.register_consumer("reader").unwrap();
                let from = head(&s);
                db.commit_batch_atomic(std::slice::from_ref(&extra), &[]).unwrap();
                db.commit_batch_atomic(&[], &[("notes".into(), extra.1.clone())]).unwrap();
                head_before = head(&s);
                test_fail_allocation(Some(site));
                expect_oom(db.read_changes(&token, from, 10), site);
                test_fail_allocation(None);
                assert_eq!(db.read_changes(&token, from, 10).unwrap().len(), 2, "the same read works once memory is back");
            }
            "journal.table_entries" => {
                let view = db.read_view_at_head().unwrap();
                test_fail_allocation(Some(site));
                expect_oom(view.table_entries("notes"), site);
                test_fail_allocation(None);
            }
            "repository.list_rows" => {
                test_fail_allocation(Some(site));
                expect_oom(repo.list_map(|n| n.id), site);
                test_fail_allocation(None);
            }
            "query.collect_rows" => {
                // Both shapes of result set: unordered (rows kept as read) and ordered (rows kept in a heap).
                let unordered = s.domain::<Note>().query().filter(Note::n.ge(0));
                let ordered = s.domain::<Note>().query().filter(Note::n.ge(0)).order_by(Note::id, clove1db::query::Desc).limit(25);
                test_fail_allocation(Some(site));
                expect_oom(unordered.collect(), site);
                expect_oom(ordered.collect(), site);
                test_fail_allocation(None);
                assert_eq!(unordered.collect().unwrap().len(), SEEDED, "the same query works once memory is back");
                assert_eq!(ordered.collect().unwrap().len(), 25);
            }
            "index.row_terms" | "index.trigram_build" => {
                // The index worker is refused while building a contains index: the programmer's queries stay
                // correct (by scan), the worker backs off, and the index is built once memory is back.
                test_fail_allocation(Some(site));
                let query = s.domain::<Note>().query().filter(Note::title.contains("note number 1"));
                let expected = (0..SEEDED).filter(|i| format!("alpha note number {i}").contains("note number 1")).count() as u64;
                for _ in 0..40 { assert_eq!(query.count().unwrap(), expected); }
                // The request waits for the index, so it runs beside the checks below. A refused worker drops
                // the request (as it does after any worker error); the optimizer or the caller asks again.
                let events_before = WORKER_OOM_EVENTS.load(Ordering::SeqCst);
                let _first_request = { let q = query.clone(); thread::spawn(move || q.test_build_indexes()) };
                thread::sleep(Duration::from_millis(1200));
                assert_eq!(query.count().unwrap(), expected, "a refused index build never changes a result");
                assert!(!s.index_report().iter().any(|r| r.ready), "no index became ready while the worker was refused");
                assert!(WORKER_OOM_EVENTS.load(Ordering::SeqCst) > events_before, "the programmer is told the index worker was refused memory");
                test_fail_allocation(None);
                query.test_build_indexes().expect("the index is built once memory is back and it is asked for again");
                assert!(s.index_report().iter().any(|r| r.ready));
                assert_eq!(query.count().unwrap(), expected);
            }
            other => panic!("site {other} has no case"),
        }

        assert_eq!(head(&s), head_before, "{site}: nothing was committed");
        assert_eq!(rows_in(&s), SEEDED, "{site}: no row was written");
        // The database keeps working in the same process once memory is back.
        db.commit_batch_atomic(&[row(SEEDED + 2)], &[]).unwrap();
        assert!(head(&s) > head_before, "{site}: writes work again");
        assert!(db.read_view_at_head().unwrap().table_entries("notes").unwrap().iter().any(|(k, _)| *k == row(SEEDED + 2).1));
        db.commit_batch_atomic(&[], &[("notes".into(), row(SEEDED + 2).1)]).unwrap();
        reopen_intact(&root, s, site);
        let _ = std::fs::remove_dir_all(&root);
    }
}
