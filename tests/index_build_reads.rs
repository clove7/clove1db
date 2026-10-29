//! While an index is being built, a reader sees what it saw before: the index is not used until it is ready,
//! and every answer equals a full scan of the same data. The worker publishes a fresh `.inx` read snapshot after
//! each build commit; this checks that doing so changes nothing a reader can observe.
#![cfg(feature = "crash-inject")]
use clove1db::{CloveFields, entity::Entity, query::optimizer::Plan, storage::{DatabaseConfig, Storage, StorageConfig}};
use serde::{Deserialize, Serialize};
use std::{thread, time::{Duration, Instant}};

#[derive(Clone, Default, Serialize, Deserialize, CloveFields)]
struct Note { id: String, n: i64, title: String }
impl Entity for Note { fn entity_id(&self) -> &str { &self.id } }

const ROWS: usize = 20_000;

fn is_index_plan(plan: Plan) -> bool { format!("{plan:?}").contains("Index") }

#[test]
fn readers_see_the_same_answers_while_an_index_is_built() {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = Storage::builder(StorageConfig::default())
        .add_database(DatabaseConfig::new("records", "store").dir_path(root.clone()).has_cache(false).register::<Note>("notes"))
        .build()
        .unwrap();
    let db = s.db_manager("store");
    let rows = (0..ROWS)
        .map(|i| {
            let id = format!("{i:06}");
            ("notes".to_string(), id.clone(), serde_json::to_vec(&Note { id, n: (i % 17) as i64, title: format!("alpha note number {i} with some more words around it to make the row longer {}", i * 7) }).unwrap())
        })
        .collect::<Vec<_>>();
    for chunk in rows.chunks(2000) { db.commit_batch_atomic(chunk, &[]).unwrap(); }

    let query = s.domain::<Note>().query().filter(Note::title.contains("number 12"));
    let scan_hint = query.test_plans(true).unwrap().into_iter().find(|h| h.plan == Plan::FullScan).unwrap();
    let expected = (0..ROWS).filter(|i| format!("alpha note number {i} with some more words around it to make the row longer {}", i * 7).contains("number 12")).count() as u64;

    // Ask for the index in another thread; the build runs in the index worker in small commits.
    let building = { let q = query.clone(); thread::spawn(move || q.test_build_indexes()) };
    let (mut during, mut after) = (0usize, 0usize);
    let started = Instant::now();
    loop {
        let ready_before = s.index_report().iter().any(|r| r.ready);
        let counted = query.count().unwrap();
        let scanned = query.clone().test_force_plan(scan_hint.clone()).count().unwrap();
        let plan = query.explain().unwrap().selected;
        let ready_after = s.index_report().iter().any(|r| r.ready);
        assert_eq!(counted, expected, "the answer is right at every moment");
        assert_eq!(scanned, expected, "and so is a full scan");
        if !ready_before && !ready_after {
            assert!(!is_index_plan(plan), "an index that is not ready is never used, got {plan:?}");
            during += 1;
        } else if ready_before {
            after += 1;
        }
        if ready_before && after >= 3 { break }
        assert!(started.elapsed() < Duration::from_secs(120), "the index never became ready");
    }
    building.join().unwrap().unwrap();
    assert!(during > 0, "the test must have read while the build was still running (read {during} times)");
    assert!(is_index_plan(query.explain().unwrap().selected), "once ready the index is used");
    assert_eq!(query.collect().unwrap().len() as u64, expected);
    s.close();
    let _ = std::fs::remove_dir_all(&root);
}
