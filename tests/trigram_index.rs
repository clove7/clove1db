//! The contains (trigram) index returns exactly what a full scan returns: after the build, after updates, deletes and new rows
//! are replayed, after a table reset, and after the database is closed and opened again.
#![cfg(feature = "crash-inject")]
use clove1db::{CloveFields, entity::Entity, query::optimizer::Plan, storage::{DatabaseConfig, Storage, StorageConfig}};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path, thread, time::{Duration, Instant}};

#[derive(Clone, Default, Serialize, Deserialize, CloveFields)]
struct Doc { id: String, text: String }
impl Entity for Doc { fn entity_id(&self) -> &str { &self.id } }

const WORDS: [&str; 24] = ["alpha", "beta", "the", "quick", "brown", "fox", "ça va", "日本語テキスト", "naïve", "😀 ok", "x1", "ab", "z", "running", "walking", "a b c", "Zeta", "THE", "mañana", "straße", "go", "i", "ing ", "  "];
const NEEDLES: [&str; 14] = ["the", "alpha", "ing ", "ça v", "日本語", "テキス", "😀 o", "a b", "zzz", "Zet", "ñan", "raße", "abc", "e q"];

fn lcg(s: &mut u64) -> u64 { *s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407); *s >> 33 }
fn text(s: &mut u64) -> String {
    let n = lcg(s) % 7;
    (0..n).map(|_| WORDS[(lcg(s) % WORDS.len() as u64) as usize]).collect::<Vec<_>>().join(" ")
}
fn bytes(id: &str, text: &str) -> Vec<u8> { serde_json::to_vec(&Doc { id: id.into(), text: text.into() }).unwrap() }

fn open(root: &Path) -> Storage {
    Storage::builder(StorageConfig::default())
        .add_database(DatabaseConfig::new("records", "store").dir_path(root.to_path_buf()).has_cache(false).register::<Doc>("docs"))
        .build()
        .unwrap()
}

/// Waits until the index worker has applied everything written (the hints appear only for a current index).
fn settled(s: &Storage, needle: &str) {
    let started = Instant::now();
    loop {
        let q = s.domain::<Doc>().query().filter(Doc::text.contains(needle));
        if q.test_plans(false).unwrap().iter().any(|h| h.plan == Plan::IndexContains) { return }
        assert!(started.elapsed() < Duration::from_secs(60), "the contains index never became current");
        thread::sleep(Duration::from_millis(10));
    }
}

/// Every needle: the automatic answer, a forced full scan and a forced contains-index plan all equal the model.
fn check(s: &Storage, model: &BTreeMap<String, String>, label: &str) {
    for needle in NEEDLES {
        settled(s, needle);
        let expected = model.iter().filter(|(_, t)| t.contains(needle)).map(|(k, _)| k.clone()).collect::<Vec<_>>();
        let q = s.domain::<Doc>().query().filter(Doc::text.contains(needle));
        let hints = q.test_plans(false).unwrap();
        let index = hints.iter().find(|h| h.plan == Plan::IndexContains).unwrap().clone();
        let scan = hints.iter().find(|h| h.plan == Plan::FullScan).unwrap().clone();
        let by_index = q.clone().test_force_plan(index).collect().unwrap().into_iter().map(|d| d.id).collect::<Vec<_>>();
        let by_scan = q.clone().test_force_plan(scan).collect().unwrap().into_iter().map(|d| d.id).collect::<Vec<_>>();
        assert_eq!(by_scan, expected, "{label}: scan {needle:?}");
        assert_eq!(by_index, expected, "{label}: index {needle:?}");
        assert_eq!(q.count().unwrap() as usize, expected.len(), "{label}: count {needle:?}");
    }
}

#[test]
fn contains_index_equals_the_scan_through_updates_deletes_reset_and_reopen() {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let mut seed = 11u64;
    let mut model = BTreeMap::<String, String>::new();
    let s = open(&root);
    let db = s.db_manager("store");
    let rows = (0..3000).map(|i| { let id = format!("d{i:05}"); let t = text(&mut seed); model.insert(id.clone(), t.clone()); ("docs".to_string(), id.clone(), bytes(&id, &t)) }).collect::<Vec<_>>();
    for chunk in rows.chunks(500) { db.commit_batch_atomic(chunk, &[]).unwrap(); }

    // Ask for the index (built in the worker), then compare.
    let q = s.domain::<Doc>().query().filter(Doc::text.contains("the"));
    q.test_build_indexes().unwrap();
    check(&s, &model, "after build");

    // Updates (same row, new text), deletes, and new rows, in several commits.
    for round in 0..4 {
        let mut upserts = vec![];
        let mut deletes = vec![];
        for _ in 0..120 {
            let id = format!("d{:05}", lcg(&mut seed) % 3200);
            if lcg(&mut seed) % 4 == 0 { if model.remove(&id).is_some() { deletes.push(("docs".to_string(), id)); } }
            else { let t = text(&mut seed); model.insert(id.clone(), t.clone()); upserts.push(("docs".to_string(), id.clone(), bytes(&id, &t))); }
        }
        // a key that is both written and deleted in one commit is not valid input for the batch: keep the deletes only
        upserts.retain(|(_, id, _)| !deletes.iter().any(|(_, d)| d == id));
        for (_, id) in &deletes { model.remove(id); }
        for (_, id, b) in &upserts { let d: Doc = serde_json::from_slice(b).unwrap(); model.insert(id.clone(), d.text); }
        db.commit_batch_atomic(&upserts, &deletes).unwrap();
        check(&s, &model, &format!("after commit {round}"));
    }

    // A reset of the whole table.
    let fresh = (0..800).map(|i| { let id = format!("r{i:04}"); (id.clone(), bytes(&id, &text(&mut seed))) }).collect::<Vec<_>>();
    model.clear();
    for (id, b) in &fresh { let d: Doc = serde_json::from_slice(b).unwrap(); model.insert(id.clone(), d.text); }
    db.replace_table("docs", &fresh).unwrap();
    check(&s, &model, "after reset");

    // Write again after the reset, then close and open.
    let more = (0..50).map(|i| { let id = format!("m{i:03}"); let t = text(&mut seed); model.insert(id.clone(), t.clone()); ("docs".to_string(), id.clone(), bytes(&id, &t)) }).collect::<Vec<_>>();
    db.commit_batch_atomic(&more, &[]).unwrap();
    check(&s, &model, "after writes following the reset");
    s.close();
    drop(s);
    let s = open(&root);
    check(&s, &model, "after reopen");
    s.close();
    let _ = std::fs::remove_dir_all(&root);
}
