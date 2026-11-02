//! Queries that run while the index file is compacted and swapped must not fail. The worker builds the
//! compacted file beside the old one, renames it over the old one, and drops the old database; a query
//! that took the published snapshot before the swap still reads from the old database, which must stay
//! open until the last such query is done.
use clove1db::{
    CloveFields, LibraryEvent,
    entity::Entity,
    query::optimizer::Plan,
    storage::{DatabaseConfig, Storage, StorageConfig},
};
use serde::{Deserialize, Serialize};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Doc {
    id: String,
    words: String,
}
impl Entity for Doc {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn words_of(i: u64) -> String {
    // Eight words per row from a vocabulary of 4096: the index has about 30,000 x 8 entries.
    let mut x = i.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(7);
    (0..8)
        .map(|_| {
            x ^= x >> 29;
            x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
            format!("w{:03x}", (x >> 20) % 4096)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// One run: returns (queries made, queries that failed, whether the index was compacted).
fn one_run() -> (u64, u64, bool) {
    const ROWS: u64 = 30_000;
    let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let compacted = Arc::new(AtomicBool::new(false));
    let flag = compacted.clone();
    let config = StorageConfig::default().event_sink(move |e: &LibraryEvent| {
        if let LibraryEvent::Index { event, .. } = e
            && *event == "index/compact"
        {
            flag.store(true, Ordering::Release);
        }
    });
    let db = DatabaseConfig::new("records", "store").dir_path(dir.clone()).has_cache(false);
    #[cfg(clove_test_encrypt_all)]
    let db = db.plain();
    let s = Storage::builder(config).add_database(db.register::<Doc>("docs")).build().unwrap();
    let domain = s.domain::<Doc>();
    let rows: Vec<Doc> = (0..ROWS).map(|i| Doc { id: format!("d{i:06}"), words: words_of(i) }).collect();
    for chunk in rows.chunks(1000) {
        let writes: Vec<(&str, &Doc)> = chunk.iter().map(|d| (d.id.as_str(), d)).collect();
        domain.repo().commit_entities(&writes, &[]).unwrap();
    }
    let needle = |i: u64| format!("w{:03x}", i % 4096);
    let expected = |w: &str| rows.iter().filter(|d| d.words.split(' ').any(|x| x == w)).count() as u64;
    let queries = Arc::new(AtomicU64::new(0));
    let failures = Arc::new(AtomicU64::new(0));
    let wrong = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    // A second thread asks all the time; this one also watches for the swap.
    let helper = {
        let (storage, queries, failures, stop) = (s.clone(), queries.clone(), failures.clone(), stop.clone());
        std::thread::spawn(move || {
            let domain = storage.domain::<Doc>();
            let mut i = 1u64;
            while !stop.load(Ordering::Relaxed) {
                match domain.query().filter(Doc::words.text(format!("w{:03x}", i % 4096))).count() {
                    Ok(_) => {}
                    Err(_) => {
                        failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
                queries.fetch_add(1, Ordering::Relaxed);
                i += 7;
            }
        })
    };
    let started = Instant::now();
    let mut after_swap = None;
    let mut i = 0u64;
    // The index is now built in one sorted pass and is hardly fragmented, so the compaction is asked for (once the index exists, and again every second until it happened)
    let mut asked = Instant::now();
    while started.elapsed() < Duration::from_secs(90) {
        if started.elapsed() > Duration::from_secs(3) && asked.elapsed() > Duration::from_secs(1) && !compacted.load(Ordering::Acquire) {
            s.test_request_index_compaction();
            asked = Instant::now();
        }
        let w = needle(i * 13 + 5);
        let q = domain.query().filter(Doc::words.text(w.clone()));
        queries.fetch_add(1, Ordering::Relaxed);
        match q.count() {
            Ok(n) => {
                // Checked against the rows only now and then: counting the rows is slow.
                if i % 97 == 0 && n != expected(&w) {
                    wrong.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(_) => {
                failures.fetch_add(1, Ordering::Relaxed);
            }
        }
        i += 1;
        if compacted.load(Ordering::Acquire) && after_swap.is_none() {
            after_swap = Some(Instant::now());
        }
        if after_swap.is_some_and(|t| t.elapsed() > Duration::from_millis(500)) {
            break;
        }
    }
    stop.store(true, Ordering::Relaxed);
    helper.join().unwrap();
    // The index answers right after the swap too.
    let w = needle(11);
    let planned = domain.query().filter(Doc::words.text(w.clone())).explain().map(|e| e.selected).ok();
    let n = domain.query().filter(Doc::words.text(w.clone())).count();
    let wrong_after = n.as_ref().map(|n| *n != expected(&w)).unwrap_or(true);
    let (made, failed, did) = (queries.load(Ordering::Relaxed), failures.load(Ordering::Relaxed), compacted.load(Ordering::Acquire));
    s.close();
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(wrong.load(Ordering::Relaxed), 0, "a query returned a wrong count");
    assert!(!wrong_after, "the query after the swap is wrong");
    assert!(planned == Some(Plan::IndexText) || !did, "the index is used after the swap: {planned:?}");
    (made, failed, did)
}

#[test]
fn no_query_fails_while_the_index_file_is_compacted_and_swapped() {
    let runs: usize = std::env::var("CLOVE_SWAP_RUNS").ok().and_then(|v| v.parse().ok()).unwrap_or(1);
    let (mut made, mut failed, mut compactions) = (0u64, 0u64, 0usize);
    let mut failing_runs = 0;
    for run in 0..runs {
        let (m, f, c) = one_run();
        made += m;
        failed += f;
        compactions += usize::from(c);
        failing_runs += usize::from(f > 0);
        println!("SWAPRUN run={run} queries={m} failed={f} compacted={c}");
    }
    println!("SWAPSTAT runs={runs} runs_with_a_failure={failing_runs} compactions_seen={compactions} queries={made} failed={failed}");
    assert_eq!(compactions, runs, "the workload did not make the index compact in every run: the test would prove nothing");
    assert_eq!(failed, 0, "{failed} queries failed in {failing_runs} of {runs} runs");
}
