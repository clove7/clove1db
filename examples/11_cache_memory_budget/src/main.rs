//! # 11 — Cache memory budget
//!
//! Six experiments on what the cache actually costs, each one printing numbers
//! you can check rather than a claim you have to believe.
//!
//! They exist because of a real incident. A production database of launcher run
//! logs was configured `cache(10_000, 300, 60)` — ten thousand entries, a
//! five-minute TTL. Each row carried a serialized snapshot, so "ten thousand
//! entries" was ten thousand times a number nobody had written down. A
//! ninety-day range scan walked the whole history through that cache, the live
//! heap rose by ~100 MiB, and it stayed there for **thirteen hours** despite the
//! five-minute TTL.
//!
//! Three separate things had to be true for that to happen, and each experiment
//! below isolates one:
//!
//! | # | Question |
//! |---|---|
//! | 1 | Does an entry count bound memory? |
//! | 2 | Does a byte budget bound it? |
//! | 3 | Does a bulk scan evict the rows the cache was for? (no - see inside) |
//! | 4 | Does `get_uncached` leave the cache alone? |
//! | 5 | Does an expired entry free its memory on its own? |
//! | 6 | What does all of it cost in time? |
//!
//! Run with `cargo run --release` from this directory.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use clove1db::{
    entity::Entity,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::Result,
};

// ═══════════════════════════════════════════════════════════
// A row whose size is the caller's business, not the cache's
// ═══════════════════════════════════════════════════════════

/// Modelled on the row that caused the incident: a handful of small fields and
/// one unbounded blob. The cache cannot know how big `snapshot` is, which is the
/// whole problem with counting entries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct RunLog {
    id: String,
    device_id: String,
    started_at: i64,
    /// The unbounded one.
    snapshot: String,
}

impl Entity for RunLog {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// A small, genuinely hot row — the kind a cache is actually for. In the real
/// database this was the per-day index of run ids.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct DayIndex {
    id: String,
    run_ids: Vec<String>,
}

impl Entity for DayIndex {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

// ═══════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════

const KIB: usize = 1024;
const MIB: u64 = 1024 * 1024;

fn mib(bytes: u64) -> f64 {
    bytes as f64 / MIB as f64
}

fn run_log(i: usize, snapshot_bytes: usize) -> RunLog {
    RunLog {
        id: format!("run-{i:06}"),
        device_id: format!("device-{}", i % 16),
        started_at: 1_700_000_000 + i as i64,
        snapshot: "x".repeat(snapshot_bytes),
    }
}

/// A fresh database directory per experiment, so no run inherits another's
/// cache or files.
fn fresh_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("clove1db_ex11_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn open(tag: &str, cache: impl FnOnce(DatabaseConfig) -> DatabaseConfig) -> (Storage, PathBuf) {
    let dir = fresh_dir(tag);
    let storage = Storage::builder(StorageConfig::default().change_dir_path(dir.clone()))
        .add_database(
            cache(DatabaseConfig::new("logs_db", "logs"))
                .backup_enabled(false)
                .register::<RunLog>("run_logs")
                .register::<DayIndex>("day_indexes"),
        )
        .build()
        .expect("storage");
    (storage, dir)
}

fn seed(storage: &Storage, count: usize, snapshot_bytes: usize) -> Result<()> {
    let repo = storage.domain::<RunLog>().repo();
    for i in 0..count {
        let row = run_log(i, snapshot_bytes);
        repo.set(&row.id, &row)?;
    }
    Ok(())
}

fn header(n: u32, title: &str) {
    println!("\n{}", "═".repeat(72));
    println!("  Experiment {n} — {title}");
    println!("{}", "═".repeat(72));
}

// ═══════════════════════════════════════════════════════════
// 1. An entry count does not bound memory
// ═══════════════════════════════════════════════════════════

/// The same cache "capacity", three row sizes. If capacity were a memory bound,
/// the three totals would be similar. They differ by the row size, exactly.
fn experiment_1_entry_count_is_not_a_bound() -> Result<()> {
    header(1, "an entry count is not a memory bound");
    println!(
        "  A 2,000-entry budget, filled with rows of three different sizes.\n\
         If 'capacity' bounded memory these would all land in the same place.\n"
    );
    println!("  {:>10} │ {:>12} │ {:>10}", "row size", "cached", "entries");
    println!("  {:─>10}─┼─{:─>12}─┼─{:─>10}", "", "", "");

    const ENTRIES: u64 = 2_000;
    for &size in &[1 * KIB, 8 * KIB, 64 * KIB] {
        // A byte budget large enough never to be the binding constraint here —
        // so what we are measuring is the entry count doing the bounding.
        let (storage, _dir) = open("e1", |c| c.cache_bytes(4096 * MIB, 300, 300));
        seed(&storage, ENTRIES as usize, size)?;

        let repo = storage.domain::<RunLog>().repo();
        for i in 0..ENTRIES as usize {
            let _ = repo.get(&format!("run-{i:06}"))?;
        }
        repo.run_cache_maintenance();
        let (bytes, entries) = repo.cache_stats();
        println!(
            "  {:>8} KiB │ {:>9.1} MiB │ {:>10}",
            size / KIB,
            mib(bytes),
            entries
        );
    }

    println!(
        "\n  Same count, ~64x the memory. This is the incident in one table:\n\
         the operator wrote a count, the machine paid a size, and nothing in\n\
         the API connected the two."
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════
// 2. A byte budget does bound memory
// ═══════════════════════════════════════════════════════════

/// The same three row sizes against a byte budget. The totals should now be
/// flat, and under the budget, regardless of how big a row is.
fn experiment_2_a_byte_budget_holds() -> Result<()> {
    header(2, "a byte budget holds, whatever the row size");
    const BUDGET_MIB: u64 = 8;
    println!(
        "  An {BUDGET_MIB} MiB budget, same three row sizes, 2,000 rows read into each.\n"
    );
    println!(
        "  {:>10} │ {:>12} │ {:>10} │ {:>8}",
        "row size", "cached", "entries", "budget"
    );
    println!(
        "  {:─>10}─┼─{:─>12}─┼─{:─>10}─┼─{:─>8}",
        "", "", "", ""
    );

    let mut all_within = true;
    for &size in &[1 * KIB, 8 * KIB, 64 * KIB] {
        let (storage, _dir) = open("e2", |c| c.cache_bytes(BUDGET_MIB * MIB, 300, 300));
        seed(&storage, 2_000, size)?;

        let repo = storage.domain::<RunLog>().repo();
        for i in 0..2_000usize {
            let _ = repo.get(&format!("run-{i:06}"))?;
        }
        repo.run_cache_maintenance();
        let (bytes, entries) = repo.cache_stats();

        // moka enforces the budget asynchronously, so allow a small overshoot
        // rather than pretending eviction is instantaneous.
        let within = bytes <= BUDGET_MIB * MIB * 2;
        all_within &= within;
        println!(
            "  {:>8} KiB │ {:>9.1} MiB │ {:>10} │ {:>8}",
            size / KIB,
            mib(bytes),
            entries,
            if within { "ok" } else { "OVER" }
        );
    }

    println!(
        "\n  {}",
        if all_within {
            "Flat, and bounded. The row size now costs budget instead of being free."
        } else {
            "!! A budget was exceeded — the weigher is not doing its job."
        }
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════
// 3. A bulk scan evicts the rows the cache was for
// ═══════════════════════════════════════════════════════════

/// Written to demonstrate cache pollution - a bulk scan flushing the small hot
/// rows out of the cache. It does not, and the measurement is kept because
/// being wrong about this is worth more than the point it was meant to make.
///
/// `moka` admits entries through a TinyLFU filter, which is frequency-aware: a
/// key seen once during a scan does not get to evict a key that is read
/// regularly, however many of them arrive. The hot set survives intact.
///
/// So a bulk scan costs **memory and time, not the hit rate** - which also
/// narrows what `get_uncached` is for. It is not protecting the hot set;
/// `moka` already does that. It is not spending the budget.
fn experiment_3_a_bulk_scan_does_not_evict_the_hot_set() -> Result<()> {
    header(3, "a bulk scan does NOT evict the hot set");
    let (storage, _dir) = open("e3", |c| c.cache_bytes(8 * MIB, 300, 300));

    // The hot set: small index rows, read constantly.
    let idx = storage.domain::<DayIndex>().repo();
    for d in 0..64 {
        let row = DayIndex {
            id: format!("day-{d:03}"),
            run_ids: (0..8).map(|i| format!("run-{i:06}")).collect(),
        };
        idx.set(&row.id, &row)?;
    }
    for d in 0..64 {
        let _ = idx.get(&format!("day-{d:03}"))?;
    }
    idx.run_cache_maintenance();
    let (before, _) = idx.cache_stats();
    println!("  hot set cached            : {:.2} MiB", mib(before));

    // Now the scan: 4,000 heavy rows, walked once, never read again.
    seed(&storage, 4_000, 8 * KIB)?;
    let logs = storage.domain::<RunLog>().repo();

    // `set` populates the cache too, so the seeding just filled it. Clear and
    // re-warm only the hot set, so what follows measures the *scan*.
    logs.clear_cache();
    for d in 0..64 {
        let _ = idx.get(&format!("day-{d:03}"))?;
    }
    idx.run_cache_maintenance();

    for i in 0..4_000usize {
        let _ = logs.get(&format!("run-{i:06}"))?;
    }
    logs.run_cache_maintenance();

    // How much of the hot set survived?
    let mut survived = 0;
    for d in 0..64 {
        let key = format!("day_indexes:day-{d:03}");
        if storage
            .db_manager("logs")
            .memory_cache
            .contains_key(&key)
        {
            survived += 1;
        }
    }
    let (after, entries) = logs.cache_stats();
    println!("  after a 4,000-row scan    : {:.2} MiB in {entries} entries", mib(after));
    println!("  hot rows still cached     : {survived} of 64");
    println!(
        "\n  {}",
        if survived == 64 {
            "The hot set survived intact. moka admits through a TinyLFU filter, so a key\n  \
             seen once during a scan does not get to evict a key read regularly. This\n  \
             experiment was written expecting the opposite; the measurement won. A scan\n  \
             costs the memory budget it consumes and the time it takes - not the hit\n  \
             rate of the workload beside it."
        } else {
            "Some of the hot set was evicted - trust the survival count above rather\n  \
             than this sentence."
        }
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════
// 4. `get_uncached` leaves the cache alone
// ═══════════════════════════════════════════════════════════

fn experiment_4_uncached_reads_leave_it_alone() -> Result<()> {
    header(4, "get_uncached leaves the cache alone");
    let (storage, _dir) = open("e4", |c| c.cache_bytes(64 * MIB, 300, 300));

    let idx = storage.domain::<DayIndex>().repo();
    for d in 0..64 {
        let row = DayIndex {
            id: format!("day-{d:03}"),
            run_ids: (0..8).map(|i| format!("run-{i:06}")).collect(),
        };
        idx.set(&row.id, &row)?;
        let _ = idx.get(&row.id)?;
    }
    seed(&storage, 4_000, 8 * KIB)?;
    let logs = storage.domain::<RunLog>().repo();

    // `set` populates the cache as well as `get`, so the seeding above just put
    // all 4,000 rows in it. Clear, then re-warm only the hot set, so what is
    // measured below is the reads and nothing else.
    logs.clear_cache();
    for d in 0..64 {
        let _ = idx.get(&format!("day-{d:03}"))?;
    }
    idx.run_cache_maintenance();
    let (before, entries_before) = idx.cache_stats();

    let mut checksum = 0usize;
    for i in 0..4_000usize {
        let row = logs.get_uncached(&format!("run-{i:06}"))?;
        checksum += row.snapshot.len();
    }
    logs.run_cache_maintenance();
    let (after, entries_after) = logs.cache_stats();

    let mut survived = 0;
    for d in 0..64 {
        if storage
            .db_manager("logs")
            .memory_cache
            .contains_key(&format!("day_indexes:day-{d:03}"))
        {
            survived += 1;
        }
    }

    println!("  hot set before scan       : {:.2} MiB in {entries_before} entries", mib(before));
    println!("  after 4,000 uncached reads: {:.2} MiB in {entries_after} entries", mib(after));
    println!("  hot rows still cached     : {survived} of 64");
    println!("  rows really read          : {} bytes of snapshot", checksum);
    println!(
        "\n  Same data, same 4,000 reads, cache untouched. This is the read for a\n\
         key you are walking past rather than coming back to."
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════
// 5. Expired is not freed
// ═══════════════════════════════════════════════════════════

/// The thirteen hours. An entry expires on a clock; its memory comes back
/// during maintenance, and maintenance runs when the cache is used.
fn experiment_5_expired_is_not_freed() -> Result<()> {
    header(5, "expired is not the same as freed");
    // A two-second TTL so the example finishes, and a budget big enough that
    // nothing is evicted for space — expiry is the only thing under test.
    let (storage, _dir) = open("e5", |c| c.cache_bytes(256 * MIB, 2, 2));
    seed(&storage, 1_500, 8 * KIB)?;

    let repo = storage.domain::<RunLog>().repo();
    for i in 0..1_500usize {
        let _ = repo.get(&format!("run-{i:06}"))?;
    }
    repo.run_cache_maintenance();
    let (filled, n_filled) = repo.cache_stats();
    println!("  just filled               : {:.2} MiB in {n_filled} entries", mib(filled));

    println!("  ... waiting 4s for a 2s TTL to pass, touching nothing ...");
    std::thread::sleep(Duration::from_secs(4));

    let (idle, n_idle) = repo.cache_stats();
    println!("  TTL long past, untouched  : {:.2} MiB in {n_idle} entries", mib(idle));

    repo.run_cache_maintenance();
    let (swept, n_swept) = repo.cache_stats();
    println!("  after maintenance         : {:.2} MiB in {n_swept} entries", mib(swept));

    println!(
        "\n  {}",
        if idle > swept {
            "Expired entries were still resident until maintenance ran. In production\n  \
             that gap was thirteen hours, because nothing read that database in between."
        } else {
            "This build reclaimed without an explicit sweep — timing-dependent, so read\n  \
             the numbers above rather than trusting the label."
        }
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════
// 6. What it costs in time
// ═══════════════════════════════════════════════════════════

/// A cache is a time-for-memory trade. None of the above is worth anything if
/// the reader cannot see both halves.
/// Returns what an uncached read cost against a warm hit, per read, in us.
fn experiment_6_what_it_costs_in_time() -> Result<f64> {
    header(6, "the other half of the trade");
    let (storage, _dir) = open("e6", |c| c.cache_bytes(256 * MIB, 300, 300));
    seed(&storage, 2_000, 8 * KIB)?;
    let repo = storage.domain::<RunLog>().repo();

    let keys: Vec<String> = (0..2_000).map(|i| format!("run-{i:06}")).collect();

    // `set` populates the cache, so seeding left every row already cached and
    // this first pass would otherwise be a warm one wearing a cold label.
    repo.clear_cache();

    // Cold: every read misses and then fills.
    let t0 = Instant::now();
    for k in &keys {
        let _ = repo.get(k)?;
    }
    let cold = t0.elapsed();

    // Warm: every read hits.
    let t1 = Instant::now();
    for k in &keys {
        let _ = repo.get(k)?;
    }
    let warm = t1.elapsed();

    // Uncached: straight to redb, every time, cache untouched.
    let t2 = Instant::now();
    for k in &keys {
        let _ = repo.get_uncached(k)?;
    }
    let uncached = t2.elapsed();

    let per = |d: Duration| d.as_secs_f64() * 1_000_000.0 / keys.len() as f64;
    println!("  {:>22} │ {:>10} │ {:>12}", "2,000 reads", "total", "per read");
    println!("  {:─>22}─┼─{:─>10}─┼─{:─>12}", "", "", "");
    println!("  {:>22} │ {:>7.1} ms │ {:>9.1} us", "cold (miss + fill)", cold.as_secs_f64() * 1000.0, per(cold));
    println!("  {:>22} │ {:>7.1} ms │ {:>9.1} us", "warm (hit)", warm.as_secs_f64() * 1000.0, per(warm));
    println!("  {:>22} │ {:>7.1} ms │ {:>9.1} us", "uncached (redb)", uncached.as_secs_f64() * 1000.0, per(uncached));

    println!(
        "\n  A hit saves {:.1} us per read here. That is the whole return on the\n  \
         memory, and it is small because redb is already served from the OS page\n  \
         cache - so measure before assuming a cache pays. For a key read once\n  \
         during a scan there is nothing to win at all.",
        per(cold) - per(warm)
    );
    Ok(per(uncached) - per(warm))
}

fn main() -> Result<()> {
    println!("\nclove1db — cache memory budget");
    println!("What the cache costs, measured rather than asserted.");

    experiment_1_entry_count_is_not_a_bound()?;
    experiment_2_a_byte_budget_holds()?;
    experiment_3_a_bulk_scan_does_not_evict_the_hot_set()?;
    experiment_4_uncached_reads_leave_it_alone()?;
    experiment_5_expired_is_not_freed()?;
    let uncached_cost_us = experiment_6_what_it_costs_in_time()?;

    println!("\n{}", "═".repeat(72));
    println!("  What to take from this");
    println!("{}", "═".repeat(72));
    for line in [
        "  * cache_bytes() takes a budget in BYTES. An entry count is a count of".to_string(),
        "    things whose size the cache does not know: 2,000 of them was 2 MiB".to_string(),
        "    or 125 MiB depending only on how big a row happened to be.".to_string(),
        String::new(),
        "  * get_uncached() for keys you are walking past. Not to protect the hot".to_string(),
        "    set - moka already does that - but to leave the budget alone. Here it".to_string(),
        format!("    cost {uncached_cost_us:.1} us against a warm hit and saved the memory entirely."),
        String::new(),
        "  * run_cache_maintenance() is how expired memory comes back. Expiry is a".to_string(),
        "    clock; reclamation is maintenance, and maintenance needs a caller.".to_string(),
        String::new(),
        "  * cache_stats() reports (bytes, entries), so a budget can be checked".to_string(),
        "    instead of assumed.".to_string(),
    ] {
        println!("{line}");
    }

    // Leave nothing behind.
    for tag in ["e1", "e2", "e3", "e4", "e5", "e6"] {
        let dir =
            std::env::temp_dir().join(format!("clove1db_ex11_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(dir);
    }
    Ok(())
}
