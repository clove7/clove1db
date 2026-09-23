//! # 12 — Opening, closing, and crash recovery
//!
//! Four experiments on what happens to a `.cldb` between one run of a program
//! and the next, each printing numbers you can check rather than a claim you
//! have to believe.
//!
//! They exist because of a real server. Its `Storage` lived in a `static`,
//! which is never dropped, so redb never closed a file cleanly — not on a
//! crash, not on a kill, not even on Ctrl+C. Every boot began by repairing
//! every file, a walk of the whole file; and redb's page cache, 1 GiB per file
//! by default, kept whatever a scan had read. 0.0.112 answers each part:
//!
//! | # | Question | Answer |
//! |---|---|---|
//! | 1 | What does a full scan leave resident? | `redb_cache_bytes(n)` |
//! | 2 | What does a kill cost the next open? | `quick_repair(true)` |
//! | 3 | Can a storage nobody drops close cleanly? | `Storage::close()` |
//! | 4 | How many times does `build()` open a file? | once |
//!
//! Run with `cargo run --release` from this directory. In a debug build redb
//! walks every page of a file on every open, which is experiment 4's subject
//! and distorts the other three.

use std::alloc::{GlobalAlloc, Layout, System};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use clove1db::{
    entity::Entity,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::Result,
};

// ═══════════════════════════════════════════════════════════
// Counting the heap
// ═══════════════════════════════════════════════════════════

/// Counts live heap bytes. redb's page cache is ordinary heap, so this sees it
/// directly — the same measurement that found it on the server.
struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            LIVE.fetch_add(new_size, Ordering::Relaxed);
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        }
        new
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn live() -> usize {
    LIVE.load(Ordering::Relaxed)
}

// ═══════════════════════════════════════════════════════════
// One table of events
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Event {
    id: String,
    device_id: String,
    payload: String,
}

impl Entity for Event {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;

/// 64 MiB of payload, about twice that on disk once serialized and paged:
/// enough that a repair and a cache are worth measuring.
const ROWS: usize = 16 * 1024;
const ROW_BYTES: usize = 4 * KIB;

fn event(i: usize) -> Event {
    Event {
        id: format!("ev-{i:06}"),
        device_id: format!("pc-{:02}", i % 32),
        payload: "x".repeat(ROW_BYTES),
    }
}

fn mib(bytes: usize) -> f64 {
    bytes as f64 / MIB as f64
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

const TAGS: &[&str] = &[
    "e1", "e2_off", "e2_on", "e2_cost_off", "e2_cost_on", "e3_no_close", "e3_close", "e3_live",
    "e4",
];

fn data_dir(tag: &str) -> PathBuf {
    env::temp_dir().join(format!("clove1db_ex12_{tag}_{}", std::process::id()))
}

fn fresh_dir(tag: &str) -> PathBuf {
    let dir = data_dir(tag);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// The database every experiment uses. The clove1db row cache is off, so what
/// is measured is redb's page cache and nothing above it.
fn open(dir: &Path, options: impl FnOnce(DatabaseConfig) -> DatabaseConfig) -> Result<Storage> {
    Storage::builder(StorageConfig::default().change_dir_path(dir.to_path_buf()))
        .add_database(
            options(DatabaseConfig::new("events_db", "events"))
                .has_cache(false)
                .backup_enabled(false)
                .register::<Event>("events"),
        )
        .build()
}

fn primary(dir: &Path) -> PathBuf {
    dir.join("events_db").join("events.cldb")
}

/// Written in batches, so the setup does not dominate the run.
fn seed(storage: &Storage, rows: usize) -> Result<()> {
    let dbm = storage.db_manager("events");
    let mut batch = Vec::with_capacity(512);
    for i in 0..rows {
        let e = event(i);
        batch.push(("events".to_string(), e.id.clone(), serde_json::to_vec(&e)?));
        if batch.len() == 512 {
            dbm.commit_batch(&batch, &[])?;
            batch.clear();
        }
    }
    if !batch.is_empty() {
        dbm.commit_batch(&batch, &[])?;
    }
    Ok(())
}

/// Open a file with redb directly and report whether redb had to repair it,
/// and how long that open took. The probe closes it cleanly, so ask once.
fn probe(path: &Path) -> (bool, Duration) {
    let repaired = Arc::new(AtomicBool::new(false));
    let seen = repaired.clone();
    let started = Instant::now();
    let db = redb::Database::builder()
        .set_repair_callback(move |_| seen.store(true, Ordering::Relaxed))
        .open(path)
        .expect("probe open");
    let took = started.elapsed();
    drop(db);
    (repaired.load(Ordering::Relaxed), took)
}

fn header(n: u32, title: &str) {
    println!("\n{}", "═".repeat(72));
    println!("  Experiment {n} — {title}");
    println!("{}", "═".repeat(72));
}

// ═══════════════════════════════════════════════════════════
// The other process
// ═══════════════════════════════════════════════════════════

/// Runs this program again as a child that writes all [`ROWS`] and then ends
/// the way a kill or a crash does.
fn run_child(dir: &Path, quick_repair: bool, close: bool) -> Result<()> {
    let flag = |b: bool| if b { "1" } else { "0" };
    let status = Command::new(env::current_exe()?)
        .env("CLOVE_EX12_CHILD", "1")
        .env("CLOVE_EX12_DIR", dir)
        .env("CLOVE_EX12_QUICK_REPAIR", flag(quick_repair))
        .env("CLOVE_EX12_CLOSE", flag(close))
        .status()?;
    assert!(status.success(), "child failed: {status}");
    Ok(())
}

/// `process::exit` runs no destructor, so nothing is closed unless the child
/// closes it on purpose — the position of a `Storage` held in a `static`.
fn child() -> Result<()> {
    let dir = PathBuf::from(env::var("CLOVE_EX12_DIR").expect("CLOVE_EX12_DIR"));
    let quick_repair = env::var("CLOVE_EX12_QUICK_REPAIR").as_deref() == Ok("1");
    let close = env::var("CLOVE_EX12_CLOSE").as_deref() == Ok("1");

    let storage = open(&dir, |c| c.quick_repair(quick_repair))?;
    seed(&storage, ROWS)?;
    if close {
        storage.close();
    }
    std::process::exit(0);
}

// ═══════════════════════════════════════════════════════════
// 1. What a full scan leaves resident
// ═══════════════════════════════════════════════════════════

/// redb keeps the pages it reads, up to its cache size, and that size is
/// 1 GiB per file unless set. A scan that reads every row once therefore
/// leaves roughly the whole file on the heap, long after its result is gone.
fn experiment_1_what_a_full_scan_leaves() -> Result<()> {
    header(1, "what a full scan leaves resident");

    let dir = fresh_dir("e1");
    {
        let storage = open(&dir, |c| c)?;
        seed(&storage, ROWS)?;
        storage.close();
    }
    let file_bytes = fs::metadata(primary(&dir))?.len() as usize;
    println!(
        "  {ROWS} rows, {:.0} MiB on disk. Open, read every row once with list(),\n  \
         drop the result, and count what is still on the heap.\n",
        mib(file_bytes)
    );
    println!("  {:>18} │ {:>12} │ {:>9}", "redb cache", "retained", "scan");
    println!("  {:─>18}─┼─{:─>12}─┼─{:─>9}", "", "", "");

    for (label, cap) in [
        ("default (1 GiB)", None),
        ("16 MiB", Some(16 * MIB)),
        ("4 MiB", Some(4 * MIB)),
    ] {
        let storage = open(&dir, |c| match cap {
            Some(bytes) => c.redb_cache_bytes(bytes),
            None => c,
        })?;
        let before = live();
        let started = Instant::now();
        let rows = storage.domain::<Event>().repo().list()?.len();
        let scan = started.elapsed();
        let retained = live().saturating_sub(before);
        assert_eq!(rows, ROWS);
        println!(
            "  {label:>18} │ {:>8.1} MiB │ {:>6.0} ms",
            mib(retained),
            ms(scan)
        );
        storage.close();
    }

    println!(
        "\n  The rows are read from the OS page cache either way, so the scan barely\n  \
         changes. What changes is what stays: without a cap, about the whole file."
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════
// 2. What a kill costs the next open
// ═══════════════════════════════════════════════════════════

/// After an unclean exit redb cannot trust its allocator state and rebuilds it
/// by walking the whole file. `quick_repair` saves that state with every
/// commit, so there is nothing to rebuild.
fn experiment_2_what_a_kill_costs() -> Result<()> {
    header(2, "what a kill costs the next open");
    println!(
        "  A child process writes the same {ROWS} rows and exits without closing\n  \
         anything. The parent then opens the file with redb and asks whether it\n  \
         had to repair it.\n"
    );
    println!(
        "  {:>12} │ {:>11} │ {:>9} │ {:>10}",
        "quick_repair", "full repair", "open", "rows after"
    );
    println!("  {:─>12}─┼─{:─>11}─┼─{:─>9}─┼─{:─>10}", "", "", "", "");

    for quick_repair in [false, true] {
        let dir = fresh_dir(if quick_repair { "e2_on" } else { "e2_off" });
        run_child(&dir, quick_repair, false)?;
        let (repaired, took) = probe(&primary(&dir));
        let storage = open(&dir, |c| c)?;
        let rows = storage.db_manager("events").count_keys("events")?;
        storage.close();
        println!(
            "  {:>12} │ {:>11} │ {:>6.1} ms │ {:>10}",
            if quick_repair { "on" } else { "off" },
            yes_no(repaired),
            ms(took),
            rows
        );
    }

    const COMMITS: usize = 300;
    println!(
        "\n  No data is lost either way — the difference is the walk. And the price, per\n  \
         commit, over {COMMITS} single-row writes in Strict durability:\n"
    );
    for quick_repair in [false, true] {
        let dir = fresh_dir(if quick_repair { "e2_cost_on" } else { "e2_cost_off" });
        let storage = open(&dir, |c| c.quick_repair(quick_repair))?;
        let repo = storage.domain::<Event>().repo();
        let started = Instant::now();
        for i in 0..COMMITS {
            let e = event(i);
            repo.set(&e.id, &e)?;
        }
        let per_commit = ms(started.elapsed()) / COMMITS as f64;
        storage.close();
        println!(
            "  quick_repair {:>3} │ {per_commit:>6.2} ms per commit",
            if quick_repair { "on" } else { "off" }
        );
    }
    println!(
        "\n  A slower commit on every write, for an open that does not depend on the\n  \
         size of the file. Worth it for large databases on machines that get killed."
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════
// 3. Closing a storage nobody drops
// ═══════════════════════════════════════════════════════════

/// redb closes a file cleanly when its `Database` is dropped. A `Storage` in a
/// `static` never is, so a clean shutdown left the files exactly like a kill.
fn experiment_3_closing_a_storage_nobody_drops() -> Result<()> {
    header(3, "closing a storage nobody drops");
    println!(
        "  The same child and the same exit — once without close(), once with it.\n  \
         quick_repair is off in both, so only close() differs.\n"
    );
    println!("  {:>8} │ {:>11} │ {:>9}", "close()", "full repair", "open");
    println!("  {:─>8}─┼─{:─>11}─┼─{:─>9}", "", "", "");

    for close in [false, true] {
        let dir = fresh_dir(if close { "e3_close" } else { "e3_no_close" });
        run_child(&dir, false, close)?;
        let (repaired, took) = probe(&primary(&dir));
        println!(
            "  {:>8} │ {:>11} │ {:>6.1} ms",
            if close { "called" } else { "never" },
            yes_no(repaired),
            ms(took)
        );
    }

    println!("\n  And inside the process that closed it:\n");
    let dir = fresh_dir("e3_live");
    let storage = open(&dir, |c| c)?;
    let e = event(1);
    storage.domain::<Event>().repo().set(&e.id, &e)?;
    let worker = storage.clone(); // a clone some other task still holds
    storage.close();

    let e = event(2);
    match worker.domain::<Event>().repo().set(&e.id, &e) {
        Err(err) => println!("  * a write through a clone afterwards fails: {err}"),
        Ok(()) => println!("  !! a write after close() succeeded"),
    }
    // `storage` is still alive, and the file is already free.
    let second = open(&dir, |c| c)?;
    println!(
        "  * a second build of the same file, with the first Storage still alive,\n    \
         opens it and finds {} row(s)",
        second.db_manager("events").count_keys("events")?
    );
    second.close();
    drop(storage);
    Ok(())
}

// ═══════════════════════════════════════════════════════════
// 4. How many opens a build costs
// ═══════════════════════════════════════════════════════════

/// `build()` inspects a file, upgrades it, and serves it. Up to 0.0.105 each
/// step opened it again — three to four opens of every file on every boot.
fn experiment_4_how_many_opens_a_build_costs() -> Result<()> {
    header(4, "how many opens a build costs");

    let dir = fresh_dir("e4");
    {
        let storage = open(&dir, |c| c)?;
        seed(&storage, ROWS)?;
        storage.close();
    }
    // Once to warm the OS file cache, so neither measurement pays for the disk.
    let _ = probe(&primary(&dir));
    let (_, one_open) = probe(&primary(&dir));

    let started = Instant::now();
    let storage = open(&dir, |c| c)?;
    let build = started.elapsed();
    storage.close();

    println!("  one redb open of the file  {:>8.1} ms", ms(one_open));
    println!(
        "  Storage::build() of it     {:>8.1} ms   ≈ {:.1} opens' worth",
        ms(build),
        build.as_secs_f64() / one_open.as_secs_f64().max(1e-9)
    );
    println!(
        "\n  build() also creates tables and writes the meta — two commits — so in a\n  \
         release build, where an open of a clean file is cheap, that fixed cost is\n  \
         most of it. The opens show in a debug build, where redb walks every page\n  \
         on each one: there build() now costs about one open, not three or four.{}",
        if cfg!(debug_assertions) {
            "\n  (This is a debug build.)"
        } else {
            ""
        }
    );
    Ok(())
}

fn main() -> Result<()> {
    if env::var("CLOVE_EX12_CHILD").is_ok() {
        return child();
    }

    println!("\nclove1db 0.0.112 — opening, closing, and crash recovery");
    println!("What happens to a .cldb between one run and the next, measured.");
    if cfg!(debug_assertions) {
        println!(
            "\n  Debug build: redb walks every page on every open, which distorts\n  \
             experiments 1–3 — experiment 1 finds the cache already full before\n  \
             its scan starts. Run with --release for the numbers that matter."
        );
    }

    experiment_1_what_a_full_scan_leaves()?;
    experiment_2_what_a_kill_costs()?;
    experiment_3_closing_a_storage_nobody_drops()?;
    experiment_4_how_many_opens_a_build_costs()?;

    println!("\n{}", "═".repeat(72));
    println!("  What to take from this");
    println!("{}", "═".repeat(72));
    for line in [
        "  * redb_cache_bytes(n) caps redb's page cache per file. Without it a",
        "    scan leaves up to 1 GiB per file resident, at no gain in speed.",
        "",
        "  * quick_repair(true) makes the open after a kill or crash independent",
        "    of the file's size, for a slower commit on every write.",
        "",
        "  * storage.close() on the way out. A Storage nobody drops otherwise",
        "    leaves every file to be repaired, even after a clean shutdown.",
        "",
        "  * build() opens each file once.",
    ] {
        println!("{line}");
    }

    // Leave nothing behind.
    for tag in TAGS {
        let _ = fs::remove_dir_all(data_dir(tag));
    }
    Ok(())
}
