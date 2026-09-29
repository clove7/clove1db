//! # 13 — A large table: opening it, and reading all of it at start-up
//!
//! A program that loads a whole large table when it starts pays for it twice:
//! once to read it, and again in memory the process never gets back. Before
//! that, it opens the file — which, after a crash or a kill, can mean redb
//! walking the whole file to repair it. This example measures all three on one
//! synthetic table: 100,000 articles, about 70% of them carrying a large `body`.
//!
//! ## Part A — reading the whole table: `Repository::list_map`
//!
//! | name          | how the table is read                           | kept per row   | redb cache |
//! |---------------|-------------------------------------------------|----------------|------------|
//! | `copy_parse`  | copy every value, then parse (`list` < 0.0.119) | all but `body` | 64 MiB     |
//! | `list_map`    | `list_map`, one row at a time                   | all but `body` | 64 MiB     |
//! | `lean`        | `list_map`                                      | card fields    | 64 MiB     |
//! | `lean_cache8` | `list_map`                                      | card fields    | 8 MiB      |
//!
//! "Copy every value, then parse" is `list_entries` here: every stored value
//! copied into one `Vec` before any is parsed, which is what `list` did.
//!
//! Columns: `+live` = bytes the program holds after the load (a counting
//! allocator); `+private` = what the load added to what Windows has committed
//! to the process (Task Manager's "Memory"); `retained` = private − live,
//! committed memory holding nothing; `peak` = the most private memory the
//! process had at any moment.
//!
//! ## Part B — rows without their bulky field: `Repository::get_uncached_as`
//!
//! The same rows read by id, as the full `Article` and as an `ArticleCard` that
//! names only the fields a list shows. serde skips `body` without building it.
//! `allocated` is every byte the reads asked the allocator for, freed or not.
//!
//! ## Part C — what the open cost: `Storage::open_report`
//!
//! | name        | how the previous run ended                                |
//! |-------------|-----------------------------------------------------------|
//! | `clean`     | `Storage::close()`                                        |
//! | `killed`    | wrote, then exited without closing; `quick_repair(false)` |
//! | `killed_qr` | wrote, then exited without closing; `quick_repair(true)`  |
//!
//! For each, the next open's report: file size, open time, and whether redb
//! had to repair the file.
//!
//! Run from this directory:
//!
//! ```text
//! cargo run --release                      # 100,000 rows
//! set ROWS=20000 && cargo run --release    # a quick run
//! ```
//!
//! Release only: a debug build of redb walks every page on each open.

use std::alloc::{GlobalAlloc, Layout, System};
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use clove1db::{
    entity::Entity,
    storage::{DatabaseConfig, Storage, StorageConfig},
};

// ═══════════════════════════════════════════════════════════
// Counting the heap, and asking Windows what it committed
// ═══════════════════════════════════════════════════════════

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
/// Every byte ever allocated, freed or not: what a loop cost the allocator.
static ALLOCATED: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
            ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
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
            ALLOCATED.fetch_add(new_size, Ordering::Relaxed);
        }
        new
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn live() -> usize {
    LIVE.load(Ordering::Relaxed)
}

fn allocated() -> usize {
    ALLOCATED.load(Ordering::Relaxed)
}

/// `(private, peak private)` of this process, in bytes.
#[cfg(windows)]
fn private_bytes() -> (usize, usize) {
    #[repr(C)]
    #[derive(Default)]
    struct Counters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
        private_usage: usize,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> isize;
        fn K32GetProcessMemoryInfo(process: isize, counters: *mut Counters, cb: u32) -> i32;
    }
    let mut c = Counters {
        cb: std::mem::size_of::<Counters>() as u32,
        ..Default::default()
    };
    // SAFETY: `c` is a correctly sized PROCESS_MEMORY_COUNTERS_EX and `cb` says so.
    unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) };
    (c.private_usage, c.peak_pagefile_usage)
}

#[cfg(not(windows))]
fn private_bytes() -> (usize, usize) {
    (0, 0)
}

// ═══════════════════════════════════════════════════════════
// A table of articles
// ═══════════════════════════════════════════════════════════

/// What a list of articles shows.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Card {
    number: u64,
    title: String,
    slug: String,
    summary: String,
    author: String,
    cover_url: Option<String>,
    published_at: Option<i64>,
    rating: Option<f64>,
    rating_count: Option<u64>,
    categories: Vec<String>,
    languages: Vec<String>,
    source_id: String,
}

/// The bulky part, which only an article's own page needs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Body {
    text: String,
    abstract_text: String,
    figures: Vec<String>,
    attachments: Vec<String>,
    links: Vec<String>,
    contributors: Vec<String>,
    keywords: Vec<String>,
    related: Vec<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Article {
    id: String,
    card: Card,
    body: Option<Box<Body>>,
    state: String,
    visible: bool,
    updated_at: i64,
}

impl Entity for Article {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// The same stored row, read with only the fields a list needs. `body` is not
/// named, so serde passes over it without building it.
#[derive(Debug, Deserialize)]
struct ArticleCard {
    card: Card,
}

const TABLE: &str = "articles";
const CATEGORIES: &[&str] = &[
    "Science", "History", "Travel", "Cooking", "Design", "Music", "Health", "Finance", "Sport",
    "Nature",
];
const LANGUAGES: &[&str] = &["en", "fr", "de", "es", "it", "pt"];

/// Deterministic, varied text.
fn text(seed: usize, min: usize, spread: usize) -> String {
    let len = min + (seed.wrapping_mul(2_654_435_761) % spread.max(1));
    let alphabet = b"abcdefghijklmnopqrstuvwxyz ";
    (0..len).map(|i| alphabet[(seed + i * 7) % alphabet.len()] as char).collect()
}

fn list(seed: usize, n: usize, len: usize) -> Vec<String> {
    (0..n).map(|i| text(seed * 31 + i, len, len / 2 + 1)).collect()
}

fn id_of(i: usize) -> String {
    format!("a{i:07}")
}

fn article(i: usize) -> Article {
    let has_body = i % 10 < 7;
    Article {
        id: id_of(i),
        card: Card {
            number: i as u64,
            title: text(i, 12, 30),
            slug: text(i + 1, 12, 30),
            summary: text(i + 2, 0, 520),
            author: text(i + 3, 8, 16),
            cover_url: (i % 5 < 3)
                .then(|| format!("https://example.org/img/{}.png", text(i + 4, 32, 1))),
            published_at: Some(946_684_800 + (i as i64 % 800) * 2_592_000),
            rating: Some((i % 100) as f64),
            rating_count: Some((i % 400) as u64),
            categories: (0..1 + i % 3)
                .map(|k| CATEGORIES[(i + k) % CATEGORIES.len()].to_string())
                .collect(),
            languages: (0..1 + i % 4)
                .map(|k| LANGUAGES[(i + k) % LANGUAGES.len()].to_string())
                .collect(),
            source_id: i.to_string(),
        },
        body: has_body.then(|| {
            Box::new(Body {
                text: text(i + 5, 80, 300),
                abstract_text: text(i + 6, 0, 400),
                figures: list(i, 5, 20),
                attachments: list(i + 1, 2, 20),
                links: list(i + 2, 3, 40),
                contributors: list(i + 3, 3, 15),
                keywords: list(i + 4, 5, 10),
                related: (0..6).map(|k| (i * 13 + k) as u64).collect(),
            })
        }),
        state: if i % 5 < 3 { "Published".into() } else { "Draft".into() },
        visible: i % 5 < 3,
        updated_at: 1_700_000_000,
    }
}

/// The in-memory copy keeps everything but `body`.
fn strip_body(mut a: Article) -> Article {
    a.body = None;
    a
}

/// The lean copy also drops the card text no list shows.
fn strip_lean(mut a: Article) -> Article {
    a.body = None;
    a.card.summary = String::new();
    a.card.slug = String::new();
    a.card.languages = Vec::new();
    a.card.source_id = String::new();
    a
}

// ═══════════════════════════════════════════════════════════
// Storage
// ═══════════════════════════════════════════════════════════

const MIB: usize = 1024 * 1024;

fn mib(bytes: usize) -> f64 {
    bytes as f64 / MIB as f64
}

fn rows() -> usize {
    env::var("ROWS").ok().and_then(|s| s.trim().parse().ok()).unwrap_or(100_000)
}

/// Bump when `article()` changes shape, so the table is built again.
const SHAPE: u32 = 1;

fn data_dir() -> PathBuf {
    PathBuf::from("./target/example13").join(format!("{}-v{SHAPE}", rows()))
}

fn open(dir: &Path, cache_mib: usize, quick_repair: bool) -> Storage {
    Storage::builder(StorageConfig::default().change_dir_path(dir.to_path_buf()))
        .add_database(
            DatabaseConfig::new("articles", "articles")
                .backup_enabled(false)
                .has_cache(false)
                .redb_cache_bytes(cache_mib * MIB)
                .quick_repair(quick_repair)
                .register::<Article>(TABLE),
        )
        .build()
        .expect("open storage")
}

/// Build the table once per row count; later runs reuse it.
fn seed() {
    let dir = data_dir();
    let n = rows();
    if dir.exists() {
        let storage = open(&dir, 64, true);
        let have = storage
            .domain::<Article>()
            .repo()
            .database_manager
            .count_keys(TABLE)
            .unwrap_or(0);
        storage.close();
        drop(storage);
        if have == n {
            return;
        }
        std::fs::remove_dir_all(&dir).expect("clear old table");
    }
    println!("seeding {n} rows into {} …", dir.display());
    let t0 = Instant::now();
    let storage = open(&dir, 64, true);
    let dbm = &storage.domain::<Article>().repo().database_manager;
    let mut start = 0;
    while start < n {
        let end = (start + 5_000).min(n);
        let writes: Vec<(String, String, Vec<u8>)> = (start..end)
            .map(|i| {
                let a = article(i);
                (TABLE.to_string(), a.id.clone(), serde_json::to_vec(&a).unwrap())
            })
            .collect();
        dbm.commit_batch(&writes, &[]).expect("seed batch");
        start = end;
    }
    storage.close();
    let file = dir.join("articles").join("articles.cldb");
    let size = std::fs::metadata(&file).map(|m| m.len() as usize).unwrap_or(0);
    println!(
        "seeded in {:.1}s — {} ({:.0} MB on disk)\n",
        t0.elapsed().as_secs_f64(),
        file.display(),
        size as f64 / 1_000_000.0
    );
}

// ═══════════════════════════════════════════════════════════
// Part A — one read of the whole table, in this process
// ═══════════════════════════════════════════════════════════

fn run_read(name: &str) {
    let (cache_mib, lean, copy_first) = match name {
        "copy_parse" => (64, false, true),
        "list_map" => (64, false, false),
        "lean" => (64, true, false),
        "lean_cache8" => (8, true, false),
        other => panic!("unknown experiment {other}"),
    };
    let strip: fn(Article) -> Article = if lean { strip_lean } else { strip_body };

    let storage = open(&data_dir(), cache_mib, true);
    let repo = storage.domain::<Article>().repo();
    let (base_private, _) = private_bytes();
    let base_live = live();

    let t0 = Instant::now();
    let kept: Vec<Article> = if copy_first {
        // How `list` read a table before 0.0.119: every stored value copied
        // into one Vec, then all parsed, then the caller drops `body`.
        let raw = repo.database_manager.list_entries(TABLE).expect("list_entries");
        let rows: Vec<Article> = raw
            .iter()
            .map(|(_, v)| serde_json::from_slice(v).unwrap())
            .collect();
        drop(raw);
        rows.into_iter().map(strip).collect()
    } else {
        repo.list_map(strip).expect("list_map")
    };
    let ms = t0.elapsed().as_secs_f64() * 1000.0;

    let (private, peak) = private_bytes();
    let held = live();
    println!(
        "RESULT {ms:.0} {} {:.1} {:.1} {:.1} {:.1}",
        kept.len(),
        mib(held.saturating_sub(base_live)),
        mib(private.saturating_sub(base_private)),
        mib(private.saturating_sub(held)),
        mib(peak),
    );
    std::hint::black_box(&kept);
    storage.close();
}

// ═══════════════════════════════════════════════════════════
// Part B — rows by id, full and as a card
// ═══════════════════════════════════════════════════════════

/// Every n-th id, about 20,000 of them.
fn sample_ids() -> Vec<String> {
    let n = rows();
    let step = (n / 20_000).max(1);
    (0..n).step_by(step).map(id_of).collect()
}

fn run_by_id(name: &str) {
    let storage = open(&data_dir(), 64, true);
    let repo = storage.domain::<Article>().repo();
    let ids = sample_ids();
    let base_allocated = allocated();

    let t0 = Instant::now();
    let mut title_bytes = 0usize;
    for id in &ids {
        title_bytes += match name {
            "get_full" => {
                let a = repo.get_uncached(id).expect("get_uncached");
                a.card.title.len()
            }
            "get_card" => {
                let c: ArticleCard = repo.get_uncached_as(id).expect("get_uncached_as");
                c.card.title.len()
            }
            other => panic!("unknown experiment {other}"),
        };
    }
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    println!(
        "RESULT {ms:.0} {} {:.2}",
        ids.len(),
        mib(allocated() - base_allocated)
    );
    std::hint::black_box(title_bytes);
    storage.close();
}

// ═══════════════════════════════════════════════════════════
// Part C — how the previous run ended, and what the next open cost
// ═══════════════════════════════════════════════════════════

/// Write one row, then exit as a kill or a crash would: no close, no destructor.
fn run_kill(quick_repair: bool) {
    let storage = open(&data_dir(), 64, quick_repair);
    let repo = storage.domain::<Article>().repo();
    repo.set(&id_of(0), &article(0)).expect("write");
    std::process::exit(0);
}

/// Open, print the open report, then close cleanly.
fn run_report(quick_repair: bool) {
    let storage = open(&data_dir(), 64, quick_repair);
    for r in storage.open_report() {
        println!(
            "REPORT {} {:.1} {:.1} {}",
            r.database,
            r.bytes as f64 / 1_000_000.0,
            r.open_time.as_secs_f64() * 1000.0,
            r.repaired
        );
    }
    storage.close();
}

// ═══════════════════════════════════════════════════════════
// Driver
// ═══════════════════════════════════════════════════════════

/// Run this program again with `args`, and return what it printed.
fn child(args: &[&str]) -> String {
    let out = Command::new(env::current_exe().expect("current exe"))
        .args(args)
        .output()
        .expect("run child");
    if !out.status.success() {
        println!("  child {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The fields after `tag` on the first line that starts with it.
fn fields<'a>(stdout: &'a str, tag: &str) -> Vec<Vec<&'a str>> {
    stdout
        .lines()
        .filter(|l| l.starts_with(tag))
        .map(|l| l.split_whitespace().skip(1).collect())
        .collect()
}

const READS: &[(&str, &str)] = &[
    ("copy_parse", "copy, then parse; drop body; cache 64"),
    ("list_map", "list_map; drop body; cache 64"),
    ("lean", "list_map; card fields; cache 64"),
    ("lean_cache8", "list_map; card fields; cache 8"),
];

const BY_ID: &[(&str, &str)] = &[
    ("get_full", "get_uncached -> Article"),
    ("get_card", "get_uncached_as -> ArticleCard"),
];

/// `(name, how the previous run ended, the child that ends it that way, mode
/// of the open that follows)`. `clean` needs no setup: every report child
/// closes, and so does every read in parts A and B.
const OPENS: &[(&str, &str, Option<&str>, &str)] = &[
    ("clean", "closed with Storage::close()", None, "qr"),
    ("killed", "wrote, exited unclosed, quick_repair(false)", Some("off"), "off"),
    ("killed_qr", "wrote, exited unclosed, quick_repair(true)", Some("qr"), "qr"),
];

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() == 3 {
        match args[1].as_str() {
            "--read" => return run_read(&args[2]),
            "--by-id" => return run_by_id(&args[2]),
            "--kill" => return run_kill(args[2] == "qr"),
            "--report" => return run_report(args[2] == "qr"),
            _ => {}
        }
    }

    seed();

    println!("Part A — the whole table, one read per process");
    println!(
        "{:<12} {:<38} {:>7} {:>8} {:>9} {:>9} {:>9} {:>9}",
        "experiment", "what", "ms", "rows", "+live", "+private", "retained", "peak"
    );
    for (name, what) in READS {
        for f in fields(&child(&["--read", name]), "RESULT ") {
            println!(
                "{:<12} {:<38} {:>7} {:>8} {:>8}M {:>8}M {:>8}M {:>8}M",
                name, what, f[0], f[1], f[2], f[3], f[4], f[5]
            );
        }
    }
    println!(
        "\n+live: what the kept rows (and redb's page cache) hold after the load.\n\
         +private: what the load added to the process as Windows counts it.\n\
         retained: private − live — committed, holding nothing.\n\
         peak: the most private memory the process had during the run.\n"
    );

    println!("Part B — rows by id");
    println!(
        "{:<10} {:<32} {:>7} {:>8} {:>12}",
        "experiment", "what", "ms", "rows", "allocated"
    );
    for (name, what) in BY_ID {
        for f in fields(&child(&["--by-id", name]), "RESULT ") {
            println!("{:<10} {:<32} {:>7} {:>8} {:>11}M", name, what, f[0], f[1], f[2]);
        }
    }
    println!();

    println!("Part C — the next open, after the previous run ended");
    println!(
        "{:<10} {:<46} {:>8} {:>9} {:>9}",
        "case", "previous run", "MB", "open ms", "repaired"
    );
    for (name, previous, kill, mode) in OPENS {
        if let Some(kill_mode) = kill {
            child(&["--kill", kill_mode]);
        }
        for f in fields(&child(&["--report", mode]), "REPORT ") {
            println!("{:<10} {:<46} {:>8} {:>9} {:>9}", name, previous, f[1], f[2], f[3]);
        }
    }
    println!(
        "\nrepaired: redb walked the whole file to rebuild its allocator state.\n\
         Each report open ends in Storage::close(), so every case starts clean."
    );
}
