#![cfg(not(clove_test_encrypt_all))]
//! The write at the level the lab measures: `Storage::commit_batch_atomic`, an encrypted database against a plain one, no index
//! definition, the same quick repair. Counters are collected from every thread, per file (main, index, ...) and per "the thread that
//! called" against the others (the index worker). Test builds only. Run alone, in release:
//!   cargo test --release --lib storage_cost_split -- --ignored --nocapture --exact encrypted_store::storage_cost_tests::storage_cost_split
use super::backend::{CHECK_LEN, Cost, global};
use super::{EncryptionConfig, KeySource};
use crate::crypto::{CipherKind, HkdfHash, Key32, KeySuite};
use crate::entity::Entity;
use crate::storage::{DatabaseConfig, Prefetch, Storage, StorageConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Instant;

const TABLE: &str = "cost_notes";
const BATCHES: u64 = 20;
const PER_BATCH: u64 = 500;
const ROUNDS: usize = 5;

#[derive(Clone, Default, Serialize, Deserialize)]
struct Note {
    id: String,
    n: i64,
    text: String,
}

impl Entity for Note {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

type Totals = HashMap<(&'static str, bool), Cost>;

fn config(cipher: CipherKind) -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite { cipher, hkdf: HkdfHash::Sha256 },
        read: Some(KeySource::Raw(Key32::from_bytes(&[11; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[12; 32]))),
    }
}

fn open(dir: &Path, cipher: Option<CipherKind>) -> Storage {
    open_with(dir, cipher, 64 << 20)
}

fn open_with(dir: &Path, cipher: Option<CipherKind>, cache_bytes: usize) -> Storage {
    let mut db = DatabaseConfig::new("records", "store")
        .dir_path(dir.to_path_buf())
        .has_cache(false)
        .quick_repair(true)
        .prefetch(Prefetch::Never)
        .redb_cache_bytes(cache_bytes)
        .register::<Note>(TABLE);
    if let Some(c) = cipher {
        db = db.encryption(config(c));
    }
    Storage::builder(StorageConfig::default()).add_database(db).build().unwrap()
}

fn row(i: u64, salt: u64) -> (String, String, Vec<u8>) {
    let id = format!("r{i:09}");
    let unit = format!("{i}-{salt}-");
    let text = unit.repeat(1000 / unit.len() + 1)[..1000].to_string();
    let note = Note { id: id.clone(), n: i as i64, text };
    (TABLE.to_string(), id, serde_json::to_vec(&note).unwrap())
}

fn snapshot() -> Totals {
    global::TOTALS.lock().unwrap().clone().unwrap_or_default()
}

/// One run: preload (not counted), then the timed writes. Returns the milliseconds of the timed loop and, with counters,
/// the totals when the loop ended and after the storage was closed.
fn run(dir: &Path, cipher: Option<CipherKind>, counters: bool, reopen: bool) -> (f64, Totals, Totals) {
    let mut s = open(dir, cipher);
    let db = s.db_manager("store");
    for b in 0..10u64 {
        let batch: Vec<_> = (b * 1000..(b + 1) * 1000).map(|i| row(i % 10_000, 0)).collect();
        db.commit_batch_atomic(&batch, &[]).unwrap();
    }
    if reopen {
        // as the lab does: a fresh open of the existing database, so redb's page cache starts empty and every page a commit
        // touches is first read from the file (decrypted, when the file is encrypted)
        s.close();
        drop(s);
        s = open(dir, cipher);
    }
    let db = s.db_manager("store");
    if counters {
        *global::TOTALS.lock().unwrap() = None;
        *global::CALLER.lock().unwrap() = Some(std::thread::current().id());
        global::ON.store(true, Relaxed);
    }
    let started = Instant::now();
    for b in 0..BATCHES {
        let batch: Vec<_> = (0..PER_BATCH).map(|i| row((b * PER_BATCH + i) % 10_000, 7)).collect();
        db.commit_batch_atomic(&batch, &[]).unwrap();
    }
    let ms = started.elapsed().as_secs_f64() * 1000.;
    let during = if counters { snapshot() } else { Totals::new() };
    s.close();
    drop(s);
    let after = if counters { snapshot() } else { Totals::new() };
    global::ON.store(false, Relaxed);
    (ms, during, after)
}

fn median(v: &mut Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn pick(t: &Totals, tag: &str, caller: bool) -> Cost {
    t.iter().find(|((g, c), _)| *g == tag && *c == caller).map(|(_, v)| *v).unwrap_or_default()
}

fn ms(ns: u128) -> f64 {
    ns as f64 / 1e6
}

/// Time in the file layer that is not the file's own write, sync or set_len: sealing, header sealing, scratch, size queries,
/// and what no line covers. This is what the plain file does not do.
fn extra_ms(c: &Cost) -> f64 {
    let layer = c.layer_read_ns + c.layer_write_ns + c.layer_setlen_ns + c.layer_sync_ns;
    let file = c.file_read_ns + c.file_write_ns + c.file_setlen_ns + c.file_sync_ns;
    ms(layer.saturating_sub(file))
}

// ---- the lab's load, one difference at a time ----------------------------------------------------------------------

/// A word list and text generator, which is much more work than `row`'s repeat.
fn lab_words() -> Vec<&'static str> {
    vec![
        "alpha", "beta", "gamma", "delta", "omega", "river", "stone", "cloud", "ember", "frost", "grove", "harbor", "island", "jungle",
        "kernel", "lantern", "meadow", "nebula", "orchid", "pebble", "quartz", "ripple", "summit", "timber", "umbra", "velvet", "willow",
        "zenith", "anchor", "bridge", "candle", "dragon",
    ]
}

fn lab_text(seed: u64, bytes: usize) -> String {
    let w = lab_words();
    let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut out = String::with_capacity(bytes + 16);
    while out.len() < bytes {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        out.push_str(w[(s % w.len() as u64) as usize]);
        out.push(' ');
    }
    out
}

fn lab_row(i: u64, salt: u64) -> (String, String, Vec<u8>) {
    let id = format!("r{i:09}");
    let note = Note { id: id.clone(), n: i as i64, text: lab_text(i * 31 + salt, 1000) };
    (TABLE.to_string(), id, serde_json::to_vec(&note).unwrap())
}

#[derive(Clone, Copy)]
struct Variant {
    name: &'static str,
    /// rows per commit while the table is built
    preload_batch: u64,
    /// redb cache = the main file's size + 25 % (else 64 MB)
    cache_plus_25: bool,
    /// two untimed commits on the same open before the timed ones
    warmup: bool,
    /// the lab's text generator, run inside the timed loop (else the rows are made before the clock starts)
    textgen_in_loop: bool,
    /// the same files are used for every round (the table is built only the first time), as the lab does
    reuse: bool,
}

/// One run of a variant: build the table, close, open again, (warm-up), then the timed 20 commits.
fn run_variant(dir: &Path, cipher: Option<CipherKind>, counters: bool, v: Variant) -> (f64, Totals) {
    if !(v.reuse && dir.join("records").join("store.cldb").exists()) {
        let s = open(dir, cipher);
        let db = s.db_manager("store");
        let mut i = 0u64;
        while i < 10_000 {
            let end = (i + v.preload_batch).min(10_000);
            let batch: Vec<_> = (i..end).map(|k| if v.textgen_in_loop { lab_row(k, 0) } else { row(k, 0) }).collect();
            db.commit_batch_atomic(&batch, &[]).unwrap();
            i = end;
        }
        s.close();
        drop(s);
    }
    let cache = if v.cache_plus_25 {
        let size = std::fs::metadata(dir.join("records").join("store.cldb")).unwrap().len() as usize;
        size + size / 4
    } else {
        64 << 20
    };
    let s = open_with(dir, cipher, cache);
    let db = s.db_manager("store");
    if v.warmup {
        for b in 0..2u64 {
            let batch: Vec<_> = (0..PER_BATCH).map(|i| row((b * PER_BATCH + i) % 10_000, 3)).collect();
            db.commit_batch_atomic(&batch, &[]).unwrap();
        }
    }
    let ready: Vec<Vec<(String, String, Vec<u8>)>> = if v.textgen_in_loop {
        vec![]
    } else {
        (0..BATCHES).map(|b| (0..PER_BATCH).map(|i| row((b * PER_BATCH + i) % 10_000, 7)).collect()).collect()
    };
    if counters {
        *global::TOTALS.lock().unwrap() = None;
        *global::CALLER.lock().unwrap() = Some(std::thread::current().id());
        global::ON.store(true, Relaxed);
    }
    let started = Instant::now();
    for b in 0..BATCHES {
        if v.textgen_in_loop {
            let batch: Vec<_> = (0..PER_BATCH).map(|i| lab_row((b * PER_BATCH + i) % 10_000, 7 + b)).collect();
            db.commit_batch_atomic(&batch, &[]).unwrap();
        } else {
            db.commit_batch_atomic(&ready[b as usize], &[]).unwrap();
        }
    }
    let ms = started.elapsed().as_secs_f64() * 1000.;
    let during = if counters { snapshot() } else { Totals::new() };
    global::ON.store(false, Relaxed);
    s.close();
    drop(s);
    (ms, during)
}

#[test]
#[ignore]
fn storage_cost_steps() {
    CHECK_LEN.with(|c| c.set(false));
    let base = std::env::temp_dir().join(format!("clove-storagesteps-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&base).unwrap();
    let steps = [
        Variant { name: "0 baseline: reopened, 1000-row build commits, 64 MB cache, no warm-up, rows made before the clock", preload_batch: 1000, cache_plus_25: false, warmup: false, textgen_in_loop: false, reuse: false },
        Variant { name: "1 + the table built in 2000-row commits (as the lab make)", preload_batch: 2000, cache_plus_25: false, warmup: false, textgen_in_loop: false, reuse: false },
        Variant { name: "2 + redb cache = file size + 25 %", preload_batch: 2000, cache_plus_25: true, warmup: false, textgen_in_loop: false, reuse: false },
        Variant { name: "3 + two untimed warm-up commits on the same open", preload_batch: 2000, cache_plus_25: true, warmup: true, textgen_in_loop: false, reuse: false },
        Variant { name: "4 + the lab text generator inside the timed loop", preload_batch: 2000, cache_plus_25: true, warmup: true, textgen_in_loop: true, reuse: false },
        Variant { name: "5 + the same files used again and again (12 rounds), so the file grows and new space is filled", preload_batch: 2000, cache_plus_25: true, warmup: true, textgen_in_loop: true, reuse: true },
    ];
    let kinds: [(&str, Option<CipherKind>); 3] =
        [("plain", None), ("XChaCha", Some(CipherKind::XChaCha20Poly1305)), ("AES", Some(CipherKind::Aes256GcmSiv))];
    println!("each step adds one difference to the one before; {ROUNDS} rounds, plain/XChaCha/AES alternating in every round; medians (ms for the 20 timed commits)");
    let mut previous = [0.0f64; 2];
    for (n, v) in steps.iter().enumerate() {
        let v = *v;
        let mut off: Vec<Vec<f64>> = vec![vec![]; 3];
        let mut on: Vec<Vec<Totals>> = vec![vec![]; 3];
        let rounds = if v.reuse { 12 } else { ROUNDS };
        for round in 0..rounds {
            for (k, (name, cipher)) in kinds.iter().enumerate() {
                let d = |tag: &str| {
                    let d = base.join(if v.reuse { format!("s{n}-{name}-{tag}") } else { format!("s{n}-{name}-{tag}-{round}") });
                    std::fs::create_dir_all(&d).unwrap();
                    d
                };
                off[k].push(run_variant(&d("off"), *cipher, false, v).0);
                if cipher.is_some() {
                    on[k].push(run_variant(&d("on"), *cipher, true, v).1);
                }
            }
        }
        let p = median(&mut off[0].clone());
        println!("\n{}\n  plain {:.1}", v.name, p);
        for (k, label) in [(1usize, "XChaCha"), (2usize, "AES")] {
            let tot = median(&mut off[k].clone());
            let gap = tot - p;
            let m = |f: &dyn Fn(&Cost) -> f64| {
                let mut x: Vec<f64> = on[k]
                    .iter()
                    .map(|t| ["main", "index", "bak", "other"].iter().map(|tag| f(&pick(t, tag, true)) + f(&pick(t, tag, false))).sum())
                    .collect();
                median(&mut x)
            };
            let seal = m(&|c| ms(c.seal_ns + c.fill_seal_ns));
            let dec = m(&|c| ms(c.open_ns));
            let fread = m(&|c| ms(c.file_read_ns));
            let layer_other = m(&|c| extra_ms(c) - ms(c.seal_ns + c.fill_seal_ns + c.open_ns));
            println!(
                "  {label:<8} total {tot:7.1}  gap {gap:+7.1} ({:+.0} %, {:+.1} vs the step before)  = seal {seal:5.1} + decrypt {dec:5.1} + layer other {layer_other:4.1} + not accounted for {:+6.1}   | blocks sealed {:.0}, read {:.0}, file read {fread:.1} ms",
                (tot / p - 1.) * 100.,
                gap - previous[k - 1],
                gap - seal - dec - layer_other,
                m(&|c| (c.seal_blocks + c.fill_blocks) as f64),
                m(&|c| c.open_blocks as f64),
            );
            println!(
                "           zero fill: {:.0} blocks sealed, {:.1} ms sealing + {:.1} ms writing; sync {:.1} ms ({:.0} syncs); set_len {:.0} calls; main file now {:.1} MB",
                m(&|c| c.fill_blocks as f64),
                m(&|c| ms(c.fill_seal_ns)),
                m(&|c| ms(c.file_write_ns)),
                m(&|c| ms(c.file_sync_ns)),
                m(&|c| c.file_sync_calls as f64),
                m(&|c| c.file_setlen_calls as f64),
                std::fs::metadata(base.join(if v.reuse { format!("s{n}-{}-on", kinds[k].0) } else { format!("s{n}-{}-on-{}", kinds[k].0, rounds - 1) }).join("records").join("store.cldb")).map(|m| m.len() as f64 / 1e6).unwrap_or(0.0),
            );
            previous[k - 1] = gap;
        }
    }
    let _ = std::fs::remove_dir_all(&base);
}

fn scenario(reopen: bool) {
    let base = std::env::temp_dir().join(format!("clove-storagecost-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&base).unwrap();
    let kinds: [(&str, Option<CipherKind>); 3] =
        [("plain", None), ("XChaCha", Some(CipherKind::XChaCha20Poly1305)), ("AES-GCM-SIV", Some(CipherKind::Aes256GcmSiv))];
    let mut off: Vec<Vec<f64>> = vec![vec![]; 3];
    let mut on_ms: Vec<Vec<f64>> = vec![vec![]; 3];
    let mut during: Vec<Vec<Totals>> = vec![vec![]; 3];
    let mut after: Vec<Vec<Totals>> = vec![vec![]; 3];
    for round in 0..ROUNDS {
        for (k, (name, cipher)) in kinds.iter().enumerate() {
            let d = |tag: &str| {
                let d = base.join(format!("{name}-{tag}-{round}"));
                std::fs::create_dir_all(&d).unwrap();
                d
            };
            off[k].push(run(&d("off"), *cipher, false, reopen).0);
            if cipher.is_some() {
                let (t, dur, aft) = run(&d("on"), *cipher, true, reopen);
                on_ms[k].push(t);
                during[k].push(dur);
                after[k].push(aft);
            }
        }
    }
    let (p, x, a) = (median(&mut off[0].clone()), median(&mut off[1].clone()), median(&mut off[2].clone()));
    println!("
=========== {} ===========", if reopen { "the database is closed and opened again before the timed writes (redb page cache empty, as in the lab)" } else { "the same open that built the table (redb page cache warm)" });
    println!("Storage::commit_batch_atomic {BATCHES} x {PER_BATCH} rows of ~1 KB, {ROUNDS} rounds, medians (ms); counters off: plain {p:.1} | XChaCha {x:.1} | AES {a:.1}");
    println!("gap: XChaCha {:+.1} ms ({:+.0} %) | AES {:+.1} ms ({:+.0} %)", x - p, (x / p - 1.) * 100., a - p, (a / p - 1.) * 100.);
    println!(
        "counters on, same loop: XChaCha {:.1} | AES {:.1}",
        median(&mut on_ms[1].clone()),
        median(&mut on_ms[2].clone())
    );
    for (k, label) in [(1usize, "XChaCha"), (2usize, "AES-GCM-SIV")] {
        for (when, runs) in [("while the 20 commits ran", &during[k]), ("after close (the worker has finished)", &after[k])] {
            println!("\n{label}, {when}: per file and thread, summed over the 20 commits (medians of {ROUNDS})");
            println!("{:<7} {:<7} {:>9} {:>9} {:>10} {:>10} {:>10} {:>9} {:>10} {:>9} {:>9} {:>10} {:>10}", "file", "thread", "sealed", "written", "seal ms", "write ms", "sync ms", "syncs", "extra ms", "us/block", "read blk", "decrypt ms", "fread ms");
            for tag in ["main", "index", "bak", "other"] {
                for caller in [true, false] {
                    let m = |f: &dyn Fn(&Cost) -> f64| {
                        let mut v: Vec<f64> = runs.iter().map(|t| f(&pick(t, tag, caller))).collect();
                        median(&mut v)
                    };
                    let sealed = m(&|c| (c.seal_blocks + c.fill_blocks) as f64);
                    let wrote = m(&|c| c.file_write_bytes as f64);
                    if sealed == 0.0 && wrote == 0.0 && m(&|c| c.file_sync_calls as f64) == 0.0 && m(&|c| c.open_blocks as f64) == 0.0 {
                        continue;
                    }
                    let seal = m(&|c| ms(c.seal_ns + c.fill_seal_ns));
                    println!(
                        "{:<7} {:<7} {:>9.0} {:>8.2}M {:>10.2} {:>10.2} {:>10.2} {:>9.0} {:>10.2} {:>9.2} {:>9.0} {:>10.2} {:>10.2}",
                        tag,
                        if caller { "caller" } else { "worker" },
                        sealed,
                        wrote / 1e6,
                        seal,
                        m(&|c| ms(c.file_write_ns)),
                        m(&|c| ms(c.file_sync_ns)),
                        m(&|c| c.file_sync_calls as f64),
                        m(&|c| extra_ms(c)),
                        if sealed > 0.0 { seal * 1000. / sealed } else { 0.0 },
                        m(&|c| c.open_blocks as f64),
                        m(&|c| ms(c.open_ns)),
                        m(&|c| ms(c.file_read_ns)),
                    );
                }
            }
        }
        // the 65 ms: what the calling thread had to do extra, against the gap
        let runs = &during[k];
        let on_caller = |f: &dyn Fn(&Cost) -> f64| {
            let mut v: Vec<f64> = runs
                .iter()
                .map(|t| ["main", "index", "bak", "other"].iter().map(|tag| f(&pick(t, tag, true))).sum())
                .collect();
            median(&mut v)
        };
        let seal = on_caller(&|c| ms(c.seal_ns + c.fill_seal_ns));
        let decrypt = on_caller(&|c| ms(c.open_ns));
        let other_extra = on_caller(&|c| extra_ms(c) - ms(c.seal_ns + c.fill_seal_ns + c.open_ns));
        let gap = if k == 1 { x - p } else { a - p };
        let seal_all = {
            let mut v: Vec<f64> = runs
                .iter()
                .map(|t| ["main", "index", "bak", "other"].iter().map(|tag| ms(pick(t, tag, true).seal_ns + pick(t, tag, false).seal_ns + pick(t, tag, true).fill_seal_ns + pick(t, tag, false).fill_seal_ns)).sum())
                .collect();
            median(&mut v)
        };
        println!("{label}: sealing on all threads together {seal_all:.1} ms (the calling thread's share above)");
        println!(
            "\n{label}: gap {gap:.1} ms = sealing on the calling thread {seal:.1} + decrypting pages redb read {decrypt:.1} + the rest of the file layer's own work on it {other_extra:.1} + not accounted for {:.1}",
            gap - seal - decrypt - other_extra
        );
    }
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
#[ignore]
fn storage_cost_split() {
    CHECK_LEN.with(|c| c.set(false));
    scenario(false);
    scenario(true);
}
