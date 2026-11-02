//! Fifty forced kills of a process that is committing to an encrypted database. A child commits
//! batches in a loop and, after each commit returns, records the batch number in a separate file;
//! the parent kills it (`TerminateProcess`) at a random moment, then opens the database with the right
//! key and checks it: every row up to the last acknowledged batch is exact, the one batch after it
//! is all there or all absent, nothing else, the index is fine or rebuilt with its event, the full
//! check of the closed files passes, and no marker text is in any file. Every 10th kill also kills
//! the reopening child while it repairs. 25 kills per allowed cipher.
//!
//! Run on purpose, alone: `cargo test --test encrypted_kills -- --ignored --nocapture`.
use clove1db::{
    CloveFields, EncryptionConfig, KeySource, LibraryEvent,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    encrypted_store::{EncryptionHandle, verify_encrypted_files},
    entity::Entity,
    storage::{DatabaseConfig, Storage, StorageConfig},
};
#[path = "child_log/mod.rs"]
mod child_log;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const TABLE: &str = "kill_notes_table";
const LARGE_ROWS: usize = 40;
const LARGE_PAD: usize = 100_000;

#[derive(Clone, Default, Serialize, Deserialize, CloveFields)]
struct Note {
    id: String,
    n: i64,
    pad: String,
}

impl Entity for Note {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn cipher_of(name: &str) -> CipherKind {
    if name == "aes" { CipherKind::Aes256GcmSiv } else { CipherKind::XChaCha20Poly1305 }
}

fn config(cipher: &str) -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite { cipher: cipher_of(cipher), hkdf: HkdfHash::Sha256 },
        read: Some(KeySource::Raw(Key32::from_bytes(&[1; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[200; 32]))),
    }
}

type Events = Arc<Mutex<Vec<String>>>;

fn open(root: &Path, cipher: &str, events: &Events) -> Result<Storage, clove1db::units::ClError> {
    let sink = events.clone();
    let storage = StorageConfig::default().event_sink(move |e| {
        if let LibraryEvent::Encryption { event, file } = e {
            sink.lock().unwrap().push(format!("{event}@{file}"));
        }
    });
    Storage::builder(storage)
        .add_database(
            DatabaseConfig::new("records", "store")
                .dir_path(root.to_path_buf())
                .backup_enabled(true)
                .has_cache(false)
                .encryption(config(cipher))
                .register::<Note>(TABLE),
        )
        .build()
}

fn rows_in_batch(large: bool) -> usize {
    if large { LARGE_ROWS } else { 1 }
}

fn pad(b: u64, i: usize, len: usize) -> String {
    let unit = format!("KILLMARK-PAD-{b}-{i}-");
    unit.repeat(len / unit.len() + 1)[..len].to_string()
}

fn note(b: u64, i: usize, large: bool) -> Note {
    Note { id: format!("KILLMARK-b{b:05}-r{i:03}"), n: (b * 1000 + i as u64) as i64, pad: pad(b, i, if large { LARGE_PAD } else { 40 }) }
}

fn batch(b: u64, large: bool) -> Vec<(String, String, Vec<u8>)> {
    (0..rows_in_batch(large))
        .map(|i| {
            let n = note(b, i, large);
            (TABLE.to_string(), n.id.clone(), serde_json::to_vec(&n).unwrap())
        })
        .collect()
}

/// The child: commits batch after batch, forever, and records each acknowledged batch.
#[test]
#[ignore]
fn kill_child() {
    let Ok(root) = std::env::var("CLOVE_KILL_ROOT") else { return };
    let cipher = std::env::var("CLOVE_KILL_CIPHER").unwrap();
    let ack = std::env::var("CLOVE_KILL_ACK").unwrap();
    let mode = std::env::var("CLOVE_KILL_MODE").unwrap();
    let events: Events = Default::default();
    let storage = open(Path::new(&root), &cipher, &events).unwrap();
    if mode == "reopen" {
        std::thread::sleep(Duration::from_secs(5));
        return;
    }
    let large = mode == "large";
    let db = storage.db_manager("store");
    let mut ack_file = std::fs::OpenOptions::new().create(true).append(true).open(&ack).unwrap();
    let mut b = std::env::var("CLOVE_KILL_FIRST").unwrap().parse::<u64>().unwrap();
    loop {
        db.commit_batch_atomic(&batch(b, large), &[]).unwrap();
        writeln!(ack_file, "{b}").unwrap();
        ack_file.sync_all().unwrap();
        b += 1;
    }
}

fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn last_ack(ack: &Path) -> u64 {
    std::fs::read_to_string(ack).unwrap_or_default().lines().filter_map(|l| l.trim().parse::<u64>().ok()).max().unwrap_or(0)
}

fn spawn(root: &Path, cipher: &str, ack: &Path, mode: &str, first: u64) -> std::process::Child {
    Command::new(std::env::current_exe().unwrap())
        .args(["kill_child", "--exact", "--ignored", "--test-threads=1"])
        .env("CLOVE_KILL_ROOT", root)
        .env("CLOVE_KILL_CIPHER", cipher)
        .env("CLOVE_KILL_ACK", ack)
        .env("CLOVE_KILL_MODE", mode)
        .env("CLOVE_KILL_FIRST", first.to_string())
        .stdout(child_log::out(root))
        .stderr(child_log::out(root))
        .spawn()
        .unwrap()
}

fn all_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            all_files(&p, out);
        } else {
            out.push(p);
        }
    }
}

fn has(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|w| w == needle)
}

/// What is wrong with the database after a kill, or nothing. `Err((class, text))`.
fn check(root: &Path, cipher: &str, ack: &Path, large: bool, first: u64) -> Result<String, (&'static str, String)> {
    let acked = last_ack(ack);
    let events: Events = Default::default();
    let storage = open(root, cipher, &events).map_err(|e| ("open", format!("{e:?}")))?;
    let rows = storage
        .db_manager("store")
        .read_view_at_head()
        .and_then(|v| v.table_entries(TABLE))
        .map_err(|e| ("read", format!("{e:?}")))?;
    let mut by_batch: std::collections::BTreeMap<u64, Vec<Note>> = Default::default();
    for (_, bytes) in &rows {
        let n: Note = serde_json::from_slice(bytes).map_err(|e| ("row", format!("unreadable row: {e}")))?;
        by_batch.entry(n.n as u64 / 1000).or_default().push(n);
    }
    for b in first..=acked {
        let got = by_batch.get(&b).map(|v| v.len()).unwrap_or(0);
        if got != rows_in_batch(large) {
            return Err(("acked-batch", format!("batch {b} (acked up to {acked}) has {got} of {} rows", rows_in_batch(large))));
        }
    }
    for (b, notes) in &by_batch {
        if *b > acked + 1 {
            return Err(("future-batch", format!("batch {b} exists but only {acked} was acknowledged")));
        }
        let all = notes.len() == rows_in_batch(large);
        if *b > acked && !all {
            return Err(("partial-batch", format!("unacknowledged batch {b} has {} of {} rows", notes.len(), rows_in_batch(large))));
        }
        for n in notes {
            let i: usize = n.id.rsplit("-r").next().unwrap().parse().unwrap();
            let want = note(*b, i, large);
            if n.id != want.id || n.n != want.n || n.pad != want.pad {
                return Err(("row-content", format!("row {} of batch {b} differs from what was written", n.id)));
            }
        }
    }
    storage.close();
    drop(storage);
    let seen = events.lock().unwrap().clone();
    if let Some(bad) = seen.iter().find(|e| *e != "encryption/index_rebuilt@index") {
        return Err(("event", format!("unexpected event {bad}")));
    }
    verify_encrypted_files(root, "records", "store", &EncryptionHandle::new(config(cipher)))
        .map_err(|e| ("verify", format!("{e:?}")))?;
    let mut files = Vec::new();
    all_files(root, &mut files);
    for f in files {
        let bytes = std::fs::read(&f).unwrap();
        for needle in [b"KILLMARK".as_slice(), TABLE.as_bytes(), b"redb\x1A\x0A\xA9\x0D\x0A".as_slice()] {
            if has(&bytes, needle) {
                return Err(("marker", format!("{} contains {:?}", f.display(), String::from_utf8_lossy(needle))));
            }
        }
    }
    Ok(format!("acked={acked} rows={} events={}", rows.len(), seen.len()))
}

#[test]
#[ignore]
fn fifty_forced_kills_leave_a_database_that_opens_exact_and_sealed() {
    let base = std::env::temp_dir().join(format!("clove-kills-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&base).unwrap();
    let mut failures = Vec::new();
    let mut passed = 0;
    for k in 0..50u32 {
        let cipher = if k % 2 == 0 { "aes" } else { "xchacha" };
        let large = (k / 2) % 2 == 1;
        let during_repair = k % 10 == 9;
        let mut rng = 0x9E37_79B9_7F4A_7C15u64 ^ (k as u64 + 1).wrapping_mul(0xD1B5_4A32_D192_ED03);
        let wait_ms = 50 + next(&mut rng) % 1951;
        let repair_ms = 1 + next(&mut rng) % 400;
        let root = base.join(format!("k{k:02}"));
        let ack = base.join(format!("k{k:02}.ack"));
        let mut child = spawn(&root, cipher, &ack, if large { "large" } else { "small" }, 1);
        let started = Instant::now();
        while last_ack(&ack) == 0 {
            assert!(started.elapsed() < Duration::from_secs(60), "kill {k}: the child never acknowledged a batch; it printed: {}", child_log::said(&root));
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(wait_ms));
        child.kill().unwrap();
        let _ = child.wait();
        if during_repair {
            let mut again = spawn(&root, cipher, &ack, "reopen", 1);
            std::thread::sleep(Duration::from_millis(repair_ms));
            again.kill().unwrap();
            let _ = again.wait();
        }
        match check(&root, cipher, &ack, large, 1) {
            Ok(text) => {
                passed += 1;
                println!("kill {k:02} {cipher:7} {} wait={wait_ms}ms{} ok {text}", if large { "large" } else { "small" }, if during_repair { format!(" +reopen-kill@{repair_ms}ms") } else { String::new() });
                let _ = std::fs::remove_dir_all(&root);
            }
            Err((class, text)) => {
                let kept = std::env::temp_dir().join(format!("clove-kill-failed-{k:02}-{}", uuid::Uuid::new_v4()));
                let _ = std::fs::rename(&root, &kept);
                let line = format!("kill {k:02} {cipher} large={large} wait={wait_ms}ms reopen-kill={during_repair}@{repair_ms}ms [{class}] {text} (kept: {})", kept.display());
                println!("FAIL {line}");
                failures.push(line);
            }
        }
    }
    println!("forced kills: {passed} of 50 passed");
    let _ = std::fs::remove_dir_all(&base);
    assert!(failures.is_empty(), "{} of 50 failed:\n{}", failures.len(), failures.join("\n"));
}
