#![cfg(feature = "crash-inject")]
//! (copy of the forced-kill harness, here for the crash points of the parallel seal)
//! Fifty forced kills of a process that is committing to an encrypted database. A child commits
//! batches in a loop and, after each commit returns, records the batch number in a separate file;
//! the parent kills it (`TerminateProcess`) at a random moment, then opens the database with the right
//! key and checks it: every row up to the last acknowledged batch is exact, the one batch after it
//! is all there or all absent, nothing else, the index is fine or rebuilt with its event, the full
//! check of the closed files passes, and no marker text is in any file. Every 10th kill also kills
//! the reopening child while it repairs. 25 kills per allowed cipher.
//!
//! Run: `cargo test --features crash-inject --test encrypted_crash_points -- --nocapture`.
use clove1db::{
    CloveFields, EncryptionConfig, KeySource, LibraryEvent,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    encrypted_store::{EncryptionHandle, verify_encrypted_files},
    entity::Entity,
    storage::{DatabaseConfig, Storage, StorageConfig},
};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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
    let db = DatabaseConfig::new("records", "store").dir_path(root.to_path_buf()).backup_enabled(true).has_cache(false);
    let db = if std::env::var("CLOVE_KILL_PLAIN").is_ok() {
        db
    } else {
        db.encryption(config(cipher)).encryption_tuning(if std::env::var("CLOVE_KILL_TUNING").ok().as_deref() == Some("off") {
            clove1db::EncryptionTuning::OFF
        } else {
            clove1db::EncryptionTuning::DEFAULT
        })
    };
    Storage::builder(storage).add_database(db.register::<Note>(TABLE)).build()
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
    if mode == "reopen_check" {
        return;
    }
    let large = mode == "large";
    let db = storage.db_manager("store");
    let mut ack_file = std::fs::OpenOptions::new().create(true).append(true).open(&ack).unwrap();
    let mut b = std::env::var("CLOVE_KILL_FIRST").unwrap().parse::<u64>().unwrap();
    let stop_after = std::env::var("CLOVE_KILL_STOP_AFTER").ok().and_then(|v| v.parse::<u64>().ok());
    loop {
        if stop_after.is_some_and(|n| b >= n) {
            return;
        }
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
        .stdout(Stdio::null())
        .stderr(Stdio::null())
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
fn the_four_new_crash_points_leave_a_database_on_the_last_durable_commit() {
    let base = std::env::temp_dir().join(format!("clove-crashpoints-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&base).unwrap();
    let mut failures = Vec::new();
    let mut runs = 0;
    for point in ["enc_drain_before_seal", "enc_drain_after_seal", "enc_drain_mid_write", "enc_drain_before_sync", "enc_drain_after_sync"] {
        for cipher in ["aes", "xchacha"] {
            for (mode, skip) in [("small", 2u64), ("small", 7), ("small", 19), ("large", 0), ("large", 2)] {
                let large = mode == "large";
                let name = format!("{point}-{cipher}-{mode}-{skip}");
                let root = base.join(&name);
                let ack = base.join(format!("{name}.ack"));
                let mut child = Command::new(std::env::current_exe().unwrap())
                    .args(["kill_child", "--exact", "--ignored", "--test-threads=1"])
                    .env("CLOVE_KILL_ROOT", &root)
                    .env("CLOVE_KILL_CIPHER", cipher)
                    .env("CLOVE_KILL_ACK", &ack)
                    .env("CLOVE_KILL_MODE", mode)
                    .env("CLOVE_KILL_FIRST", "1")
                    .env("CLOVE_CRASH_POINT", point)
                    .env("CLOVE_CRASH_SKIP", skip.to_string())
                    .env("CLOVE_KILL_STOP_AFTER", "40")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();
                let status = child.wait().unwrap();
                runs += 1;
                if status.code() != Some(99) {
                    failures.push(format!("{name}: the child ended with {:?}, the crash point was not reached", status.code()));
                    continue;
                }
                match check(&root, cipher, &ack, large, 1) {
                    Ok(text) => {
                        println!("{name}: exit 99, reopened: {text}");
                        let _ = std::fs::remove_dir_all(&root);
                    }
                    Err((class, text)) => {
                        let kept = std::env::temp_dir().join(format!("clove-crashpoint-failed-{}-{}", name, uuid::Uuid::new_v4()));
                        let _ = std::fs::rename(&root, &kept);
                        failures.push(format!("{name}: [{class}] {text} (kept: {})", kept.display()));
                    }
                }
            }
        }
    }
    println!("crash points: {} of {runs} runs reopened on the last durable commit (the ones that fell in the creation of the database reopen as a new, empty database), {} failed", runs - failures.len(), failures.len());
    let _ = std::fs::remove_dir_all(&base);
    assert!(failures.is_empty(), "{} of {runs} failed:
{}", failures.len(), failures.join("
"));
}

fn files_of(root: &Path) -> Vec<String> {
    let mut files = Vec::new();
    if root.exists() {
        all_files(root, &mut files);
    }
    let mut names: Vec<String> = files.iter().map(|p| p.strip_prefix(root).unwrap().display().to_string()).collect();
    names.sort();
    names
}

/// The creation of a new encrypted database is atomic: whatever point of it the process dies at (the pages of its first commits, the
/// pending file, the closing, the placing), the next open finds either no database (and makes one) or a complete one. Never `NotCloveDatabase`.
#[test]
fn a_crash_at_any_point_of_the_creation_leaves_no_database_or_a_whole_one() {
    let base = std::env::temp_dir().join(format!("clove-creation-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&base).unwrap();
    // (crash point, first skip, last skip, tuning)
    let plan: Vec<(&str, u64, u64, &str)> = vec![
        ("enc_write_page", 0, 90, "off"),
        ("enc_drain_before_seal", 0, 8, "on"),
        ("enc_drain_after_seal", 0, 8, "on"),
        ("enc_drain_mid_write", 0, 8, "on"),
        ("enc_drain_before_sync", 0, 8, "on"),
        ("enc_drain_after_sync", 0, 8, "on"),
        ("create_after_pending", 0, 0, "on"),
        ("create_before_place", 0, 0, "on"),
        ("create_after_place", 0, 0, "on"),
        ("create_after_folder_sync", 0, 0, "on"),
    ];
    let (mut runs, mut no_database, mut whole, mut leftovers) = (0, 0, 0, 0);
    let mut failures = Vec::new();
    for cipher in ["aes", "xchacha"] {
        for (point, from, to, tuning) in &plan {
            for skip in *from..=*to {
                // the pages of the first commits are many; every 3rd is enough for the long range
                if *point == "enc_write_page" && skip % 3 != 0 {
                    continue;
                }
                let name = format!("{point}-{cipher}-{skip}");
                let root = base.join(&name);
                let ack = base.join(format!("{name}.ack"));
                let status = Command::new(std::env::current_exe().unwrap())
                    .args(["kill_child", "--exact", "--ignored", "--test-threads=1"])
                    .env("CLOVE_KILL_ROOT", &root)
                    .env("CLOVE_KILL_CIPHER", cipher)
                    .env("CLOVE_KILL_ACK", &ack)
                    .env("CLOVE_KILL_MODE", "small")
                    .env("CLOVE_KILL_FIRST", "1")
                    .env("CLOVE_KILL_TUNING", tuning)
                    .env("CLOVE_CRASH_POINT", point)
                    .env("CLOVE_CRASH_SKIP", skip.to_string())
                    .env("CLOVE_KILL_STOP_AFTER", "6")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .unwrap();
                if status.code() != Some(99) {
                    // the point is not reached that many times: the child ended normally; nothing to check for this skip
                    let _ = std::fs::remove_dir_all(&root);
                    continue;
                }
                runs += 1;
                let before = files_of(&root);
                let final_exists = before.iter().any(|f| f.ends_with("store.cldb"));
                let pending = before.iter().any(|f| f.ends_with("store.cldb.new") || f.ends_with("store.cldb.new.creating"));
                if final_exists { whole += 1 } else { no_database += 1 }
                if pending { leftovers += 1 }
                match check(&root, cipher, &ack, false, 1) {
                    Ok(_) => {}
                    Err((class, text)) => failures.push(format!("{name}: [{class}] {text} (before the reopen: {before:?})")),
                }
                let after = files_of(&root);
                if after.iter().any(|f| f.ends_with(".new") || f.ends_with(".creating")) {
                    failures.push(format!("{name}: a pending file is left after the reopen: {after:?}"));
                }
                let _ = std::fs::remove_dir_all(&root);
            }
        }
    }
    println!("creation crashes: {runs} runs (both ciphers); at the crash {no_database} had no database file ({leftovers} runs had a pending file), {whole} had the final file; failures {}", failures.len());
    let _ = std::fs::remove_dir_all(&base);
    assert!(runs > 40 && no_database > 0 && whole > 0, "the plan did not cover both states: {runs} {no_database} {whole}");
    assert!(failures.is_empty(), "{} failed:\n{}", failures.len(), failures.join("\n"));
}

/// A pending file left beside a database that exists is removed at the next open, and the database is untouched.
#[test]
fn a_pending_file_beside_a_whole_database_is_removed_at_the_next_open() {
    let base = std::env::temp_dir().join(format!("clove-pending-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&base).unwrap();
    let ack = base.join("a.ack");
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["kill_child", "--exact", "--ignored", "--test-threads=1"])
        .env("CLOVE_KILL_ROOT", &base)
        .env("CLOVE_KILL_CIPHER", "aes")
        .env("CLOVE_KILL_ACK", &ack)
        .env("CLOVE_KILL_MODE", "small")
        .env("CLOVE_KILL_FIRST", "1")
        .env("CLOVE_KILL_STOP_AFTER", "4")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    let dir = base.join("records");
    std::fs::write(dir.join("store.cldb.new"), b"half a file").unwrap();
    std::fs::write(dir.join("store.cldb.new.creating"), b"half a file").unwrap();
    check(&base, "aes", &ack, false, 1).unwrap();
    assert!(!dir.join("store.cldb.new").exists() && !dir.join("store.cldb.new.creating").exists());
    assert!(dir.join("store.cldb").exists() && std::fs::metadata(dir.join("store.cldb")).unwrap().len() > 0);
    let _ = std::fs::remove_dir_all(&base);
}

/// The plain database (no encryption), looked at and not changed: is there a window in its creation too? The child dies after the file was
/// created and before its first meta commit; then the next open.
#[cfg(not(clove_test_encrypt_all))]
#[test]
fn the_plain_database_creation_window_is_reported_not_fixed() {
    let base = std::env::temp_dir().join(format!("clove-plain-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&base).unwrap();
    let ack = base.join("p.ack");
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["kill_child", "--exact", "--ignored", "--test-threads=1"])
        .env("CLOVE_KILL_ROOT", &base)
        .env("CLOVE_KILL_CIPHER", "aes")
        .env("CLOVE_KILL_ACK", &ack)
        .env("CLOVE_KILL_MODE", "small")
        .env("CLOVE_KILL_FIRST", "1")
        .env("CLOVE_KILL_PLAIN", "1")
        .env("CLOVE_CRASH_POINT", "create_plain_before_first_commit")
        .env("CLOVE_KILL_STOP_AFTER", "4")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(99), "the plain crash point was not reached");
    let files = files_of(&base);
    // the next open, in a child (the setting travels in its environment, not in this process)
    let reopened = Command::new(std::env::current_exe().unwrap())
        .args(["kill_child", "--exact", "--ignored", "--test-threads=1"])
        .env("CLOVE_KILL_ROOT", &base)
        .env("CLOVE_KILL_CIPHER", "aes")
        .env("CLOVE_KILL_ACK", &ack)
        .env("CLOVE_KILL_MODE", "reopen_check")
        .env("CLOVE_KILL_FIRST", "1")
        .env("CLOVE_KILL_PLAIN", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    let state = if reopened.status.success() {
        "reopens (a new database is made)".to_string()
    } else {
        let text = format!("{}{}", String::from_utf8_lossy(&reopened.stdout), String::from_utf8_lossy(&reopened.stderr));
        format!("does NOT reopen: {}", text.lines().find(|l| l.contains("panicked") || l.contains("Err")).unwrap_or("(no message)").trim())
    };
    println!("PLAIN database, process killed after the file was created and before its first meta commit: files {files:?}; the next open {state}");
    let _ = std::fs::remove_dir_all(&base);
}

/// A process that dies while the file of an encrypted database is being extended (the new space is only partly filled with sealed blocks)
/// leaves a database that opens, reads, passes the full check of every block, and can be written to afterwards in the space that was added.
#[test]
fn a_crash_while_the_file_grows_leaves_every_block_sealed() {
    let base = std::env::temp_dir().join(format!("clove-grow-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&base).unwrap();
    let mut failures = Vec::new();
    let mut reached = 0;
    for cipher in ["aes", "xchacha"] {
        for skip in [2u64, 6, 12, 30] {
            let name = format!("grow-{cipher}-{skip}");
            let root = base.join(&name);
            let ack = base.join(format!("{name}.ack"));
            let status = Command::new(std::env::current_exe().unwrap())
                .args(["kill_child", "--exact", "--ignored", "--test-threads=1"])
                .env("CLOVE_KILL_ROOT", &root)
                .env("CLOVE_KILL_CIPHER", cipher)
                .env("CLOVE_KILL_ACK", &ack)
                .env("CLOVE_KILL_MODE", "large")
                .env("CLOVE_KILL_FIRST", "1")
                .env("CLOVE_CRASH_POINT", "enc_fill_mid")
                .env("CLOVE_CRASH_SKIP", skip.to_string())
                .env("CLOVE_KILL_STOP_AFTER", "40")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            if status.code() != Some(99) {
                failures.push(format!("{name}: the child ended with {:?}, the crash point was not reached", status.code()));
                continue;
            }
            reached += 1;
            // the file exactly as the crash left it, before any open could trim it
            if let Err(e) = verify_encrypted_files(&root, "records", "store", &EncryptionHandle::new(config(cipher))) {
                failures.push(format!("{name}: [verify before the reopen] {e:?}"));
                continue;
            }
            match check(&root, cipher, &ack, true, 1) {
                Ok(_) => {}
                Err((class, text)) => {
                    failures.push(format!("{name}: [{class}] {text}"));
                    continue;
                }
            }
            // writing afterwards into the free space is sound, and the full check still passes
            let events: Events = Default::default();
            let storage = open(&root, cipher, &events).unwrap();
            let db = storage.db_manager("store");
            let first = last_ack(&ack) + 1;
            for b in first..first + 6 {
                db.commit_batch_atomic(&batch(b, true), &[]).unwrap();
            }
            storage.close();
            drop(storage);
            if let Err(e) = verify_encrypted_files(&root, "records", "store", &EncryptionHandle::new(config(cipher))) {
                failures.push(format!("{name}: [verify after writing] {e:?}"));
            }
        }
    }
    let _ = std::fs::remove_dir_all(&base);
    assert!(reached > 0 && failures.is_empty(), "{} failed ({reached} reached the point):\n{}", failures.len(), failures.join("\n"));
}
