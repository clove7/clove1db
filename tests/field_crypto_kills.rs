//! Rows with protected fields (and rows with a protected attachment) written by a process that is
//! killed. A child writes row after row and, after each write returns, records the row number in a
//! separate file; the parent kills it at a random moment (or the child exits at a named crash point),
//! then opens the database with the same keys and checks it: every acknowledged row is exact and its
//! protected values open to what was written, the one row after it is all there or all absent, an
//! attachment is exact, nothing is left over, and no marker text is in any file.
//!
//! Fifty forced kills, on purpose, alone:
//! `cargo test --test field_crypto_kills -- --ignored --nocapture fifty_forced`
//! The crash points run with `--features crash-inject` (they are part of an all-features run).
use clove1db::{
    CloveFields, EncryptionConfig, KeySource,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    entity::Entity,
    field_crypto::{Sealed, SearchPrint},
    storage::{DatabaseConfig, Storage, StorageConfig},
};
#[path = "child_log/mod.rs"]
mod child_log;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Rec {
    id: String,
    title: String,
    #[clove(encrypt, id = 1)]
    phone: Sealed<String>,
    #[clove(encrypt, id = 2)]
    note: Sealed<String>,
    #[clove(search_print, id = 3)]
    token: SearchPrint,
}
impl Entity for Rec {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// The same shape, in a table whose rows carry an attachment.
#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct FileRec {
    id: String,
    title: String,
    #[clove(encrypt, id = 1)]
    phone: Sealed<String>,
    #[clove(encrypt, id = 2)]
    note: Sealed<String>,
    #[clove(search_print, id = 3)]
    token: SearchPrint,
}
impl Entity for FileRec {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn row_id(i: u64) -> String {
    format!("r{i:05}")
}
fn phone(i: u64) -> String {
    format!("KILLMARK-PHONE-{i:05}")
}
fn note(i: u64) -> String {
    format!("KILLMARK-NOTE-{i:05}-").repeat(120)
}
fn token(i: u64) -> String {
    format!("KILLMARK-TOKEN-{i:05}")
}
/// More than two sealed blocks.
fn blob(i: u64) -> Vec<u8> {
    format!("KILLMARK-BLOB-{i:05}-").repeat(7000).into_bytes()
}

fn cipher_of(name: &str) -> CipherKind {
    if name == "aes" { CipherKind::Aes256GcmSiv } else { CipherKind::XChaCha20Poly1305 }
}

fn keys(cipher: &str) -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite { cipher: cipher_of(cipher), hkdf: HkdfHash::Sha256 },
        read: Some(KeySource::Raw(Key32::from_bytes(&[1; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[200; 32]))),
    }
}

/// The keys for the protected fields: their own keys in an ordinary database, the keys of the
/// encryption of the whole database under the test cfg.
fn with_keys(db: DatabaseConfig, cipher: &str) -> DatabaseConfig {
    #[cfg(clove_test_encrypt_all)]
    {
        db.encryption(keys(cipher))
    }
    #[cfg(not(clove_test_encrypt_all))]
    {
        db.field_encryption(keys(cipher))
    }
}

/// A database with attachments keeps no backup file (the library turns the one off when the other is
/// on), so the rows without attachments run with the backup file and the others with attachments.
fn open(root: &Path, cipher: &str, with_file: bool) -> clove1db::units::Result<Storage> {
    let db = DatabaseConfig::new("records", "store").dir_path(root.to_path_buf()).has_cache(false);
    let db = if with_file {
        with_keys(db.blob_enabled(true), cipher).register_sealed_blob::<FileRec>("files")
    } else {
        with_keys(db.backup_enabled(true), cipher).register_sealed::<Rec>("recs")
    };
    Storage::builder(StorageConfig::default()).add_database(db).build()
}

fn write_row(storage: &Storage, with_file: bool, i: u64) -> clove1db::units::Result<()> {
    if with_file {
        let rec = FileRec {
            id: row_id(i),
            title: format!("KILLVISIBLE-{i}"),
            phone: Sealed::new(phone(i)),
            note: Sealed::new(note(i)),
            token: SearchPrint::new(token(i)),
        };
        storage.domain::<FileRec>().repo().set_with_blob(&row_id(i), &rec, &blob(i))
    } else {
        let rec = Rec {
            id: row_id(i),
            title: format!("KILLVISIBLE-{i}"),
            phone: Sealed::new(phone(i)),
            note: Sealed::new(note(i)),
            token: SearchPrint::new(token(i)),
        };
        storage.domain::<Rec>().repo().set(&row_id(i), &rec)
    }
}

/// The child: writes row after row and records each acknowledged row. With `CLOVE_KILL_COUNT` it
/// stops after that many rows; the crash points make it exit early.
#[test]
#[ignore]
fn kill_child() {
    let Ok(root) = std::env::var("CLOVE_KILL_ROOT") else { return };
    let cipher = std::env::var("CLOVE_KILL_CIPHER").unwrap();
    let ack = std::env::var("CLOVE_KILL_ACK").unwrap();
    let mode = std::env::var("CLOVE_KILL_MODE").unwrap();
    let with_file = mode.ends_with("files");
    let storage = open(Path::new(&root), &cipher, with_file).unwrap();
    if mode.starts_with("reopen") {
        std::thread::sleep(Duration::from_secs(5));
        return;
    }
    let mut ack_file = std::fs::OpenOptions::new().create(true).append(true).open(&ack).unwrap();
    let mut i = std::env::var("CLOVE_KILL_FIRST").unwrap().parse::<u64>().unwrap();
    let count = std::env::var("CLOVE_KILL_COUNT").ok().and_then(|c| c.parse::<u64>().ok());
    let mut done = 0u64;
    loop {
        if count.is_some_and(|c| done >= c) {
            storage.close();
            return;
        }
        write_row(&storage, with_file, i).unwrap();
        writeln!(ack_file, "{i}").unwrap();
        ack_file.sync_all().unwrap();
        i += 1;
        done += 1;
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

fn spawn(root: &Path, cipher: &str, ack: &Path, mode: &str, first: u64, count: Option<u64>, crash: Option<&str>) -> std::process::Child {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["kill_child", "--exact", "--ignored", "--test-threads=1"])
        .env("CLOVE_KILL_ROOT", root)
        .env("CLOVE_KILL_CIPHER", cipher)
        .env("CLOVE_KILL_ACK", ack)
        .env("CLOVE_KILL_MODE", mode)
        .env("CLOVE_KILL_FIRST", first.to_string())
        .stdout(child_log::out(root))
        .stderr(child_log::out(root));
    if let Some(count) = count {
        command.env("CLOVE_KILL_COUNT", count.to_string());
    }
    if let Some(point) = crash {
        command.env("CLOVE_CRASH_POINT", point);
    }
    command.spawn().unwrap()
}

fn all_files(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                all_files(&p, out);
            } else {
                out.push(p);
            }
        }
    }
}

fn has(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|w| w == needle)
}

/// What is wrong with the database after a kill, or nothing. `Err((class, text))`.
fn check(root: &Path, cipher: &str, ack: &Path, with_file: bool, first: u64) -> Result<String, (&'static str, String)> {
    let acked = last_ack(ack);
    let storage = open(root, cipher, with_file).map_err(|e| ("open", format!("{e:?}")))?;
    let (grant, verifier);
    // (id, phone, note, token matches, attachment) of every row present, as read and opened.
    let mut seen: Vec<(u64, String, String, bool, Option<Vec<u8>>)> = Vec::new();
    if with_file {
        let domain = storage.domain::<FileRec>();
        grant = domain.read_grant().map_err(|e| ("grant", format!("{e:?}")))?;
        verifier = domain.verifier().map_err(|e| ("verifier", format!("{e:?}")))?;
        let rows = domain.repo().list_map(|r| r).map_err(|e| ("read", format!("{e:?}")))?;
        for r in rows {
            let i: u64 = r.id[1..].parse().map_err(|_| ("row", format!("odd id {}", r.id)))?;
            let phone = r.phone.open(&grant).map_err(|e| ("open-value", format!("{e:?}")))?;
            let note = r.note.open(&grant).map_err(|e| ("open-value", format!("{e:?}")))?;
            let matched = r.token.matches(token(i), &verifier).map_err(|e| ("match", format!("{e:?}")))?;
            let mut bytes = Vec::new();
            domain
                .repo()
                .open_blob(&r.id)
                .and_then(|mut b| b.read_to_end(&mut bytes).map_err(Into::into))
                .map_err(|e| ("attachment", format!("{e:?}")))?;
            seen.push((i, phone, note, matched, Some(bytes)));
        }
    } else {
        let domain = storage.domain::<Rec>();
        grant = domain.read_grant().map_err(|e| ("grant", format!("{e:?}")))?;
        verifier = domain.verifier().map_err(|e| ("verifier", format!("{e:?}")))?;
        let rows = domain.repo().list_map(|r| r).map_err(|e| ("read", format!("{e:?}")))?;
        for r in rows {
            let i: u64 = r.id[1..].parse().map_err(|_| ("row", format!("odd id {}", r.id)))?;
            let phone = r.phone.open(&grant).map_err(|e| ("open-value", format!("{e:?}")))?;
            let note = r.note.open(&grant).map_err(|e| ("open-value", format!("{e:?}")))?;
            let matched = r.token.matches(token(i), &verifier).map_err(|e| ("match", format!("{e:?}")))?;
            seen.push((i, phone, note, matched, None));
        }
    }
    for (i, phone_text, note_text, matched, attachment) in &seen {
        if *i > acked + 1 {
            return Err(("future-row", format!("row {i} exists but only {acked} was acknowledged")));
        }
        if *phone_text != phone(*i) || *note_text != note(*i) || !*matched {
            return Err(("row-content", format!("row {i} differs from what was written")));
        }
        if let Some(bytes) = attachment {
            if *bytes != blob(*i) {
                return Err(("attachment-content", format!("the attachment of row {i} differs")));
            }
        }
    }
    // Rows without attachments: the history file kept a version of every acknowledged row.
    let history = storage.db_manager("store").backup_manager.as_ref();
    if !with_file && history.is_none() {
        return Err(("history", "the database has no backup file".to_string()));
    }
    for i in first..=acked {
        if !seen.iter().any(|(n, ..)| *n == i) {
            return Err(("acked-row", format!("row {i} (acked up to {acked}) is missing")));
        }
        if let Some(history) = history {
            let versions = history.current_version("recs", &row_id(i)).map_err(|e| ("history", format!("{e:?}")))?;
            if versions == 0 {
                return Err(("history", format!("row {i} was acknowledged but the history file holds no version of it")));
            }
        }
    }
    storage.close();
    drop(storage);
    let mut files = Vec::new();
    all_files(root, &mut files);
    if with_file {
        let attachments = files.iter().filter(|p| p.to_string_lossy().contains(".pblobs")).count();
        if attachments != seen.len() {
            return Err(("leftover", format!("{attachments} attachment files for {} rows", seen.len())));
        }
    }
    let mut ordinary = false;
    for f in &files {
        let bytes = std::fs::read(f).unwrap();
        if has(&bytes, b"KILLMARK") {
            return Err(("marker", format!("{} contains the marker text", f.display())));
        }
        ordinary |= has(&bytes, b"KILLVISIBLE");
    }
    #[cfg(not(clove_test_encrypt_all))]
    if !seen.is_empty() && !ordinary {
        return Err(("blind-scan", "an ordinary field was not found in any file".into()));
    }
    let _ = ordinary;
    Ok(format!("acked={acked} rows={}", seen.len()))
}

#[test]
#[ignore]
fn fifty_forced_kills_leave_rows_that_open_exact_and_hold_no_marker_text() {
    let base = std::env::temp_dir().join(format!("clove-field-kills-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&base).unwrap();
    let mut failures = Vec::new();
    let mut passed = 0;
    for k in 0..50u32 {
        let cipher = if k % 2 == 0 { "aes" } else { "xchacha" };
        let with_file = (k / 2) % 2 == 1;
        let during_repair = k % 10 == 9;
        let mut rng = 0x9E37_79B9_7F4A_7C15u64 ^ (k as u64 + 1).wrapping_mul(0xD1B5_4A32_D192_ED03);
        let wait_ms = 50 + next(&mut rng) % 1951;
        let repair_ms = 1 + next(&mut rng) % 400;
        let root = base.join(format!("k{k:02}"));
        let ack = base.join(format!("k{k:02}.ack"));
        let mode = if with_file { "files" } else { "rows" };
        let mut child = spawn(&root, cipher, &ack, mode, 1, None, None);
        let started = Instant::now();
        while last_ack(&ack) == 0 {
            assert!(started.elapsed() < Duration::from_secs(60), "kill {k}: the child never acknowledged a row; it printed: {}", child_log::said(&root));
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(wait_ms));
        child.kill().unwrap();
        let _ = child.wait();
        if during_repair {
            let mut again = spawn(&root, cipher, &ack, &format!("reopen-{mode}"), 1, None, None);
            std::thread::sleep(Duration::from_millis(repair_ms));
            again.kill().unwrap();
            let _ = again.wait();
        }
        match check(&root, cipher, &ack, with_file, 1) {
            Ok(text) => {
                passed += 1;
                println!("kill {k:02} {cipher:7} {mode:5} wait={wait_ms}ms{} ok {text}", if during_repair { format!(" +reopen-kill@{repair_ms}ms") } else { String::new() });
                let _ = std::fs::remove_dir_all(&root);
            }
            Err((class, text)) => {
                let kept = std::env::temp_dir().join(format!("clove-field-kill-failed-{k:02}-{}", uuid::Uuid::new_v4()));
                let _ = std::fs::rename(&root, &kept);
                let line = format!("kill {k:02} {cipher} {mode} wait={wait_ms}ms reopen-kill={during_repair}@{repair_ms}ms [{class}] {text} (kept: {})", kept.display());
                println!("FAIL {line}");
                failures.push(line);
            }
        }
    }
    println!("forced kills: {passed} of 50 passed");
    let _ = std::fs::remove_dir_all(&base);
    assert!(failures.is_empty(), "{} of 50 failed:\n{}", failures.len(), failures.join("\n"));
}

/// The child exits at a named point of the write path; after each, the same checks.
#[cfg(feature = "crash-inject")]
#[test]
fn a_crash_at_any_point_of_a_protected_write_leaves_rows_that_open_exact() {
    let points = [
        "before_commit",
        "after_commit",
        "journal_during_append",
        "journal_before_commit",
        "journal_after_commit",
        "journal_blob_before_descriptor",
        "journal_blob_after_descriptor",
        "backup_after_version",
    ];
    let base = std::env::temp_dir().join(format!("clove-field-crash-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&base).unwrap();
    let mut failures = Vec::new();
    let mut reached = 0;
    for (n, point) in points.iter().enumerate() {
        for (m, mode) in ["rows", "files"].iter().enumerate() {
            let cipher = if (n + m) % 2 == 0 { "aes" } else { "xchacha" };
            let root = base.join(format!("p{n}{m}"));
            let ack = base.join(format!("p{n}{m}.ack"));
            // Three rows written normally, then one write that stops at the point.
            let mut setup = spawn(&root, cipher, &ack, mode, 1, Some(3), None);
            let setup_status = setup.wait().unwrap();
            assert!(setup_status.success(), "{point}: setup child failed: {}", child_log::why(&root, setup_status));
            assert_eq!(last_ack(&ack), 3);
            let mut crashing = spawn(&root, cipher, &ack, mode, 4, Some(1), Some(point));
            let status = crashing.wait().unwrap();
            let unexpected = if status.code() == Some(99) { String::new() } else { format!(" (the child ended with {})", child_log::why(&root, status)) };
            if status.code() == Some(99) {
                reached += 1;
            }
            let with_file = *mode == "files";
            match check(&root, cipher, &ack, with_file, 1) {
                Ok(text) => println!("{point:32} {mode:5} exit={:?} ok {text}", status.code()),
                Err((class, text)) => failures.push(format!("{point} {mode} exit={:?} [{class}] {text}{unexpected}", status.code())),
            }
            // And it opens again, the same.
            if let Err((class, text)) = check(&root, cipher, &ack, with_file, 1) {
                failures.push(format!("{point} {mode} second open [{class}] {text}"));
            }
        }
    }
    println!("crash points reached: {reached} of {}", points.len() * 2);
    let _ = std::fs::remove_dir_all(&base);
    assert!(reached > 0, "no crash point was reached");
    assert!(failures.is_empty(), "{} failed:\n{}", failures.len(), failures.join("\n"));
}
