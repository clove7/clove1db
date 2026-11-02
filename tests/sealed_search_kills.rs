//! Rows with fingerprints (a whole-value fingerprint, fingerprints of parts, a search print) written by a
//! process that is killed. A child writes row after row and, after each write returns, records the row
//! number in a separate file; the parent kills it at a random moment (or the child exits at a named crash
//! point), then opens the database with the same keys and checks it: every row present is exact, it has
//! its fingerprints, and every kind of search (`print_eq`, `part_candidates`, the confirmed `part_search`,
//! and `scan_sealed`) gives what a witness that opens every row gives; a second row with the value of
//! one that exists is refused; no marker text is in any file.
//!
//! Fifty forced kills, on purpose, alone:
//! `cargo test --test sealed_search_kills -- --ignored --nocapture fifty_forced`
//! The crash points run with `--features crash-inject` (they are part of an all-features run).
use clove1db::{
    CloveFields, EncryptionConfig, KeySource, Unique,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    entity::Entity,
    field_crypto::{Sealed, SearchPrint},
    storage::{DatabaseConfig, Storage, StorageConfig},
};
#[path = "child_log/mod.rs"]
mod child_log;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Rec {
    id: String,
    title: String,
    #[clove(encrypt, id = 1, print = "full", normalize = "trim")]
    phone: Sealed<String>,
    #[clove(encrypt, id = 2, print = "parts", window = 3, grade = "balanced", normalize = "trim")]
    name: Sealed<String>,
    #[clove(search_print, id = 3)]
    token: SearchPrint,
}
impl Entity for Rec {
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
fn name(i: u64) -> String {
    format!("KILLMARK-NAME-{i:05}-ENDING")
}
fn token(i: u64) -> String {
    format!("KILLMARK-TOKEN-{i:05}")
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

fn open(root: &Path, cipher: &str) -> clove1db::units::Result<Storage> {
    let db = DatabaseConfig::new("records", "store").dir_path(root.to_path_buf()).has_cache(false);
    let db = with_keys(db.backup_enabled(true), cipher).unique(Unique::on(Rec::phone.print_field())).register_sealed::<Rec>("recs");
    Storage::builder(StorageConfig::default()).add_database(db).build()
}

fn write_row(storage: &Storage, i: u64) -> clove1db::units::Result<()> {
    let rec = Rec {
        id: row_id(i),
        title: format!("KILLVISIBLE-{i}"),
        phone: Sealed::new(phone(i)),
        name: Sealed::new(name(i)),
        token: SearchPrint::new(token(i)),
    };
    storage.domain::<Rec>().repo().set(&row_id(i), &rec)
}

/// The child: writes row after row and records each acknowledged row. With `CLOVE_KILL_COUNT` it stops
/// after that many rows; the crash points make it exit early.
#[test]
#[ignore]
fn kill_child() {
    let Ok(root) = std::env::var("CLOVE_KILL_ROOT") else { return };
    let cipher = std::env::var("CLOVE_KILL_CIPHER").unwrap();
    let ack = std::env::var("CLOVE_KILL_ACK").unwrap();
    let mode = std::env::var("CLOVE_KILL_MODE").unwrap();
    let storage = open(Path::new(&root), &cipher).unwrap();
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
        write_row(&storage, i).unwrap();
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

type Failure = (&'static str, String);

fn ids_of(rows: Vec<Rec>) -> BTreeSet<String> {
    rows.into_iter().map(|r| r.id).collect()
}

/// What is wrong with the database after a kill, or nothing. `Err((class, text))`.
fn check(root: &Path, cipher: &str, ack: &Path, first: u64) -> Result<String, Failure> {
    let acked = last_ack(ack);
    let storage = open(root, cipher).map_err(|e| ("open", format!("{e:?}")))?;
    let domain = storage.domain::<Rec>();
    let read = domain.read_grant().map_err(|e| ("grant", format!("{e:?}")))?;
    let search = domain.search_grant().map_err(|e| ("search-grant", format!("{e:?}")))?;
    let verifier = domain.verifier().map_err(|e| ("verifier", format!("{e:?}")))?;
    // The witness: every row present, read as stored and opened one by one.
    let rows = domain.repo().list_map(|r| r).map_err(|e| ("read", format!("{e:?}")))?;
    let mut witness: Vec<(u64, String, String)> = Vec::new();
    for r in &rows {
        let i: u64 = r.id[1..].parse().map_err(|_| ("row", format!("odd id {}", r.id)))?;
        if i > acked + 1 {
            return Err(("future-row", format!("row {i} exists but only {acked} was acknowledged")));
        }
        let phone_text = r.phone.open(&read).map_err(|e| ("open-value", format!("{e:?}")))?;
        let name_text = r.name.open(&read).map_err(|e| ("open-value", format!("{e:?}")))?;
        let matched = r.token.matches(token(i), &verifier).map_err(|e| ("match", format!("{e:?}")))?;
        if phone_text != phone(i) || name_text != name(i) || !matched {
            return Err(("row-content", format!("row {i} differs from what was written")));
        }
        witness.push((i, phone_text, name_text));
    }
    for i in first..=acked {
        if !witness.iter().any(|(n, ..)| *n == i) {
            return Err(("acked-row", format!("row {i} (acked up to {acked}) is missing")));
        }
    }
    let truth = |want: &dyn Fn(&str, &str) -> bool| -> BTreeSet<String> {
        witness.iter().filter(|(_, p, n)| want(p, n)).map(|(i, ..)| row_id(*i)).collect()
    };
    // Every row has its fingerprints: the equality search finds it, alone, and so does a piece of its name.
    for (i, p, n) in &witness {
        let id = row_id(*i);
        let by_print = ids_of(domain.query().filter(Rec::phone.print_eq(p, &search)).collect().map_err(|e| ("print_eq", format!("{e:?}")))?);
        if by_print != BTreeSet::from([id.clone()]) {
            return Err(("no-print", format!("row {i}: print_eq gave {by_print:?}")));
        }
        let piece = &n[5..21];
        let found = Rec::name.part_search(piece).run(domain, &search).map_err(|e| ("part_search", format!("{e:?}")))?;
        if !found.is_confirmed() || !ids_of(found.into_rows()).contains(&id) {
            return Err(("no-parts", format!("row {i}: a piece of its name does not find it")));
        }
    }
    // Sets of rows: each search against the witness.
    let mut needles: Vec<String> = vec!["NAME-0000".into(), "NAME-0001".into(), "KILLMARK-NAME-000".into(), "ENDING".into(), "NO-SUCH-TEXT".into()];
    if let Some((i, _, _)) = witness.last() {
        needles.push(format!("NAME-{i:05}"));
    }
    for needle in &needles {
        let want = truth(&|_, n| n.contains(needle.as_str()));
        let candidates = ids_of(domain.query().filter(Rec::name.part_candidates(needle, &search)).collect().map_err(|e| ("part_candidates", format!("{e:?}")))?);
        if !want.is_subset(&candidates) {
            return Err(("candidates", format!("{needle:?}: a matching row is missing from the candidates")));
        }
        let confirmed = ids_of(Rec::name.part_search(needle).run(domain, &search).map_err(|e| ("part_search", format!("{e:?}")))?.into_confirmed().map_err(|e| ("part_search", format!("{e:?}")))?);
        if confirmed != want {
            return Err(("part_search", format!("{needle:?}: {} rows against {} in the witness", confirmed.len(), want.len())));
        }
        let scanned = ids_of(Rec::name.scan_sealed(&read).run(domain, |v: &String| v.contains(needle.as_str())).map_err(|e| ("scan", format!("{e:?}")))?);
        if scanned != want {
            return Err(("scan", format!("{needle:?}: {} rows against {} in the witness", scanned.len(), want.len())));
        }
    }
    // A scan by a range, and one by whole values, against the witness.
    let upper = format!("KILLMARK-PHONE-{:05}", acked / 2);
    let want = truth(&|p, _| p <= upper.as_str());
    let scanned = ids_of(Rec::phone.scan_sealed(&read).run(domain, |v: &String| v.as_str() <= upper.as_str()).map_err(|e| ("scan", format!("{e:?}")))?);
    if scanned != want {
        return Err(("scan-range", format!("{} rows against {} in the witness", scanned.len(), want.len())));
    }
    // The unique constraint holds: no two rows share a phone, and a second row with a present phone is refused.
    let phones: BTreeSet<&str> = witness.iter().map(|(_, p, _)| p.as_str()).collect();
    if phones.len() != witness.len() {
        return Err(("unique", "two rows hold the same phone".into()));
    }
    if let Some((i, p, _)) = witness.first() {
        let twin = Rec { id: "twin".into(), title: "twin".into(), phone: Sealed::new(p.clone()), name: Sealed::new("TWIN".into()), token: SearchPrint::new("twin") };
        if domain.repo().set("twin", &twin).is_ok() {
            return Err(("unique", format!("a second row with the phone of row {i} was accepted")));
        }
        if domain.repo().get("twin").is_ok() {
            return Err(("unique", "the refused row was kept".into()));
        }
    }
    storage.close();
    drop(storage);
    let mut files = Vec::new();
    all_files(root, &mut files);
    let mut ordinary = false;
    for f in &files {
        let bytes = std::fs::read(f).unwrap();
        if has(&bytes, b"KILLMARK") {
            return Err(("marker", format!("{} contains the marker text", f.display())));
        }
        ordinary |= has(&bytes, b"KILLVISIBLE");
    }
    #[cfg(not(clove_test_encrypt_all))]
    if !witness.is_empty() && !ordinary {
        return Err(("blind-scan", "an ordinary field was not found in any file".into()));
    }
    let _ = ordinary;
    Ok(format!("acked={acked} rows={}", witness.len()))
}

#[test]
#[ignore]
fn fifty_forced_kills_leave_rows_whose_searches_match_the_witness() {
    let base = std::env::temp_dir().join(format!("clove-search-kills-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&base).unwrap();
    let mut failures = Vec::new();
    let mut passed = 0;
    for k in 0..50u32 {
        let cipher = if k % 2 == 0 { "aes" } else { "xchacha" };
        let during_repair = k % 10 == 9;
        let mut rng = 0x9E37_79B9_7F4A_7C15u64 ^ (k as u64 + 1).wrapping_mul(0xD1B5_4A32_D192_ED03);
        let wait_ms = 50 + next(&mut rng) % 1951;
        let repair_ms = 1 + next(&mut rng) % 400;
        let root = base.join(format!("k{k:02}"));
        let ack = base.join(format!("k{k:02}.ack"));
        let mut child = spawn(&root, cipher, &ack, "rows", 1, None, None);
        let started = Instant::now();
        while last_ack(&ack) == 0 {
            assert!(started.elapsed() < Duration::from_secs(60), "kill {k}: the child never acknowledged a row; it printed: {}", child_log::said(&root));
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(wait_ms));
        child.kill().unwrap();
        let _ = child.wait();
        if during_repair {
            let mut again = spawn(&root, cipher, &ack, "reopen-rows", 1, None, None);
            std::thread::sleep(Duration::from_millis(repair_ms));
            again.kill().unwrap();
            let _ = again.wait();
        }
        match check(&root, cipher, &ack, 1) {
            Ok(text) => {
                passed += 1;
                println!("kill {k:02} {cipher:7} wait={wait_ms}ms{} ok {text}", if during_repair { format!(" +reopen-kill@{repair_ms}ms") } else { String::new() });
                let _ = std::fs::remove_dir_all(&root);
            }
            Err((class, text)) => {
                let kept = std::env::temp_dir().join(format!("clove-search-kill-failed-{k:02}-{}", uuid::Uuid::new_v4()));
                let _ = std::fs::rename(&root, &kept);
                let line = format!("kill {k:02} {cipher} wait={wait_ms}ms reopen-kill={during_repair}@{repair_ms}ms [{class}] {text} (kept: {})", kept.display());
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
fn a_crash_at_any_point_of_a_write_with_fingerprints_leaves_searches_that_match_the_witness() {
    let points = ["before_commit", "after_commit", "journal_during_append", "journal_before_commit", "journal_after_commit", "backup_after_version"];
    let base = std::env::temp_dir().join(format!("clove-search-crash-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&base).unwrap();
    let mut failures = Vec::new();
    let mut reached = 0;
    for (n, point) in points.iter().enumerate() {
        let cipher = if n % 2 == 0 { "aes" } else { "xchacha" };
        let root = base.join(format!("p{n}"));
        let ack = base.join(format!("p{n}.ack"));
        // Three rows written normally, then one write that stops at the point.
        let mut setup = spawn(&root, cipher, &ack, "rows", 1, Some(3), None);
        let setup_status = setup.wait().unwrap();
        assert!(setup_status.success(), "{point}: setup child failed: {}", child_log::why(&root, setup_status));
        assert_eq!(last_ack(&ack), 3);
        let mut crashing = spawn(&root, cipher, &ack, "rows", 4, Some(1), Some(point));
        let status = crashing.wait().unwrap();
        let unexpected = if status.code() == Some(99) { String::new() } else { format!(" (the child ended with {})", child_log::why(&root, status)) };
        if status.code() == Some(99) {
            reached += 1;
        }
        match check(&root, cipher, &ack, 1) {
            Ok(text) => println!("{point:28} exit={:?} ok {text}", status.code()),
            Err((class, text)) => failures.push(format!("{point} exit={:?} [{class}] {text}{unexpected}", status.code())),
        }
        if let Err((class, text)) = check(&root, cipher, &ack, 1) {
            failures.push(format!("{point} second open [{class}] {text}"));
        }
    }
    println!("crash points reached: {reached} of {}", points.len());
    let _ = std::fs::remove_dir_all(&base);
    assert!(reached > 0, "no crash point was reached");
    assert!(failures.is_empty(), "{} failed:\n{}", failures.len(), failures.join("\n"));
}
