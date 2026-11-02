//! Changing the keys of a database that has protected fields, with real processes: a program that is
//! stopped at any moment leaves the database either as it was or as it was meant to become, with the
//! values, the verification hash, the fingerprint and the attachments all still working, and the next
//! open settles what is left.
//!
//! The test program starts itself as the child that runs the change (the `child_entry` test does
//! nothing unless the child variables are set).
use clove1db::{
    CloveFields, EncryptionConfig, KeySource,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    entity::Entity,
    field_crypto::{Hashed, Sealed, SearchPrint},
    migration::ChangeProtection,
    storage::{DatabaseConfig, Storage, StorageConfig},
};
#[path = "child_log/mod.rs"]
mod child_log;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const PHONE: &str = "+155-KILL-PHONE-";
const PASSWORD: &str = "KILL-SECRET-PASSWORD";
const EMAIL: &str = "kill.mail@example.test";
const ORDINARY: &str = "KILL-VISIBLE-";

#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Account {
    id: String,
    name: String,
    #[clove(encrypt, id = 1)]
    phone: Sealed<String>,
    #[clove(hash = "argon2id", id = 2)]
    password: Hashed,
    #[clove(search_print, id = 3)]
    email: SearchPrint,
}
impl Entity for Account {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// Plain rows that lengthen the change (the hash of a row costs far more than the copy of one).
#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Note {
    id: String,
    name: String,
}
impl Entity for Note {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// How many plain rows an `Accounts` database holds beside the protected ones.
const NOTES: usize = 12_000;

/// The same fields, in a table whose rows carry an attachment.
#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Dossier {
    id: String,
    name: String,
    #[clove(encrypt, id = 1)]
    phone: Sealed<String>,
    #[clove(search_print, id = 3)]
    email: SearchPrint,
}
impl Entity for Dossier {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// How the keys of the protected fields are held: by the whole database (`w:N`), or by the fields
/// alone in a plain database (`f:N`). `N` is the key; even is AES, odd is XChaCha.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Prot {
    Whole(u8),
    Fields(u8),
}

impl Prot {
    fn text(self) -> String {
        match self {
            Prot::Whole(n) => format!("w:{n}"),
            Prot::Fields(n) => format!("f:{n}"),
        }
    }
    fn parse(text: &str) -> Prot {
        let (kind, n) = text.split_once(':').expect("kind:key");
        let n = n.parse().expect("a key number");
        match kind {
            "w" => Prot::Whole(n),
            _ => Prot::Fields(n),
        }
    }
    fn config(self) -> EncryptionConfig {
        let n = match self {
            Prot::Whole(n) | Prot::Fields(n) => n,
        };
        EncryptionConfig {
            suite: KeySuite {
                cipher: if n % 2 == 0 { CipherKind::Aes256GcmSiv } else { CipherKind::XChaCha20Poly1305 },
                hkdf: HkdfHash::Sha256,
            },
            read: Some(KeySource::Raw(Key32::from_bytes(&[n; 32]))),
            search: Some(KeySource::Raw(Key32::from_bytes(&[n.wrapping_add(100); 32]))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    /// Rows with a hash and a fingerprint, and a backup history.
    Accounts,
    /// Rows with a sealed value and a fingerprint, and an attachment each (no history file).
    Files,
}

impl Shape {
    fn text(self) -> &'static str {
        match self {
            Shape::Accounts => "accounts",
            Shape::Files => "files",
        }
    }
}

fn db_config(root: &Path, shape: Shape, prot: Prot) -> DatabaseConfig {
    let db = DatabaseConfig::new("records", "store").dir_path(root.to_path_buf()).has_cache(false);
    let db = match shape {
        Shape::Accounts => db.backup_enabled(true).register_sealed::<Account>("accounts").register::<Note>("notes"),
        Shape::Files => db.blob_enabled(true).register_sealed_blob::<Dossier>("dossiers"),
    };
    match prot {
        Prot::Whole(_) => db.encryption(prot.config()),
        Prot::Fields(_) => {
            #[cfg(clove_test_encrypt_all)]
            let db = db.plain();
            db.field_encryption(prot.config())
        }
    }
}

fn open(root: &Path, shape: Shape, prot: Prot) -> clove1db::units::Result<Storage> {
    Storage::builder(StorageConfig::default()).add_database(db_config(root, shape, prot)).build()
}

fn attachment(i: usize, scale: usize) -> Vec<u8> {
    let mut v = b"KILL-ATTACHMENT-MARKER-".to_vec();
    v.extend((0..(2_000 * (i + 1) * scale)).map(|k| (k % 251) as u8));
    v
}

fn make(shape: Shape, prot: Prot, rows: usize, scale: usize) -> PathBuf {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = open(&root, shape, prot).unwrap();
    match shape {
        Shape::Accounts => {
            let repo = s.domain::<Account>().repo();
            for i in 0..rows {
                for version in 1..=2 {
                    let a = Account {
                        id: format!("a{i:04}"),
                        name: format!("{ORDINARY}{i}"),
                        phone: Sealed::new(format!("{PHONE}{i}-v{version}")),
                        password: Hashed::new(PASSWORD),
                        email: SearchPrint::new(EMAIL),
                    };
                    repo.set(&a.id, &a).unwrap();
                }
            }
            let db = s.db_manager("store");
            let mut batch = Vec::new();
            for i in 0..NOTES {
                let note = Note { id: format!("n{i:06}"), name: format!("{ORDINARY}note-{i}") };
                batch.push(("notes".to_string(), note.id.clone(), serde_json::to_vec(&note).unwrap()));
                if batch.len() == 500 {
                    db.commit_batch(&batch, &[]).unwrap();
                    batch.clear();
                }
            }
            if !batch.is_empty() {
                db.commit_batch(&batch, &[]).unwrap();
            }
        }
        Shape::Files => {
            let repo = s.domain::<Dossier>().repo();
            for i in 0..rows {
                let d = Dossier {
                    id: format!("d{i:04}"),
                    name: format!("{ORDINARY}{i}"),
                    phone: Sealed::new(format!("{PHONE}{i}")),
                    email: SearchPrint::new(EMAIL),
                };
                repo.set_with_blob(&d.id, &d, &attachment(i % 7, scale)).unwrap();
            }
        }
    }
    s.close();
    root
}

/// Everything the database holds, read through a normal open, and checked: the sealed value, the
/// hash, the fingerprint and the attachment of each row. An open that fails is the answer `Err`.
fn read(root: &Path, shape: Shape, prot: Prot, rows: usize, scale: usize) -> Result<usize, String> {
    let s = open(root, shape, prot).map_err(|e| format!("{e:?}"))?;
    let count = match shape {
        Shape::Accounts => {
            let domain = s.domain::<Account>();
            let (grant, verifier) = (domain.read_grant().unwrap(), domain.verifier().unwrap());
            let list = domain.repo().list().unwrap();
            assert_eq!(list.len(), rows);
            for row in list {
                let i: usize = row.id[1..].parse().unwrap();
                assert_eq!(row.phone.open(&grant).unwrap(), format!("{PHONE}{i}-v2"));
                assert!(row.password.verify(PASSWORD, &verifier).unwrap(), "the hash no longer verifies");
                assert!(row.email.matches(EMAIL, &verifier).unwrap(), "the fingerprint no longer matches");
            }
            assert_eq!(s.db_manager("store").list_entries("notes").unwrap().len(), NOTES);
            rows
        }
        Shape::Files => {
            let domain = s.domain::<Dossier>();
            let (grant, verifier) = (domain.read_grant().unwrap(), domain.verifier().unwrap());
            let repo = domain.repo();
            let list = repo.list().unwrap();
            assert_eq!(list.len(), rows);
            for row in list {
                let i: usize = row.id[1..].parse().unwrap();
                assert_eq!(row.phone.open(&grant).unwrap(), format!("{PHONE}{i}"));
                assert!(row.email.matches(EMAIL, &verifier).unwrap());
                let mut bytes = Vec::new();
                repo.open_blob(&row.id).unwrap().read_to_end(&mut bytes).unwrap();
                assert_eq!(bytes, attachment(i % 7, scale), "an attachment is not what it was");
            }
            rows
        }
    };
    s.close();
    Ok(count)
}

fn all_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().filter_map(|e| e.ok()) {
        if e.path().is_dir() {
            all_files(&e.path(), out);
        } else {
            out.push(e.path());
        }
    }
}

fn no_leftovers(root: &Path) {
    let mut files = Vec::new();
    all_files(root, &mut files);
    for p in files {
        let n = p.strip_prefix(root).unwrap().display().to_string();
        assert!(!n.contains(".mig-") && !n.contains(".migrating") && !n.contains(".creating"), "left behind: {n}");
    }
}

fn clear_value_in_files(root: &Path) -> bool {
    let mut files = Vec::new();
    all_files(root, &mut files);
    files.iter().any(|p| {
        let bytes = std::fs::read(p).unwrap_or_default();
        [PHONE, ORDINARY, "KILL-ATTACHMENT"].iter().any(|n| bytes.windows(n.len()).any(|w| w == n.as_bytes()))
    })
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().filter_map(|e| e.ok()) {
        let target = to.join(e.file_name());
        if e.path().is_dir() {
            copy_dir(&e.path(), &target);
        } else {
            std::fs::copy(e.path(), &target).unwrap();
        }
    }
}

// ---- the child -----------------------------------------------------------------------------------

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// Run by the parent in another process. Does nothing in a normal run.
#[test]
fn child_entry() {
    let Some(root) = var("CLOVE_MIG_ROOT") else { return };
    let (from, to) = (Prot::parse(&var("CLOVE_MIG_FROM").unwrap()), Prot::parse(&var("CLOVE_MIG_TO").unwrap()));
    let change = ChangeProtection::new(PathBuf::from(root), "records", "store");
    let change = match from {
        Prot::Whole(_) => change.from_whole_database(from.config()),
        Prot::Fields(_) => change.from_field_keys(from.config()),
    };
    let change = match to {
        Prot::Whole(_) => change.to_whole_database(to.config()),
        Prot::Fields(_) => change.to_field_keys(to.config()),
    };
    let change = match var("CLOVE_MIG_SHAPE").as_deref() {
        Some("files") => change.protected_table::<Dossier>("dossiers"),
        _ => change.protected_table::<Account>("accounts"),
    };
    change.execute().unwrap();
}

fn child(root: &Path, shape: Shape, from: Prot, to: Prot) -> Command {
    let mut c = Command::new(std::env::current_exe().unwrap());
    c.args(["--exact", "child_entry", "--nocapture", "--test-threads=1"])
        .env("CLOVE_MIG_ROOT", root)
        .env("CLOVE_MIG_SHAPE", shape.text())
        .env("CLOVE_MIG_FROM", from.text())
        .env("CLOVE_MIG_TO", to.text())
        .stdout(child_log::out(root))
        .stderr(child_log::out(root));
    c
}

// ---- the tests -----------------------------------------------------------------------------------

/// Each direction is stopped many times. The moments are not random: they are spread over the whole
/// length of the change, measured on runs that are not stopped, so that every stage is stopped in.
/// Prints a line, and appends it to the file named by `CLOVE_KILLS_LOG` when that is set (a passing
/// test shows no output, so the distribution of the stops would be lost).
fn record(line: &str) {
    use std::io::Write;
    // the seconds since 1970 (UTC), so a line can be matched with another log
    let at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    println!("[{at}] {line}");
    if let Some(path) = var("CLOVE_KILLS_LOG")
        && let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path)
    {
        let _ = writeln!(file, "[{at}] {line}");
    }
}

fn stopped_in(shape: Shape, from: Prot, to: Prot) {
    let stops: u64 = var("CLOVE_KILLS").and_then(|v| v.parse().ok()).unwrap_or(100);
    {
        let (rows, scale) = match shape {
            Shape::Accounts => (40, 1),
            Shape::Files => (1500, 4),
        };
        let (mut old_state, mut new_state, mut killed) = (0u64, 0u64, 0u64);
        let template = make(shape, from, rows, scale);
        assert_eq!(read(&template, shape, from, rows, scale), Ok(rows));
        // the length of the change, program start included: the middle one of the last five whole runs
        // (a run that is slowed by something else on the machine must not stretch the spread). The
        // speed of the machine can change in the middle of a test, so the length is measured again
        // with one more whole run every ten stops, and the stops that follow use the newest middle.
        let measure = || {
            let probe = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
            copy_dir(&template, &probe);
            let started = Instant::now();
            let st = child(&probe, shape, from, to).status().unwrap();
            assert!(st.success(), "the measuring run failed: {}", child_log::why(&probe, st));
            let took = started.elapsed();
            child_log::clean(&probe);
            took
        };
        let middle = |lengths: &[Duration]| {
            let mut last: Vec<Duration> = lengths.iter().rev().take(5).copied().collect();
            last.sort();
            last[last.len() / 2].as_millis() as f64
        };
        let mut lengths: Vec<Duration> = (0..5).map(|_| measure()).collect();
        record(&format!(
            "{shape:?} {from:?} to {to:?}: the five measuring runs took {:?} ms",
            lengths.iter().map(|l| l.as_millis()).collect::<Vec<_>>()
        ));
        let mut whole_ms = middle(&lengths);
        for i in 0..stops {
            if i > 0 && i % 10 == 0 {
                lengths.push(measure());
                whole_ms = middle(&lengths);
                record(&format!("{shape:?} {from:?} to {to:?}: before stop {i} measured again: {} ms, the middle of the last five {whole_ms:.0} ms", lengths.last().unwrap().as_millis()));
            }
            let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
            copy_dir(&template, &root);
            let mut running = child(&root, shape, from, to).spawn().unwrap();
            // the odd stops are tied to the decision: the program is stopped as soon as the commit
            // marker is on disk; the even ones are spread over the length of the change
            let tied = i % 2 == 1;
            if tied {
                let commit = root.join("records").join("store.migrating.commit");
                let until = Instant::now() + Duration::from_secs(300);
                while !commit.exists() && running.try_wait().unwrap().is_none() {
                    assert!(Instant::now() < until, "{shape:?} {from:?} to {to:?}, stop {i}: the commit marker never appeared");
                    std::thread::sleep(Duration::from_millis(1));
                }
            } else {
                let spread = (stops / 2).max(1) as f64;
                std::thread::sleep(Duration::from_millis((whole_ms * ((i / 2) as f64 + 0.5) / spread) as u64));
            }
            match running.try_wait().unwrap() {
                Some(status) => assert!(status.success(), "{shape:?} {from:?} to {to:?}, stop {i}: the change failed: {}", child_log::why(&root, status)),
                None => {
                    running.kill().unwrap();
                    killed += 1;
                }
            }
            let _ = running.wait();
            // the next open settles what is left: with the old keys if the old files are the
            // database, with the new ones if the new files are
            let state = match read(&root, shape, from, rows, scale) {
                Ok(_) => "old",
                Err(_) => {
                    read(&root, shape, to, rows, scale)
                        .unwrap_or_else(|e| panic!("{shape:?} {from:?} to {to:?}, stop {i}: neither opens: {e}"));
                    "new"
                }
            };
            no_leftovers(&root);
            if tied {
                assert_eq!(state, "new", "{shape:?} {from:?} to {to:?}, stop {i}: stopped after the commit, the old files were the database");
            }
            if state == "old" {
                old_state += 1;
            } else {
                new_state += 1;
                if matches!(to, Prot::Whole(_)) {
                    assert!(!clear_value_in_files(&root), "{shape:?} {from:?} to {to:?}, stop {i}: the new state shows a clear value");
                }
            }
            child_log::clean(&root);
        }
        record(&format!(
            "{shape:?} {from:?} to {to:?}: {stops} stops spread over {whole_ms:.0} ms at the end ({killed} killed while running), {old_state} left the old files, {new_state} the new ones"
        ));
        assert_eq!(old_state + new_state, stops);
        assert!(killed * 10 >= stops * 4, "only {killed} of {stops} were stopped while the change was running");
        let least = (stops / 5).min(20);
        assert!(old_state >= least && new_state >= least, "the stops did not reach both sides of the decision ({old_state} old, {new_state} new)");
        let _ = std::fs::remove_dir_all(&template);
    }
}

/// One test for each direction (even keys are AES, odd keys are XChaCha), so that each is its own run.
macro_rules! stopped {
    ($name:ident, $shape:expr, $from:expr, $to:expr) => {
        #[test]
        #[ignore = "a hundred forced kills of a real process: minutes for each direction; run on purpose with --run-ignored"]
        fn $name() {
            stopped_in($shape, $from, $to);
        }
    };
}

stopped!(accounts_whole_to_whole_xchacha_to_aes, Shape::Accounts, Prot::Whole(5), Prot::Whole(6));
stopped!(accounts_whole_to_whole_aes_to_aes, Shape::Accounts, Prot::Whole(4), Prot::Whole(8));
stopped!(accounts_fields_to_fields_xchacha_to_aes, Shape::Accounts, Prot::Fields(5), Prot::Fields(6));
stopped!(accounts_fields_to_fields_aes_to_aes, Shape::Accounts, Prot::Fields(4), Prot::Fields(8));
stopped!(accounts_whole_to_fields, Shape::Accounts, Prot::Whole(5), Prot::Fields(4));
stopped!(accounts_fields_to_whole, Shape::Accounts, Prot::Fields(6), Prot::Whole(3));
stopped!(files_whole_to_whole_xchacha_to_aes, Shape::Files, Prot::Whole(5), Prot::Whole(6));
stopped!(files_whole_to_whole_aes_to_aes, Shape::Files, Prot::Whole(4), Prot::Whole(8));
stopped!(files_fields_to_fields_xchacha_to_aes, Shape::Files, Prot::Fields(5), Prot::Fields(6));
stopped!(files_fields_to_fields_aes_to_aes, Shape::Files, Prot::Fields(4), Prot::Fields(8));

/// With the crash points of the library: the process ends at the named place.
#[cfg(feature = "crash-inject")]
#[test]
fn a_crash_at_every_point_of_the_protected_change_is_settled_by_the_next_open() {
    // (point, is the decision already made?)
    let mut points: Vec<(String, bool)> = [
        ("migration_after_begin", false),
        ("migration_after_main_written", false),
        ("migration_after_history_written", false),
        ("migration_after_protected_attachments_written", false),
        ("migration_before_commit", false),
        ("migration_after_commit", true),
        ("migration_before_markers_removed", true),
        ("migration_after_markers_removed", true),
        ("migration_after_swap", true),
    ]
    .iter()
    .map(|(p, d)| (p.to_string(), *d))
    .collect();
    for i in 0..4 {
        for what in ["before_aside", "after_aside", "before_place", "after_place", "before_remove"] {
            points.push((format!("migration_{what}_{i}"), true));
        }
    }
    let mut cases = Vec::new();
    for shape in [Shape::Accounts, Shape::Files] {
        for (from, to) in [(Prot::Whole(5), Prot::Whole(6)), (Prot::Fields(5), Prot::Whole(4)), (Prot::Whole(5), Prot::Fields(4))] {
            for (point, decided) in &points {
                cases.push((shape, from, to, point, *decided));
            }
        }
    }
    // each case has its own database and its own program, so the cases run side by side
    let reached = std::sync::Mutex::new(std::collections::BTreeSet::new());
    let next = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..std::thread::available_parallelism().map_or(4, |n| n.get()).min(8) {
            scope.spawn(|| {
                loop {
                    let Some(&(shape, from, to, point, decided)) = cases.get(next.fetch_add(1, std::sync::atomic::Ordering::SeqCst)) else { break };
                    let (rows, scale) = (6, 1);
                    let root = make(shape, from, rows, scale);
                    let status = child(&root, shape, from, to).env("CLOVE_CRASH_POINT", point).status().unwrap();
                    if status.code() == Some(99) {
                        reached.lock().unwrap().insert(point.clone());
                        let key = if decided { to } else { from };
                        read(&root, shape, key, rows, scale).unwrap_or_else(|e| panic!("{shape:?} {from:?} to {to:?} at {point}: {e}"));
                        no_leftovers(&root);
                    } else {
                        assert!(
                            status.success(),
                            "{shape:?} {from:?} to {to:?} at {point}: {}",
                            child_log::why(&root, status)
                        );
                        read(&root, shape, to, rows, scale).unwrap();
                    }
                    child_log::clean(&root);
                }
            });
        }
    });
    let reached = reached.into_inner().unwrap();
    let unreached: Vec<&String> = points.iter().map(|(p, _)| p).filter(|p| !reached.contains(*p)).collect();
    println!("reached {} of {} points; not reached: {unreached:?}", reached.len(), points.len());
    // a database of this size replaces at most four files or folders; the points that name a
    // fifth cannot exist
    assert!(reached.contains("migration_after_protected_attachments_written"), "the attachments point was never reached");
    assert!(reached.len() >= 20, "only {} points were reached", reached.len());
}
