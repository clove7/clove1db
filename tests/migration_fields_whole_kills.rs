//! Changing how the fields of a table are protected in a database encrypted as a whole, with real
//! processes: the new files are made with the same data key as the old ones, so after a program is
//! stopped at any moment the database opens with the one password, either as it was (a plain field)
//! or as it was meant to become (a sealed field), with every value, history version and attachment
//! as it was, and the next open settles what is left.
//!
//! The test program starts itself as the child that runs the change (the `child_entry` test does
//! nothing unless the child variables are set).
use clove1db::{
    CloveFields, EncryptionConfig, KeySource,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    entity::Entity,
    field_crypto::Sealed,
    migration::ChangeFields,
    storage::{DatabaseConfig, Storage, StorageConfig},
};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const PHONE: &str = "+155-WHOLE-PHONE-";
const NAME: &str = "WHOLE-VISIBLE-";

/// A person before any field was protected.
#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Plain {
    id: String,
    name: String,
    phone: String,
}
impl Entity for Plain {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// The same person with the phone sealed.
#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Protected {
    id: String,
    name: String,
    #[clove(encrypt, id = 1)]
    phone: Sealed<String>,
}
impl Entity for Protected {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// `n` is the key; even is AES, odd is XChaCha.
fn keys(n: u8) -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite {
            cipher: if n % 2 == 0 { CipherKind::Aes256GcmSiv } else { CipherKind::XChaCha20Poly1305 },
            hkdf: HkdfHash::Sha256,
        },
        read: Some(KeySource::Raw(Key32::from_bytes(&[n; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[n.wrapping_add(100); 32]))),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    /// Rows with a backup history.
    History,
    /// Rows with an attachment each (no history file).
    Files,
}

impl Shape {
    fn text(self) -> &'static str {
        match self {
            Shape::History => "history",
            Shape::Files => "files",
        }
    }
    fn rows(self) -> usize {
        match self {
            Shape::History => 4000,
            Shape::Files => 600,
        }
    }
}

fn config(root: &Path, shape: Shape, n: u8) -> DatabaseConfig {
    let db = DatabaseConfig::new("records", "store").dir_path(root.to_path_buf()).has_cache(false).encryption(keys(n));
    match shape {
        Shape::History => db.backup_enabled(true),
        Shape::Files => db.blob_enabled(true),
    }
}

fn open(root: &Path, shape: Shape, n: u8, sealed: bool) -> clove1db::units::Result<Storage> {
    let db = config(root, shape, n);
    let db = match (shape, sealed) {
        (Shape::History, false) => db.register::<Plain>("people"),
        (Shape::History, true) => db.register_sealed::<Protected>("people"),
        (Shape::Files, false) => db.register_blob::<Plain>("people"),
        (Shape::Files, true) => db.register_sealed_blob::<Protected>("people"),
    };
    Storage::builder(StorageConfig::default()).add_database(db).build()
}

fn attachment(i: usize) -> Vec<u8> {
    let mut v = b"WHOLE-ATTACHMENT-MARKER-".to_vec();
    v.extend((0..(3_000 * (i % 7 + 1))).map(|k| (k % 251) as u8));
    v
}

fn make(shape: Shape, n: u8) -> PathBuf {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = open(&root, shape, n, false).unwrap();
    let repo = s.domain::<Plain>().repo();
    match shape {
        Shape::History => {
            let db = s.db_manager("store");
            for round in 0..2 {
                let mut batch = Vec::new();
                for i in 0..shape.rows() {
                    let row = Plain { id: format!("p{i:05}"), name: format!("{NAME}{i}"), phone: format!("{PHONE}{i}-v{round}") };
                    batch.push(("people".to_string(), row.id.clone(), serde_json::to_vec(&row).unwrap()));
                    if batch.len() == 500 {
                        db.commit_batch(&batch, &[]).unwrap();
                        batch.clear();
                    }
                }
                if !batch.is_empty() {
                    db.commit_batch(&batch, &[]).unwrap();
                }
            }
        }
        Shape::Files => {
            for i in 0..shape.rows() {
                let row = Plain { id: format!("p{i:05}"), name: format!("{NAME}{i}"), phone: format!("{PHONE}{i}-v1") };
                repo.set_with_blob(&row.id, &row, &attachment(i)).unwrap();
            }
        }
    }
    drop(repo);
    s.close();
    if shape == Shape::History {
        assert!(root.join("records").join("store.cldb.bak").is_file(), "the history shape has no history file");
    }
    root
}

/// What the database holds, read through a normal open as the plain or the sealed table, and checked.
/// An open that fails is the answer `Err`.
fn read(root: &Path, shape: Shape, n: u8, sealed: bool) -> Result<usize, String> {
    let s = open(root, shape, n, sealed).map_err(|e| format!("{e:?}"))?;
    let rows = shape.rows();
    let count = if sealed {
        let domain = s.domain::<Protected>();
        let grant = domain.read_grant().unwrap();
        let repo = domain.repo();
        let list = repo.list().unwrap();
        for row in &list {
            let i: usize = row.id[1..].parse().unwrap();
            assert_eq!(row.phone.open(&grant).unwrap(), format!("{PHONE}{i}-v1"));
            if shape == Shape::Files {
                let mut out = Vec::new();
                repo.open_blob(&row.id).unwrap().read_to_end(&mut out).unwrap();
                assert!(out == attachment(i), "an attachment is not what it was");
            }
        }
        list.len()
    } else {
        let repo = s.domain::<Plain>().repo();
        let list = repo.list().unwrap();
        for row in &list {
            let i: usize = row.id[1..].parse().unwrap();
            assert_eq!(row.phone, format!("{PHONE}{i}-v1"));
            if shape == Shape::Files {
                let mut out = Vec::new();
                repo.open_blob(&row.id).unwrap().read_to_end(&mut out).unwrap();
                assert!(out == attachment(i), "an attachment is not what it was");
            }
        }
        list.len()
    };
    assert_eq!(count, rows);
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
        [PHONE, NAME, "WHOLE-ATTACHMENT"].iter().any(|n| bytes.windows(n.len()).any(|w| w == n.as_bytes()))
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

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

// ---- the child -----------------------------------------------------------------------------------

/// Run by the parent in another process. Does nothing in a normal run.
#[test]
fn child_entry() {
    let Some(root) = var("CLOVE_MIG_ROOT") else { return };
    let n: u8 = var("CLOVE_MIG_KEY").unwrap().parse().unwrap();
    let change = ChangeFields::new(PathBuf::from(root), "records", "store").whole_database_keys(keys(n));
    let change = change.table::<Protected>("people");
    change.execute().unwrap();
}

fn child(root: &Path, shape: Shape, n: u8) -> Command {
    let mut c = Command::new(std::env::current_exe().unwrap());
    c.args(["--exact", "child_entry", "--nocapture", "--test-threads=1"])
        .env("CLOVE_MIG_ROOT", root)
        .env("CLOVE_MIG_SHAPE", shape.text())
        .env("CLOVE_MIG_KEY", n.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    c
}

/// Appends one line to the file named by `CLOVE_KILLS_LOG`, if it is set.
fn record(line: &str) {
    // the seconds since 1970 (UTC), so a line can be matched with another log
    let at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    println!("[{at}] {line}");
    if let Some(path) = var("CLOVE_KILLS_LOG")
        && let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path)
    {
        let _ = writeln!(file, "[{at}] {line}");
    }
}

/// A plain field becomes a sealed one in a database encrypted as a whole, stopped at 100 moments:
/// half spread over the length of the change, half tied to the decision (the commit file shows).
fn stopped_in(shape: Shape, n: u8) {
    let stops: u64 = var("CLOVE_KILLS").and_then(|v| v.parse().ok()).unwrap_or(100);
    let (mut old_state, mut new_state, mut killed) = (0u64, 0u64, 0u64);
    let template = make(shape, n);
    assert_eq!(read(&template, shape, n, false), Ok(shape.rows()));
    let mut lengths = Vec::new();
    for _ in 0..5 {
        let probe = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        copy_dir(&template, &probe);
        let started = Instant::now();
        assert!(child(&probe, shape, n).status().unwrap().success());
        lengths.push(started.elapsed());
        let _ = std::fs::remove_dir_all(&probe);
    }
    record(&format!(
        "whole-database field change {shape:?} key {n}: the five measuring runs took {:?} ms",
        lengths.iter().map(|l| l.as_millis()).collect::<Vec<_>>()
    ));
    lengths.sort();
    let whole_ms = lengths[lengths.len() / 2].as_millis() as f64;
    for i in 0..stops {
        let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        copy_dir(&template, &root);
        let mut running = child(&root, shape, n).spawn().unwrap();
        let tied = i % 2 == 1;
        if tied {
            let commit = root.join("records").join("store.migrating.commit");
            let until = Instant::now() + Duration::from_secs(300);
            while !commit.exists() && running.try_wait().unwrap().is_none() {
                assert!(Instant::now() < until, "{shape:?} key {n}, stop {i}: the commit marker never appeared");
                std::thread::sleep(Duration::from_millis(1));
            }
        } else {
            let spread = (stops / 2).max(1) as f64;
            std::thread::sleep(Duration::from_millis((whole_ms * ((i / 2) as f64 + 0.5) / spread) as u64));
        }
        match running.try_wait().unwrap() {
            Some(status) => assert!(status.success(), "{shape:?} key {n}, stop {i}: the change failed: {status:?}"),
            None => {
                running.kill().unwrap();
                killed += 1;
            }
        }
        let _ = running.wait();
        // the next open settles what is left: as the plain table if the old files are the database,
        // as the sealed one if the new files are (the one password opens both)
        let state = match read(&root, shape, n, false) {
            Ok(_) => "old",
            Err(_) => {
                read(&root, shape, n, true).unwrap_or_else(|e| panic!("{shape:?} key {n}, stop {i}: neither opens: {e}"));
                "new"
            }
        };
        no_leftovers(&root);
        if tied {
            assert_eq!(state, "new", "{shape:?} key {n}, stop {i}: stopped after the commit, the old files were the database");
        }
        if state == "old" {
            old_state += 1;
        } else {
            new_state += 1;
        }
        assert!(!clear_value_in_files(&root), "{shape:?} key {n}, stop {i}: a clear value shows in a file");
        let _ = std::fs::remove_dir_all(&root);
    }
    record(&format!(
        "whole-database field change {shape:?} key {n} ({}): {stops} stops over {whole_ms:.0} ms ({killed} killed while running): {old_state} left the old files, {new_state} the new ones",
        if n % 2 == 0 { "AES" } else { "XChaCha" }
    ));
    assert_eq!(old_state + new_state, stops);
    assert!(killed * 10 >= stops * 4, "only {killed} of {stops} were stopped while the change was running");
    let least = (stops / 5).min(20);
    assert!(old_state >= least && new_state >= least, "the stops did not reach both sides of the decision ({old_state} old, {new_state} new)");
    let _ = std::fs::remove_dir_all(&template);
}

macro_rules! stopped {
    ($name:ident, $shape:expr, $n:expr) => {
        #[test]
        #[ignore = "a hundred forced kills of a real process: minutes for each direction; run on purpose with --run-ignored"]
        fn $name() {
            stopped_in($shape, $n);
        }
    };
}

stopped!(history_aes, Shape::History, 4);
stopped!(history_xchacha, Shape::History, 5);
stopped!(files_aes, Shape::Files, 4);
stopped!(files_xchacha, Shape::Files, 5);
