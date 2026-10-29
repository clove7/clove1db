//! Changing how a whole database is protected, with real processes: a second program is refused
//! while the change runs, a program that is stopped at any moment leaves the database either as it
//! was or as it was meant to become, and the next open settles what is left.
//!
//! The test program starts itself as the child that runs the change (the `child_entry` test does
//! nothing unless the child variables are set).
use clove1db::{
    CloveFields, EncryptionConfig, KeySource, LibraryEvent, Unique,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    entity::Entity,
    migration::ChangeProtection,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Note {
    id: String,
    name: String,
    n: i64,
}
impl Entity for Note {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
struct Doc {
    id: String,
}
impl Entity for Doc {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

const SECRET: &str = "swordfish-marker-7731";

fn keys(read: u8, cipher: CipherKind) -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite { cipher, hkdf: HkdfHash::Sha256 },
        read: Some(KeySource::Raw(Key32::from_bytes(&[read; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[read.wrapping_add(1); 32]))),
    }
}

/// `None` is a plain database; `Some(n)` an encrypted one with key `n` (even: AES, odd: XChaCha).
fn protection(key: Option<u8>) -> Option<EncryptionConfig> {
    key.map(|k| keys(k, if k % 2 == 0 { CipherKind::Aes256GcmSiv } else { CipherKind::XChaCha20Poly1305 }))
}

fn config(root: &Path, key: Option<u8>) -> DatabaseConfig {
    let db = DatabaseConfig::new("records", "store")
        .dir_path(root.to_path_buf())
        .has_cache(false)
        .blob_enabled(true)
        .register::<Note>("notes")
        .register_blob::<Doc>("files")
        .unique::<Note>(Unique::on(Note::name));
    match protection(key) {
        Some(c) => db.encryption(c),
        None => {
            #[cfg(clove_test_encrypt_all)]
            {
                db.plain()
            }
            #[cfg(not(clove_test_encrypt_all))]
            {
                db
            }
        }
    }
}

fn open(root: &Path, key: Option<u8>) -> clove1db::units::Result<Storage> {
    Storage::builder(StorageConfig::default()).add_database(config(root, key)).build()
}

fn attachment(i: usize, scale: usize) -> Vec<u8> {
    let mut v = SECRET.as_bytes().to_vec();
    v.extend((0..(20_000 * i * scale)).map(|k| (k % 251) as u8));
    v
}

fn make(key: Option<u8>) -> PathBuf {
    make_sized(key, 60, 1)
}

/// `rows` rows that carry the secret, and three attachments of about `scale` times 20 KB, 40 KB
/// and 60 KB.
fn make_sized(key: Option<u8>, rows: usize, scale: usize) -> PathBuf {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = open(&root, key).unwrap();
    let db = s.db_manager("store");
    let mut batch = Vec::new();
    for i in 0..rows {
        let note = Note { id: format!("n{i:05}"), name: format!("{SECRET}-{i}"), n: i as i64 };
        batch.push(("notes".to_string(), note.id.clone(), serde_json::to_vec(&note).unwrap()));
        if batch.len() == 500 {
            db.commit_batch(&batch, &[]).unwrap();
            batch.clear();
        }
    }
    if !batch.is_empty() {
        db.commit_batch(&batch, &[]).unwrap();
    }
    for i in 0..3 {
        db.write_blob("files", &format!("f{i}"), &attachment(i + 1, scale)).unwrap();
    }
    drop(db);
    s.close();
    root
}

type Contents = (Vec<(String, Vec<u8>)>, Vec<Vec<u8>>);

fn contents(root: &Path, key: Option<u8>) -> clove1db::units::Result<Contents> {
    let s = open(root, key)?;
    let db = s.db_manager("store");
    let rows = db.list_entries("notes")?;
    let mut blobs = Vec::new();
    for i in 0..3 {
        let mut reader = db.open_blob("files", &format!("f{i}"))?;
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut reader, &mut bytes).unwrap();
        blobs.push(bytes);
    }
    drop(db);
    s.close();
    Ok((rows, blobs))
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

fn names(root: &Path) -> Vec<String> {
    let mut files = Vec::new();
    all_files(root, &mut files);
    let mut v: Vec<String> = files.iter().map(|p| p.strip_prefix(root).unwrap().display().to_string()).collect();
    v.sort();
    v
}

fn secret_in_files(root: &Path) -> bool {
    let mut files = Vec::new();
    all_files(root, &mut files);
    files.iter().any(|p| std::fs::read(p).map(|b| b.windows(SECRET.len()).any(|w| w == SECRET.as_bytes())).unwrap_or(false))
}

fn no_leftovers(root: &Path) {
    for n in names(root) {
        assert!(!n.contains(".mig-") && !n.contains(".migrating") && !n.contains(".creating"), "left behind: {n}");
    }
}

// ---- the child -----------------------------------------------------------------------------------

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn key_of(text: &str) -> Option<u8> {
    text.strip_prefix("enc:").and_then(|n| n.parse().ok())
}

fn describe(key: Option<u8>) -> String {
    key.map_or("plain".to_string(), |k| format!("enc:{k}"))
}

/// Run by the parent in another process. Does nothing in a normal run.
#[test]
fn child_entry() {
    let Some(root) = var("CLOVE_MIG_ROOT") else { return };
    let root = PathBuf::from(root);
    let (from, to) = (var("CLOVE_MIG_FROM").unwrap(), var("CLOVE_MIG_TO").unwrap());
    let mut change = ChangeProtection::new(&root, "records", "store");
    change = match key_of(&from).and_then(|k| protection(Some(k))) {
        Some(c) => change.from_whole_database(c),
        None => change.from_plain(),
    };
    change = match key_of(&to).and_then(|k| protection(Some(k))) {
        Some(c) => change.to_whole_database(c),
        None => change.to_plain(),
    };
    if let Some(backup) = var("CLOVE_MIG_BACKUP") {
        // the history file lives in another folder
        change = change.backup_dir_path(backup);
    }
    if var("CLOVE_MIG_WIPE").is_some() {
        change = change.wipe_originals(true);
    }
    if let Some(hold) = var("CLOVE_MIG_HOLD") {
        // announce the start, then wait to be released (the marker is locked all that time)
        let hold = PathBuf::from(hold);
        change = change.on_event(move |e| {
            if let LibraryEvent::Migration { event: "migration/started", .. } = e {
                std::fs::write(hold.join("started.flag"), b"1").unwrap();
                let until = Instant::now() + Duration::from_secs(60);
                while !hold.join("release.flag").exists() && Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        });
    }
    change.execute().unwrap();
}

fn child(root: &Path, from: Option<u8>, to: Option<u8>) -> Command {
    let mut c = Command::new(std::env::current_exe().unwrap());
    c.args(["--exact", "child_entry", "--nocapture", "--test-threads=1"])
        .env("CLOVE_MIG_ROOT", root)
        .env("CLOVE_MIG_FROM", describe(from))
        .env("CLOVE_MIG_TO", describe(to))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    c
}

fn wait_for(path: &Path, seconds: u64) {
    let until = Instant::now() + Duration::from_secs(seconds);
    while !path.exists() {
        assert!(Instant::now() < until, "{} did not appear", path.display());
        std::thread::sleep(Duration::from_millis(10));
    }
}

// ---- the tests -----------------------------------------------------------------------------------

#[test]
fn a_second_program_cannot_open_the_database_while_it_is_changed_and_the_change_goes_on() {
    let root = make(None);
    let before = contents(&root, None).unwrap();
    let hold = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir_all(&hold).unwrap();
    let mut running = child(&root, None, Some(5)).env("CLOVE_MIG_HOLD", &hold).spawn().unwrap();
    wait_for(&hold.join("started.flag"), 60);
    let seen = names(&root);
    // the old and the new key, plain and encrypted: all refused, and nothing is changed by trying
    for key in [None, Some(5u8)] {
        let result = open(&root, key);
        assert!(matches!(result, Err(ClError::DatabaseInUse { .. })), "{key:?}: {:?}", result.err());
    }
    assert_eq!(names(&root), seen, "trying to open changed the folder");
    std::fs::write(hold.join("release.flag"), b"1").unwrap();
    assert!(running.wait().unwrap().success());
    assert_eq!(contents(&root, Some(5)).unwrap(), before, "the change went on to the end");
    assert!(!secret_in_files(&root));
    no_leftovers(&root);
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&hold);
}

#[test]
fn a_program_stopped_at_any_moment_leaves_the_database_as_it_was_or_as_it_is_to_be() {
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
    const STOPS: u64 = 100;
    // plain to encrypted, and back, and to other keys, each stopped 100 times. The moments are not
    // random: they are spread over the whole length of the change, measured on a run that is not
    // stopped (from 0.5% of it to 99.5%), so that every stage of the change is stopped in.
    for (from, to) in [(None, Some(5u8)), (Some(5u8), None), (Some(5u8), Some(6u8))] {
        let mut old_state = 0;
        let mut new_state = 0;
        let mut killed = 0;
        let template = make_sized(from, 6000, 40);
        let before = contents(&template, from).unwrap();
        // the length of the change, program start included: the longer of two whole runs
        let mut whole = Duration::ZERO;
        for _ in 0..2 {
            let probe = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
            copy_dir(&template, &probe);
            let started = Instant::now();
            assert!(child(&probe, from, to).status().unwrap().success());
            whole = whole.max(started.elapsed());
            let _ = std::fs::remove_dir_all(&probe);
        }
        let whole_ms = whole.as_millis() as f64;
        for i in 0..STOPS {
            let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
            copy_dir(&template, &root);
            let mut running = child(&root, from, to).spawn().unwrap();
            std::thread::sleep(Duration::from_millis((whole_ms * (i as f64 + 0.5) / STOPS as f64) as u64));
            match running.try_wait().unwrap() {
                // it ran to the end before it was stopped: that is a success or a bug, not a stop
                Some(status) => assert!(status.success(), "{from:?} to {to:?}, stop {i}: the change failed: {status:?}"),
                None => {
                    running.kill().unwrap();
                    killed += 1;
                }
            }
            let _ = running.wait();
            // the next open settles what is left: with the old keys if the old files are the
            // database, with the new ones if the new files are (an encrypted file does not open
            // plain, nor with other keys)
            let (state, got) = match contents(&root, from) {
                Ok(got) => ("old", got),
                Err(_) => ("new", contents(&root, to).unwrap_or_else(|e| panic!("{from:?} to {to:?}, stop {i}: neither opens: {e:?}"))),
            };
            assert_eq!(got, before, "{from:?} to {to:?}, stop {i}: not the same database");
            no_leftovers(&root);
            if state == "old" {
                old_state += 1;
                if from.is_none() {
                    assert!(secret_in_files(&root), "the old state is the plain one");
                }
            } else {
                new_state += 1;
                if to.is_some() {
                    assert!(!secret_in_files(&root), "{from:?} to {to:?}, stop {i}: the new state shows a clear value");
                }
            }
            let _ = std::fs::remove_dir_all(&root);
        }
        println!(
            "{from:?} to {to:?}: {STOPS} stops spread over {whole_ms:.0} ms ({killed} killed while running), {old_state} left the old files, {new_state} the new ones"
        );
        assert_eq!(old_state + new_state, STOPS);
        assert!(killed >= 40, "only {killed} of {STOPS} were stopped while the change was running");
        assert!(old_state >= 5 && new_state >= 5, "the stops did not reach both sides of the decision");
        let _ = std::fs::remove_dir_all(&template);
    }
}

// A second shape of database: a backup history and no attachments (a database with attachments
// keeps no history file), so that the files of the history are part of the change.
fn config_history(root: &Path, key: Option<u8>) -> DatabaseConfig {
    let db = DatabaseConfig::new("records", "store")
        .dir_path(root.to_path_buf())
        .has_cache(false)
        .backup_enabled(true)
        .backup_dir(root.join("bk"))
        .register::<Note>("notes")
        .unique::<Note>(Unique::on(Note::name));
    match protection(key) {
        Some(c) => db.encryption(c),
        None => {
            #[cfg(clove_test_encrypt_all)]
            {
                db.plain()
            }
            #[cfg(not(clove_test_encrypt_all))]
            {
                db
            }
        }
    }
}

fn open_history(root: &Path, key: Option<u8>) -> clove1db::units::Result<Storage> {
    Storage::builder(StorageConfig::default()).add_database(config_history(root, key)).build()
}

fn make_history(key: Option<u8>) -> PathBuf {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = open_history(&root, key).unwrap();
    let db = s.db_manager("store");
    for round in 0..3 {
        for i in 0..40 {
            let note = Note { id: format!("n{i:02}"), name: format!("{SECRET}-{i}-{round}"), n: round };
            db.set(redb::TableDefinition::new("notes"), "notes", &note.id, serde_json::to_vec(&note).unwrap()).unwrap();
        }
    }
    drop(db);
    s.close();
    root
}

fn rows_history(root: &Path, key: Option<u8>) -> clove1db::units::Result<Vec<(String, Vec<u8>)>> {
    let s = open_history(root, key)?;
    let rows = s.db_manager("store").list_entries("notes")?;
    s.close();
    Ok(rows)
}

/// Every crash point of the change is reached by some database shape, and the database is right
/// after each: the points that need a backup file, a second folder or the overwriting of the old
/// files included.
#[cfg(feature = "crash-inject")]
#[test]
fn every_crash_point_is_reached_and_settled() {
    let mut points: Vec<(String, bool)> = [
        ("migration_after_begin", false),
        ("migration_after_main_written", false),
        ("migration_after_history_written", false),
        ("migration_after_attachments_written", false),
        ("migration_after_records_written", false),
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
        for what in ["before_aside", "after_aside", "before_place", "after_place", "before_remove", "before_wipe", "after_wipe"] {
            points.push((format!("migration_{what}_{i}"), true));
        }
    }
    let mut reached = std::collections::BTreeSet::new();
    for shape in ["blobs", "history"] {
        for (from, to) in [(None, Some(5u8)), (Some(5u8), None)] {
            for wipe in [false, true] {
                for (point, decided) in &points {
                    let root = if shape == "blobs" { make(from) } else { make_history(from) };
                    let read = |k: Option<u8>| -> clove1db::units::Result<Contents> {
                        if shape == "blobs" { contents(&root, k) } else { rows_history(&root, k).map(|r| (r, Vec::new())) }
                    };
                    let before = read(from).unwrap();
                    let mut c = child(&root, from, to);
                    c.env("CLOVE_CRASH_POINT", point);
                    if wipe {
                        c.env("CLOVE_MIG_WIPE", "1");
                    }
                    if shape == "history" {
                        c.env("CLOVE_MIG_BACKUP", root.join("bk"));
                    }
                    let status = c.status().unwrap();
                    if status.code() == Some(99) {
                        reached.insert(point.clone());
                        let key = if *decided { to } else { from };
                        let got = read(key).unwrap_or_else(|e| panic!("{shape} {from:?} to {to:?} wipe={wipe} at {point}: {e:?}"));
                        assert_eq!(got, before, "{shape} {from:?} to {to:?} wipe={wipe} at {point}");
                        no_leftovers(&root);
                    } else {
                        assert!(status.success(), "{point}: {status:?}");
                    }
                    let _ = std::fs::remove_dir_all(&root);
                }
            }
        }
    }
    let unreached: Vec<&String> = points.iter().map(|(p, _)| p).filter(|p| !reached.contains(*p)).collect();
    println!("reached {} of {} points; not reached: {unreached:?}", reached.len(), points.len());
    // a database of this size replaces at most four files or folders, and the points that name a
    // fifth cannot exist; a point with an index below four must be reachable
    assert!(unreached.is_empty(), "points that no shape reached: {unreached:?}");
}

/// With the crash points of the library: the process ends at the named place.
#[cfg(feature = "crash-inject")]
#[test]
fn a_crash_at_every_point_of_the_change_is_settled_by_the_next_open() {
    // (point, is the decision already made?)
    let points: &[(&str, bool)] = &[
        ("migration_after_begin", false),
        ("migration_after_main_written", false),
        ("migration_after_history_written", false),
        ("migration_after_attachments_written", false),
        ("migration_after_records_written", false),
        ("migration_before_commit", false),
        ("migration_after_commit", true),
        ("migration_before_aside_0", true),
        ("migration_after_aside_0", true),
        ("migration_before_place_0", true),
        ("migration_after_place_0", true),
        ("migration_before_aside_1", true),
        ("migration_after_aside_1", true),
        ("migration_before_place_1", true),
        ("migration_after_place_1", true),
        ("migration_before_aside_2", true),
        ("migration_after_aside_2", true),
        ("migration_before_remove_0", true),
        ("migration_before_markers_removed", true),
        ("migration_after_markers_removed", true),
        ("migration_after_swap", true),
    ];
    let mut reached = 0;
    for (from, to) in [(None, Some(5u8)), (Some(5u8), Some(6u8))] {
        for (point, decided) in points {
            let root = make(from);
            let before = contents(&root, from).unwrap();
            let status = child(&root, from, to).env("CLOVE_CRASH_POINT", point).status().unwrap();
            if status.code() != Some(99) {
                // the point is not on this path (no backup file, say): the change ran to the end
                assert!(status.success(), "{point}: {status:?}");
                assert_eq!(contents(&root, to).unwrap(), before);
                let _ = std::fs::remove_dir_all(&root);
                continue;
            }
            reached += 1;
            let got = if *decided {
                // the decision was made: the new files are the database
                contents(&root, to).unwrap_or_else(|e| panic!("{from:?} to {to:?} at {point}: {e:?}"))
            } else {
                contents(&root, from).unwrap_or_else(|e| panic!("{from:?} to {to:?} at {point}: {e:?}"))
            };
            assert_eq!(got, before, "{from:?} to {to:?} at {point}");
            no_leftovers(&root);
            let _ = std::fs::remove_dir_all(&root);
        }
    }
    println!("crash points reached: {reached}");
    assert!(reached >= 20, "only {reached} points were reached");
}
