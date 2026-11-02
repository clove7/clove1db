//! Changing how the fields of a table are protected, with real processes: a program that is stopped
//! at any moment of the change leaves the database either as it was or as it was meant to become,
//! with the same rows in both, and the next open settles what is left. Both ciphers; sealing,
//! opening, adding fingerprints and making a hash.
//!
//! The test program starts itself as the child that runs the change (the `child_entry` test does
//! nothing unless the child variables are set).
use clove1db::{
    CloveFields, EncryptionConfig, KeySource,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    entity::Entity,
    field_crypto::{Hashed, Sealed},
    migration::ChangeFields,
    storage::{DatabaseConfig, Storage, StorageConfig},
};
#[path = "child_log/mod.rs"]
mod child_log;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

macro_rules! person {
    ($name:ident { $($body:tt)* }) => {
        #[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
        struct $name {
            id: String,
            name: String,
            $($body)*
        }
        impl Entity for $name {
            fn entity_id(&self) -> &str {
                &self.id
            }
        }
    };
}

person!(Plain { phone: String, password: String });
person!(Sealed1 {
    #[clove(encrypt, id = 1)]
    phone: Sealed<String>,
    password: String,
});
person!(Printed1 {
    #[clove(encrypt, id = 1, print = "full")]
    phone: Sealed<String>,
    password: String,
});
person!(Hashed2 {
    phone: String,
    #[clove(hash = "argon2id", id = 2)]
    password: Hashed,
});

const SECRET: &str = "swordfish-marker-7731";
const PHONE_MARK: &[u8] = b"+155500000";
const PASSWORD_MARK: &[u8] = b"pw-marker-";

fn keys(k: u8) -> EncryptionConfig {
    // even: AES, odd: XChaCha
    let cipher = if k % 2 == 0 { CipherKind::Aes256GcmSiv } else { CipherKind::XChaCha20Poly1305 };
    EncryptionConfig {
        suite: KeySuite { cipher, hkdf: HkdfHash::Sha256 },
        read: Some(KeySource::Raw(Key32::from_bytes(&[k; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[k.wrapping_add(1); 32]))),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Plain,
    Sealed,
    Printed,
    Hashed,
}

fn base(root: &Path) -> DatabaseConfig {
    let db = DatabaseConfig::new("records", "store").dir_path(root.to_path_buf()).has_cache(false).backup_enabled(true);
    #[cfg(clove_test_encrypt_all)]
    let db = db.plain();
    db
}

fn open(root: &Path, state: State, k: u8) -> clove1db::units::Result<Storage> {
    let db = match state {
        State::Plain => base(root).register::<Plain>("people"),
        State::Sealed => base(root).field_encryption(keys(k)).register_sealed::<Sealed1>("people"),
        State::Printed => base(root).field_encryption(keys(k)).register_sealed::<Printed1>("people"),
        State::Hashed => base(root).field_encryption(keys(k)).register_sealed::<Hashed2>("people"),
    };
    Storage::builder(StorageConfig::default()).add_database(db).build()
}

fn id(i: usize) -> String {
    format!("p{i:05}")
}

/// A plain database of `rows` people written `rounds` times (so each has saved versions).
fn make_plain(rows: usize, rounds: usize) -> PathBuf {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = open(&root, State::Plain, 0).unwrap();
    let db = s.db_manager("store");
    for round in 0..rounds {
        let mut batch = Vec::new();
        for i in 0..rows {
            let row = serde_json::json!({
                "id": id(i),
                "name": format!("{SECRET}-{i}"),
                "phone": format!("+1555000000{i:05}-{round}"),
                "password": format!("pw-marker-{i}-{round}"),
            });
            batch.push(("people".to_string(), id(i), serde_json::to_vec(&row).unwrap()));
        }
        db.commit_batch(&batch, &[]).unwrap();
    }
    drop(db);
    s.close();
    root
}

/// What each person holds, read through a normal open in `state`: (id, name, phone).
type Rows = Vec<(String, String, String)>;

fn contents(root: &Path, state: State, k: u8, rows: usize) -> clove1db::units::Result<Rows> {
    let s = open(root, state, k)?;
    let mut out = Vec::new();
    for i in 0..rows {
        let key = id(i);
        match state {
            State::Plain => {
                let p = s.domain::<Plain>().repo().get(&key)?;
                out.push((p.id, p.name, p.phone));
            }
            State::Hashed => {
                let p = s.domain::<Hashed2>().repo().get(&key)?;
                out.push((p.id, p.name, p.phone));
            }
            State::Sealed => {
                let grant = s.domain::<Sealed1>().read_grant()?;
                let p = s.domain::<Sealed1>().repo().get(&key)?;
                out.push((p.id, p.name, p.phone.open(&grant)?));
            }
            State::Printed => {
                let grant = s.domain::<Printed1>().read_grant()?;
                let p = s.domain::<Printed1>().repo().get(&key)?;
                out.push((p.id, p.name, p.phone.open(&grant)?));
            }
        }
    }
    s.close();
    Ok(out)
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

fn in_files(root: &Path, needle: &[u8]) -> bool {
    let mut files = Vec::new();
    all_files(root, &mut files);
    files.iter().any(|p| std::fs::read(p).map(|b| b.windows(needle.len()).any(|w| w == needle)).unwrap_or(false))
}

fn no_leftovers(root: &Path) {
    for n in names(root) {
        assert!(!n.contains(".mig-") && !n.contains(".migrating") && !n.contains(".creating"), "left behind: {n}");
    }
}

/// The file that is the decision: once it is there the new files are the database.
fn commit_file(root: &Path) -> PathBuf {
    root.join("records").join("store.migrating.commit")
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

// ---- the change, in the child ------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Kind {
    Seal,
    Open,
    Prints,
    Hash,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Seal => "seal",
            Kind::Open => "open",
            Kind::Prints => "prints",
            Kind::Hash => "hash",
        }
    }

    fn from_name(text: &str) -> Kind {
        [Kind::Seal, Kind::Open, Kind::Prints, Kind::Hash].into_iter().find(|k| k.name() == text).expect("a kind")
    }

    /// (before, after)
    fn states(self) -> (State, State) {
        match self {
            Kind::Seal => (State::Plain, State::Sealed),
            Kind::Open => (State::Sealed, State::Plain),
            Kind::Prints => (State::Sealed, State::Printed),
            Kind::Hash => (State::Plain, State::Hashed),
        }
    }

    fn rows(self) -> (usize, usize) {
        // the hash is slow on purpose: fewer values
        match self {
            Kind::Hash => (30, 2),
            _ => (3000, 2),
        }
    }

    fn change(self, root: &Path, k: u8) -> ChangeFields {
        let c = ChangeFields::new(root, "records", "store").field_keys(keys(k));
        match self {
            Kind::Seal => c.table::<Sealed1>("people"),
            Kind::Open => c.table_without_protected_fields("people"),
            Kind::Prints => c.table::<Printed1>("people"),
            Kind::Hash => c.table::<Hashed2>("people").confirm_one_way(),
        }
    }
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// Run by the parent in another process. Does nothing in a normal run.
#[test]
fn child_entry() {
    let Some(root) = var("CLOVE_FLD_ROOT") else { return };
    let kind = Kind::from_name(&var("CLOVE_FLD_KIND").unwrap());
    let k: u8 = var("CLOVE_FLD_KEY").unwrap().parse().unwrap();
    kind.change(&PathBuf::from(root), k).execute().unwrap();
}

fn child(root: &Path, kind: Kind, k: u8) -> Command {
    let mut c = Command::new(std::env::current_exe().unwrap());
    c.args(["--exact", "child_entry", "--nocapture", "--test-threads=1"])
        .env("CLOVE_FLD_ROOT", root)
        .env("CLOVE_FLD_KIND", kind.name())
        .env("CLOVE_FLD_KEY", k.to_string())
        .stdout(child_log::out(root))
        .stderr(child_log::out(root));
    c
}

/// The database a `kind` starts from, made once: plain, or plain and then sealed.
fn template(kind: Kind, k: u8) -> PathBuf {
    let (rows, rounds) = kind.rows();
    let root = make_plain(rows, rounds);
    if matches!(kind, Kind::Open | Kind::Prints) {
        Kind::Seal.change(&root, k).execute().unwrap();
    }
    root
}

/// The secret that must be gone from every file once the database is in its new state.
fn gone_after(kind: Kind) -> Option<&'static [u8]> {
    match kind {
        Kind::Seal | Kind::Prints => Some(PHONE_MARK),
        Kind::Hash => Some(PASSWORD_MARK),
        Kind::Open => None,
    }
}

// ---- the tests ---------------------------------------------------------------------------------------

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

#[test]
#[ignore = "a hundred and four forced kills of a real process: minutes; run on purpose with --run-ignored"]
fn a_program_stopped_at_any_moment_leaves_the_database_as_it_was_or_as_it_is_to_be() {
    const STOPS: u64 = 13;
    // the first seven stops are spread over the whole change; the rest are tied to the decision
    // (the file `{db}.migrating.commit`), because what follows it is a small part of the whole and
    // the spread alone hardly ever falls there
    const TIMED: u64 = 7;
    let (mut total_old, mut total_new, mut total_killed, mut stops_made) = (0u64, 0u64, 0u64, 0u64);
    // each change, each cipher (key 4: AES, key 5: XChaCha), stopped 13 times: 104 stops in all. The
    // moments are not random: they are spread over the whole length of the change, measured on runs
    // that are not stopped (from 0.5% of it to 99.5%).
    for kind in [Kind::Seal, Kind::Open, Kind::Prints, Kind::Hash] {
        for k in [4u8, 5u8] {
            let (before_state, after_state) = kind.states();
            let (rows, _) = kind.rows();
            let template = template(kind, k);
            let before = contents(&template, before_state, k, rows).unwrap();
            let mut whole = Duration::ZERO;
            let mut after_decision = Duration::from_millis(2);
            for _ in 0..2 {
                let probe = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
                copy_dir(&template, &probe);
                let started = Instant::now();
                let mut running = child(&probe, kind, k).spawn().unwrap();
                // when the decision appears, and how long the rest of the change takes after it
                let mut decided_at = None;
                while running.try_wait().unwrap().is_none() {
                    if decided_at.is_none() && commit_file(&probe).exists() {
                        decided_at = Some(started.elapsed());
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                let st = running.wait().unwrap();
                assert!(st.success(), "the measuring run failed: {}", child_log::why(&probe, st));
                let total = started.elapsed();
                whole = whole.max(total);
                if let Some(at) = decided_at {
                    after_decision = after_decision.max(total.saturating_sub(at));
                }
                assert_eq!(contents(&probe, after_state, k, rows).unwrap(), before, "{kind:?} key {k}: the whole change");
                child_log::clean(&probe);
            }
            let whole_ms = whole.as_millis() as f64;
            let (mut old_state, mut new_state, mut killed) = (0u64, 0u64, 0u64);
            for i in 0..STOPS {
                let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
                copy_dir(&template, &root);
                let mut running = child(&root, kind, k).spawn().unwrap();
                if i < TIMED {
                    std::thread::sleep(Duration::from_millis((whole_ms * (i as f64 + 0.5) / TIMED as f64) as u64));
                } else {
                    // tied to the decision: wait for it, then stop after 0 to the time the rest takes
                    let until = Instant::now() + Duration::from_secs(120);
                    while !commit_file(&root).exists() && running.try_wait().unwrap().is_none() && Instant::now() < until {
                        std::thread::sleep(Duration::from_micros(500));
                    }
                    let steps = STOPS - TIMED;
                    let delay = after_decision.as_micros() as f64 * (i - TIMED) as f64 / steps as f64;
                    std::thread::sleep(Duration::from_micros(delay as u64));
                }
                match running.try_wait().unwrap() {
                    Some(status) => assert!(status.success(), "{kind:?} key {k}, stop {i}: the change failed: {}", child_log::why(&root, status)),
                    None => {
                        running.kill().unwrap();
                        killed += 1;
                    }
                }
                let _ = running.wait();
                stops_made += 1;
                // the next open settles what is left: as it was if the old files are the database,
                // as it is to be if the new files are (the other layout does not open)
                let (state, got) = match contents(&root, before_state, k, rows) {
                    Ok(got) => ("old", got),
                    Err(_) => (
                        "new",
                        contents(&root, after_state, k, rows).unwrap_or_else(|e| panic!("{kind:?} key {k}, stop {i}: neither opens: {e:?}")),
                    ),
                };
                assert_eq!(got, before, "{kind:?} key {k}, stop {i}: not the same rows");
                no_leftovers(&root);
                if state == "old" {
                    old_state += 1;
                } else {
                    new_state += 1;
                    if let Some(mark) = gone_after(kind) {
                        assert!(!in_files(&root, mark), "{kind:?} key {k}, stop {i}: the new state shows a clear value");
                    }
                }
                child_log::clean(&root);
            }
            record(&format!(
                "{kind:?} key {k}: {STOPS} stops over {whole_ms:.0} ms ({killed} killed while running): {old_state} left the old files, {new_state} the new ones"
            ));
            assert_eq!(old_state + new_state, STOPS);
            total_old += old_state;
            total_new += new_state;
            total_killed += killed;
            let _ = std::fs::remove_dir_all(&template);
        }
    }
    record(&format!("{stops_made} stops, {total_killed} while the change was running, {total_old} old, {total_new} new"));
    assert!(stops_made >= 100);
    assert!(total_killed >= 60, "only {total_killed} stops fell inside the change");
    assert!(total_old >= 20 && total_new >= 20, "the stops did not reach both sides of the decision");
}

/// With the crash points of the library: the process ends at the named place.
#[cfg(feature = "crash-inject")]
#[test]
fn a_crash_at_every_point_of_the_change_is_settled_by_the_next_open() {
    // (point, is the decision already made?)
    let points: &[(&str, bool)] = &[
        ("migration_after_begin", false),
        ("fields_after_main_written", false),
        ("fields_after_history_written", false),
        ("fields_after_keyfile_written", false),
        ("migration_before_commit", false),
        ("migration_after_commit", true),
        ("migration_before_aside_0", true),
        ("migration_after_aside_0", true),
        ("migration_before_place_0", true),
        ("migration_after_place_0", true),
        ("migration_before_aside_1", true),
        ("migration_after_place_1", true),
        ("migration_before_remove_0", true),
        ("fields_after_swap", true),
        ("migration_before_markers_removed", true),
        ("migration_after_markers_removed", true),
    ];
    let reached = std::sync::Mutex::new(std::collections::BTreeSet::new());
    let new_files_checked = std::sync::atomic::AtomicUsize::new(0);
    // each change with each cipher has its own databases and its own programs, so they run side by side
    let mut units = Vec::new();
    for kind in [Kind::Seal, Kind::Open, Kind::Prints, Kind::Hash] {
        for k in [4u8, 5u8] {
            units.push((kind, k));
        }
    }
    std::thread::scope(|scope| {
        for (kind, k) in units {
            let (reached, new_files_checked) = (&reached, &new_files_checked);
            scope.spawn(move || {
            let (before_state, after_state) = kind.states();
            let (_, rounds) = kind.rows();
            // small: only the points matter here
            let rows = 20;
            let root0 = make_plain(rows, rounds);
            if matches!(kind, Kind::Open | Kind::Prints) {
                Kind::Seal.change(&root0, k).execute().unwrap();
            }
            let before = contents(&root0, before_state, k, rows).unwrap();
            for (point, decided) in points {
                let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
                copy_dir(&root0, &root);
                let status = child(&root, kind, k).env("CLOVE_CRASH_POINT", point).status().unwrap();
                if status.code() == Some(99) {
                    reached.lock().unwrap().insert((*point).to_string());
                    // before the decision the new files made so far hold no clear value (the old files
                    // still do, they are the database): looked at before the next open settles them
                    if !*decided && let Some(mark) = gone_after(kind) {
                        let mut files = Vec::new();
                        all_files(&root, &mut files);
                        for file in files.iter().filter(|f| f.file_name().is_some_and(|n| n.to_string_lossy().contains(".mig-"))) {
                            let bytes = std::fs::read(file).unwrap();
                            assert!(!bytes.windows(mark.len()).any(|w| w == mark), "{kind:?} key {k} at {point}: a clear value in {}", file.display());
                            new_files_checked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        }
                    }
                    let got = if *decided {
                        contents(&root, after_state, k, rows)
                    } else {
                        contents(&root, before_state, k, rows)
                    }
                    .unwrap_or_else(|e| panic!("{kind:?} key {k} at {point}: {e:?}"));
                    assert_eq!(got, before, "{kind:?} key {k} at {point}");
                    no_leftovers(&root);
                    if *decided && let Some(mark) = gone_after(kind) {
                        assert!(!in_files(&root, mark), "{kind:?} key {k} at {point}: a clear value in the new state");
                    }
                } else {
                    // the point is not on this path (no keys file to write, say): it ran to the end
                    assert!(status.success(), "{point}: {}", child_log::why(&root, status));
                    assert_eq!(contents(&root, after_state, k, rows).unwrap(), before, "{kind:?} key {k} past {point}");
                }
                child_log::clean(&root);
            }
            let _ = std::fs::remove_dir_all(&root0);
            });
        }
    });
    let reached = reached.into_inner().unwrap();
    let new_files_checked = new_files_checked.into_inner();
    println!("crash points reached: {} of {}: {reached:?}; new files looked at before the decision: {new_files_checked}", reached.len(), points.len());
    assert!(new_files_checked >= 10, "only {new_files_checked} new files were looked at before the decision");
    for own in ["fields_after_main_written", "fields_after_history_written", "fields_after_keyfile_written", "fields_after_swap"] {
        assert!(reached.contains(own), "{own} was never reached");
    }
    assert!(reached.len() >= 12, "only {} points were reached", reached.len());
}
