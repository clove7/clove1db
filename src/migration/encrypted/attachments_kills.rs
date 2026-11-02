//! The move of attachments inside the frame of the marker files, with real processes: a program that
//! is stopped at any moment leaves the attachments either where they were or where they are meant
//! to be, complete, and the next open settles what is left.
//!
//! This is a test of the crate (not a file of `tests/`) because the marker frame is not part of the
//! public interface. The test program starts itself as the child that does the move (the
//! `child_entry` test does nothing unless the child variables are set).
//!
//! Two directions: plain files (`{db}.blobs`) to files sealed with the keys of protected fields
//! (`{db}.pblobs`), and back. The main file is not changed by either; the frame is the one a
//! change of fields uses: the new folder is written next to the old one, the decision is the
//! commit file, the swap follows.
use super::attachments::{Place, check_after_swap, copy_all, plan};
use super::marker::{Migration, Places, Root, Target};
use crate::crypto::{CipherKind, DataKey, HkdfHash, Key32, KeySuite, LockedDataKey, LockedKey, ProgrammerKey};
use crate::encrypted_store::FileKeys;
use crate::entity::Entity;
use crate::field_crypto::FieldKeys;
use crate::storage::{DatabaseConfig, Storage, StorageConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
struct File {
    id: String,
}
impl Entity for File {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

const SECRET: &str = "swordfish-marker-7731";
const DB: &str = "store";
/// The first object of each pair is what the attachments are before the move.
const PLAIN_TO_PROTECTED: u8 = 0;
const PROTECTED_TO_PLAIN: u8 = 1;

fn suite() -> KeySuite {
    KeySuite { cipher: CipherKind::Aes256GcmSiv, hkdf: HkdfHash::Sha256 }
}

/// The keys are made once by the parent and stored beside the database, so that the child opens
/// the same files.
fn make_lock(root: &Path) {
    let data = DataKey::generate().unwrap();
    let (read, search) = (Key32::from_bytes(&[1u8; 32]), Key32::from_bytes(&[2u8; 32]));
    let locked = data.lock(&suite(), &ProgrammerKey::Raw(&read), &ProgrammerKey::Raw(&search)).unwrap();
    std::fs::write(root.join("lock-read.bin"), locked.read.as_bytes()).unwrap();
    std::fs::write(root.join("lock-search.bin"), locked.search.as_bytes()).unwrap();
}

fn keys(root: &Path) -> Arc<FieldKeys> {
    let locked = LockedDataKey {
        read: LockedKey::from_bytes(std::fs::read(root.join("lock-read.bin")).unwrap()),
        search: LockedKey::from_bytes(std::fs::read(root.join("lock-search.bin")).unwrap()),
    };
    let (read, search) = (Key32::from_bytes(&[1u8; 32]), Key32::from_bytes(&[2u8; 32]));
    let access = locked.unlock(&suite(), Some(&ProgrammerKey::Raw(&read)), Some(&ProgrammerKey::Raw(&search))).unwrap();
    Arc::new(FieldKeys::with_access(suite(), access).unwrap())
}

fn plain_place(dir: &Path) -> Place {
    Place::Plain { root: dir.join(format!("{DB}.blobs")) }
}

fn protected_place(root: &Path, dir: &Path) -> Place {
    let ids = HashMap::from([("files".to_string(), "table-one".to_string())]);
    Place::Protected { root: dir.join(format!("{DB}.pblobs")), keys: keys(root) as Arc<dyn FileKeys>, ids: Arc::new(ids) }
}

/// (where the attachments are before, where they are to be after).
fn places(root: &Path, dir: &Path, direction: u8) -> (Place, Place) {
    if direction == PLAIN_TO_PROTECTED {
        (plain_place(dir), protected_place(root, dir))
    } else {
        (protected_place(root, dir), plain_place(dir))
    }
}

fn data(len: usize, seed: u8) -> Vec<u8> {
    let mut v = SECRET.as_bytes().to_vec();
    v.extend((0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)));
    v
}

/// What the database holds: the bytes of each attachment, by row.
type Expected = HashMap<String, Vec<u8>>;

/// A plain database with attachments of about `scale` times 0.4 to 3.2 MB, and what it holds. The
/// keys are stored in `root`. For the direction "back" the attachments are moved to the sealed
/// place first.
fn make(direction: u8, scale: usize) -> (PathBuf, PathBuf, Expected) {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir_all(&root).unwrap();
    make_lock(&root);
    let db = DatabaseConfig::new("records", DB).dir_path(root.clone()).blob_enabled(true).register_blob::<File>("files");
    #[cfg(clove_test_encrypt_all)]
    let db = db.plain();
    let s = Storage::builder(StorageConfig::default()).add_database(db).build().unwrap();
    let mut expected = Expected::new();
    for i in 0..8 {
        let bytes = data((i + 1) * 400_000 * scale / 4, i as u8);
        s.db_manager(DB).write_blob("files", &format!("r{i}"), &bytes).unwrap();
        expected.insert(format!("r{i}"), bytes);
    }
    s.close();
    let dir = root.join("records");
    if direction == PROTECTED_TO_PLAIN {
        run_move(&root, &dir, PLAIN_TO_PROTECTED).unwrap();
    }
    (root, dir, expected)
}

/// The move, in the frame of the marker files: everything the change of fields will do with the
/// attachments of a table.
fn run_move(root: &Path, dir: &Path, direction: u8) -> crate::units::Result<()> {
    let places_dirs = Places { main: dir, backup: dir };
    Migration::recover(places_dirs, DB)?;
    let (from, to_final) = places(root, dir, direction);
    let (new_name, old_name) = match direction {
        PLAIN_TO_PROTECTED => (format!("{DB}.pblobs"), format!("{DB}.blobs")),
        _ => (format!("{DB}.blobs"), format!("{DB}.pblobs")),
    };
    // the folder that is made new, then the one that goes (it is made again by the library when needed)
    let targets = vec![Target::new(Root::Main, &new_name, true), Target::new(Root::Main, &old_name, false)];
    let migration = Migration::begin_with(places_dirs, DB, targets, false)?;
    let main = redb::Database::builder()
        .open_read_only(dir.join(format!("{DB}.cldb")))
        .map_err(|e| crate::units::ClError::MigrationError(e.to_string()))?;
    let to = match &to_final {
        Place::Plain { .. } => Place::Plain { root: migration.new_path(0) },
        Place::Protected { keys, ids, .. } => Place::Protected { root: migration.new_path(0), keys: keys.clone(), ids: ids.clone() },
        Place::WholeDb { .. } => unreachable!("not a direction of this test"),
    };
    let done = copy_all(&main, None, &from, &to, &mut |_| {}).and_then(|_| migration.commit());
    if let Err(e) = done {
        let _ = migration.roll_back();
        return Err(e);
    }
    migration.swap()?;
    check_after_swap(&main, &to_final, None)?;
    drop(main);
    migration.finish()
}

fn all_files(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.filter_map(|e| e.ok()) {
            if e.path().is_dir() {
                all_files(&e.path(), out);
            } else {
                out.push(e.path());
            }
        }
    }
}

fn files_in(dir: &Path) -> usize {
    let mut v = Vec::new();
    all_files(dir, &mut v);
    v.len()
}

fn secret_in_files(dir: &Path) -> bool {
    let mut files = Vec::new();
    all_files(dir, &mut files);
    files.iter().any(|p| std::fs::read(p).map(|b| b.windows(SECRET.len()).any(|w| w == SECRET.as_bytes())).unwrap_or(false))
}

fn no_leftovers(dir: &Path) {
    let mut files = Vec::new();
    all_files(dir, &mut files);
    for p in files {
        let n = p.strip_prefix(dir).unwrap().display().to_string();
        assert!(!n.contains(".mig-") && !n.contains(".migrating") && !n.contains(".creating") && !n.contains(".tmp"), "left behind: {n}");
    }
    for n in [".mig-new", ".mig-old"] {
        for base in [format!("{DB}.blobs{n}"), format!("{DB}.pblobs{n}")] {
            assert!(!dir.join(&base).exists(), "left behind: {base}");
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum State {
    Old,
    New,
}

/// The next open: settle what a stopped move left, then say where the attachments are and check
/// that they are all there, there only, and hold the right bytes.
fn settle(root: &Path, dir: &Path, direction: u8, expected: &Expected, what: &str) -> State {
    Migration::recover(Places { main: dir, backup: dir }, DB).unwrap_or_else(|e| panic!("{what}: recover failed: {e:?}"));
    let (old, new) = places(root, dir, direction);
    let (old_files, new_files) = (files_in(old.root()), files_in(new.root()));
    assert!(
        (old_files > 0) != (new_files > 0),
        "{what}: the attachments are in both places or in neither ({old_files} / {new_files})"
    );
    let (place, state, other) = if old_files > 0 { (&old, State::Old, &new) } else { (&new, State::New, &old) };
    assert!(!other.root().exists() || files_in(other.root()) == 0, "{what}: files left in the other place");
    let main = redb::Database::builder().open_read_only(dir.join(format!("{DB}.cldb"))).unwrap();
    let mut seen = 0usize;
    plan(&main, None, &mut |item| {
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut place.open(&item)?, &mut bytes).map_err(|e| crate::units::ClError::MigrationError(e.to_string()))?;
        assert_eq!(&bytes, expected.get(&item.row).unwrap(), "{what}: attachment {} differs", item.row);
        seen += 1;
        Ok(())
    })
    .unwrap_or_else(|e| panic!("{what}: an attachment does not open: {e:?}"));
    assert_eq!(seen, expected.len(), "{what}");
    let in_place = if old_files > 0 { old_files } else { new_files };
    assert_eq!(in_place, expected.len(), "{what}: the place holds other files than the attachments");
    drop(main);
    no_leftovers(dir);
    // sealed files hold nothing readable
    let sealed_root = if direction == PLAIN_TO_PROTECTED { new.root() } else { old.root() };
    let sealed_state = (direction == PLAIN_TO_PROTECTED && state == State::New) || (direction == PROTECTED_TO_PLAIN && state == State::Old);
    if sealed_state {
        assert!(!secret_in_files(sealed_root), "{what}: the sealed place shows a clear value");
    }
    state
}

// ---- the child -----------------------------------------------------------------------------------

/// Run by the parent in another process. Does nothing in a normal run.
#[test]
fn child_entry() {
    let Ok(root) = std::env::var("CLOVE_ATT_ROOT") else { return };
    let root = PathBuf::from(root);
    let direction: u8 = std::env::var("CLOVE_ATT_DIRECTION").unwrap().parse().unwrap();
    run_move(&root, &root.join("records"), direction).unwrap();
}

fn child(root: &Path, direction: u8) -> Command {
    let mut c = Command::new(std::env::current_exe().unwrap());
    // what the child prints is kept beside the database, so that a child that ends with an error says why
    let log = std::fs::File::create(root.join("child.log")).unwrap();
    c.args(["--exact", "migration::encrypted::attachments_kills::child_entry", "--nocapture", "--test-threads=1"])
        .env("CLOVE_ATT_ROOT", root)
        .env("CLOVE_ATT_DIRECTION", direction.to_string())
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log));
    c
}

fn child_log(root: &Path) -> String {
    std::fs::read_to_string(root.join("child.log")).unwrap_or_default()
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

fn name(direction: u8) -> &'static str {
    if direction == PLAIN_TO_PROTECTED { "plain to protected" } else { "protected to plain" }
}

// ---- the tests -----------------------------------------------------------------------------------

#[test]
fn a_move_that_is_not_stopped_ends_in_the_new_place_in_both_directions() {
    for direction in [PLAIN_TO_PROTECTED, PROTECTED_TO_PLAIN] {
        let (root, dir, expected) = make(direction, 1);
        assert_eq!(settle(&root, &dir, direction, &expected, "before"), State::Old);
        assert!(child(&root, direction).status().unwrap().success());
        assert_eq!(settle(&root, &dir, direction, &expected, name(direction)), State::New);
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[test]
fn a_program_stopped_at_any_moment_leaves_the_attachments_where_they_were_or_where_they_are_to_be() {
    const STOPS: u64 = 20;
    // each direction stopped 20 times (it was 100 on 22 MB: the same two sides of the decision are reached, in a fraction of the
    // time). The moments are not random: they are measured on runs that
    // are not stopped. Half are spread over the whole length of the move (from 0.5% of it to 99.5%);
    // the other half over the end of it, from a little before the decision (the commit file shows)
    // to the last moment, since what follows the decision is a short part of the whole.
    for direction in [PLAIN_TO_PROTECTED, PROTECTED_TO_PLAIN] {
        // about 3.5 MB of attachments, so that the move itself is most of what the program does
        let (template, _, expected) = make(direction, 1);
        let (mut old_state, mut new_state, mut killed) = (0, 0, 0);
        // the length of the move, program start included: the shortest of three whole runs (a stop
        // later than a run is long is no stop, so the short one is the safe measure)
        let mut whole = Duration::MAX;
        for _ in 0..3 {
            let probe = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
            copy_dir(&template, &probe);
            let started = Instant::now();
            assert!(child(&probe, direction).status().unwrap().success());
            whole = whole.min(started.elapsed());
            let _ = std::fs::remove_dir_all(&probe);
        }
        let whole_ms = whole.as_secs_f64() * 1000.0;
        // how long the end of the move lasts after the decision (the commit file shows), seen by
        // polling for it in two more runs: the swap and the removal of the old files
        let mut tail_ms = 5.0f64;
        for _ in 0..2 {
            let probe = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
            copy_dir(&template, &probe);
            let started = Instant::now();
            let mut running = child(&probe, direction).spawn().unwrap();
            let commit_file = probe.join("records").join(format!("{DB}.migrating.commit"));
            let mut seen = None;
            loop {
                if seen.is_none() && commit_file.exists() {
                    seen = Some(started.elapsed());
                }
                if let Some(status) = running.try_wait().unwrap() {
                    assert!(status.success());
                    break;
                }
                std::thread::yield_now();
            }
            if let Some(at) = seen {
                tail_ms = tail_ms.max((started.elapsed() - at).as_secs_f64() * 1000.0);
            }
            let _ = std::fs::remove_dir_all(&probe);
        }
        for i in 0..STOPS {
            let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
            copy_dir(&template, &root);
            let dir = root.join("records");
            let mut running = child(&root, direction).spawn().unwrap();
            let step = ((i / 2) as f64 + 0.5) / (STOPS / 2) as f64;
            let from = Instant::now();
            if i % 2 == 0 {
                // a moment of the whole length
                while from.elapsed().as_secs_f64() * 1000.0 < whole_ms * step {
                    std::thread::yield_now();
                }
            } else {
                // a moment of the end: wait for the decision, then a part of the time it takes
                let commit_file = root.join("records").join(format!("{DB}.migrating.commit"));
                while !commit_file.exists() && running.try_wait().unwrap().is_none() {
                    std::thread::yield_now();
                }
                let after = Instant::now();
                while after.elapsed().as_secs_f64() * 1000.0 < tail_ms * step {
                    std::thread::yield_now();
                }
            }
            match running.try_wait().unwrap() {
                // it ran to the end before it was stopped: that is a success or a bug, not a stop
                Some(status) => assert!(status.success(), "{}, stop {i}: the move failed: {status:?}; the child printed: {}", name(direction), child_log(&root)),
                None => {
                    running.kill().unwrap();
                    killed += 1;
                }
            }
            let _ = running.wait();
            match settle(&root, &dir, direction, &expected, &format!("{}, stop {i}", name(direction))) {
                State::Old => old_state += 1,
                State::New => new_state += 1,
            }
            let _ = std::fs::remove_dir_all(&root);
        }
        println!(
            "{}: {STOPS} stops (half over the {whole_ms:.0} ms of the move, half over the {tail_ms:.0} ms after the decision), {killed} killed while running, {old_state} left the old place, {new_state} the new one",
            name(direction)
        );
        assert_eq!(old_state + new_state, STOPS);
        // seen with 100 stops on 22 MB in 7 runs (2 directions each): 71 to 100 stopped while running; 47 to 49 left the old place and 51 to 53
        // the new one (half the stops are aimed at the end, after the decision, so the two sides are not left to chance). The bounds keep the
        // same shares for 20 stops: 8 of 20 stopped while running (40%), and 4 of 20 on each side (20%).
        assert!(killed >= 8, "{}: only {killed} of {STOPS} were stopped while the move was running", name(direction));
        assert!(old_state >= 4 && new_state >= 4, "{}: the stops did not reach both sides of the decision", name(direction));
        let _ = std::fs::remove_dir_all(&template);
    }
}

/// With the crash points of the library: the process ends at the named place.
#[cfg(feature = "crash-inject")]
#[test]
fn a_crash_at_every_point_of_the_move_is_settled_by_the_next_open() {
    // (point, how many hits to let pass first, is the decision already made?)
    let points: &[(&str, u64, bool)] = &[
        ("migration_after_begin", 0, false),
        ("attach_before_first_file", 0, false),
        ("attach_after_file", 0, false),
        ("attach_after_file", 3, false),
        ("attach_after_file", 7, false),
        ("attach_before_verify", 0, false),
        ("attach_before_verify", 4, false),
        ("attach_after_verify", 0, false),
        ("attach_after_verify", 6, false),
        ("attach_after_sync", 0, false),
        ("migration_before_commit", 0, false),
        ("migration_after_commit", 0, true),
        ("migration_before_aside_0", 0, true),
        ("migration_after_aside_0", 0, true),
        ("migration_before_place_0", 0, true),
        ("migration_after_place_0", 0, true),
        ("migration_before_aside_1", 0, true),
        ("migration_after_aside_1", 0, true),
        ("migration_before_remove_0", 0, true),
        ("migration_before_remove_1", 0, true),
        ("migration_before_markers_removed", 0, true),
        ("migration_after_markers_removed", 0, true),
    ];
    let mut cases = Vec::new();
    for direction in [PLAIN_TO_PROTECTED, PROTECTED_TO_PLAIN] {
        for (point, skip, decided) in points {
            cases.push((direction, *point, *skip, *decided));
        }
    }
    // each case has its own database and its own program, so the cases run side by side
    let reached = std::sync::Mutex::new(std::collections::BTreeSet::new());
    let next = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..std::thread::available_parallelism().map_or(4, |n| n.get()).min(8) {
            scope.spawn(|| {
                while let Some(&(direction, point, skip, decided)) = cases.get(next.fetch_add(1, std::sync::atomic::Ordering::SeqCst)) {
                    let (root, dir, expected) = make(direction, 1);
                    let status = child(&root, direction).env("CLOVE_CRASH_POINT", point).env("CLOVE_CRASH_SKIP", skip.to_string()).status().unwrap();
                    let what = format!("{} at {point} (after {skip} hits)", name(direction));
                    if status.code() == Some(99) {
                        reached.lock().unwrap().insert(point.to_string());
                        let state = settle(&root, &dir, direction, &expected, &what);
                        assert_eq!(state, if decided { State::New } else { State::Old }, "{what}: wrong side of the decision");
                    } else {
                        // the point is not on this path (the old folder is not removed when it is not there, say)
                        assert!(status.success(), "{what}: {status:?}");
                        assert_eq!(settle(&root, &dir, direction, &expected, &what), State::New);
                    }
                    let _ = std::fs::remove_dir_all(&root);
                }
            });
        }
    });
    let reached = reached.into_inner().unwrap();
    println!("reached {} different points: {reached:?}", reached.len());
    for must in [
        "migration_after_begin",
        "attach_before_first_file",
        "attach_after_file",
        "attach_before_verify",
        "attach_after_verify",
        "attach_after_sync",
        "migration_before_commit",
        "migration_after_commit",
        "migration_after_markers_removed",
    ] {
        assert!(reached.contains(must), "{must} was never reached");
    }
}
