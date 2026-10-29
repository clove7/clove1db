use super::marker::{Migration, NEW_SUFFIX, OLD_SUFFIX, Places, Recovery, Root, Target};
use super::rows::{BatchLimits, copy_bytes_table, copy_number_table};
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use std::path::{Path, PathBuf};

fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ---- rows in batches -------------------------------------------------------------------------

const BYTES: TableDefinition<&str, &[u8]> = TableDefinition::new("rows");
const NUMBERS: TableDefinition<&str, u64> = TableDefinition::new("rows_version");

fn source(dir: &Path, count: usize, value_len: usize) -> Database {
    let db = Database::create(dir.join("from.db")).unwrap();
    let write = db.begin_write().unwrap();
    {
        let mut t = write.open_table(BYTES).unwrap();
        let mut v = write.open_table(NUMBERS).unwrap();
        for i in 0..count {
            let key = format!("k{i:06}");
            t.insert(key.as_str(), vec![(i % 251) as u8; value_len].as_slice()).unwrap();
            v.insert(key.as_str(), i as u64).unwrap();
        }
    }
    write.commit().unwrap();
    db
}

#[test]
fn a_table_is_copied_in_batches_and_every_row_is_changed() {
    let dir = temp_dir();
    let from = source(&dir, 1000, 40);
    let to = Database::create(dir.join("to.db")).unwrap();
    let limits = BatchLimits { max_rows: 100, max_bytes: 1 << 20 };
    let done = copy_bytes_table(&from, &to, "rows", limits, &mut |_, v| Ok([v, b"!"].concat())).unwrap();
    assert_eq!((done.rows, done.batches), (1000, 10));
    let read = to.begin_read().unwrap();
    let t = read.open_table(BYTES).unwrap();
    assert_eq!(t.len().unwrap(), 1000);
    let (k, v) = t.iter().unwrap().nth(7).unwrap().map(|(k, v)| (k.value().to_string(), v.value().to_vec())).unwrap();
    assert_eq!(k, "k000007");
    assert_eq!(v, [vec![7u8; 40], b"!".to_vec()].concat());
    drop(t);
    drop(read);
    drop((from, to));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_memory_held_does_not_grow_with_the_table() {
    let dir = temp_dir();
    let limits = BatchLimits { max_rows: 1_000_000, max_bytes: 64 * 1024 };
    let mut largest = Vec::new();
    for count in [200usize, 2000] {
        let from = source(&dir, count, 1000);
        let to = Database::create(dir.join(format!("to{count}.db"))).unwrap();
        let done = copy_bytes_table(&from, &to, "rows", limits, &mut |_, v| Ok(v.to_vec())).unwrap();
        assert_eq!(done.rows, count as u64);
        largest.push(done.largest_batch_bytes);
        drop((from, to));
        std::fs::remove_file(dir.join("from.db")).unwrap();
    }
    // one batch ends at the byte limit plus the row that crossed it, whatever the table size
    for bytes in &largest {
        assert!(*bytes < 64 * 1024 + 2000, "a batch held {bytes} bytes");
    }
    assert!(largest[1] < largest[0] * 2, "a table ten times larger held a larger batch: {largest:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_row_larger_than_the_limit_is_a_batch_of_its_own() {
    let dir = temp_dir();
    let from = source(&dir, 3, 5000);
    let to = Database::create(dir.join("to.db")).unwrap();
    let done = copy_bytes_table(&from, &to, "rows", BatchLimits { max_rows: 100, max_bytes: 10 }, &mut |_, v| Ok(v.to_vec())).unwrap();
    assert_eq!((done.rows, done.batches), (3, 3));
    drop((from, to));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_empty_table_is_made_in_the_new_file_and_the_counters_are_copied() {
    let dir = temp_dir();
    let from = source(&dir, 0, 1);
    let to = Database::create(dir.join("to.db")).unwrap();
    let limits = BatchLimits::DEFAULT;
    let done = copy_bytes_table(&from, &to, "rows", limits, &mut |_, v| Ok(v.to_vec())).unwrap();
    assert_eq!((done.rows, done.batches), (0, 0));
    assert!(to.begin_read().unwrap().open_table(BYTES).is_ok(), "the table must exist");
    drop((from, to));
    std::fs::remove_file(dir.join("from.db")).unwrap();

    let from = source(&dir, 50, 1);
    let to2 = Database::create(dir.join("to2.db")).unwrap();
    let done = copy_number_table(&from, &to2, "rows_version", BatchLimits { max_rows: 20, max_bytes: 1 << 20 }).unwrap();
    assert_eq!((done.rows, done.batches), (50, 3));
    let read = to2.begin_read().unwrap();
    assert_eq!(read.open_table(NUMBERS).unwrap().get("k000049").unwrap().unwrap().value(), 49);
    drop((read, from, to2));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_failing_change_stops_the_copy_and_a_zero_batch_is_refused() {
    let dir = temp_dir();
    let from = source(&dir, 10, 1);
    let to = Database::create(dir.join("to.db")).unwrap();
    let mut seen = 0;
    let err = copy_bytes_table(&from, &to, "rows", BatchLimits { max_rows: 3, max_bytes: 1 << 20 }, &mut |_, v| {
        seen += 1;
        if seen == 5 { Err(crate::units::ClError::MigrationError("stop".into())) } else { Ok(v.to_vec()) }
    });
    assert!(err.is_err());
    assert!(copy_bytes_table(&from, &to, "rows", BatchLimits { max_rows: 0, max_bytes: 1 }, &mut |_, v| Ok(v.to_vec())).is_err());
    drop((from, to));
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- replacing files ---------------------------------------------------------------------------

struct Fixture {
    main: PathBuf,
    backup: PathBuf,
}

fn targets() -> Vec<Target> {
    vec![
        Target::new(Root::Main, "d.cldb", true),
        Target::new(Root::Backup, "d.cldb.bak", true),
        Target::new(Root::Main, "d.inx", false),
        Target::new(Root::Main, "d.keys", true), // did not exist before
    ]
}

fn fixture() -> Fixture {
    let root = temp_dir();
    let (main, backup) = (root.join("main"), root.join("backup"));
    std::fs::create_dir_all(&main).unwrap();
    std::fs::create_dir_all(&backup).unwrap();
    std::fs::write(main.join("d.cldb"), b"old main").unwrap();
    std::fs::write(backup.join("d.cldb.bak"), b"old backup").unwrap();
    std::fs::write(main.join("d.inx"), b"old index").unwrap();
    Fixture { main, backup }
}

fn listing(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut v: Vec<(String, Vec<u8>)> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| (e.file_name().to_string_lossy().into_owned(), std::fs::read(e.path()).unwrap_or_default()))
        .collect();
    v.sort();
    v
}

fn state(f: &Fixture) -> (Vec<(String, Vec<u8>)>, Vec<(String, Vec<u8>)>) {
    (listing(&f.main), listing(&f.backup))
}

fn old_state() -> (Vec<(String, Vec<u8>)>, Vec<(String, Vec<u8>)>) {
    let s = |n: &str, c: &str| (n.to_string(), c.as_bytes().to_vec());
    (vec![s("d.cldb", "old main"), s("d.inx", "old index")], vec![s("d.cldb.bak", "old backup")])
}

fn new_state() -> (Vec<(String, Vec<u8>)>, Vec<(String, Vec<u8>)>) {
    let s = |n: &str, c: &str| (n.to_string(), c.as_bytes().to_vec());
    (vec![s("d.cldb", "new main"), s("d.keys", "new keys")], vec![s("d.cldb.bak", "new backup")])
}

/// Every step of a migration, one closure each, in order. `COMMIT_AT` is the index of the commit.
fn steps<'a>(f: &'a Fixture, m: &'a Migration<'a>) -> Vec<Box<dyn Fn() + 'a>> {
    let mut v: Vec<Box<dyn Fn() + 'a>> = Vec::new();
    for (index, content) in [(0usize, "new main"), (1, "new backup"), (3, "new keys")] {
        v.push(Box::new(move || std::fs::write(m.new_path(index), content).unwrap()));
    }
    v.push(Box::new(|| m.commit().unwrap()));
    for index in 0..4 {
        v.push(Box::new(move || m.aside(index).unwrap()));
        v.push(Box::new(move || m.place(index).unwrap()));
    }
    for index in 0..4 {
        v.push(Box::new(move || m.remove_old(index).unwrap()));
    }
    v.push(Box::new(|| m.remove_intent().unwrap()));
    v.push(Box::new(|| m.remove_commit().unwrap()));
    let _ = f;
    v
}

const COMMIT_AT: usize = 3;

#[test]
fn a_crash_after_any_step_leaves_the_old_files_or_the_new_ones_never_a_mix() {
    // the number of steps is taken from a run that is not cut
    let total = {
        let f = fixture();
        let places = Places { main: &f.main, backup: &f.backup };
        let m = Migration::begin(places, "d", targets()).unwrap();
        steps(&f, &m).len()
    };
    for cut in 0..=total {
        let f = fixture();
        let places = Places { main: &f.main, backup: &f.backup };
        {
            let m = Migration::begin(places, "d", targets()).unwrap();
            for step in steps(&f, &m).iter().take(cut) {
                step();
            }
        }
        // the process is gone: only the files are left
        let found = Migration::recover(places, "d").unwrap();
        let committed = cut > COMMIT_AT;
        let expected = if cut == total {
            Recovery::Nothing // every marker was already removed
        } else if committed {
            Recovery::RolledForward
        } else {
            Recovery::RolledBack
        };
        assert_eq!(found, expected, "cut after {cut} steps");
        assert_eq!(state(&f), if committed { new_state() } else { old_state() }, "cut after {cut} steps");
        // a second recovery has nothing to do
        assert_eq!(Migration::recover(places, "d").unwrap(), Recovery::Nothing, "cut after {cut} steps");
        let _ = std::fs::remove_dir_all(f.main.parent().unwrap());
    }
}

#[test]
fn a_crash_while_the_old_files_are_being_put_back_is_settled_by_the_next_recovery() {
    // the new files are in place (the swap is done), then putting back is cut after `cut` steps:
    // withdraw the decision, restore each target, remove the marker
    for cut in 0..=6 {
        let f = fixture();
        let places = Places { main: &f.main, backup: &f.backup };
        {
            let m = Migration::begin(places, "d", targets()).unwrap();
            for (i, c) in [(0, "new main"), (1, "new backup"), (3, "new keys")] {
                std::fs::write(m.new_path(i), c).unwrap();
            }
            m.commit().unwrap();
            m.swap().unwrap();
            let back: Vec<Box<dyn Fn() + '_>> = vec![
                Box::new(|| m.remove_commit().unwrap()),
                Box::new(|| m.restore(0).unwrap()),
                Box::new(|| m.restore(1).unwrap()),
                Box::new(|| m.restore(2).unwrap()),
                Box::new(|| m.restore(3).unwrap()),
                Box::new(|| m.remove_intent().unwrap()),
            ];
            for step in back.iter().take(cut) {
                step();
            }
        }
        Migration::recover(places, "d").unwrap();
        // until the decision is withdrawn (the first step) the new files are the database
        assert_eq!(state(&f), if cut == 0 { new_state() } else { old_state() }, "cut after {cut} steps of putting back");
        let _ = std::fs::remove_dir_all(f.main.parent().unwrap());
    }
}

#[test]
fn a_second_migration_is_refused_while_one_is_under_way() {
    let f = fixture();
    let places = Places { main: &f.main, backup: &f.backup };
    let first = Migration::begin(places, "d", targets()).unwrap();
    assert!(Migration::begin(places, "d", targets()).is_err());
    drop(first);
    assert_eq!(Migration::recover(places, "d").unwrap(), Recovery::RolledBack);
    assert!(Migration::begin(places, "d", targets()).is_ok());
    let _ = std::fs::remove_dir_all(f.main.parent().unwrap());
}

#[test]
fn nothing_is_committed_while_a_new_file_is_missing() {
    let f = fixture();
    let places = Places { main: &f.main, backup: &f.backup };
    let m = Migration::begin(places, "d", targets()).unwrap();
    std::fs::write(m.new_path(0), b"new main").unwrap();
    assert!(m.commit().is_err());
    assert!(!f.main.join("d.migrating.commit").exists());
    m.roll_back().unwrap();
    assert_eq!(state(&f), old_state());
    let _ = std::fs::remove_dir_all(f.main.parent().unwrap());
}

#[test]
fn after_the_swap_the_old_files_can_still_be_put_back() {
    let f = fixture();
    let places = Places { main: &f.main, backup: &f.backup };
    let m = Migration::begin(places, "d", targets()).unwrap();
    for (i, c) in [(0, "new main"), (1, "new backup"), (3, "new keys")] {
        std::fs::write(m.new_path(i), c).unwrap();
    }
    m.commit().unwrap();
    m.swap().unwrap();
    assert!(f.main.join(format!("d.cldb{OLD_SUFFIX}")).exists());
    m.roll_back().unwrap();
    assert_eq!(state(&f), old_state());
    assert!(!f.main.join(format!("d.keys{NEW_SUFFIX}")).exists());
    let _ = std::fs::remove_dir_all(f.main.parent().unwrap());
}

#[test]
fn a_state_the_steps_cannot_produce_is_an_error_and_nothing_is_changed() {
    let f = fixture();
    let places = Places { main: &f.main, backup: &f.backup };
    let m = Migration::begin(places, "d", targets()).unwrap();
    for (i, c) in [(0, "new main"), (1, "new backup"), (3, "new keys")] {
        std::fs::write(m.new_path(i), c).unwrap();
    }
    m.commit().unwrap();
    // all three names of one file exist
    std::fs::write(f.main.join(format!("d.cldb{OLD_SUFFIX}")), b"x").unwrap();
    drop(m); // the marker is no longer held: what is wrong is the state, not the lock
    let before = state(&f);
    assert!(matches!(Migration::recover(places, "d"), Err(crate::units::ClError::MigrationError(_))));
    assert_eq!(state(&f), before);
    // a marker that cannot be read
    std::fs::remove_file(f.main.join(format!("d.cldb{OLD_SUFFIX}"))).unwrap();
    std::fs::write(f.main.join("d.migrating"), b"not json").unwrap();
    assert!(Migration::recover(places, "d").is_err());
    let _ = std::fs::remove_dir_all(f.main.parent().unwrap());
}

#[test]
fn a_marker_held_by_a_live_migration_is_neither_undone_nor_finished() {
    use crate::units::ClError;
    let f = fixture();
    let places = Places { main: &f.main, backup: &f.backup };
    let m = Migration::begin(places, "d", targets()).unwrap();
    std::fs::write(m.new_path(0), b"new main").unwrap();
    let before = state(&f);
    // before the decision: not undone (the new file it is writing stays)
    assert!(matches!(Migration::recover(places, "d"), Err(ClError::DatabaseInUse { .. })));
    assert_eq!(state(&f), before);
    // after the decision: not finished either
    for (i, c) in [(1, "new backup"), (3, "new keys")] {
        std::fs::write(m.new_path(i), c).unwrap();
    }
    m.commit().unwrap();
    let before = state(&f);
    assert!(matches!(Migration::recover(places, "d"), Err(ClError::DatabaseInUse { .. })));
    assert_eq!(state(&f), before);
    // when the migration ends (or its process dies) the lock is free and the decision stands
    drop(m);
    assert_eq!(Migration::recover(places, "d").unwrap(), Recovery::RolledForward);
    assert_eq!(state(&f), new_state());
    let _ = std::fs::remove_dir_all(f.main.parent().unwrap());
}

#[test]
fn a_marker_that_is_still_being_made_is_not_taken_away_and_a_dead_one_is_cleared() {
    use crate::units::ClError;
    let f = fixture();
    let places = Places { main: &f.main, backup: &f.backup };
    let temporary = f.main.join("d.migrating.begin");
    let held = std::fs::File::create(&temporary).unwrap();
    held.lock().unwrap();
    assert!(matches!(Migration::recover(places, "d"), Err(ClError::DatabaseInUse { .. })));
    assert!(temporary.exists());
    assert!(Migration::begin(places, "d", targets()).is_err(), "a second migration does not start over a marker being made");
    drop(held);
    assert_eq!(Migration::recover(places, "d").unwrap(), Recovery::Nothing);
    assert!(!temporary.exists());
    assert_eq!(state(&f), old_state());
    let _ = std::fs::remove_dir_all(f.main.parent().unwrap());
}

#[test]
fn the_half_made_file_of_an_encrypted_creation_is_removed_with_the_rest_of_the_attempt() {
    let f = fixture();
    let places = Places { main: &f.main, backup: &f.backup };
    {
        let m = Migration::begin(places, "d", targets()).unwrap();
        // the process stopped while the new encrypted main file was under its temporary name
        let mut creating = m.new_path(0).into_os_string();
        creating.push(".creating");
        std::fs::write(&creating, b"half").unwrap();
    }
    assert_eq!(Migration::recover(places, "d").unwrap(), Recovery::RolledBack);
    assert_eq!(state(&f), old_state());
    let _ = std::fs::remove_dir_all(f.main.parent().unwrap());
}

#[test]
fn names_that_could_leave_the_folder_are_refused() {
    let f = fixture();
    let places = Places { main: &f.main, backup: &f.backup };
    for bad in ["", "..", "a/b", "a\\b", "x.mig-new"] {
        let t = vec![Target::new(Root::Main, bad, true)];
        assert!(Migration::begin(places, "d", t).is_err(), "{bad:?}");
    }
    let twice = vec![targets()[0].clone(), targets()[0].clone()];
    assert!(Migration::begin(places, "d", twice).is_err());
    assert!(!f.main.join("d.migrating").exists());
    let _ = std::fs::remove_dir_all(f.main.parent().unwrap());
}

#[test]
fn a_folder_can_be_replaced_like_a_file() {
    let f = fixture();
    let places = Places { main: &f.main, backup: &f.backup };
    std::fs::create_dir_all(f.main.join("d.pblobs")).unwrap();
    std::fs::write(f.main.join("d.pblobs").join("a"), b"old part").unwrap();
    let t = vec![Target::new(Root::Main, "d.pblobs", true)];
    let m = Migration::begin(places, "d", t).unwrap();
    std::fs::create_dir_all(m.new_path(0)).unwrap();
    std::fs::write(m.new_path(0).join("b"), b"new part").unwrap();
    m.commit().unwrap();
    m.swap().unwrap();
    m.finish().unwrap();
    assert_eq!(std::fs::read(f.main.join("d.pblobs").join("b")).unwrap(), b"new part");
    assert!(!f.main.join("d.pblobs").join("a").exists());
    let _ = std::fs::remove_dir_all(f.main.parent().unwrap());
}

// ---- overwriting the old files, and the space a migration needs ------------------------------------

fn swapped(f: &Fixture, wipe: bool) -> Migration<'_> {
    let places = Places { main: &f.main, backup: &f.backup };
    let m = Migration::begin_with(places, "d", targets(), wipe).unwrap();
    for (i, c) in [(0, "new main"), (1, "new backup"), (3, "new keys")] {
        std::fs::write(m.new_path(i), c).unwrap();
    }
    m.commit().unwrap();
    m.swap().unwrap();
    m
}

#[test]
fn an_old_file_is_overwritten_before_it_is_removed_when_asked() {
    let f = fixture();
    let m = swapped(&f, true);
    let old = f.main.join(format!("d.cldb{OLD_SUFFIX}"));
    m.wipe_old(0).unwrap();
    let after = std::fs::read(&old).unwrap();
    assert_eq!(after.len(), b"old main".len(), "the length stays");
    assert_ne!(after, b"old main", "the content is still the old one");
    m.finish().unwrap();
    assert_eq!(state(&f), new_state());
    let _ = std::fs::remove_dir_all(f.main.parent().unwrap());
}

#[test]
fn without_the_option_nothing_is_overwritten_and_a_recovery_keeps_the_choice() {
    // the old file is only removed
    let f = fixture();
    let m = swapped(&f, false);
    assert_eq!(std::fs::read(f.main.join(format!("d.cldb{OLD_SUFFIX}"))).unwrap(), b"old main");
    m.finish().unwrap();
    let _ = std::fs::remove_dir_all(f.main.parent().unwrap());

    // the choice is in the marker: a recovery after a crash overwrites too. Watch the old file
    // through a hard link: it is the same data, and it stays after the name is removed.
    let f = fixture();
    let places = Places { main: &f.main, backup: &f.backup };
    {
        let m = swapped(&f, true);
        let _ = &m;
    }
    let watch = f.main.join("watch");
    std::fs::hard_link(f.main.join(format!("d.cldb{OLD_SUFFIX}")), &watch).unwrap();
    assert_eq!(Migration::recover(places, "d").unwrap(), Recovery::RolledForward);
    assert!(!f.main.join(format!("d.cldb{OLD_SUFFIX}")).exists());
    let seen = std::fs::read(&watch).unwrap();
    assert_eq!(seen.len(), b"old main".len());
    assert_ne!(seen, b"old main", "the recovery removed the file without overwriting it");
    let _ = std::fs::remove_dir_all(f.main.parent().unwrap());
}

#[test]
fn a_rollback_never_overwrites_the_old_files() {
    let f = fixture();
    let m = swapped(&f, true);
    m.roll_back().unwrap();
    assert_eq!(state(&f), old_state());
    let _ = std::fs::remove_dir_all(f.main.parent().unwrap());
}

#[test]
fn the_space_needed_is_counted_per_folder_and_grows_with_a_kept_copy() {
    use super::space::{Available, Required, check, required, size_of};
    let f = fixture();
    std::fs::write(f.main.join("big"), vec![0u8; 1_000_000]).unwrap();
    std::fs::create_dir_all(f.main.join("dir")).unwrap();
    std::fs::write(f.main.join("dir").join("a"), vec![0u8; 500_000]).unwrap();
    assert_eq!(size_of(&f.main.join("dir")), 500_000);
    assert_eq!(size_of(&f.main.join("missing")), 0);
    let places = Places { main: &f.main, backup: &f.backup };
    let files = [(Root::Main, "big"), (Root::Main, "dir"), (Root::Backup, "d.cldb.bak")];
    let plain = required(places, &files, false);
    let kept = required(places, &files, true);
    // each item: its size, 2%, and 8 KiB; the backup folder is counted apart
    assert_eq!(plain.main, (1_000_000 + 1_000_000 / 50 + 8192) + (500_000 + 500_000 / 50 + 8192));
    assert!(plain.backup.is_some_and(|b| b > 0));
    assert_eq!(kept.main, plain.main * 2);
    // the same folder twice: one number
    let same = Places { main: &f.main, backup: &f.main };
    assert_eq!(required(same, &files, false).backup, None);
    // the check
    assert!(check(plain, Available::default()).is_ok(), "nothing said, nothing checked");
    assert!(check(plain, Available { main: Some(plain.main), backup: plain.backup }).is_ok());
    let short = check(plain, Available { main: Some(plain.main - 1), backup: None });
    assert!(short.is_err());
    assert!(check(plain, Available { main: None, backup: Some(0) }).is_err());
    let _ = Required::default();
    let _ = std::fs::remove_dir_all(f.main.parent().unwrap());
}
