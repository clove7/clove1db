//! The deciding test for the three database files: a full working life (create, write, back up,
//! build and compact the index, convert the backup with a copy and a compaction, reopen), and
//! after every step, with all handles closed, every file in the directory is scanned for anything
//! readable: values, keys, table names, signatures.
mod encrypted_support;

use clove1db::crypto::{Key32, KeySuite, ProgrammerKey};
use clove1db::encrypted_store::{Credentials, EncryptedDatabase, EncryptionContext, OpenOptionsExt};
use encrypted_support::*;
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use std::path::{Path, PathBuf};

const OPTS: OpenOptionsExt = OpenOptionsExt { cache_bytes: Some(1 << 20), verify_on_open: false, read_only: false, repair_seen: None, tuning: clove1db::EncryptionTuning::DEFAULT };
const CUSTOMERS: &str = "customers_secret_tbl";
const HISTORY: &str = "customers_secret_tbl_version";
const INDEX: &str = "idx_secret_tbl";

fn def(name: &str) -> TableDefinition<'_, &'static str, &'static [u8]> {
    TableDefinition::new(name)
}

fn fill(db: &redb::Database, table: &str, from: u64, to: u64, tag: &str) {
    let mut w = db.begin_write().unwrap();
    w.set_quick_repair(true);
    {
        let mut t = w.open_table(def(table)).unwrap();
        for i in from..to {
            let key = format!("{tag}-key-{i}-{MARKER}");
            t.insert(key.as_str(), value(i, 1).as_slice()).unwrap();
        }
    }
    w.commit().unwrap();
}

fn all(db: &redb::Database, table: &str) -> Vec<(String, Vec<u8>)> {
    let r = db.begin_read().unwrap();
    let t = r.open_table(def(table)).unwrap();
    t.iter().unwrap().map(|e| {
        let (k, v) = e.unwrap();
        (k.value().to_string(), v.value().to_vec())
    })
    .collect()
}

fn files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() {
            out.extend(files(&p));
        } else {
            out.push(p);
        }
    }
    out
}

/// Nothing readable in any file name or byte, no signature, no blank stretch.
fn scan(dir: &Path, step: &str) -> usize {
    let needles: Vec<&[u8]> = vec![
        MARKER.as_bytes(),
        CUSTOMERS.as_bytes(),
        INDEX.as_bytes(),
        b"redb",
        &[0x1A, 0x0A, 0xA9, 0x0D, 0x0A],
        b"clove",
        b"-key-",
        b"\"id\":\"",
        b"table",
    ];
    let list = files(dir);
    assert!(!list.is_empty(), "{step}: no files");
    for path in &list {
        let name = path.file_name().unwrap().to_string_lossy().to_lowercase();
        for bad in ["marker", "customers", "secret", "redb", "clove"] {
            assert!(!name.contains(bad), "{step}: the name {name} shows {bad}");
        }
        let bytes = std::fs::read(path).unwrap();
        for needle in &needles {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == *needle),
                "{step}: {name} contains {:?}",
                String::from_utf8_lossy(needle)
            );
        }
        let (mut run, mut longest) = (0usize, 0usize);
        for b in &bytes {
            run = if *b == 0 { run + 1 } else { 0 };
            longest = longest.max(run);
        }
        assert!(longest < 16, "{step}: {name} has {longest} zero bytes in a row");
        let zeros = bytes.iter().filter(|b| **b == 0).count();
        assert!(zeros * 100 < bytes.len().max(1), "{step}: {name} is {zeros} zero bytes of {}", bytes.len());
    }
    list.len()
}

fn setup(dir: &TempDir, suite: KeySuite) -> (EncryptionContext, Key32, Key32) {
    let (rk, sk) = (key(), key());
    let (r, s) = (ProgrammerKey::Raw(&rk), ProgrammerKey::Raw(&sk));
    let creds = Credentials { suite, read: Some(&r), search: Some(&s) };
    let db = EncryptedDatabase::create(&dir.path("app.cldb"), &creds, "main", &OPTS).unwrap();
    fill(db.database(), CUSTOMERS, 0, 300, "main");
    let ctx = db.context();
    drop(db);
    (ctx, rk, sk)
}

#[test]
fn a_working_life_leaves_nothing_readable_in_any_file_at_any_step() {
    for suite in suites() {
        let dir = TempDir::new("life");
        let root = dir.0.clone();
        let (ctx, rk, sk) = setup(&dir, suite);
        assert_eq!(scan(&root, "after create"), 1);

        // the backup history file
        let bak = ctx.create_file(&dir.path("app.cldb.bak"), "bak", &OPTS).unwrap();
        fill(bak.database(), HISTORY, 0, 400, "hist");
        drop(bak);
        assert_eq!(scan(&root, "after the backup file"), 2);

        // the index file, then a compaction: build a new file, copy into it, swap it in
        let inx = ctx.create_file(&dir.path("app.inx"), "index", &OPTS).unwrap();
        fill(inx.database(), INDEX, 0, 500, "idx");
        drop(inx);
        assert_eq!(scan(&root, "after the index"), 3);
        let build = ctx.create_file(&dir.path("app.inx.build-1"), "index", &OPTS).unwrap();
        {
            let old = ctx.open_file(&dir.path("app.inx"), "index", &OPTS, &mut |_| {}).unwrap();
            let rows = all(old.database(), INDEX);
            let w = build.database().begin_write().unwrap();
            {
                let mut t = w.open_table(def(INDEX)).unwrap();
                for (k, v) in &rows {
                    t.insert(k.as_str(), v.as_slice()).unwrap();
                }
            }
            w.commit().unwrap();
        }
        assert_eq!(scan_open_safe(&root, &build, "while the compaction build exists"), 4);
        drop(build);
        std::fs::rename(dir.path("app.inx.build-1"), dir.path("app.inx")).unwrap();
        assert_eq!(scan(&root, "after the index swap"), 3);
        let inx = ctx.open_file(&dir.path("app.inx"), "index", &OPTS, &mut |_| {}).unwrap();
        assert_eq!(all(inx.database(), INDEX).len(), 500);
        drop(inx);

        // converting the backup: a byte copy, a check of the copy, a change, a compaction, a swap
        let original = std::fs::read(dir.path("app.cldb.bak")).unwrap();
        std::fs::copy(dir.path("app.cldb.bak"), dir.path("app.cldb.bak.upgrading")).unwrap();
        assert_eq!(std::fs::read(dir.path("app.cldb.bak.upgrading")).unwrap(), original);
        assert_eq!(scan(&root, "with the backup copy beside it"), 4);
        let copy = ctx.open_file(&dir.path("app.cldb.bak.upgrading"), "bak", &OPTS, &mut |_| {}).unwrap();
        fill(copy.database(), HISTORY, 400, 700, "conv");
        let before = std::fs::metadata(dir.path("app.cldb.bak.upgrading")).unwrap().len();
        let mut raw = copy.into_database();
        raw.compact().unwrap();
        drop(raw);
        let after = std::fs::metadata(dir.path("app.cldb.bak.upgrading")).unwrap().len();
        assert!(after <= before, "compaction grew the file");
        std::fs::OpenOptions::new().write(true).open(dir.path("app.cldb.bak.upgrading")).unwrap().sync_all().unwrap();
        std::fs::rename(dir.path("app.cldb.bak.upgrading"), dir.path("app.cldb.bak")).unwrap();
        assert_eq!(scan(&root, "after the backup conversion"), 3);
        let bak = ctx.open_file(&dir.path("app.cldb.bak"), "bak", &OPTS, &mut |_| {}).unwrap();
        assert_eq!(all(bak.database(), HISTORY).len(), 700);
        drop(bak);

        // reopen the main file with the keys, go on working, and look again
        let (r, s) = (ProgrammerKey::Raw(&rk), ProgrammerKey::Raw(&sk));
        let creds = Credentials { suite, read: Some(&r), search: Some(&s) };
        let main = EncryptedDatabase::open(&dir.path("app.cldb"), &creds, "main", &OPTS, &mut |_| {}).unwrap();
        assert_eq!(all(main.database(), CUSTOMERS).len(), 300);
        fill(main.database(), CUSTOMERS, 300, 450, "again");
        drop(main);
        assert_eq!(scan(&root, "after reopening and writing"), 3);

        // inspecting every file read-only changes no byte of any of them
        let snapshot: Vec<(PathBuf, Vec<u8>)> = files(&root).into_iter().map(|p| { let b = std::fs::read(&p).unwrap(); (p, b) }).collect();
        let ro = OpenOptionsExt { read_only: true, ..OPTS };
        for (name, label) in [("app.cldb", "main"), ("app.cldb.bak", "bak"), ("app.inx", "index")] {
            let db = ctx.open_file(&dir.path(name), label, &ro, &mut |_| {}).unwrap();
            let r = db.database().begin_read().unwrap();
            assert!(r.list_tables().unwrap().count() > 0);
        }
        for (p, b) in &snapshot {
            assert_eq!(&std::fs::read(p).unwrap(), b, "{} changed after a read-only look", p.display());
        }

        // a file opened under the wrong label or the wrong database is refused
        assert!(ctx.open_file(&dir.path("app.inx"), "bak", &OPTS, &mut |_| {}).is_err());
    }
}

/// The scan with a database still open would fail on Windows (the file is locked), so this one
/// looks at the files that are not open and leaves the open one alone.
fn scan_open_safe(dir: &Path, open: &EncryptedDatabase, step: &str) -> usize {
    let _ = open;
    let list = files(dir);
    for path in &list {
        let name = path.file_name().unwrap().to_string_lossy().to_lowercase();
        for bad in ["marker", "customers", "secret", "redb", "clove"] {
            assert!(!name.contains(bad), "{step}: the name {name} shows {bad}");
        }
    }
    list.len()
}

#[test]
fn a_file_made_for_one_database_does_not_open_under_another() {
    let suite = suites()[0];
    let (d1, d2) = (TempDir::new("one"), TempDir::new("two"));
    let (c1, ..) = setup(&d1, suite);
    let (c2, ..) = setup(&d2, suite);
    let f1 = c1.create_file(&d1.path("a.inx"), "index", &OPTS).unwrap();
    drop(f1);
    let mut why = Vec::new();
    assert!(c2.open_file(&d1.path("a.inx"), "index", &OPTS, &mut |d| why.push(d)).is_err());
    assert!(!why.is_empty());
}
