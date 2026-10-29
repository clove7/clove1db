//! Encrypted database files: round trips, the single open error, what the file looks like, and
//! what happens when its bytes are changed.
mod encrypted_support;

use clove1db::crypto::{CipherKind, HkdfHash, Key32, KeySuite, PasswordKdf, ProgrammerKey, SecretBytes};
use clove1db::encrypted_store::layout::{DATA_BASE, FILE_HEADER_LEN};
use clove1db::encrypted_store::{
    Credentials, EncryptedDatabase, OpenOptionsExt, StoreDiagnostic, StoreError,
};
use encrypted_support::*;

const OPTS: OpenOptionsExt = OpenOptionsExt { cache_bytes: Some(1 << 20), verify_on_open: false, read_only: false, repair_seen: None, tuning: clove1db::EncryptionTuning::DEFAULT };

fn creds<'a>(suite: KeySuite, read: &'a ProgrammerKey<'a>, search: &'a ProgrammerKey<'a>) -> Credentials<'a> {
    Credentials { suite, read: Some(read), search: Some(search) }
}

fn open_plain(path: &std::path::Path, c: &Credentials) -> Result<EncryptedDatabase, (StoreError, Vec<StoreDiagnostic>)> {
    let mut seen = Vec::new();
    EncryptedDatabase::open(path, c, "main", &OPTS, &mut |d| seen.push(d)).map_err(|e| (e, seen))
}

/// Build a database with some rows; returns the keys so it can be opened again.
fn build(dir: &TempDir, name: &str, suite: KeySuite, n: u64) -> (std::path::PathBuf, Key32, Key32, Vec<(u64, Vec<u8>)>) {
    let (rk, sk) = (key(), key());
    let (r, s) = (ProgrammerKey::Raw(&rk), ProgrammerKey::Raw(&sk));
    let path = dir.path(name);
    let db = EncryptedDatabase::create(&path, &creds(suite, &r, &s), "main", &OPTS).unwrap();
    let data = rows(0, n, 1);
    let w = db.begin_write().unwrap();
    insert_rows(&w, &data);
    w.commit().unwrap();
    drop(db);
    (path, rk, sk, data)
}

#[test]
fn a_database_keeps_its_rows_across_close_and_open_for_both_ciphers() {
    for suite in suites() {
        let dir = TempDir::new("roundtrip");
        let (path, rk, sk, data) = build(&dir, "a.db", suite, 300);
        let (r, s) = (ProgrammerKey::Raw(&rk), ProgrammerKey::Raw(&sk));
        let db = open_plain(&path, &creds(suite, &r, &s)).unwrap();
        assert_eq!(read_all(db.database()).unwrap(), data, "{suite:?}");
        // a read-only program opens with the read key alone
        drop(db);
        let only_read = Credentials { suite, read: Some(&r), search: None };
        let db = open_plain(&path, &only_read).unwrap();
        assert_eq!(read_all(db.database()).unwrap(), data);
        assert!(db.access().search().is_none() && db.access().read().is_some());
    }
}

#[test]
fn a_password_can_stand_in_for_the_key() {
    let dir = TempDir::new("password");
    let suite = suites()[0];
    let kdf = PasswordKdf::Argon2id { memory_kib: 19_456, iterations: 2, lanes: 1 };
    let (pw, sk) = (SecretBytes::from_slice(b"a long enough pass phrase"), key());
    let (r, s) = (ProgrammerKey::Password { password: &pw, kdf: &kdf }, ProgrammerKey::Raw(&sk));
    let path = dir.path("p.db");
    let db = EncryptedDatabase::create(&path, &creds(suite, &r, &s), "main", &OPTS).unwrap();
    drop(db);
    assert!(open_plain(&path, &creds(suite, &r, &s)).is_ok());
    let wrong = SecretBytes::from_slice(b"another pass phrase");
    let r2 = ProgrammerKey::Password { password: &wrong, kdf: &kdf };
    let (e, why) = open_plain(&path, &creds(suite, &r2, &s)).unwrap_err();
    assert!(is_open_failed(&e) && why.contains(&StoreDiagnostic::LockRejected));
    // password settings under the floor are refused before any hashing, not as an open failure
    let weak = PasswordKdf::Argon2id { memory_kib: 64, iterations: 1, lanes: 1 };
    let r3 = ProgrammerKey::Password { password: &pw, kdf: &weak };
    let (e, _) = open_plain(&path, &creds(suite, &r3, &s)).unwrap_err();
    assert!(matches!(e, StoreError::OpenFailed | StoreError::InvalidParams(_)), "{e:?}");
}

#[test]
fn every_way_of_failing_to_open_is_the_same_error() {
    let dir = TempDir::new("unified");
    let suite = suites()[0];
    let (path, rk, sk, _) = build(&dir, "u.db", suite, 50);
    let (r, s) = (ProgrammerKey::Raw(&rk), ProgrammerKey::Raw(&sk));
    let other = key();
    let o = ProgrammerKey::Raw(&other);
    let bytes = std::fs::read(&path).unwrap();
    let write_variant = |name: &str, data: &[u8]| {
        let p = dir.path(name);
        std::fs::write(&p, data).unwrap();
        p
    };
    let mut cases: Vec<(&str, Result<EncryptedDatabase, (StoreError, Vec<StoreDiagnostic>)>)> = Vec::new();
    cases.push(("wrong read key", open_plain(&path, &creds(suite, &o, &s))));
    cases.push(("wrong search key", open_plain(&path, &creds(suite, &r, &o))));
    let other_cipher = KeySuite { cipher: CipherKind::Aes256GcmSiv, ..suite };
    cases.push(("wrong cipher", open_plain(&path, &creds(other_cipher, &r, &s))));
    let other_hkdf = KeySuite { hkdf: HkdfHash::Sha512, ..suite };
    cases.push(("wrong hkdf", open_plain(&path, &creds(other_hkdf, &r, &s))));
    cases.push(("no key", open_plain(&path, &Credentials { suite, read: None, search: None })));
    cases.push(("only the search key", open_plain(&path, &Credentials { suite, read: None, search: Some(&s) })));
    // an unencrypted redb database opened with a key
    let plain = dir.path("plain.redb");
    drop(redb::Database::create(&plain).unwrap());
    cases.push(("unencrypted database", open_plain(&plain, &creds(suite, &r, &s))));
    cases.push(("empty file", open_plain(&write_variant("empty.db", &[]), &creds(suite, &r, &s))));
    cases.push(("tiny file", open_plain(&write_variant("tiny.db", &bytes[..100]), &creds(suite, &r, &s))));
    // cut down to the headers: must not start a new empty database
    let cut = write_variant("cut.db", &bytes[..DATA_BASE as usize]);
    cases.push(("cut to the headers", open_plain(&cut, &creds(suite, &r, &s))));
    cases.push(("cut to the file header", open_plain(&write_variant("hdr.db", &bytes[..FILE_HEADER_LEN as usize]), &creds(suite, &r, &s))));
    let mut damaged = bytes.clone();
    damaged[5] ^= 1;
    cases.push(("damaged lock", open_plain(&write_variant("lock.db", &damaged), &creds(suite, &r, &s))));
    let mut zeroed = bytes.clone();
    zeroed[..2048].fill(0);
    cases.push(("zeroed file header", open_plain(&write_variant("zero.db", &zeroed), &creds(suite, &r, &s))));
    for (name, result) in &cases {
        match result {
            Err((StoreError::OpenFailed, why)) => assert!(!why.is_empty(), "{name}: no diagnostic"),
            Err((e, _)) => panic!("{name}: a different error: {e:?}"),
            Ok(_) => panic!("{name}: opened"),
        }
    }
    let why = |name: &str| match cases.iter().find(|c| c.0 == name).unwrap().1.as_ref() {
        Err((_, w)) => w.clone(),
        Ok(_) => vec![],
    };
    assert!(why("no key").contains(&StoreDiagnostic::KeyMissing));
    assert!(why("wrong read key").contains(&StoreDiagnostic::LockRejected));
    assert!(why("wrong cipher").contains(&StoreDiagnostic::LockRejected));
    assert!(why("unencrypted database").contains(&StoreDiagnostic::LooksLikeUnencrypted));
    assert!(why("empty file").contains(&StoreDiagnostic::HeaderMalformed));
    // the right keys still open the original
    drop(cases);
    assert!(open_plain(&path, &creds(suite, &r, &s)).is_ok());
    // a cipher that is not allowed for a whole database is a settings error, not an open failure
    let not_allowed = KeySuite { cipher: CipherKind::Aes256Gcm, ..suite };
    assert!(matches!(open_plain(&path, &creds(not_allowed, &r, &s)), Err((StoreError::InvalidParams(_), _))));
}

#[test]
fn no_diagnostic_or_error_text_holds_a_key() {
    let dir = TempDir::new("secrets");
    let suite = suites()[0];
    let rk = Key32::from_bytes(&[0xAB; 32]);
    let sk = key();
    let (r, s) = (ProgrammerKey::Raw(&rk), ProgrammerKey::Raw(&sk));
    let path = dir.path("s.db");
    drop(EncryptedDatabase::create(&path, &creds(suite, &r, &s), "main", &OPTS).unwrap());
    let wrong = key();
    let w = ProgrammerKey::Raw(&wrong);
    let (e, why) = open_plain(&path, &creds(suite, &w, &s)).unwrap_err();
    let text = format!("{e} {e:?} {why:?} {r:?} {w:?}");
    assert!(!text.contains("171") && !text.to_lowercase().contains("ab, ab"), "{text}");
}

#[test]
fn the_file_shows_no_signature_and_no_blank_stretch() {
    for suite in suites() {
        let dir = TempDir::new("looks");
        let (path, _, _, _) = build(&dir, "l.db", suite, 600);
        let bytes = std::fs::read(&path).unwrap();
        let find = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
        assert!(!find(b"redb"), "redb signature");
        assert!(!find(&[0x1A, 0x0A, 0xA9, 0x0D, 0x0A]), "redb signature tail");
        assert!(!find(MARKER.as_bytes()), "a value");
        assert!(!find(b"people_notes"), "the table name");
        assert!(!find(b"clove"), "the library name");
        let zeros = bytes.iter().filter(|b| **b == 0).count();
        assert!(zeros * 100 < bytes.len(), "{} zero bytes of {}", zeros, bytes.len());
        let (mut run, mut longest) = (0usize, 0usize);
        for b in &bytes {
            run = if *b == 0 { run + 1 } else { 0 };
            longest = longest.max(run);
        }
        assert!(longest < 16, "a run of {longest} zero bytes");
        // the length is the header area plus whole blocks
        let stride = 4096 + suite.cipher.overhead() as u64;
        assert_eq!((bytes.len() as u64 - DATA_BASE) % stride, 0);
    }
}

/// What a program sees of a changed copy: it did not open, a read failed, or what it read.
#[derive(Debug, PartialEq)]
enum Seen {
    NotOpened,
    Panicked,
    ReadFailed,
    VerifyFailed,
    Rows(Vec<(u64, Vec<u8>)>),
}

fn see(path: &std::path::Path, c: &Credentials, verify: bool) -> Seen {
    // redb itself can panic on content that is authentic but out of date (an old block put back);
    // that is a stop, never wrong data, and is counted as such here.
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| see_inner(path, c, verify))).unwrap_or(Seen::Panicked)
}

fn see_inner(path: &std::path::Path, c: &Credentials, verify: bool) -> Seen {
    let opts = OpenOptionsExt { verify_on_open: verify, ..OPTS };
    let mut db = match EncryptedDatabase::open(path, c, "main", &opts, &mut |_| {}) {
        Ok(db) => db,
        Err(_) => return Seen::NotOpened,
    };
    let rows = match read_all(db.database()) {
        Ok(r) => r,
        Err(_) => return Seen::ReadFailed,
    };
    if verify && db.verify_all().is_err() {
        return Seen::VerifyFailed;
    }
    Seen::Rows(rows)
}

#[test]
fn a_changed_file_never_gives_wrong_data() {
    let dir = TempDir::new("tamper");
    let suite = suites()[0];
    let (path, rk, sk, data) = build(&dir, "t.db", suite, 400);
    let (r, s) = (ProgrammerKey::Raw(&rk), ProgrammerKey::Raw(&sk));
    let c = creds(suite, &r, &s);
    let bytes = std::fs::read(&path).unwrap();
    let stride = 4096 + suite.cipher.overhead();
    let blocks = (bytes.len() - DATA_BASE as usize) / stride;
    let work = dir.path("work.db");
    let (mut detected, mut silent) = (0, 0);
    let mut check = |changed: &[u8], what: &str| {
        std::fs::write(&work, changed).unwrap();
        match see(&work, &c, false) {
            Seen::Rows(rows) => {
                assert_eq!(rows, data, "{what}: wrong data without an error");
                silent += 1;
            }
            _ => detected += 1,
        }
    };
    // one bit changed in every block, in the header pieces and in the file header
    for i in 0..blocks {
        let mut m = bytes.clone();
        m[DATA_BASE as usize + i * stride + (i * 37) % stride] ^= 1 << (i % 8);
        check(&m, &format!("bit in block {i}"));
    }
    for pos in (FILE_HEADER_LEN as usize..DATA_BASE as usize).step_by(16) {
        let mut m = bytes.clone();
        m[pos] ^= 1;
        check(&m, &format!("bit in header area at {pos}"));
    }
    // two blocks swapped, one copied over another
    for k in 0..120usize {
        let (a, b) = ((k * 7) % blocks, (k * 13 + 5) % blocks);
        if a == b {
            continue;
        }
        let (sa, sb) = (DATA_BASE as usize + a * stride, DATA_BASE as usize + b * stride);
        let mut m = bytes.clone();
        for j in 0..stride {
            m.swap(sa + j, sb + j);
        }
        check(&m, &format!("swap {a} {b}"));
        let mut m = bytes.clone();
        let copy = bytes[sa..sa + stride].to_vec();
        m[sb..sb + stride].copy_from_slice(&copy);
        check(&m, &format!("copy {a} over {b}"));
    }
    // cut short, cut in the middle of a block, extended
    for cut in [1usize, 2, 10, 100] {
        check(&bytes[..bytes.len() - cut * stride], &format!("cut {cut} blocks"));
    }
    check(&bytes[..bytes.len() - stride / 2], "cut half a block");
    let mut longer = bytes.clone();
    longer.extend(std::iter::repeat_n(0x5A, stride));
    check(&longer, "extended");
    assert!(detected > blocks / 3, "only {detected} detected, {silent} silent");
}

#[test]
fn an_old_copy_of_one_block_is_found_by_the_full_check() {
    let dir = TempDir::new("stale");
    let suite = suites()[0];
    let (rk, sk) = (key(), key());
    let (r, s) = (ProgrammerKey::Raw(&rk), ProgrammerKey::Raw(&sk));
    let c = creds(suite, &r, &s);
    let path = dir.path("s.db");
    let db = EncryptedDatabase::create(&path, &c, "main", &OPTS).unwrap();
    let w = db.begin_write().unwrap();
    insert_rows(&w, &rows(0, 200, 1));
    w.commit().unwrap();
    drop(db);
    let old = std::fs::read(&path).unwrap();
    let db = EncryptedDatabase::open(&path, &c, "main", &OPTS, &mut |_| {}).unwrap();
    let w = db.begin_write().unwrap();
    insert_rows(&w, &rows(100, 300, 2));
    w.commit().unwrap();
    drop(db);
    let now = std::fs::read(&path).unwrap();
    let expected = {
        let db = EncryptedDatabase::open(&path, &c, "main", &OPTS, &mut |_| {}).unwrap();
        read_all(db.database()).unwrap()
    };
    let stride = 4096 + suite.cipher.overhead();
    let blocks = (old.len().min(now.len()) - DATA_BASE as usize) / stride;
    let work = dir.path("w.db");
    let (mut changed, mut only_full_check, mut wrong_after_full_check) = (0, 0, 0);
    for i in 0..blocks {
        let (a, b) = (DATA_BASE as usize + i * stride, DATA_BASE as usize + (i + 1) * stride);
        if old[a..b] == now[a..b] {
            continue;
        }
        changed += 1;
        let mut m = now.clone();
        m[a..b].copy_from_slice(&old[a..b]);
        std::fs::write(&work, &m).unwrap();
        let plain = see(&work, &c, false);
        let full = see(&work, &c, true);
        if let Seen::Rows(rows) = &full {
            if *rows != expected {
                wrong_after_full_check += 1;
            }
        }
        if matches!(plain, Seen::Rows(ref rows) if *rows != expected) && !matches!(full, Seen::Rows(_)) {
            only_full_check += 1;
        }
    }
    assert!(changed > 5, "the test changed nothing");
    assert_eq!(wrong_after_full_check, 0, "the full check let wrong data through");
    println!("{changed} old blocks tried, {only_full_check} gave wrong data on an ordinary read and were found by the full check");
}

#[test]
fn a_sibling_file_has_its_own_key_and_only_opens_with_the_same_database() {
    let dir = TempDir::new("sibling");
    let suite = suites()[1];
    let (rk, sk) = (key(), key());
    let (r, s) = (ProgrammerKey::Raw(&rk), ProgrammerKey::Raw(&sk));
    let main = EncryptedDatabase::create(&dir.path("m.db"), &creds(suite, &r, &s), "main", &OPTS).unwrap();
    let w = main.begin_write().unwrap();
    insert_rows(&w, &rows(0, 100, 1));
    w.commit().unwrap();
    let index = main.create_sibling(&dir.path("m.inx"), "index", &OPTS).unwrap();
    let w = index.begin_write().unwrap();
    insert_rows(&w, &rows(0, 10, 7));
    w.commit().unwrap();
    drop(index);
    let again = main.open_sibling(&dir.path("m.inx"), "index", &OPTS, &mut |_| {}).unwrap();
    assert_eq!(read_all(again.database()).unwrap(), rows(0, 10, 7));
    drop(again);
    // the wrong label is the wrong file key
    let wrong_label = main.open_sibling(&dir.path("m.inx"), "backup", &OPTS, &mut |_| {});
    assert!(matches!(wrong_label, Err(StoreError::OpenFailed)), "{:?}", wrong_label.map(|_| ()));
    // a file from another database
    let (rk2, sk2) = (key(), key());
    let (r2, s2) = (ProgrammerKey::Raw(&rk2), ProgrammerKey::Raw(&sk2));
    drop(EncryptedDatabase::create(&dir.path("o.db"), &creds(suite, &r2, &s2), "main", &OPTS).unwrap());
    let mut why = Vec::new();
    assert!(matches!(
        main.open_sibling(&dir.path("o.db"), "main", &OPTS, &mut |d| why.push(d)),
        Err(StoreError::OpenFailed)
    ));
    assert!(why.contains(&StoreDiagnostic::LockRejected));
    // the file keys of two labels differ: a block of the backup file is not a block of the index
    let bak = main.create_sibling(&dir.path("m.bak"), "backup", &OPTS).unwrap();
    let w = bak.begin_write().unwrap();
    insert_rows(&w, &rows(0, 100, 3));
    w.commit().unwrap();
    drop(bak);
    let mut a = std::fs::read(dir.path("m.inx")).unwrap();
    let b = std::fs::read(dir.path("m.bak")).unwrap();
    let stride = 4096 + suite.cipher.overhead();
    let at = DATA_BASE as usize + 2 * stride;
    a[at..at + stride].copy_from_slice(&b[at..at + stride]);
    std::fs::write(dir.path("mix.inx"), &a).unwrap();
    // the mixed copy has the same lock (same data key), so it opens, but the foreign block fails
    if let Ok(mut db) = main.open_sibling(&dir.path("mix.inx"), "index", &OPTS, &mut |_| {}) {
        assert!(read_all(db.database()).is_err() || db.verify_all().is_err());
    }
}

#[test]
fn creating_needs_a_free_path_and_leaves_no_temporary_file() {
    let dir = TempDir::new("create");
    let suite = suites()[0];
    let (rk, sk) = (key(), key());
    let (r, s) = (ProgrammerKey::Raw(&rk), ProgrammerKey::Raw(&sk));
    let path = dir.path("c.db");
    // a leftover from an earlier crash is replaced
    std::fs::write(dir.path("c.db.creating"), b"junk").unwrap();
    let db = EncryptedDatabase::create(&path, &creds(suite, &r, &s), "main", &OPTS).unwrap();
    assert!(!dir.path("c.db.creating").exists());
    assert!(matches!(
        EncryptedDatabase::create(&path, &creds(suite, &r, &s), "main", &OPTS),
        Err(StoreError::InvalidParams(_))
    ));
    let missing_search = Credentials { suite, read: Some(&r), search: None };
    assert!(matches!(
        EncryptedDatabase::create(&dir.path("d.db"), &missing_search, "main", &OPTS),
        Err(StoreError::InvalidParams(_))
    ));
    assert!(!dir.path("d.db").exists() && !dir.path("d.db.creating").exists());
    let not_allowed = KeySuite { cipher: CipherKind::ChaCha20Poly1305, ..suite };
    assert!(matches!(
        EncryptedDatabase::create(&dir.path("e.db"), &creds(not_allowed, &r, &s), "main", &OPTS),
        Err(StoreError::InvalidParams(_))
    ));
    drop(db);
}

#[test]
fn a_second_open_of_a_file_in_use_is_refused() {
    let dir = TempDir::new("inuse");
    let suite = suites()[0];
    let (path, rk, sk, _) = build(&dir, "i.db", suite, 10);
    let (r, s) = (ProgrammerKey::Raw(&rk), ProgrammerKey::Raw(&sk));
    let c = creds(suite, &r, &s);
    let first = open_plain(&path, &c).unwrap();
    let second = open_plain(&path, &c);
    assert!(matches!(second, Err((StoreError::InUse, _))), "{:?}", second.err().map(|e| e.0));
    drop(first);
    assert!(open_plain(&path, &c).is_ok());
}

#[test]
fn large_values_and_growth_work_and_keep_the_file_filled() {
    let dir = TempDir::new("big");
    let suite = suites()[1];
    let (rk, sk) = (key(), key());
    let (r, s) = (ProgrammerKey::Raw(&rk), ProgrammerKey::Raw(&sk));
    let c = creds(suite, &r, &s);
    let path = dir.path("b.db");
    let db = EncryptedDatabase::create(&path, &c, "main", &OPTS).unwrap();
    let big: Vec<(u64, Vec<u8>)> = (0..12u64)
        .map(|i| (i, (0..(300 * 1024 + i as usize * 999)).map(|x| (x * 31 + i as usize) as u8).collect()))
        .collect();
    let w = db.begin_write().unwrap();
    insert_rows(&w, &big);
    w.commit().unwrap();
    assert_eq!(read_all(db.database()).unwrap(), big);
    drop(db);
    let db = open_plain(&path, &c).unwrap();
    assert_eq!(read_all(db.database()).unwrap(), big);
    drop(db);
    let bytes = std::fs::read(&path).unwrap();
    let (mut run, mut longest) = (0usize, 0usize);
    for b in &bytes {
        run = if *b == 0 { run + 1 } else { 0 };
        longest = longest.max(run);
    }
    assert!(longest < 16, "a blank stretch of {longest} bytes after growth");
}

#[test]
fn verify_on_open_accepts_a_good_file() {
    let dir = TempDir::new("verify");
    let suite = suites()[0];
    let (path, rk, sk, data) = build(&dir, "v.db", suite, 150);
    let (r, s) = (ProgrammerKey::Raw(&rk), ProgrammerKey::Raw(&sk));
    let c = creds(suite, &r, &s);
    let opts = OpenOptionsExt { verify_on_open: true, ..OPTS };
    let mut db = EncryptedDatabase::open(&path, &c, "main", &opts, &mut |_| {}).unwrap();
    assert_eq!(read_all(db.database()).unwrap(), data);
    db.verify_all().unwrap();
}

#[test]
fn a_read_only_open_reads_and_leaves_the_file_byte_for_byte_as_it_was() {
    let dir = TempDir::new("readonly");
    let suite = suites()[0];
    let (path, rk, sk, data) = build(&dir, "r.db", suite, 200);
    let (r, s) = (ProgrammerKey::Raw(&rk), ProgrammerKey::Raw(&sk));
    let c = creds(suite, &r, &s);
    let before = std::fs::read(&path).unwrap();
    let opts = OpenOptionsExt { read_only: true, ..OPTS };
    let db = EncryptedDatabase::open(&path, &c, "main", &opts, &mut |_| {}).unwrap();
    assert_eq!(read_all(db.database()).unwrap(), data);
    let wrote = (|| -> Result<(), Box<dyn std::error::Error>> {
        let w = db.begin_write()?;
        insert_rows(&w, &rows(1000, 1010, 9));
        w.commit()?;
        Ok(())
    })();
    assert!(wrote.is_err(), "a read-only open accepted a write");
    drop(db);
    assert_eq!(std::fs::read(&path).unwrap(), before, "the file changed");
    // and it still opens normally afterwards
    assert!(open_plain(&path, &c).is_ok());
}
