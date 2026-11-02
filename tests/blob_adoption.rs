//! Attachment files written by an older version (`write_blob`: a file named by its key, no row and no reference)
//! stay and open when the database is opened by this version; they are adopted once per attachment table.
//! `tests/fixtures/db126` is a small database really written by clove1db 0.0.126: twelve files in three
//! attachment tables (`att`: six files with no row, keys with spaces, a dot, Arabic letters and a name that ends in `.tmp`; `docs`: two
//! files with rows and one without; `later`: three files with no row).
use clove1db::{
    entity::Entity,
    storage::{DatabaseConfig, Storage, StorageConfig},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

macro_rules! row {
    ($n:ident) => {
        #[derive(Clone, Default, Serialize, Deserialize)]
        struct $n {
            id: String,
            name: String,
        }
        impl Entity for $n {
            fn entity_id(&self) -> &str {
                &self.id
            }
        }
    };
}
row!(Att);
row!(Doc);
row!(Later);

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/db126");

/// The bytes the fixture's files hold.
fn bytes(seed: u8, n: usize) -> Vec<u8> {
    (0..n).map(|k| (k as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

/// (table, key, bytes) of every file the fixture holds.
fn old_files() -> Vec<(&'static str, &'static str, Vec<u8>)> {
    let mut out = Vec::new();
    for (i, key) in ["plain", "with space", "dot.name.txt", "ملف عربي", "a b.c d", "report.tmp"].iter().enumerate() {
        out.push(("att", *key, bytes(i as u8, 300 + i * 17)));
    }
    for (i, key) in ["l1", "l2", "l 3"].iter().enumerate() {
        out.push(("later", *key, bytes(100 + i as u8, 200 + i)));
    }
    out.push(("docs", "d1", bytes(50, 400)));
    out.push(("docs", "d2", bytes(51, 401)));
    out.push(("docs", "bare", bytes(77, 123)));
    out
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn old_database() -> PathBuf {
    let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    copy_dir(Path::new(FIXTURE), &dir);
    dir
}

fn open(dir: &Path, tables: &[&str]) -> Storage {
    let mut config = DatabaseConfig::new("", "f").dir_path(dir.to_path_buf()).blob_enabled(true);
    for table in tables {
        config = match *table {
            "att" => config.register_blob::<Att>("att"),
            "docs" => config.register_blob::<Doc>("docs"),
            "later" => config.register_blob::<Later>("later"),
            other => panic!("{other}"),
        };
    }
    Storage::builder(StorageConfig::default().change_dir_path(dir.to_path_buf())).add_database(config).build().unwrap()
}

/// Every file under `f.blobs`, by relative name.
fn on_disk(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                out.insert(path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/"), std::fs::read(&path).unwrap());
            }
        }
    }
    let root = dir.join("f.blobs");
    let mut out = BTreeMap::new();
    walk(&root, &root, &mut out);
    out
}

fn read(s: &Storage, table: &str, key: &str) -> clove1db::units::Result<Vec<u8>> {
    let mut reader = s.db_manager("f").open_blob(table, key)?;
    let mut out = Vec::new();
    reader.read_to_end(&mut out)?;
    Ok(out)
}

fn assert_all_open(s: &Storage, tables: &[&str]) {
    for (table, key, expected) in old_files().into_iter().filter(|(t, _, _)| tables.contains(t)) {
        assert_eq!(read(s, table, key).unwrap(), expected, "{table}/{key}");
    }
}

#[test]
fn files_with_no_rows_and_files_with_rows_stay_and_open_with_the_same_bytes() {
    let dir = old_database();
    let before = on_disk(&dir);
    assert_eq!(before.len(), 12, "the fixture holds twelve files");
    for round in 0..3 {
        let s = open(&dir, &["att", "docs", "later"]);
        assert_all_open(&s, &["att", "docs", "later"]);
        // the rows' own attachments open through their table too
        assert_eq!(s.domain::<Doc>().repo().get("d1").unwrap().name, "doc0");
        let mut got = Vec::new();
        s.domain::<Doc>().open_blob("d2").unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, bytes(51, 401));
        s.close();
        assert_eq!(on_disk(&dir), before, "round {round}: a file changed, vanished or appeared");
    }
}

#[test]
fn an_attachment_the_user_deletes_does_not_come_back() {
    let dir = old_database();
    let s = open(&dir, &["att", "docs", "later"]);
    assert!(s.db_manager("f").delete_blob("att", "with space").unwrap());
    assert!(read(&s, "att", "with space").is_err());
    s.close();
    for _ in 0..2 {
        let s = open(&dir, &["att", "docs", "later"]);
        assert!(read(&s, "att", "with space").is_err(), "the deleted attachment came back");
        assert_all_open(&s, &["docs", "later"]);
        for (table, key, expected) in old_files().into_iter().filter(|(t, k, _)| *t == "att" && *k != "with space") {
            assert_eq!(read(&s, table, key).unwrap(), expected);
        }
        s.close();
    }
    assert!(!on_disk(&dir).contains_key("att/with space"), "the deleted file was left in the folder");
}

#[test]
fn a_table_left_out_of_one_open_keeps_its_files_and_is_adopted_when_it_is_registered() {
    let dir = old_database();
    let before = on_disk(&dir);
    // `later` is not registered in this open: its folder is not cleaned
    let s = open(&dir, &["att", "docs"]);
    assert_all_open(&s, &["att", "docs"]);
    s.close();
    assert_eq!(on_disk(&dir), before);
    let s = open(&dir, &["att", "docs", "later"]);
    assert_all_open(&s, &["att", "docs", "later"]);
    s.close();
    assert_eq!(on_disk(&dir), before);
    // and a table that is never registered again keeps its files for good
    let s = open(&dir, &["att"]);
    s.close();
    assert_eq!(on_disk(&dir), before);
}

#[test]
fn a_database_of_this_version_adopts_nothing_twice() {
    let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = open(&dir, &["docs"]);
    s.domain::<Doc>().set_with_blob("x", &Doc { id: "x".into(), name: "n".into() }, b"content").unwrap();
    s.close();
    // a stray file with an old-style name appears after the first open; this version never wrote it
    std::fs::write(dir.join("f.blobs").join("docs").join("stray"), b"stray").unwrap();
    let s = open(&dir, &["docs"]);
    let mut got = Vec::new();
    s.domain::<Doc>().open_blob("x").unwrap().read_to_end(&mut got).unwrap();
    assert_eq!(got, b"content");
    s.close();
    let files = on_disk(&dir);
    assert!(!files.contains_key("docs/stray"), "an unreferenced file of a table that was adopted already is cleaned: {:?}", files.keys());
    assert_eq!(files.len(), 1);
}

#[test]
fn names_that_this_version_writes_or_that_are_temporary_are_not_adopted() {
    let dir = old_database();
    let folder = dir.join("f.blobs").join("att");
    std::fs::write(folder.join("__v_old-style"), b"ours").unwrap();
    std::fs::write(folder.join("x.tmp.1.2.3"), b"temporary").unwrap();
    let s = open(&dir, &["att", "docs", "later"]);
    assert_all_open(&s, &["att", "docs", "later"]);
    s.close();
    let files = on_disk(&dir);
    assert!(!files.contains_key("att/__v_old-style") && !files.contains_key("att/x.tmp.1.2.3"), "{:?}", files.keys());
    assert_eq!(files.len(), 12);
}

/// The child: opens the old database and is killed after the log was created and before the files are adopted.
#[cfg(feature = "crash-inject")]
#[test]
#[ignore]
fn child_opens_the_old_database_and_is_killed_before_the_adoption() {
    let dir = PathBuf::from(std::env::var("CLOVE_KILL_ROOT").unwrap());
    let _s = open(&dir, &["att", "docs", "later"]);
}

#[cfg(feature = "crash-inject")]
#[test]
fn a_kill_between_the_log_and_the_adoption_loses_nothing() {
    let dir = old_database();
    let before = on_disk(&dir);
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--include-ignored", "--exact", "child_opens_the_old_database_and_is_killed_before_the_adoption"])
        .env("CLOVE_KILL_ROOT", &dir)
        .env("CLOVE_CRASH_POINT", "blob_before_reconcile")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(99), "the child was killed at the point");
    assert_eq!(on_disk(&dir), before, "the kill changed the files");
    let s = open(&dir, &["att", "docs", "later"]);
    assert_all_open(&s, &["att", "docs", "later"]);
    s.close();
    assert_eq!(on_disk(&dir), before);
}

/// A database written by 0.0.126 changed straight into an encrypted one (whole database): its files with no
/// row are carried over too, and open afterwards with the same bytes.
#[cfg(feature = "encryption")]
#[test]
fn an_old_database_changed_straight_into_an_encrypted_one_keeps_its_files() {
    use clove1db::{
        EncryptionConfig, KeySource,
        crypto::{CipherKind, HkdfHash, Key32, KeySuite},
        migration::ChangeProtection,
    };
    let dir = old_database();
    let encrypted = || EncryptionConfig {
        suite: KeySuite { cipher: CipherKind::XChaCha20Poly1305, hkdf: HkdfHash::Sha256 },
        read: Some(KeySource::Raw(Key32::from_bytes(&[5; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[6; 32]))),
    };
    ChangeProtection::new(&dir, "", "f").from_plain().to_whole_database(encrypted()).execute().unwrap();
    let open_encrypted = || {
        let config = DatabaseConfig::new("", "f")
            .dir_path(dir.clone())
            .blob_enabled(true)
            .register_blob::<Att>("att")
            .register_blob::<Doc>("docs")
            .register_blob::<Later>("later")
            .encryption(encrypted());
        Storage::builder(StorageConfig::default().change_dir_path(dir.clone())).add_database(config).build()
    };
    for _ in 0..2 {
        let s = open_encrypted().unwrap();
        assert_all_open(&s, &["att", "docs", "later"]);
        assert_eq!(s.domain::<Doc>().repo().get("d1").unwrap().name, "doc0");
        s.close();
    }
    // nothing readable is left in the folder
    for (name, content) in on_disk(&dir) {
        for (_, key, expected) in old_files() {
            assert!(key.len() < 6 || !name.contains(key), "{name} shows a key");
            let probe = &expected[..expected.len().min(64)];
            assert!(!content.windows(probe.len()).any(|w| w == probe), "{name} holds plain content");
        }
    }
}
