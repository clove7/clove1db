//! A database file that grew can be given back to the disk: `Storage::compact_database`.
use clove1db::{
    CloveFields, EncryptionConfig, KeySource,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    entity::Entity,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize, CloveFields)]
struct Entry {
    id: String,
    body: String,
}
impl Entity for Entry {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn keys() -> EncryptionConfig {
    EncryptionConfig {
        suite: KeySuite { cipher: CipherKind::XChaCha20Poly1305, hkdf: HkdfHash::Sha256 },
        read: Some(KeySource::Raw(Key32::from_bytes(&[1; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[2; 32]))),
    }
}

fn temp_dir() -> PathBuf {
    std::env::temp_dir().join(uuid::Uuid::new_v4().to_string())
}

fn open(dir: &Path, encrypted: bool) -> Storage {
    let config = DatabaseConfig::new("records", "store")
        .dir_path(dir.to_path_buf())
        .has_cache(false)
        .backup_enabled(true)
        .register::<Entry>("entries");
    let config = if encrypted { config.encryption(keys()) } else { config };
    Storage::builder(StorageConfig::default()).add_database(config).build().unwrap()
}

fn size(dir: &Path, file: &str) -> u64 {
    std::fs::metadata(dir.join("records").join(file)).map(|m| m.len()).unwrap_or(0)
}

/// `rows` rows of about a kilobyte in one commit each hundred, then all but every tenth deleted.
fn grow_then_delete(s: &Storage, rows: usize) {
    let db = s.db_manager("store");
    for chunk in (0..rows).collect::<Vec<_>>().chunks(100) {
        let writes: Vec<(String, String, Vec<u8>)> = chunk
            .iter()
            .map(|i| {
                let e = Entry { id: format!("e{i:05}"), body: "x".repeat(1000) };
                ("entries".to_string(), e.id.clone(), serde_json::to_vec(&e).unwrap())
            })
            .collect();
        db.commit_batch_atomic(&writes, &[]).unwrap();
    }
    for chunk in (0..rows).filter(|i| i % 10 != 0).collect::<Vec<_>>().chunks(100) {
        let deletes: Vec<(String, String)> = chunk.iter().map(|i| ("entries".to_string(), format!("e{i:05}"))).collect();
        db.commit_batch_atomic(&[], &deletes).unwrap();
    }
}

#[test]
fn a_file_that_grew_shrinks_and_keeps_its_rows_plain_and_encrypted() {
    for encrypted in [false, true] {
        let dir = temp_dir();
        let s = open(&dir, encrypted);
        grow_then_delete(&s, 3000);
        // the history of a row, so that the history file has something in it
        s.domain::<Entry>().repo().set("h1", &Entry { id: "h1".into(), body: "one".into() }).unwrap();
        s.domain::<Entry>().repo().set("h1", &Entry { id: "h1".into(), body: "two".into() }).unwrap();
        let grown = size(&dir, "store.cldb");

        let report = s.compact_database("store").unwrap();
        let shrunk = size(&dir, "store.cldb");
        assert!(shrunk < grown / 2, "encrypted={encrypted}: {grown} -> {shrunk}");
        assert!(report.after < report.before, "{report:?}");
        assert!(report.before >= grown, "{report:?}");

        // all the rows are there, and a write after the compaction works
        for i in (0..3000).step_by(10) {
            assert_eq!(s.domain::<Entry>().repo().get(&format!("e{i:05}")).unwrap().body.len(), 1000);
        }
        assert!(s.domain::<Entry>().repo().get("e00001").is_err());
        assert_eq!(s.domain::<Entry>().repo().get("h1").unwrap().body, "two");
        s.domain::<Entry>().repo().set("h2", &Entry { id: "h2".into(), body: "after".into() }).unwrap();
        s.close();

        // and after a reopen
        let s = open(&dir, encrypted);
        assert_eq!(s.domain::<Entry>().repo().get("h2").unwrap().body, "after");
        assert_eq!(s.domain::<Entry>().repo().get("e02990").unwrap().body.len(), 1000);
        assert!(!s.domain::<Entry>().history("h1").unwrap().is_empty(), "the history is kept");
    }
}

#[test]
fn another_database_keeps_working_and_an_unknown_name_is_an_error() {
    let dir = temp_dir();
    let s = open(&dir, false);
    let err = s.compact_database("nothing").unwrap_err();
    assert!(matches!(err, ClError::Validation(_)), "{err:?}");
    s.compact_database("store").unwrap();
    s.domain::<Entry>().repo().set("a", &Entry { id: "a".into(), body: "b".into() }).unwrap();
}

#[test]
fn a_transaction_left_open_is_reported_and_nothing_changes() {
    let dir = temp_dir();
    let s = open(&dir, false);
    grow_then_delete(&s, 300);
    let held = s.db_manager("store").db().unwrap().begin_read().unwrap();
    let before = size(&dir, "store.cldb");
    let err = s.compact_database("store").unwrap_err();
    assert!(err.to_string().to_lowercase().contains("transaction"), "{err}");
    assert_eq!(size(&dir, "store.cldb"), before);
    drop(held);
    s.compact_database("store").unwrap();
    assert_eq!(s.domain::<Entry>().repo().get("e00000").unwrap().body.len(), 1000);
}

/// The index worker holds reads on the main file while it serves an index; compaction makes it let go,
/// and the index goes on answering afterwards.
#[test]
fn a_database_with_a_live_index_is_compacted_and_the_index_still_answers() {
    use clove1db::query::optimizer::Plan;
    use std::time::{Duration, Instant};
    #[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
    struct Marked {
        id: String,
        n: i64,
        body: String,
    }
    impl Entity for Marked {
        fn entity_id(&self) -> &str {
            &self.id
        }
    }
    let dir = temp_dir();
    let s = Storage::builder(StorageConfig::default())
        .add_database(DatabaseConfig::new("records", "store").dir_path(dir.clone()).has_cache(false).register::<Marked>("marked"))
        .build()
        .unwrap();
    let rows: Vec<(String, String, Vec<u8>)> = (0..3000)
        .map(|i| {
            let m = Marked { id: format!("{i:05}"), n: i % 7, body: "y".repeat(800) };
            ("marked".to_string(), m.id.clone(), serde_json::to_vec(&m).unwrap())
        })
        .collect();
    s.db_manager("store").commit_batch_atomic(&rows, &[]).unwrap();
    let q = s.domain::<Marked>().query().filter(Marked::n.eq(3));
    let start = Instant::now();
    loop {
        let _ = q.count().unwrap();
        if q.explain().unwrap().selected == Plan::IndexEquality {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(10), "the index did not become usable");
        std::thread::sleep(Duration::from_millis(10));
    }
    let deletes: Vec<(String, String)> = (0..3000).filter(|i| i % 7 != 3).map(|i| ("marked".to_string(), format!("{i:05}"))).collect();
    for chunk in deletes.chunks(200) {
        s.db_manager("store").commit_batch_atomic(&[], chunk).unwrap();
    }
    let expected = (0..3000).filter(|i| i % 7 == 3).count() as u64;
    let start = Instant::now();
    while q.count().unwrap() != expected {
        assert!(start.elapsed() < Duration::from_secs(10), "the index did not catch up");
        std::thread::sleep(Duration::from_millis(10));
    }
    let before = size(&dir, "store.cldb");
    s.compact_database("store").unwrap();
    assert!(size(&dir, "store.cldb") < before, "the file did not shrink");
    // the index answers, and takes new writes
    assert_eq!(q.count().unwrap(), expected);
    s.db_manager("store")
        .commit_batch_atomic(&[("marked".to_string(), "99999".to_string(), serde_json::to_vec(&Marked { id: "99999".into(), n: 3, body: String::new() }).unwrap())], &[])
        .unwrap();
    let start = Instant::now();
    while q.count().unwrap() != expected + 1 {
        assert!(start.elapsed() < Duration::from_secs(10), "the index stopped following writes");
        std::thread::sleep(Duration::from_millis(10));
    }
}
