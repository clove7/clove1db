//! `DatabaseConfig::prefetch` only reads the `.cldb` before opening it: the database behaves the same
//! (new, existing, and locked by another program). By default ([`Prefetch::Auto`]) the read happens for a file of 64 MiB or more.
use clove1db::{CloveFields, entity::Entity, storage::{DatabaseConfig, PREFETCH_AUTO_BYTES, PREFETCH_AUTO_MAX_BYTES, Prefetch, Storage, StorageConfig}, units::ClError};
use serde::{Deserialize, Serialize};
use std::{path::{Path, PathBuf}, time::{Duration, Instant}};

#[derive(Clone, Default, Serialize, Deserialize, CloveFields)]
struct Note { id: String, n: i64 }
impl Entity for Note { fn entity_id(&self) -> &str { &self.id } }

fn build(root: &Path, prefetch: impl Into<Prefetch>) -> Result<Storage, ClError> {
    Storage::builder(StorageConfig::default())
        .add_database(DatabaseConfig::new("records", "store").dir_path(root.to_path_buf()).prefetch(prefetch).has_cache(false).register::<Note>("notes"))
        .build()
}

/// Opened with the default setting (what an application that never calls `prefetch` gets).
fn build_default(root: &Path) -> Result<Storage, ClError> {
    Storage::builder(StorageConfig::default())
        .add_database(DatabaseConfig::new("records", "store").dir_path(root.to_path_buf()).has_cache(false).register::<Note>("notes"))
        .build()
}

fn fresh() -> PathBuf { std::env::temp_dir().join(uuid::Uuid::new_v4().to_string()) }

fn cldb(root: &Path) -> PathBuf { root.join("records").join("store.cldb") }

fn rows(s: &Storage) -> usize { s.domain::<Note>().query().count().unwrap() as usize }

/// A closed database of `count` rows whose values are `pad` bytes of padding each.
fn filled(count: usize, pad: usize) -> PathBuf {
    let root = fresh();
    let s = build(&root, false).unwrap();
    let padding = "x".repeat(pad);
    for start in (0..count).step_by(100) {
        let batch = (start..(start + 100).min(count))
            .map(|i| {
                let id = format!("{i:06}");
                let value = format!(r#"{{"id":"{id}","n":{i},"pad":"{padding}"}}"#).into_bytes();
                ("notes".to_string(), id, value)
            })
            .collect::<Vec<_>>();
        s.db_manager("store").commit_batch_atomic(&batch, &[]).unwrap();
    }
    s.close();
    root
}

fn small() -> PathBuf {
    let root = filled(500, 0);
    assert!(std::fs::metadata(cldb(&root)).unwrap().len() < PREFETCH_AUTO_BYTES);
    root
}

fn big() -> PathBuf {
    let root = filled(2_200, 32 * 1024);
    assert!(std::fs::metadata(cldb(&root)).unwrap().len() >= PREFETCH_AUTO_BYTES, "the fixture must reach the limit");
    root
}

#[cfg(feature = "crash-inject")]
fn prefetched(root: &Path) -> u64 { clove1db::test_prefetched_bytes(&cldb(root)) }

#[test]
fn prefetch_on_a_new_and_an_existing_database_changes_nothing() {
    let root = fresh();
    let s = build(&root, true).unwrap(); // the file does not exist yet
    let batch = (0..500).map(|i| ("notes".to_string(), format!("{i:04}"), serde_json::to_vec(&Note { id: format!("{i:04}"), n: i }).unwrap())).collect::<Vec<_>>();
    s.db_manager("store").commit_batch_atomic(&batch, &[]).unwrap();
    s.close();
    for prefetch in [Prefetch::Always, Prefetch::Never, Prefetch::Auto] {
        let s = build(&root, prefetch).unwrap();
        assert_eq!(rows(&s), 500, "prefetch={prefetch:?}");
        s.close();
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn prefetch_does_not_hide_a_database_in_use() {
    let root = fresh();
    build(&root, false).unwrap().close();
    let held = std::fs::OpenOptions::new().read(true).write(true).open(cldb(&root)).unwrap();
    held.lock().unwrap();
    let started = Instant::now();
    match build(&root, true) {
        Err(ClError::DatabaseInUse { .. }) => {}
        Err(other) => panic!("expected DatabaseInUse, got {other:?}"),
        Ok(_) => panic!("a locked database opened"),
    }
    assert!(started.elapsed() < Duration::from_secs(5), "returns at once");
    drop(held);
    assert_eq!(rows(&build(&root, true).unwrap()), 0);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_default_is_automatic_and_reads_from_64_mib_up_to_1_gib() {
    assert_eq!(Prefetch::default(), Prefetch::Auto);
    assert_eq!((PREFETCH_AUTO_BYTES, PREFETCH_AUTO_MAX_BYTES), (67_108_864, 1_073_741_824));
    assert!(!Prefetch::Auto.reads(0), "a file that does not exist yet");
    assert!(!Prefetch::Auto.reads(PREFETCH_AUTO_BYTES - 1), "one byte under the lower limit");
    assert!(Prefetch::Auto.reads(PREFETCH_AUTO_BYTES), "the lower limit itself");
    assert!(Prefetch::Auto.reads(PREFETCH_AUTO_MAX_BYTES), "the upper limit itself");
    assert!(!Prefetch::Auto.reads(PREFETCH_AUTO_MAX_BYTES + 1), "one byte over the upper limit");
    assert!(!Prefetch::Auto.reads(u64::MAX));
    assert!(Prefetch::Always.reads(0) && Prefetch::Always.reads(PREFETCH_AUTO_MAX_BYTES + 1) && Prefetch::Always.reads(u64::MAX), "Always reads above the limit too");
    assert!(!Prefetch::Never.reads(PREFETCH_AUTO_BYTES) && !Prefetch::Never.reads(u64::MAX));
    assert_eq!((Prefetch::from(true), Prefetch::from(false)), (Prefetch::Always, Prefetch::Never));
}

#[cfg(feature = "crash-inject")]
#[test]
fn a_file_under_the_limit_is_not_read_by_default() {
    let root = small();
    let s = build_default(&root).unwrap();
    assert_eq!(rows(&s), 500);
    assert_eq!(prefetched(&root), 0, "nothing was read ahead");
    s.close();
    let _ = std::fs::remove_dir_all(&root);
}

#[cfg(feature = "crash-inject")]
#[test]
fn a_file_over_the_limit_is_read_by_default() {
    let root = big();
    let length = std::fs::metadata(cldb(&root)).unwrap().len();
    let s = build_default(&root).unwrap();
    assert_eq!(rows(&s), 2_200);
    assert_eq!(prefetched(&root), length, "the whole file was read before it opened");
    s.close();
    let _ = std::fs::remove_dir_all(&root);
}

#[cfg(feature = "crash-inject")]
#[test]
fn false_turns_it_off_over_the_limit() {
    let root = big();
    let s = build(&root, false).unwrap();
    assert_eq!(rows(&s), 2_200);
    assert_eq!(prefetched(&root), 0);
    s.close();
    let _ = std::fs::remove_dir_all(&root);
}

#[cfg(feature = "crash-inject")]
#[test]
fn true_turns_it_on_under_the_limit() {
    let root = small();
    let length = std::fs::metadata(cldb(&root)).unwrap().len();
    let s = build(&root, true).unwrap();
    assert_eq!(rows(&s), 500);
    assert_eq!(prefetched(&root), length);
    s.close();
    let _ = std::fs::remove_dir_all(&root);
}
