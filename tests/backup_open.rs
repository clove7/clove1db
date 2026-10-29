//! Backup history was asked for: a `.cldb.bak` that cannot be opened stops the open with a clear error,
//! instead of opening the database without recording history. Opening normally is unaffected.
use clove1db::{CloveFields, entity::Entity, repository::Repository, storage::{DatabaseConfig, Storage, StorageConfig}, units::ClError};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Default, Serialize, Deserialize, CloveFields)]
struct Note { id: String, n: i64 }
impl Entity for Note { fn entity_id(&self) -> &str { &self.id } }

fn build(root: &Path, backup: bool) -> Result<Storage, ClError> {
    Storage::builder(StorageConfig::default())
        .add_database(DatabaseConfig::new("records", "store").dir_path(root.to_path_buf()).backup_enabled(backup).has_cache(false).register::<Note>("notes"))
        .build()
}

fn rows(s: &Storage) -> usize { s.db_manager("store").read_view_at_head().unwrap().table_entries("notes").unwrap().len() }

fn fresh() -> PathBuf { std::env::temp_dir().join(uuid::Uuid::new_v4().to_string()) }

fn seed(root: &Path) {
    let s = build(root, true).unwrap();
    let repo = Repository::<Note>::new("notes", s.db_manager("store").clone());
    for i in 0..20 { repo.set(&format!("{i:03}"), &Note { id: format!("{i:03}"), n: i }).unwrap(); }
    s.close();
}

#[test]
fn normal_open_with_backup_records_history_and_reopens() {
    let root = fresh();
    seed(&root);
    let bak = root.join("records").join("store.cldb.bak");
    assert!(std::fs::metadata(&bak).unwrap().len() > 0, "history was recorded");
    let s = build(&root, true).unwrap();
    assert_eq!(rows(&s), 20);
    s.close();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_backup_file_that_cannot_be_opened_stops_the_open() {
    let root = fresh();
    seed(&root);
    let bak = root.join("records").join("store.cldb.bak");
    let good = std::fs::read(&bak).unwrap();

    std::fs::write(&bak, vec![0xABu8; 8192]).unwrap();
    match build(&root, true) {
        Err(ClError::BackupOpenFailed { path, reason }) => {
            assert!(path.ends_with("store.cldb.bak"), "the error names the history file, got {path}");
            assert!(!reason.is_empty(), "the error says why");
        }
        Err(other) => panic!("expected BackupOpenFailed, got {other:?}"),
        Ok(_) => panic!("the database opened without its backup history"),
    }
    // Nothing was lost: with the history file back, the same database opens with every row.
    std::fs::write(&bak, &good).unwrap();
    let s = build(&root, true).unwrap();
    assert_eq!(rows(&s), 20);
    s.close();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_damaged_backup_file_does_not_matter_when_backup_is_off() {
    let root = fresh();
    seed(&root);
    std::fs::write(root.join("records").join("store.cldb.bak"), vec![0xABu8; 8192]).unwrap();
    let s = build(&root, false).unwrap();
    assert_eq!(rows(&s), 20);
    s.close();
    let _ = std::fs::remove_dir_all(&root);
}
