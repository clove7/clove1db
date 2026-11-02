//! A build without the `encryption` feature does not open what it cannot read: a table with protected
//! fields, and a file that is not an ordinary redb database (an encrypted one has no mark by design).
#![cfg(not(feature = "encryption"))]
use clove1db::{
    entity::Entity,
    metadata::SealedField,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
struct Customer {
    id: String,
}
impl Entity for Customer {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn temp_dir() -> PathBuf {
    std::env::temp_dir().join(uuid::Uuid::new_v4().to_string())
}

fn open(dir: &Path) -> clove1db::units::Result<Storage> {
    Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("records", "store").dir_path(dir.to_path_buf()).has_cache(false).register::<Customer>("customers"),
        )
        .build()
}

fn main_file(dir: &Path) -> PathBuf {
    dir.join("records").join("store.cldb")
}

#[test]
fn a_database_with_a_protected_table_is_refused_before_anything_is_written() {
    let dir = temp_dir();
    let s = open(&dir).unwrap();
    let db = s.db_manager("store");
    let mut meta = db.read_meta().unwrap().unwrap();
    meta.tables[0].sealed.push(SealedField { id: 1, name: "phone".into(), method: 1, check: None, window: None, bits: None });
    db.write_meta(&meta).unwrap();
    s.close();
    drop(s);

    let before = std::fs::read(main_file(&dir)).unwrap();
    match open(&dir) {
        Err(ClError::Validation(t)) => {
            assert!(t.contains("`customers`") && t.contains("enable the `encryption` feature"), "{t}");
        }
        Err(other) => panic!("expected the refusal, got {other:?}"),
        Ok(_) => panic!("the database with a protected table was opened"),
    }
    assert_eq!(std::fs::read(main_file(&dir)).unwrap(), before, "the refused open changed the file");
}

#[test]
fn a_file_that_is_not_a_redb_database_says_how_to_open_it() {
    let dir = temp_dir();
    std::fs::create_dir_all(dir.join("records")).unwrap();
    std::fs::write(main_file(&dir), vec![0xABu8; 8192]).unwrap();
    match open(&dir) {
        Err(ClError::Validation(t)) => {
            assert!(t.contains("not an ordinary redb database file") && t.contains("`encryption` feature"), "{t}");
        }
        Err(other) => panic!("expected the hint, got {other:?}"),
        Ok(_) => panic!("random bytes were opened as a database"),
    }
}

#[test]
fn a_protected_database_that_needs_repair_is_refused_too() {
    // What a crash leaves: the recovery flag set in the header, so the read-only look cannot open it.
    let dir = temp_dir();
    let s = open(&dir).unwrap();
    let db = s.db_manager("store");
    let mut meta = db.read_meta().unwrap().unwrap();
    meta.tables[0].sealed.push(SealedField { id: 1, name: "phone".into(), method: 1, check: None, window: None, bits: None });
    db.write_meta(&meta).unwrap();
    s.close();
    drop(s);
    let mut bytes = std::fs::read(main_file(&dir)).unwrap();
    bytes[9] |= 2;
    std::fs::write(main_file(&dir), &bytes).unwrap();

    match open(&dir) {
        Err(ClError::Validation(t)) => assert!(t.contains("`customers`") && t.contains("enable the `encryption` feature"), "{t}"),
        Err(other) => panic!("expected the refusal, got {other:?}"),
        Ok(_) => panic!("a protected database that needed repair was opened"),
    }
}
