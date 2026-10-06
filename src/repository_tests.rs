//! Reading a whole table: `Repository::list`, `list_map` and `get_uncached_as`.
//!
//! `list` used to copy every stored value into one `Vec<Vec<u8>>` and parse
//! them only once the whole table was in memory, so a large table was held
//! twice while it was read. These pin the row-at-a-time read that replaced it.

use std::path::{Path, PathBuf};

use redb::TableDefinition;
use serde::{Deserialize, Serialize};

use crate::entity::Entity;
use crate::storage::{DatabaseConfig, Storage, StorageConfig};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
struct Note {
    id: String,
    name: String,
    /// The bulky field a list view does not need.
    detail: String,
}

impl Entity for Note {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// A lighter view of the same stored row: `detail` is not named, so serde
/// skips it without building it.
#[derive(Debug, Clone, PartialEq, Deserialize)]
struct NoteTitle {
    id: String,
    name: String,
}

fn fresh_dir(tag: &str) -> PathBuf {
    let dir = PathBuf::from("./target/test_repository").join(tag);
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn build(dir: &Path) -> Storage {
    Storage::builder(StorageConfig::default().change_dir_path(dir.to_path_buf()))
        .add_database(DatabaseConfig::new("notes", "notes").register::<Note>("notes"))
        .build()
        .unwrap()
}

fn note(i: usize) -> Note {
    Note {
        id: format!("n{i:03}"),
        name: format!("Note {i}"),
        detail: "x".repeat(4096),
    }
}

fn seeded(tag: &str, n: usize) -> Storage {
    let storage = build(&fresh_dir(tag));
    let repo = storage.domain::<Note>().repo();
    for i in 0..n {
        let n = note(i);
        repo.set(&n.id, &n).unwrap();
    }
    storage
}

#[test]
fn list_returns_every_row() {
    let storage = seeded("list_all", 40);
    let mut rows = storage.domain::<Note>().repo().list().unwrap();
    rows.sort_by(|a, b| a.id.cmp(&b.id));
    assert_eq!(rows, (0..40).map(note).collect::<Vec<_>>());
}

#[test]
fn list_is_sized_from_the_table() {
    let storage = seeded("list_capacity", 33);
    let rows = storage.domain::<Note>().repo().list().unwrap();
    assert_eq!(rows.len(), 33);
    assert_eq!(rows.capacity(), 33, "not grown by doubling");
}

#[test]
fn list_map_maps_each_row_as_it_is_read() {
    let storage = seeded("list_map", 25);
    let mut names = storage
        .domain::<Note>()
        .repo()
        .list_map(|n| (n.id, n.name))
        .unwrap();
    assert_eq!(names.capacity(), 25);
    names.sort();
    assert_eq!(names.len(), 25);
    assert_eq!(names[0], ("n000".to_string(), "Note 0".to_string()));
}

#[test]
fn get_uncached_as_reads_a_lighter_view_of_the_row() {
    let storage = seeded("get_as", 3);
    let repo = storage.domain::<Note>().repo();
    let view: NoteTitle = repo.get_uncached_as("n001").unwrap();
    assert_eq!(
        view,
        NoteTitle {
            id: "n001".into(),
            name: "Note 1".into()
        }
    );
    assert!(matches!(
        repo.get_uncached_as::<NoteTitle>("nope"),
        Err(crate::units::ClError::NotFound(_))
    ));
}

/// `list` used to `unwrap()` the parse: one bad row took the process down.
#[test]
fn a_row_that_does_not_parse_is_an_error_not_a_panic() {
    let storage = seeded("bad_row", 2);
    let repo = storage.domain::<Note>().repo();
    let table: TableDefinition<'_, &str, &[u8]> = TableDefinition::new("notes");
    repo.database_manager
        .set(table, "notes", "broken", b"not json".to_vec())
        .unwrap();

    assert!(repo.list().is_err());
    assert!(repo.list_map(|n| n.id).is_err());
}

fn add_wrongly_typed_table(storage: &Storage) {
    let manager = &storage.domain::<Note>().repo().database_manager;
    let db = manager.db().unwrap();
    let txn = db.begin_write().unwrap();
    {
        let numbers: TableDefinition<&str, u64> = TableDefinition::new("fault_numbers");
        txn.open_table(numbers).unwrap();
    }
    txn.commit().unwrap();
}

#[test]
fn atomic_batch_failure_never_keeps_a_committed_prefix() {
    let storage = build(&fresh_dir("atomic_write_failure"));
    add_wrongly_typed_table(&storage);
    let manager = &storage.domain::<Note>().repo().database_manager;
    let mut writes: Vec<_> = (0..999)
        .map(|i| {
            let row = note(i);
            (
                "notes".to_string(),
                row.id.clone(),
                serde_json::to_vec(&row).unwrap(),
            )
        })
        .collect();
    writes.push(("fault_numbers".into(), "wrong_type".into(), vec![1]));
    assert!(manager.commit_batch_atomic(&writes, &[]).is_err());
    assert_eq!(manager.count_keys("notes").unwrap(), 0);
    assert!(storage.domain::<Note>().repo().get("n000").is_err());
}

#[test]
fn atomic_write_and_delete_failure_preserves_the_old_row_and_cache() {
    let storage = build(&fresh_dir("atomic_delete_failure"));
    let original = note(0);
    let repo = storage.domain::<Note>().repo();
    repo.set(&original.id, &original).unwrap();
    assert_eq!(repo.get(&original.id).unwrap(), original);
    add_wrongly_typed_table(&storage);
    let writes: Vec<_> = (0..1000)
        .map(|i| {
            let mut row = note(i);
            row.name = "replacement".into();
            (
                "notes".to_string(),
                row.id.clone(),
                serde_json::to_vec(&row).unwrap(),
            )
        })
        .collect();
    let deletes = vec![
        ("notes".into(), original.id.clone()),
        ("fault_numbers".into(), "wrong_type".into()),
    ];
    assert!(
        repo.database_manager
            .commit_batch_atomic(&writes, &deletes)
            .is_err()
    );
    assert_eq!(repo.database_manager.count_keys("notes").unwrap(), 1);
    assert_eq!(repo.get(&original.id).unwrap(), original);
}
