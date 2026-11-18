//! A table changed in place by `migrate`: the change of an empty table is recorded, and the table
//! is still checked against its registered type at every later open.
use clove1db::{
    entity::Entity,
    migration::{FieldLayout, MigrateOutcome, MigrateTo, migrate_value},
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::{ClError, Result},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
struct V1 {
    id: String,
    text: String,
}

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
struct V2 {
    id: String,
    text: String,
    extra: String,
}

/// `V2` changed again (a field renamed, one added), with no migration to it.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
struct V3 {
    id: String,
    body: String,
    extra: String,
    owner: String,
}

/// A second table shape, so that its change is another step than `V1` to `V2`.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
struct Plain {
    id: String,
    title: String,
}

/// `Plain` with a field that is left out while empty: the same shape as `Plain`.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
struct WithNote {
    id: String,
    title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

/// `WithNote` with a field that is always written. It keeps the left-out field.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
struct WithNoteAndExtra {
    id: String,
    title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    extra: String,
}

macro_rules! entity {
    ($($t:ty),*) => {$(
        impl Entity for $t {
            fn entity_id(&self) -> &str {
                &self.id
            }
        }
    )*};
}
entity!(V1, V2, V3, Plain, WithNote, WithNoteAndExtra);

impl MigrateTo<V2> for V1 {
    fn migrate_json(value: Value) -> Result<MigrateOutcome<Value>> {
        let old: V1 = serde_json::from_value(value)?;
        migrate_value(V2 { id: old.id, text: old.text, extra: String::new() })
    }
}

impl MigrateTo<WithNoteAndExtra> for WithNote {
    fn migrate_json(value: Value) -> Result<MigrateOutcome<Value>> {
        let old: WithNote = serde_json::from_value(value)?;
        migrate_value(WithNoteAndExtra { id: old.id, title: old.title, note: old.note, extra: String::new() })
    }
}

fn temp_dir() -> PathBuf {
    std::env::temp_dir().join(uuid::Uuid::new_v4().to_string())
}

fn config<E: Entity + Serialize + Default>(dir: &Path) -> DatabaseConfig {
    DatabaseConfig::new("records", "store").dir_path(dir.to_path_buf()).has_cache(false).create_missing_tables(true).register::<E>("notes")
}

fn open<E: Entity + Serialize + Default>(dir: &Path) -> Result<Storage> {
    Storage::builder(StorageConfig::default()).add_database(config::<E>(dir)).build()
}

fn refused<E: Entity + Serialize + Default>(dir: &Path) -> bool {
    match open::<E>(dir) {
        Ok(storage) => {
            storage.close();
            false
        }
        Err(ClError::LayoutMismatch { .. }) => true,
        Err(other) => panic!("another error than a layout mismatch: {other}"),
    }
}

/// Every file named `name` under `dir`.
fn find(dir: &Path, name: &str, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            find(&path, name, out);
        } else if path.file_name().is_some_and(|n| n == name) {
            out.push(path);
        }
    }
}

#[test]
fn the_change_of_an_empty_table_is_recorded_and_the_table_opens() {
    let dir = temp_dir();
    open::<V1>(&dir).unwrap().close();
    assert!(refused::<V2>(&dir), "the new type before the change");

    let storage = Storage::builder(StorageConfig::default()).migration_step::<V1, V2>().add_database(config::<V1>(&dir)).build().unwrap();
    let done = storage.migrate::<V1, V2>().from_db("store", "notes").execute().unwrap();
    assert_eq!(done.records_migrated, 0);
    assert!(done.report.errors.is_empty(), "{:?}", done.report.errors);
    storage.close();

    let storage = open::<V2>(&dir).expect("the table opens under the type it was changed to");
    let notes = storage.domain::<V2>();
    let row = V2 { id: "n1".into(), text: "first".into(), extra: "x".into() };
    notes.repo().set("n1", &row).unwrap();
    assert_eq!(notes.repo().get("n1").unwrap(), row);
    storage.close();
    assert!(refused::<V1>(&dir), "the old type after the change");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_changed_table_is_still_checked_against_its_type() {
    let dir = temp_dir();
    let storage = open::<V1>(&dir).unwrap();
    storage.domain::<V1>().repo().set("n1", &V1 { id: "n1".into(), text: "first".into() }).unwrap();
    storage.close();
    assert!(refused::<V3>(&dir), "another type before any change");

    let storage = Storage::builder(StorageConfig::default()).migration_step::<V1, V2>().add_database(config::<V1>(&dir)).build().unwrap();
    assert_eq!(storage.migrate::<V1, V2>().from_db("store", "notes").execute().unwrap().records_migrated, 1);
    storage.close();

    let storage = open::<V2>(&dir).unwrap();
    assert_eq!(storage.domain::<V2>().repo().get("n1").unwrap().text, "first");
    storage.close();
    // After one change the table used to open under any type, and the rows failed to read later.
    assert!(refused::<V3>(&dir), "another type after one change");
    assert!(refused::<V1>(&dir), "the old type after one change");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_changed_table_opens_whatever_its_first_row_holds() {
    let dir = temp_dir();
    let storage = open::<Plain>(&dir).unwrap();
    storage.domain::<Plain>().repo().set("n1", &Plain { id: "n1".into(), title: "first".into() }).unwrap();
    storage.close();
    // A field left out while empty is added with no change of the table's shape.
    let storage = open::<WithNote>(&dir).unwrap();
    let first = WithNote { id: "a0".into(), title: "lowest key".into(), note: Some("kept".into()) };
    storage.domain::<WithNote>().repo().set("a0", &first).unwrap();
    assert_eq!(storage.domain::<WithNote>().repo().get("n1").unwrap().note, None);
    storage.close();

    let storage = Storage::builder(StorageConfig::default()).migration_step::<WithNote, WithNoteAndExtra>().add_database(config::<WithNote>(&dir)).build().unwrap();
    assert_eq!(storage.migrate::<WithNote, WithNoteAndExtra>().from_db("store", "notes").execute().unwrap().records_migrated, 2);
    storage.close();

    // The stored shape is the type's, not the first row's (that row holds the left-out field).
    let mut layouts = vec![];
    find(&dir, "v2.json", &mut layouts);
    assert_eq!(layouts.len(), 1, "{layouts:?}");
    let of_type = FieldLayout::capture_from_entity_json(&WithNoteAndExtra::default()).unwrap();
    let stored: FieldLayout = serde_json::from_slice(&std::fs::read(&layouts[0]).unwrap()).unwrap();
    assert_eq!(stored, of_type);

    let storage = open::<WithNoteAndExtra>(&dir).expect("the table opens under the type it was changed to");
    assert_eq!(storage.domain::<WithNoteAndExtra>().repo().get("a0").unwrap().note.as_deref(), Some("kept"));
    storage.close();

    // A table changed before the shape was taken from the type holds the shape of its first row.
    // It still opens under the type its change was declared to reach, and under no other.
    let moved = WithNoteAndExtra { id: first.id.clone(), title: first.title.clone(), note: first.note.clone(), extra: String::new() };
    let of_row = FieldLayout::capture_from_sample_json(&serde_json::to_vec(&moved).unwrap()).unwrap();
    assert_ne!(of_row.layout_hash, of_type.layout_hash);
    std::fs::write(&layouts[0], serde_json::to_vec_pretty(&of_row).unwrap()).unwrap();
    open::<WithNoteAndExtra>(&dir).expect("a table changed by an earlier version opens").close();
    assert!(refused::<V3>(&dir), "another type");
    let _ = std::fs::remove_dir_all(dir);
}
