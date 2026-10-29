//! The tables of the main file: all of them are accounted for, copied or rebuilt, and the new file
//! opens as the same database.
use super::convert::{Kind, copy_main, describe, plan_main, verify_main};
use super::rows::BatchLimits;
use crate::{
    CloveFields, Unique,
    entity::Entity,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
struct Note {
    id: String,
    name: String,
    n: i64,
}
impl Entity for Note {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
struct Tag {
    id: String,
}
impl Entity for Tag {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn config(root: &Path) -> DatabaseConfig {
    let db = DatabaseConfig::new("records", "store")
        .dir_path(root.to_path_buf())
        .has_cache(false)
        .backup_enabled(true)
        .register::<Note>("notes")
        .register::<Tag>("tags")
        .unique::<Note>(Unique::on(Note::name));
    // the test reads the file with plain redb: it is an ordinary database under every test cfg
    #[cfg(clove_test_encrypt_all)]
    {
        db.plain()
    }
    #[cfg(not(clove_test_encrypt_all))]
    {
        db
    }
}

pub(super) fn main_file(root: &Path) -> PathBuf {
    root.join("records").join("store.cldb")
}

fn put(s: &Storage, table: &str, id: &str, name: &str) {
    let bytes = if table == "notes" {
        serde_json::to_vec(&Note { id: id.into(), name: name.into(), n: 1 }).unwrap()
    } else {
        serde_json::to_vec(&Tag { id: id.into() }).unwrap()
    };
    s.db_manager("store").set(TableDefinition::new(table), table, id, bytes).unwrap();
}

/// A database with two tables, a unique constraint, deleted rows, a history and two readers of the
/// log. Returns the root and the tokens of the readers (`late` never acknowledged anything).
pub(super) fn source() -> (PathBuf, crate::ConsumerToken, crate::ConsumerToken) {
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = Storage::builder(StorageConfig::default()).add_database(config(&root)).build().unwrap();
    let db = s.db_manager("store");
    let late = db.register_consumer("late").unwrap();
    for i in 0..25 {
        put(&s, "notes", &format!("a{i:02}"), &format!("name{i}"));
    }
    for i in 0..5 {
        put(&s, "tags", &format!("t{i}"), "");
    }
    for i in 0..3 {
        db.delete_raw("notes", &format!("a{i:02}")).unwrap();
    }
    let current = db.register_consumer("current").unwrap();
    drop(db);
    s.close();
    (root, late, current)
}

pub(super) fn small() -> BatchLimits {
    BatchLimits { max_rows: 7, max_bytes: 4096 }
}

fn count(db: &Database, name: &str) -> u64 {
    let read = db.begin_read().unwrap();
    read.open_table(TableDefinition::<&str, &[u8]>::new(name)).unwrap().len().unwrap()
}

#[test]
fn every_table_of_the_main_file_is_accounted_for() {
    let (root, _, _) = source();
    let from = Database::open(main_file(&root)).unwrap();
    let plan = plan_main(&from).unwrap();
    let kinds = |k: Kind| plan.items.iter().filter(|i| i.kind == k).count();
    assert_eq!(plan.user_tables, vec!["notes".to_string(), "tags".to_string()]);
    assert_eq!(kinds(Kind::User), 2);
    assert_eq!(kinds(Kind::Seq), 1);
    assert_eq!(kinds(Kind::Changes), 1);
    assert_eq!(kinds(Kind::Consumers), 1);
    assert_eq!(kinds(Kind::LastWrite), 1);
    assert_eq!(kinds(Kind::UniqueKeys), 1);
    assert_eq!(kinds(Kind::UniqueRows), 1);
    let names: Vec<String> = plan.items.iter().map(|i| i.name.clone()).collect();
    for expected in ["_clove_meta", "__unique_definitions", "__id_contracts", "__blob_refs"] {
        assert!(names.iter().any(|n| n == expected), "{expected} is not in {names:?}");
    }
    // the report of a dry run names every table and what happens to it
    let report = describe(&plan);
    assert_eq!(report.len(), plan.items.len());
    assert!(report.iter().any(|(n, how, rows)| n == "notes" && *how == "copied" && *rows == 22));
    assert!(report.iter().any(|(n, how, _)| n == "__lastwrite" && *how == "rebuilt"));
    drop(from);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_table_nobody_knows_stops_the_plan_before_anything_is_written() {
    let (root, _, _) = source();
    let path = main_file(&root);
    {
        let db = Database::open(&path).unwrap();
        let write = db.begin_write().unwrap();
        write.open_table(TableDefinition::<&str, &[u8]>::new("mystery")).unwrap();
        write.commit().unwrap();
    }
    let before = std::fs::read(&path).unwrap();
    let from = Database::open(&path).unwrap();
    let err = plan_main(&from).unwrap_err();
    assert!(matches!(&err, ClError::MigrationError(m) if m.contains("mystery")), "{err:?}");
    drop(from);
    // a multimap table is refused too
    {
        let db = Database::open(&path).unwrap();
        let write = db.begin_write().unwrap();
        write.delete_table(TableDefinition::<&str, &[u8]>::new("mystery")).unwrap();
        write.open_multimap_table(redb::MultimapTableDefinition::<&str, &str>::new("pairs")).unwrap();
        write.commit().unwrap();
    }
    let from = Database::open(&path).unwrap();
    assert!(plan_main(&from).is_err());
    let _ = before;
    drop(from);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_copy_moves_every_table_and_the_log_starts_again_with_one_reset_for_each_table() {
    let (root, _, _) = source();
    let from = Database::open(main_file(&root)).unwrap();
    let plan = plan_main(&from).unwrap();
    let to = Database::create(root.join("new.db")).unwrap();
    let head_old = {
        let read = from.begin_read().unwrap();
        crate::journal::read_number(&read, "head").unwrap()
    };
    let moved = copy_main(&from, &to, &plan, small()).unwrap();
    verify_main(&from, &to, &plan).unwrap();
    // in batches, held in memory a little at a time
    assert!(moved.largest_batch_bytes < 4096 + 1024, "{}", moved.largest_batch_bytes);
    assert!(moved.left_out.contains(&"__changes".to_string()));
    // the log
    let read = to.begin_read().unwrap();
    assert_eq!(crate::journal::read_number(&read, "head").unwrap(), head_old + 2);
    assert_eq!(crate::journal::read_number(&read, "floor").unwrap(), head_old + 1);
    let log = read.open_table(crate::journal::CHANGES).unwrap();
    assert_eq!(log.len().unwrap(), 2);
    let first = crate::journal::ChangeKind::decode(log.get(head_old + 1).unwrap().unwrap().value()).unwrap();
    assert!(matches!(&first, crate::journal::ChangeKind::TableReset { table, .. } if table == "notes"));
    let bytes: u64 = log.iter().unwrap().map(|r| 8 + r.unwrap().1.value().len() as u64).sum();
    assert_eq!(crate::journal::read_number(&read, "journal_bytes").unwrap(), bytes);
    // when each row was last written: the reset of its table, in the form `lastwrite` reads
    assert_eq!(crate::lastwrite::get(&read, "notes", "a10").unwrap(), head_old + 1);
    assert_eq!(crate::lastwrite::get(&read, "tags", "t3").unwrap(), head_old + 2);
    assert_eq!(crate::lastwrite::get(&read, "notes", "a00").unwrap(), 0, "a deleted row has none");
    // the constraint and the readers came along
    assert_eq!(count(&to, "__consumers"), 2);
    assert_eq!(count(&to, "notes"), 22);
    drop((read, log, from, to));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_new_file_opens_as_the_same_database_and_readers_are_told_where_they_stand() {
    let (root, late, current) = source();
    let path = main_file(&root);
    let rows_before = {
        let s = Storage::builder(StorageConfig::default()).add_database(config(&root)).build().unwrap();
        let db = s.db_manager("store");
        let rows = (db.list_entries("notes").unwrap(), db.list_entries("tags").unwrap());
        let head = db.journal_head().unwrap();
        drop(db);
        s.close();
        (rows, head)
    };
    // make the new file and put it where the old one was
    let new = root.join("records").join("store.cldb.mig-new");
    {
        let from = Database::open(&path).unwrap();
        let plan = plan_main(&from).unwrap();
        let to = Database::create(&new).unwrap();
        copy_main(&from, &to, &plan, small()).unwrap();
        verify_main(&from, &to, &plan).unwrap();
    }
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(&new, &path).unwrap();
    let _ = std::fs::remove_file(root.join("records").join("store.inx"));
    let s = Storage::builder(StorageConfig::default()).add_database(config(&root)).build().unwrap();
    let db = s.db_manager("store");
    assert_eq!((db.list_entries("notes").unwrap(), db.list_entries("tags").unwrap()), rows_before.0, "the rows are the same");
    let head_old = rows_before.1;
    assert_eq!(db.journal_head().unwrap(), head_old + 2);
    // a reader that was up to date takes both tables again
    let changes = db.read_changes(&current, head_old, 10).unwrap();
    assert_eq!(changes.len(), 2);
    assert!(changes.iter().all(|c| matches!(c.kind, crate::journal::ChangeKind::TableReset { .. })));
    let image = db.read_reset(&current, changes[0].seq).unwrap();
    assert_eq!(image.len(), 22);
    // a reader that was behind is told its place is gone, not given a wrong answer
    assert!(matches!(db.read_changes(&late, 0, 10), Err(ClError::ConsumerExpired)));
    // and the database goes on working: a new write is the next entry, the constraint still holds
    put(&s, "notes", "z1", "fresh");
    assert_eq!(db.journal_head().unwrap(), head_old + 3);
    let dup = db.set(
        TableDefinition::new("notes"),
        "notes",
        "z2",
        serde_json::to_vec(&Note { id: "z2".into(), name: "fresh".into(), n: 1 }).unwrap(),
    );
    assert!(matches!(dup, Err(ClError::UniqueViolation)), "{dup:?}");
    drop(db);
    s.close();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_check_finds_a_row_changed_a_row_missing_and_a_table_nobody_asked_for() {
    let (root, _, _) = source();
    let from = Database::open(main_file(&root)).unwrap();
    let plan = plan_main(&from).unwrap();
    let make = |name: &str| {
        let to = Database::create(root.join(name)).unwrap();
        copy_main(&from, &to, &plan, small()).unwrap();
        to
    };
    let def = TableDefinition::<&str, &[u8]>::new("notes");
    // a changed value
    let to = make("a.db");
    {
        let w = to.begin_write().unwrap();
        w.open_table(def).unwrap().insert("a10", b"{}".as_slice()).unwrap();
        w.commit().unwrap();
    }
    assert!(verify_main(&from, &to, &plan).is_err());
    // a missing row
    let to = make("b.db");
    {
        let w = to.begin_write().unwrap();
        w.open_table(def).unwrap().remove("a10").unwrap();
        w.commit().unwrap();
    }
    assert!(verify_main(&from, &to, &plan).is_err());
    // an extra table
    let to = make("c.db");
    {
        let w = to.begin_write().unwrap();
        w.open_table(TableDefinition::<&str, &[u8]>::new("extra")).unwrap();
        w.commit().unwrap();
    }
    assert!(verify_main(&from, &to, &plan).is_err());
    // nothing wrong
    assert!(verify_main(&from, &make("d.db"), &plan).is_ok());
    drop(from);
    let _ = std::fs::remove_dir_all(&root);
}

// ---- the history file ----------------------------------------------------------------------------

use super::history::{self, copy_history, plan_history, verify_history};

pub(super) fn history_file(root: &Path) -> PathBuf {
    root.join("records").join("store.cldb.bak")
}

#[test]
fn every_version_of_the_history_is_copied_with_its_counters() {
    let (root, _, _) = source();
    let from = Database::open(history_file(&root)).unwrap();
    let plan = plan_history(&from).unwrap();
    let kinds = |k: history::Kind| plan.items.iter().filter(|i| i.kind == k).count();
    assert_eq!((kinds(history::Kind::Versions), kinds(history::Kind::Counter), kinds(history::Kind::Bulk)), (2, 2, 2));
    // 25 puts and 3 deletes of "notes" are 28 saved versions
    let notes = plan.items.iter().find(|i| i.name == "notes").unwrap();
    assert_eq!(notes.entries, 28);
    let to = Database::create(root.join("history.db")).unwrap();
    let largest = copy_history(&from, &to, &plan, small()).unwrap();
    assert!(largest < 4096 + 1024, "{largest}");
    verify_history(&from, &to, &plan).unwrap();
    // a changed counter, a missing version and an extra table are each found
    {
        let w = to.begin_write().unwrap();
        w.open_table(TableDefinition::<&str, u64>::new("notes_version")).unwrap().insert("a05", 99u64).unwrap();
        w.commit().unwrap();
    }
    assert!(verify_history(&from, &to, &plan).is_err());
    drop((from, to));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_table_of_the_history_file_that_fits_no_shape_stops_the_plan() {
    let (root, _, _) = source();
    let path = history_file(&root);
    {
        let db = Database::open(&path).unwrap();
        let w = db.begin_write().unwrap();
        w.open_table(TableDefinition::<&str, &[u8]>::new("stray")).unwrap();
        w.commit().unwrap();
    }
    let from = Database::open(&path).unwrap();
    let err = plan_history(&from).unwrap_err();
    assert!(matches!(&err, ClError::MigrationError(m) if m.contains("stray")), "{err:?}");
    drop(from);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_history_of_a_table_that_is_no_longer_registered_is_kept() {
    let (root, _, _) = source();
    let path = history_file(&root);
    {
        let db = Database::open(&path).unwrap();
        let w = db.begin_write().unwrap();
        w.open_table(TableDefinition::<&str, &[u8]>::new("retired")).unwrap().insert("k", b"v".as_slice()).unwrap();
        w.open_table(TableDefinition::<&str, u64>::new("retired_version")).unwrap().insert("k", 1u64).unwrap();
        w.open_table(TableDefinition::<&str, &[u8]>::new("retired_bulk")).unwrap();
        w.commit().unwrap();
    }
    let from = Database::open(&path).unwrap();
    let plan = plan_history(&from).unwrap();
    let to = Database::create(root.join("history.db")).unwrap();
    copy_history(&from, &to, &plan, small()).unwrap();
    verify_history(&from, &to, &plan).unwrap();
    assert_eq!(count(&to, "retired"), 1);
    drop((from, to));
    let _ = std::fs::remove_dir_all(&root);
}
