//! The hooks of the copy: a change rewrites the rows of some tables on the way, and everything it
//! does not rewrite stays byte for byte. With no hooks the copy is the one that was already there.
use super::convert::{
    MainHooks, NoHooks, copy_main, copy_main_with, plan_main, plan_main_with, verify_main, verify_main_with,
};
use super::convert_tests::{history_file, main_file, small, source};
use super::history::{HistoryHooks, copy_history_with, plan_history, verify_history, verify_history_with};
use crate::units::{ClError, Result};
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};

#[allow(non_snake_case)]
fn BYTES(name: &str) -> TableDefinition<'_, &str, &[u8]> {
    TableDefinition::new(name)
}

/// Appends a space (valid JSON, other bytes) to the rows of `notes` whose key starts with `a1`.
#[derive(Default)]
struct Spaces {
    mapped: Vec<String>,
    checked: usize,
    meta_seen: bool,
}

impl MainHooks for Spaces {
    fn changes(&self, table: &str) -> bool {
        table == "notes" || table == "_clove_meta"
    }
    fn map_row(&mut self, table: &str, key: &str, old: &[u8]) -> Result<Option<Vec<u8>>> {
        if table == "_clove_meta" {
            self.meta_seen = true;
            return Ok(None);
        }
        if key.starts_with("a1") {
            self.mapped.push(key.to_string());
            let mut new = old.to_vec();
            new.push(b' ');
            return Ok(Some(new));
        }
        Ok(None)
    }
    fn extra_tables(&mut self, to: &Database) -> Result<()> {
        let write = to.begin_write().map_err(super::rows::io)?;
        write.open_table(BYTES("__field_keys")).map_err(super::rows::io)?.insert("lock", b"sealed".as_slice()).map_err(super::rows::io)?;
        write.commit().map_err(super::rows::io)?;
        Ok(())
    }
    fn extra_names(&self) -> Vec<String> {
        vec!["__field_keys".to_string()]
    }
    fn verify_row(&mut self, table: &str, key: &str, old: &[u8], new: &[u8]) -> Result<()> {
        self.checked += 1;
        let expected: Vec<u8> = if table == "notes" && key.starts_with("a1") { [old, b" "].concat() } else { old.to_vec() };
        if new == expected.as_slice() {
            Ok(())
        } else {
            Err(ClError::MigrationError(format!("{table}/{key} is not what the change makes of it")))
        }
    }
}

#[test]
fn a_table_the_hooks_rewrite_changes_row_by_row_and_every_other_byte_stays() {
    let (root, _, _) = source();
    let from = Database::open(main_file(&root)).unwrap();
    let plan = plan_main(&from).unwrap();
    let to = Database::create(root.join("new.db")).unwrap();
    let mut hooks = Spaces::default();
    copy_main_with(&from, &to, &plan, small(), &mut hooks).unwrap();
    // the rows the hooks named: a10 .. a19 minus the three deleted before (a00 to a02 are gone)
    assert_eq!(hooks.mapped.len(), 10);
    assert!(hooks.meta_seen);
    verify_main_with(&from, &to, &plan, &mut hooks).unwrap();
    assert!(hooks.checked >= 22, "every row of a rewritten table passes through the check: {}", hooks.checked);
    // the rewritten rows are in the new file, the others are as they were
    let read = to.begin_read().unwrap();
    let notes = read.open_table(BYTES("notes")).unwrap();
    let old_read = from.begin_read().unwrap();
    let old_notes = old_read.open_table(BYTES("notes")).unwrap();
    assert_eq!(notes.len().unwrap(), old_notes.len().unwrap());
    for row in old_notes.iter().unwrap() {
        let (k, v) = row.unwrap();
        let new = notes.get(k.value()).unwrap().unwrap().value().to_vec();
        let want = if k.value().starts_with("a1") { [v.value(), b" "].concat() } else { v.value().to_vec() };
        assert_eq!(new, want, "{}", k.value());
    }
    // the table the hooks wrote whole is there, and the plain check would not have accepted it
    assert_eq!(read.open_table(BYTES("__field_keys")).unwrap().len().unwrap(), 1);
    // the log's image of the table is taken from the table as the hooks left it
    let log = read.open_table(crate::journal::CHANGES).unwrap();
    let first = crate::journal::ChangeKind::decode(log.iter().unwrap().next().unwrap().unwrap().1.value()).unwrap();
    let crate::journal::ChangeKind::TableReset { snapshot, .. } = first else { panic!("not a reset") };
    {
        let image = read.open_table(TableDefinition::<&str, &[u8]>::new(&snapshot)).unwrap();
        assert_eq!(image.get("a10").unwrap().unwrap().value().last(), Some(&b' '));
    }
    drop((read, notes, old_read, old_notes, log, from, to));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_check_without_the_hooks_refuses_what_the_hooks_made() {
    let (root, _, _) = source();
    let from = Database::open(main_file(&root)).unwrap();
    let plan = plan_main(&from).unwrap();
    let to = Database::create(root.join("new.db")).unwrap();
    let mut hooks = Spaces::default();
    copy_main_with(&from, &to, &plan, small(), &mut hooks).unwrap();
    // the plain check compares bytes: it finds the rows that changed
    assert!(verify_main(&from, &to, &plan).is_err());
    // the hooks' check without the name of the table they wrote: nothing accounts for it
    struct Forgets(Spaces);
    impl MainHooks for Forgets {
        fn changes(&self, t: &str) -> bool {
            self.0.changes(t)
        }
        fn verify_row(&mut self, t: &str, k: &str, o: &[u8], n: &[u8]) -> Result<()> {
            self.0.verify_row(t, k, o, n)
        }
    }
    assert!(verify_main_with(&from, &to, &plan, &mut Forgets(Spaces::default())).is_err());
    // and a check that finds a row not as the change makes it
    {
        let w = to.begin_write().unwrap();
        w.open_table(BYTES("notes")).unwrap().insert("a10", b"{}".as_slice()).unwrap();
        w.commit().unwrap();
    }
    assert!(verify_main_with(&from, &to, &plan, &mut Spaces::default()).is_err());
    drop((from, to));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn with_no_hooks_the_copy_is_the_one_that_was_there() {
    let (root, _, _) = source();
    let from = Database::open(main_file(&root)).unwrap();
    let plan = plan_main(&from).unwrap();
    let (a, b) = (Database::create(root.join("a.db")).unwrap(), Database::create(root.join("b.db")).unwrap());
    copy_main(&from, &a, &plan, small()).unwrap();
    copy_main_with(&from, &b, &plan, small(), &mut NoHooks).unwrap();
    verify_main(&from, &a, &plan).unwrap();
    verify_main_with(&from, &b, &plan, &mut NoHooks).unwrap();
    for name in ["notes", "tags", "_clove_meta"] {
        let (ra, rb) = (a.begin_read().unwrap(), b.begin_read().unwrap());
        let (ta, tb) = (ra.open_table(BYTES(name)).unwrap(), rb.open_table(BYTES(name)).unwrap());
        let rows = |t: &redb::ReadOnlyTable<&str, &[u8]>| t.iter().unwrap().map(|r| { let (k, v) = r.unwrap(); (k.value().to_string(), v.value().to_vec()) }).collect::<Vec<_>>();
        assert_eq!(rows(&ta), rows(&tb), "{name}");
    }
    drop((from, a, b));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_table_with_protected_fields_is_planned_only_when_the_change_says_it_handles_it() {
    use crate::{
        CloveFields,
        crypto::{CipherKind, HkdfHash, Key32, KeySuite},
        encrypted_store::{EncryptionConfig, KeySource},
        entity::Entity,
        field_crypto::Sealed,
        storage::{DatabaseConfig, Storage, StorageConfig},
    };
    use serde::{Deserialize, Serialize};
    #[derive(Clone, Default, Debug, Serialize, Deserialize, CloveFields)]
    struct Person {
        id: String,
        #[clove(encrypt, id = 1)]
        phone: Sealed<String>,
    }
    impl Entity for Person {
        fn entity_id(&self) -> &str {
            &self.id
        }
    }
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let keys = EncryptionConfig {
        suite: KeySuite { cipher: CipherKind::Aes256GcmSiv, hkdf: HkdfHash::Sha256 },
        read: Some(KeySource::Raw(Key32::from_bytes(&[5; 32]))),
        search: Some(KeySource::Raw(Key32::from_bytes(&[6; 32]))),
    };
    let db = DatabaseConfig::new("records", "store").dir_path(root.clone()).has_cache(false);
    #[cfg(clove_test_encrypt_all)]
    let db = db.plain();
    let db = db.field_encryption(keys).register_sealed::<Person>("people");
    Storage::builder(StorageConfig::default()).add_database(db).build().unwrap().close();
    let from = Database::open(main_file(&root)).unwrap();
    let refused = plan_main(&from);
    assert!(matches!(&refused, Err(ClError::MigrationError(m)) if m.contains("protected fields")), "{refused:?}");
    let plan = plan_main_with(&from, true).unwrap();
    assert_eq!(plan.user_tables, vec!["people".to_string()]);
    // the table that holds the keys of the protected fields is part of the plan
    assert!(plan.items.iter().any(|i| i.name == "__field_keys"));
    drop(from);
    let _ = std::fs::remove_dir_all(&root);
}

/// Appends a space to the saved versions of `notes`.
#[derive(Default)]
struct HistorySpaces {
    mapped: usize,
    checked: usize,
}

impl HistoryHooks for HistorySpaces {
    fn changes(&self, table: &str) -> bool {
        table == "notes"
    }
    fn map_row(&mut self, _table: &str, _key: &str, old: &[u8]) -> Result<Option<Vec<u8>>> {
        self.mapped += 1;
        Ok(Some([old, b" "].concat()))
    }
    fn verify_row(&mut self, _table: &str, _key: &str, old: &[u8], new: &[u8]) -> Result<()> {
        self.checked += 1;
        if new == [old, b" "].concat().as_slice() { Ok(()) } else { Err(ClError::MigrationError("a saved version is not what the change makes of it".into())) }
    }
}

#[test]
fn the_saved_versions_of_a_table_pass_through_the_hooks_and_the_counters_do_not() {
    let (root, _, _) = source();
    let from = Database::open(history_file(&root)).unwrap();
    let plan = plan_history(&from).unwrap();
    let to = Database::create(root.join("history.db")).unwrap();
    let mut hooks = HistorySpaces::default();
    copy_history_with(&from, &to, &plan, small(), &mut hooks).unwrap();
    assert_eq!(hooks.mapped, 28, "25 puts and 3 deletes of notes");
    verify_history_with(&from, &to, &plan, &mut hooks).unwrap();
    assert_eq!(hooks.checked, 28);
    // the plain check finds what the hooks changed; the counters and the other table are as they were
    assert!(verify_history(&from, &to, &plan).is_err());
    let read = to.begin_read().unwrap();
    assert_eq!(read.open_table(TableDefinition::<&str, u64>::new("notes_version")).unwrap().len().unwrap(), 25);
    drop((read, from, to));
    let _ = std::fs::remove_dir_all(&root);
}
