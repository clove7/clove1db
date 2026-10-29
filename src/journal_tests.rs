use crate::{
    entity::Entity,
    storage::{DatabaseConfig, Storage, StorageConfig},
};
use redb::ReadableTable;
use serde::{Deserialize, Serialize};
#[derive(Default, Clone, Serialize, Deserialize)]
struct Note {
    id: String,
}
impl Entity for Note {
    fn entity_id(&self) -> &str {
        &self.id
    }
}
fn storage(name: &str) -> Storage {
    let path = std::env::temp_dir().join(format!("clove-journal-{name}-{}", uuid::Uuid::new_v4()));
    Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("records", "store")
                .dir_path(path)
                .has_cache(false)
                .register::<Note>("notes"),
        )
        .build()
        .unwrap()
}
#[test]
fn initialized_sequence_tables() {
    let s = storage("init");
    let db = s.db_manager("store").db().unwrap();
    let tx = db.begin_read().unwrap();
    let t = tx
        .open_table(redb::TableDefinition::<&str, &[u8]>::new("__seq"))
        .unwrap();
    assert_eq!(t.get("head").unwrap().unwrap().value(), 0u64.to_be_bytes());
}

fn head(s: &Storage) -> u64 {
    let d = s.db_manager("store").db().unwrap();
    crate::journal::read_number(&d.begin_read().unwrap(), "head").unwrap()
}
fn effects(s: &Storage) -> Vec<crate::journal::ChangeKind> {
    let d = s.db_manager("store").db().unwrap();
    let tx = d.begin_read().unwrap();
    let t = tx.open_table(crate::journal::CHANGES).unwrap();
    t.iter()
        .unwrap()
        .map(|r| crate::journal::ChangeKind::decode(r.unwrap().1.value()).unwrap())
        .collect()
}
#[test]
fn journal_exact_write_paths_and_rollback() {
    let s = storage("paths");
    let db = s.db_manager("store");
    let _reader = db.register_consumer("reader").unwrap();
    let t = redb::TableDefinition::new("notes");
    db.set(t, "notes", "a", b"one".to_vec()).unwrap();
    assert_eq!(head(&s), 1);
    db.delete(t, "notes", "missing").unwrap();
    assert_eq!(head(&s), 1);
    db.commit_batch_atomic(
        &[
            ("notes".into(), "a".into(), b"two".to_vec()),
            ("notes".into(), "b".into(), b"three".to_vec()),
        ],
        &[
            ("notes".into(), "a".into()),
            ("notes".into(), "absent".into()),
        ],
    )
    .unwrap();
    assert_eq!(head(&s), 4);
    assert_eq!(effects(&s).len(), 4);
    let d = db.db().unwrap();
    let failed: crate::units::Result<()> =
        crate::journal::write(&d, crate::journal::Retention::Default, |tx, c| {
            tx.open_table(t)?.insert("failed", b"data".as_slice())?;
            c.push(crate::journal::ChangeKind::Delete {
                table: "notes".into(),
                key: "b".into(),
            });
            Err(crate::units::ClError::Validation("abort".into()))
        });
    assert!(failed.is_err());
    drop(d);
    assert_eq!(head(&s), 4);
    assert!(db.get_raw("notes", "failed").unwrap().is_none());
    db.delete_raw("notes", "b").unwrap();
    assert_eq!(head(&s), 5);
}

#[test]
fn reset_is_one_immutable_generation() {
    let s = storage("reset");
    let db = s.db_manager("store");
    let _reader = db.register_consumer("reader").unwrap();
    db.replace_table("notes", &[("a".into(), b"old".to_vec())])
        .unwrap();
    assert_eq!(head(&s), 1);
    let c = effects(&s).pop().unwrap();
    let crate::journal::ChangeKind::TableReset { snapshot, .. } = c else {
        panic!("reset expected")
    };
    db.commit_batch_atomic(&[("notes".into(), "a".into(), b"new".to_vec())], &[])
        .unwrap();
    let d = db.db().unwrap();
    let tx = d.begin_read().unwrap();
    let t = tx
        .open_table(redb::TableDefinition::<&str, &[u8]>::new(&snapshot))
        .unwrap();
    assert_eq!(t.get("a").unwrap().unwrap().value(), b"old");
    assert_eq!(head(&s), 2);
}

#[test]
fn immutable_blob_versions_and_descriptor_order() {
    use std::io::Read;
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("records", "store")
                .dir_path(root)
                .blob_enabled(true)
                .register_blob::<Note>("notes"),
        )
        .build()
        .unwrap();
    let db = s.db_manager("store");
    let _reader = db.register_consumer("reader").unwrap();
    let d = s.domain::<Note>();
    d.set_with_blob("a", &Note { id: "a".into() }, b"old")
        .unwrap();
    let c = effects(&s);
    let crate::journal::ChangeKind::BlobPut { blob_id, .. } = &c[0] else {
        panic!("blob first")
    };
    let old_id = blob_id.clone();
    d.set_with_blob("a", &Note { id: "a".into() }, b"new")
        .unwrap();
    let mut old = Vec::new();
    db.open_blob_version("notes", &old_id)
        .unwrap()
        .read_to_end(&mut old)
        .unwrap();
    assert_eq!(old, b"old");
    d.delete("a").unwrap();
    assert!(d.open_blob("a").is_err());
    assert_eq!(effects(&s).len(), 6);
    assert!(matches!(
        effects(&s)[5],
        crate::journal::ChangeKind::BlobDelete { .. }
    ));
}

#[test]
fn consumer_generation_ack_prune_and_consistent_view() {
    let s = storage("consumers");
    let db = s.db_manager("store");
    let a = db.register_consumer("a").unwrap();
    let b = db.register_consumer("b").unwrap();
    db.replace_table("notes", &[("a".into(), b"one".to_vec())])
        .unwrap();
    let view = db.read_view_at_head().unwrap();
    db.commit_batch_atomic(&[("notes".into(), "a".into(), b"two".to_vec())], &[])
        .unwrap();
    assert_eq!(view.head, 1);
    assert_eq!(view.get_raw("notes", "a").unwrap().unwrap(), b"one");
    assert_eq!(db.read_reset(&a, 1).unwrap()[0].1, b"one");
    db.ack(&a, 2).unwrap();
    assert_eq!(db.journal_stats().unwrap().floor, 1);
    db.ack(&b, 1).unwrap();
    assert_eq!(db.journal_stats().unwrap().floor, 2);
    assert!(db.read_reset(&a, 1).is_err());
    let new = db.register_consumer("a").unwrap();
    assert!(matches!(
        db.ack(&a, 2),
        Err(crate::units::ClError::ConsumerExpired)
    ));
    db.ack(&new, 2).unwrap();
    db.unregister_consumer("b").unwrap();
    assert_eq!(db.journal_stats().unwrap().journal_bytes, 0);
}
#[test]
fn retention_expires_oldest_and_unlimited_does_not() {
    let s = storage("cap");
    let mut db = s.db_manager("store").clone();
    db.set_journal_retention(crate::journal::Retention::Limit { max_bytes: 100 })
        .unwrap();
    let old = db.register_consumer("old").unwrap();
    db.commit_batch_atomic(&[("notes".into(), "a".into(), vec![0; 10])], &[])
        .unwrap();
    let newer = db.register_consumer("new").unwrap();
    db.commit_batch_atomic(&[("notes".into(), "b".into(), vec![0; 10])], &[])
        .unwrap();
    assert!(matches!(
        db.read_changes(&old, 0, 10),
        Err(crate::units::ClError::ConsumerExpired)
    ));
    assert!(db.read_changes(&newer, 1, 10).is_ok());
    assert!(db.ack(&old, 1).is_err());
    db.set_journal_retention(crate::journal::Retention::Unlimited)
        .unwrap();
    let token = db.register_consumer("unlimited").unwrap();
    for i in 0..10 {
        db.commit_batch_atomic(&[("notes".into(), i.to_string(), vec![0; 200])], &[])
            .unwrap();
    }
    assert_eq!(
        db.read_changes(&token, db.journal_head().unwrap() - 10, 20)
            .unwrap()
            .len(),
        10
    );
    assert_eq!(
        crate::journal::Retention::default(),
        crate::journal::Retention::Default
    );
    assert_eq!(crate::journal::DEFAULT_JOURNAL_MAX_BYTES, 268435456);
}
#[test]
fn internal_consumer_requests_rebuild_without_expiring() {
    let s = storage("internal");
    let mut db = s.db_manager("store").clone();
    db.set_journal_retention(crate::journal::Retention::Limit { max_bytes: 1 })
        .unwrap();
    let token = db.register_journal_consumer("index", true).unwrap();
    db.commit_batch_atomic(&[("notes".into(), "a".into(), vec![1; 2])], &[])
        .unwrap();
    assert!(matches!(
        db.read_changes(&token, 0, 10),
        Err(crate::units::ClError::ConsumerNeedsRebuild)
    ));
    assert_eq!(db.journal_stats().unwrap().journal_bytes, 0);
}

#[cfg(feature = "crash-inject")]
#[path = "journal_crash_tests.rs"]
mod crashes;

#[test]
fn concurrent_writes_and_read_views_share_a_sequence() {
    let s = storage("concurrent");
    let db = s.db_manager("store").clone();
    let token = db.register_consumer("reader").unwrap();
    let writer = db.clone();
    let thread = std::thread::spawn(move || {
        for i in 1..=200u64 {
            writer
                .commit_batch_atomic(
                    &[("notes".into(), "head".into(), i.to_be_bytes().to_vec())],
                    &[],
                )
                .unwrap();
        }
    });
    for _ in 0..300 {
        let view = db.read_view_at_head().unwrap();
        let value = view
            .get_raw("notes", "head")
            .unwrap()
            .map(|v| u64::from_be_bytes(v.try_into().unwrap()))
            .unwrap_or(0);
        assert_eq!(view.head, value);
    }
    thread.join().unwrap();
    let changes = db.read_changes(&token, 0, 1000).unwrap();
    assert_eq!(changes.len(), 200);
    for (i, c) in changes.iter().enumerate() {
        assert_eq!(c.seq, i as u64 + 1);
    }
}

impl crate::dto::InputDto<Note> for Note {
    fn into_entity(self) -> crate::units::Result<Note> {
        Ok(self)
    }
}
impl crate::dto::OutputDto<Note> for Note {
    fn from_entity(n: Note) -> Self {
        n
    }
}
#[test]
fn domain_bulk_restore_and_metadata_have_exact_effects() {
    let path = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("records", "store")
                .dir_path(path)
                .backup_enabled(true)
                .register::<Note>("notes"),
        )
        .build()
        .unwrap();
    let d = s.domain::<Note>();
    let db = s.db_manager("store");
    let token = db.register_consumer("reader").unwrap();
    let _: Note = d.create(Note { id: "a".into() }).unwrap();
    assert_eq!(head(&s), 1);
    let _: Note = d.update("a", Note { id: "b".into() }).unwrap();
    assert_eq!(head(&s), 2);
    d.delete("a").unwrap();
    assert_eq!(head(&s), 3);
    d.restore_by_version("a", 1).unwrap();
    assert_eq!(head(&s), 4);
    d.restore_at("a", i64::MAX).unwrap();
    assert_eq!(head(&s), 5);
    let (_, bulk): (Vec<Note>, String) = d
        .update_bulk(vec![("a".into(), Note { id: "x".into() })])
        .unwrap();
    assert_eq!(head(&s), 6);
    d.restore_bulk(&bulk).unwrap();
    assert_eq!(head(&s), 7);
    d.restore_by_version("a", 3).unwrap();
    assert_eq!(head(&s), 8);
    d.restore_by_version("a", 3).unwrap();
    assert_eq!(head(&s), 8);
    let (_, deleted): (Vec<Note>, String) = d
        .update_bulk(vec![(
            "missing".into(),
            Note {
                id: "missing".into(),
            },
        )])
        .unwrap();
    assert_eq!(head(&s), 9);
    assert!(d.restore_bulk(&deleted).is_err());
    assert_eq!(head(&s), 9);
    let meta = db.read_meta().unwrap().unwrap();
    db.write_meta(&meta).unwrap();
    assert_eq!(head(&s), 9);
    let changes = db.read_changes(&token, 0, 100).unwrap();
    assert_eq!(changes.len(), 9);
    for (i, c) in changes.iter().enumerate() {
        assert_eq!(c.seq, i as u64 + 1);
    }
    assert!(matches!(changes[2].kind, crate::ChangeKind::Delete { .. }));
    assert!(matches!(changes[7].kind, crate::ChangeKind::Delete { .. }));
}
#[test]
fn split_batches_and_reserved_tables_are_exact() {
    let path = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("records", "store")
                .dir_path(path)
                .max_commit_batch_entries(2)
                .register::<Note>("notes"),
        )
        .build()
        .unwrap();
    let db = s.db_manager("store");
    let token = db.register_consumer("reader").unwrap();
    let rows = (0..7)
        .map(|i| ("notes".into(), i.to_string(), vec![1]))
        .collect::<Vec<_>>();
    db.commit_batch(
        &rows,
        &[
            ("notes".into(), "0".into()),
            ("notes".into(), "absent".into()),
        ],
    )
    .unwrap();
    assert_eq!(head(&s), 8);
    assert_eq!(db.read_changes(&token, 0, 100).unwrap().len(), 8);
    assert!(
        db.commit_batch_atomic(&[("__bad".into(), "a".into(), vec![1])], &[])
            .is_err()
    );
    assert_eq!(head(&s), 8);
    let large = storage("mixed-append");
    let db = large.db_manager("store");
    let token = db.register_consumer("reader").unwrap();
    let n = crate::DEFAULT_MAX_COMMIT_BATCH_ENTRIES + 1;
    db.commit_batch(
        &(0..n)
            .map(|i| ("notes".into(), i.to_string(), vec![1]))
            .collect::<Vec<_>>(),
        &[],
    )
    .unwrap();
    assert_eq!(db.journal_head().unwrap(), n as u64);
    assert_eq!(db.count_keys("notes").unwrap(), n);
    assert_eq!(db.read_changes(&token, 0, n).unwrap().len(), n);
}

/// Under `--cfg clove_test_encrypt_all` every database starts encrypted; a test that needs a plain file says so
/// (each use is listed in 7-5-plain-only.md).
#[allow(dead_code)]
fn plain(db: DatabaseConfig) -> DatabaseConfig {
    #[cfg(clove_test_encrypt_all)]
    {
        db.plain()
    }
    #[cfg(not(clove_test_encrypt_all))]
    {
        db
    }
}

#[test]
fn orphan_cleanup_keeps_current_and_retained_versions() {
    use std::io::Read;
    let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let open = || {
        Storage::builder(StorageConfig::default())
            .add_database(
                plain(DatabaseConfig::new("records", "store"))
                    .dir_path(root.clone())
                    .blob_enabled(true)
                    .register_blob::<Note>("notes"),
            )
            .build()
            .unwrap()
    };
    let s = open();
    let db = s.db_manager("store");
    let token = db.register_consumer("reader").unwrap();
    let d = s.domain::<Note>();
    d.set_with_blob("a", &Note { id: "a".into() }, b"old")
        .unwrap();
    d.set_with_blob("a", &Note { id: "a".into() }, b"new")
        .unwrap();
    let old = db.read_changes(&token, 0, 10).unwrap();
    let crate::ChangeKind::BlobPut { blob_id, .. } = &old[0].kind else {
        panic!()
    };
    let old_id = blob_id.clone();
    let path = db.blobs_root().unwrap().join("notes");
    std::fs::write(path.join("orphan"), b"unpublished").unwrap();
    s.close();
    drop(s);
    let s = open();
    let db = s.db_manager("store");
    assert!(!path.join("orphan").exists());
    assert!(db.open_blob_version("notes", &old_id).is_ok());
    db.ack(&token, 4).unwrap();
    s.close();
    drop(s);
    let s = open();
    let db = s.db_manager("store");
    assert!(!path.join(&old_id).exists());
    let mut bytes = Vec::new();
    db.open_blob("notes", "a")
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes, b"new");
    db.replace_table("notes", &[]).unwrap();
    assert!(db.open_blob("notes", "a").is_err());
}

#[test]
fn reset_blob_references_are_immutable() {
    let path = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("records", "store")
                .dir_path(path)
                .blob_enabled(true)
                .register_blob::<Note>("notes"),
        )
        .build()
        .unwrap();
    let d = s.domain::<Note>();
    let db = s.db_manager("store");
    let token = db.register_consumer("reader").unwrap();
    d.set_with_blob("a", &Note { id: "a".into() }, b"old")
        .unwrap();
    let view = db.read_view_at_head().unwrap();
    let reference = view.blob_reference("notes", "a").unwrap().unwrap();
    drop(view);
    db.replace_table("notes", &db.list_entries("notes").unwrap())
        .unwrap();
    let seq = db.journal_head().unwrap();
    d.set_with_blob("a", &Note { id: "a".into() }, b"new")
        .unwrap();
    let refs = db.read_reset_blobs(&token, seq).unwrap();
    assert_eq!(refs, vec![("a".into(), reference.0, reference.1)]);
}

#[test]
fn standalone_blob_copy_and_delete_paths_are_journaled() {
    let path = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("records", "store")
                .dir_path(path)
                .blob_enabled(true)
                .register_blob::<Note>("notes"),
        )
        .build()
        .unwrap();
    let d = s.domain::<Note>();
    let db = s.db_manager("store");
    let token = db.register_consumer("reader").unwrap();
    let _: Note = d
        .create_with_blob(Note { id: "a".into() }, b"created".to_vec())
        .unwrap();
    db.write_blob("notes", "raw", b"raw").unwrap();
    db.copy_blob("notes", "raw", db, "notes", "copy").unwrap();
    assert!(db.delete_blob("notes", "raw").unwrap());
    db.delete_raw("notes", "copy").unwrap();
    d.delete("a").unwrap();
    let changes = db.read_changes(&token, 0, 100).unwrap();
    assert_eq!(changes.len(), 8);
    assert_eq!(db.journal_head().unwrap(), 8);
    assert!(matches!(changes[0].kind, crate::ChangeKind::BlobPut { .. }));
    assert!(matches!(changes[1].kind, crate::ChangeKind::Upsert { .. }));
    assert!(matches!(changes[6].kind, crate::ChangeKind::Delete { .. }));
    assert!(matches!(
        changes[7].kind,
        crate::ChangeKind::BlobDelete { .. }
    ));
}

#[derive(Default, Clone, Serialize, Deserialize)]
struct EditedNote {
    id: String,
    flag: bool,
}
impl Entity for EditedNote {
    fn entity_id(&self) -> &str {
        &self.id
    }
}
impl crate::migration::MigrateTo<EditedNote> for Note {
    fn migrate_json(
        value: serde_json::Value,
    ) -> crate::units::Result<crate::migration::MigrateOutcome<serde_json::Value>> {
        let n: Note = serde_json::from_value(value)?;
        crate::migration::migrate_value(EditedNote {
            id: n.id,
            flag: true,
        })
    }
}
#[test]
fn migration_batch_and_runner_each_publish_one_reset() {
    let s = storage("migration-journal");
    let db = s.db_manager("store");
    let token = db.register_consumer("reader").unwrap();
    let writes = (0..3)
        .map(|i| {
            let n = Note { id: i.to_string() };
            (
                "notes".into(),
                n.id.clone(),
                serde_json::to_vec(&n).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    db.commit_batch_atomic(&writes, &[]).unwrap();
    let mut batch = crate::migration::batch::MigrationBatch::new();
    batch.stage_write(
        "notes",
        "0",
        serde_json::to_vec(&Note { id: "0".into() }).unwrap(),
    );
    batch.commit(db).unwrap();
    assert_eq!(db.journal_head().unwrap(), 4);
    s.migrate::<Note, EditedNote>()
        .from_db("store", "notes")
        .execute()
        .unwrap();
    assert_eq!(db.journal_head().unwrap(), 5);
    let changes = db.read_changes(&token, 3, 10).unwrap();
    assert_eq!(changes.len(), 2);
    assert!(
        changes
            .iter()
            .all(|c| matches!(c.kind, crate::ChangeKind::TableReset { .. }))
    );
    assert_eq!(db.read_reset(&token, 4).unwrap().len(), 3);
    assert!(
        db.list_entries("notes")
            .unwrap()
            .iter()
            .all(|(_, v)| serde_json::from_slice::<EditedNote>(v).unwrap().flag)
    );
    db.rewrite_backup_table("notes", "other").unwrap();
    assert_eq!(db.journal_head().unwrap(), 5);
}
#[test]
fn bulk_restore_of_deleted_version_emits_one_delete() {
    let path = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
    let s = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("records", "store")
                .dir_path(path)
                .backup_enabled(true)
                .register::<Note>("notes"),
        )
        .build()
        .unwrap();
    let d = s.domain::<Note>();
    let db = s.db_manager("store");
    let token = db.register_consumer("reader").unwrap();
    d.repo().set("a", &Note { id: "a".into() }).unwrap();
    d.delete("a").unwrap();
    let bulk = d.repo().set_bulk(vec![("a".into(), 2)]).unwrap();
    d.repo().set("a", &Note { id: "a".into() }).unwrap();
    d.restore_bulk(&bulk).unwrap();
    assert_eq!(db.journal_head().unwrap(), 4);
    assert!(db.get_raw("notes", "a").unwrap().is_none());
    assert!(matches!(
        db.read_changes(&token, 3, 10).unwrap()[0].kind,
        crate::ChangeKind::Delete { .. }
    ));
}

fn assert_unobserved_journal_empty(s: &Storage, expected_head: u64) {
    use redb::TableHandle;
    let db = s.db_manager("store");
    let stats = db.journal_stats().unwrap();
    assert_eq!(stats.head, expected_head);
    assert_eq!(stats.journal_bytes, 0);
    assert_eq!(stats.floor, expected_head + 1);
    assert!(effects(s).is_empty());
    let d = db.db().unwrap();
    let tx = d.begin_read().unwrap();
    assert!(
        tx.list_tables()
            .unwrap()
            .all(|t| !t.name().starts_with("__reset_"))
    );
}

fn check_unobserved_writes_are_pruned(retention: crate::Retention) {
    let s = storage("unobserved");
    let mut db = s.db_manager("store").clone();
    db.set_journal_retention(retention).unwrap();
    let t = redb::TableDefinition::new("notes");
    db.set(t, "notes", "a", b"one".to_vec()).unwrap();
    assert_unobserved_journal_empty(&s, 1);
    db.delete(t, "notes", "a").unwrap();
    assert_unobserved_journal_empty(&s, 2);
    db.commit_batch_atomic(
        &[
            ("notes".into(), "a".into(), b"two".to_vec()),
            ("notes".into(), "b".into(), b"three".to_vec()),
        ],
        &[],
    )
    .unwrap();
    assert_unobserved_journal_empty(&s, 4);
    let rows = (0..513)
        .map(|i| ("notes".into(), i.to_string(), vec![1]))
        .collect::<Vec<_>>();
    db.commit_batch(&rows, &[]).unwrap();
    assert_unobserved_journal_empty(&s, 517);
    db.replace_table("notes", &[("a".into(), b"reset".to_vec())])
        .unwrap();
    assert_unobserved_journal_empty(&s, 518);
    assert_eq!(
        db.list_entries("notes").unwrap(),
        vec![("a".into(), b"reset".to_vec())]
    );
    let token = db.register_consumer("late").unwrap();
    assert!(db.read_changes(&token, 518, 10).unwrap().is_empty());
    assert_eq!(db.read_view_at_head().unwrap().head, 518);
}

#[test]
fn unobserved_writes_are_pruned_default() {
    check_unobserved_writes_are_pruned(crate::Retention::Default);
}

#[test]
fn unobserved_writes_are_pruned_unlimited() {
    check_unobserved_writes_are_pruned(crate::Retention::Unlimited);
}

#[test]
fn active_consumers_keep_changes_and_reset_until_smallest_ack() {
    for retention in [crate::Retention::Default, crate::Retention::Unlimited] {
        let s = storage("active-pruning");
        let mut db = s.db_manager("store").clone();
        db.set_journal_retention(retention).unwrap();
        let slow = db.register_consumer("slow").unwrap();
        let fast = db.register_consumer("fast").unwrap();
        db.set(
            redb::TableDefinition::new("notes"),
            "notes",
            "a",
            b"one".to_vec(),
        )
        .unwrap();
        db.replace_table("notes", &[("a".into(), b"snapshot".to_vec())])
            .unwrap();
        assert_eq!(db.read_changes(&slow, 0, 10).unwrap().len(), 2);
        assert!(db.journal_stats().unwrap().journal_bytes > 0);
        db.ack(&fast, 2).unwrap();
        assert_eq!(
            db.read_reset(&slow, 2).unwrap(),
            vec![("a".into(), b"snapshot".to_vec())]
        );
        db.ack(&slow, 1).unwrap();
        db.commit_batch_atomic(&[("notes".into(), "b".into(), b"later".to_vec())], &[])
            .unwrap();
        assert_eq!(db.journal_stats().unwrap().floor, 2);
        assert_eq!(db.read_changes(&slow, 1, 10).unwrap().len(), 2);
        assert_eq!(db.read_reset(&slow, 2).unwrap().len(), 1);
        db.ack(&slow, 3).unwrap();
        assert_eq!(db.journal_stats().unwrap().floor, 3);
        assert!(db.read_reset(&fast, 2).is_err());
        db.unregister_consumer("fast").unwrap();
        assert_unobserved_journal_empty(&s, 3);
        db.unregister_consumer("slow").unwrap();
        db.set(
            redb::TableDefinition::new("notes"),
            "notes",
            "c",
            b"unobserved".to_vec(),
        )
        .unwrap();
        assert_unobserved_journal_empty(&s, 4);
    }
}
