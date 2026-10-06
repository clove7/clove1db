use crate::{RedbOptions, backup::BackupManager, durability::DurabilityMode};
use redb::{ReadableDatabase, ReadableTableMetadata, TableDefinition};
use std::path::PathBuf;
const NOTES: TableDefinition<&str, &[u8]> = TableDefinition::new("notes");
fn manager(tag: &str) -> BackupManager {
    let dir = PathBuf::from("target/test_backup").join(tag);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let m = BackupManager::new(
        &dir.join("notes.bak"),
        true,
        DurabilityMode::Strict,
        RedbOptions::default(),
    )
    .unwrap();
    m.init_table("notes").unwrap();
    m
}
fn insert(m: &BackupManager, key: &str, bytes: &[u8]) {
    let db = m.db().unwrap();
    let tx = db.begin_write().unwrap();
    {
        tx.open_table(NOTES).unwrap().insert(key, bytes).unwrap();
    }
    tx.commit().unwrap();
}
fn legacy() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"version":2,"timestamp":123,"date":"original date","operation":"Set","table":"notes","key":"a","data":b" [1, 2, 3] ".to_vec()})).unwrap()
}
#[test]
fn codec_history_and_rename_read_every_legacy_format() {
    let m = manager("codec_legacy");
    insert(&m, "a:1", br#"{"z":1.00,"id":"a"}"#);
    insert(&m, "a:2", &legacy());
    let rows = m.history(NOTES, "a").unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[0].data.as_deref(),
        Some(br#"{"z":1.00,"id":"a"}"#.as_slice())
    );
    assert_eq!(m.view_by_version(NOTES, "a", 1).unwrap(), rows[0].data);
    m.rewrite_table_name("notes", "articles").unwrap();
    let renamed = m.history(TableDefinition::new("articles"), "a").unwrap();
    assert_eq!(renamed.len(), 2);
    assert!(renamed.iter().all(|r| r.table == "articles"));
    assert!(
        renamed[0].date_from_migration && renamed[0].timestamp > 0 && !renamed[0].date.is_empty()
    );
    assert_eq!(renamed[1].date, "original date");
    assert!(m.history(NOTES, "a").unwrap().is_empty());
}
#[test]
fn codec_history_reports_unreadable_count_and_rename_aborts() {
    let m = manager("codec_unreadable");
    insert(&m, "a:1", &legacy());
    insert(&m,"a:2", br#"{"version":2,"timestamp":123,"date":"d","operation":"Set","table":"notes","key":"a","data":"wrong type"}"#);
    insert(&m,"a:3", br#"{"version":3,"timestamp":123,"date":"d","operation":"Set","table":"notes","key":"a","data":[999]}"#);
    let error = m.history(NOTES, "a").unwrap_err().to_string();
    assert!(error.contains("2 unreadable"), "{error}");
    assert!(m.rewrite_table_name("notes", "articles").is_err());
    let db = m.db().unwrap();
    let tx = db.begin_read().unwrap();
    assert_eq!(tx.open_table(NOTES).unwrap().len().unwrap(), 3);
}

#[test]
fn v2_payloads_are_byte_exact_through_history_views_and_bulk_restore() {
    let m = manager("v2_payloads");
    let payloads: &[&[u8]] = &[
        b" \n {\"z\":1.2300,\"a\":2e+03,\"s\":\"\\u0061\"} \t ",
        b" [123, 34, 105] \n",
        b" null \t",
        &[0, 255, 128, 1],
        b"",
    ];
    for (i, payload) in payloads.iter().enumerate() {
        let key = format!("p{i}");
        m.record_set(NOTES, "notes", &key, payload.to_vec())
            .unwrap();
        let rows = m.history(NOTES, &key).unwrap();
        assert_eq!(rows[0].data.as_deref(), Some(*payload));
        assert_eq!(
            m.view_by_version(NOTES, &key, 1).unwrap().as_deref(),
            Some(*payload)
        );
        assert_eq!(
            m.view_at(NOTES, &key, i64::MAX).unwrap().as_deref(),
            Some(*payload)
        );
        let db = m.db().unwrap();
        let tx = db.begin_read().unwrap();
        let row = tx
            .open_table(NOTES)
            .unwrap()
            .get(format!("{key}:1").as_str())
            .unwrap()
            .unwrap()
            .value()
            .to_vec();
        let wire: serde_json::Value = serde_json::from_slice(&row).unwrap();
        assert!(wire.get("data").is_none(), "v2 must not contain data");
        assert!(wire.get("date_from_migration").is_none());
        if serde_json::from_slice::<serde_json::Value>(payload).is_ok() {
            assert!(wire.get("doc").is_some());
        } else {
            assert!(wire.get("data_b64").is_some());
        }
    }
    let entries = (0..payloads.len()).map(|i| (format!("p{i}"), 1)).collect();
    let id = m.write_bulk("notes", entries).unwrap();
    let restored = m.restore_bulk(NOTES, "notes", &id).unwrap();
    for (i, (_, data)) in restored.iter().enumerate() {
        assert_eq!(data.as_deref(), Some(payloads[i]));
    }
    m.record_delete(NOTES, "notes", "p0").unwrap();
    assert!(m.view_by_version(NOTES, "p0", 3).unwrap().is_none());
}
#[test]
fn a_failed_record_write_never_advances_the_version_counter() {
    let m = manager("version_atomic");
    let db = m.db().unwrap();
    let tx = db.begin_write().unwrap();
    {
        tx.open_table(TableDefinition::<&str, u64>::new("fault_numbers"))
            .unwrap();
    }
    tx.commit().unwrap();
    drop(db);
    assert!(
        m.record_set(
            TableDefinition::new("fault_numbers"),
            "notes",
            "a",
            b"{}".to_vec()
        )
        .is_err()
    );
    assert_eq!(m.current_version("notes", "a").unwrap(), 0);
    assert!(m.history(NOTES, "a").unwrap().is_empty());
}

use crate::{
    entity::Entity,
    storage::{DatabaseConfig, Storage, StorageConfig},
};
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct Note {
    id: String,
    title: String,
}
impl Entity for Note {
    fn entity_id(&self) -> &str {
        &self.id
    }
}
fn build(dir: &std::path::Path) -> Storage {
    Storage::builder(StorageConfig::default().change_dir_path(dir.to_path_buf()))
        .add_database(
            DatabaseConfig::new("notes", "notes")
                .backup_enabled(true)
                .register::<Note>("notes"),
        )
        .build()
        .unwrap()
}
fn mixed_fixture(tag: &str) -> (PathBuf, Vec<(String, Vec<u8>)>) {
    let dir = PathBuf::from("target/test_backup").join(tag);
    let _ = std::fs::remove_dir_all(&dir);
    let storage = build(&dir);
    let mut meta = storage.db_manager("notes").read_meta().unwrap().unwrap();
    meta.backup_format = "json_wrapped_v1".into();
    storage.db_manager("notes").write_meta(&meta).unwrap();
    storage.close();
    drop(storage);
    let path = dir.join("notes/notes.cldb.bak");
    let db = redb::Database::open(&path).unwrap();
    let tx = db.begin_write().unwrap();
    let records:Vec<(String,Vec<u8>)>=vec![("a:1".into(),b" \n {\"id\":\"a\",\"z\":1.00} \t".to_vec()),("a:2".into(),legacy()),
        ("b:1".into(),serde_json::to_vec(&serde_json::json!({"version":1,"timestamp":456,"date":"second date","operation":"Restore","table":"notes","key":"b","data":[0,255,128],"bulk_id":"batch","restored_version":7})).unwrap())];
    {
        let mut table = tx.open_table(NOTES).unwrap();
        for (k, v) in &records {
            table.insert(k.as_str(), v.as_slice()).unwrap();
        }
    }
    {
        let mut table = tx
            .open_table(TableDefinition::<&str, u64>::new("notes_version"))
            .unwrap();
        table.insert("a", 2).unwrap();
        table.insert("b", 1).unwrap();
    }
    tx.commit().unwrap();
    drop(db);
    (dir, records)
}
#[test]
fn conversion_preserves_every_record_and_marks_raw_dates_once() {
    let (dir, records) = mixed_fixture("mixed_conversion");
    let storage = build(&dir);
    assert_eq!(
        storage
            .db_manager("notes")
            .read_meta()
            .unwrap()
            .unwrap()
            .backup_format,
        "json_wrapped_v2",
        "{:?}",
        storage.db_manager("notes").read_meta().unwrap()
    );
    let manager = storage.db_manager("notes");
    let bm = manager.backup_manager.as_ref().unwrap();
    for (key, bytes) in &records {
        let before = crate::backup::codec::decode_record("notes", key, bytes).unwrap();
        let (id, v) = key.rsplit_once(':').unwrap();
        let after = manager
            .get_by_version(NOTES, id, v.parse().unwrap())
            .unwrap();
        assert_eq!(before.data, after.data);
        assert_eq!(before.operation, after.operation);
        assert_eq!(before.bulk_id, after.bulk_id);
        assert_eq!(before.restored_version, after.restored_version);
        if before.date_from_migration {
            assert!(after.timestamp > 0 && after.date_from_migration && !after.date.is_empty());
        } else {
            assert_eq!(before, after);
        }
    }
    assert_eq!(bm.current_version("notes", "a").unwrap(), 2);
    let first = bm.history(NOTES, "a").unwrap()[0].clone();
    assert!(
        storage
            .open_report()
            .iter()
            .any(|r| r.format_check && r.path.to_string_lossy().ends_with(".upgrading"))
    );
    storage.close();
    drop(storage);
    assert!(!dir.join("notes/notes.cldb.bak.upgrading").exists());
    let storage = build(&dir);
    assert!(storage.open_report().iter().all(|r| !r.format_check));
    assert_eq!(
        storage
            .db_manager("notes")
            .backup_manager
            .as_ref()
            .unwrap()
            .history(NOTES, "a")
            .unwrap()[0],
        first
    );
}

#[test]
fn conversion_verification_failure_keeps_original_bytes_and_retries() {
    use redb::ReadableTable;

    let (dir, records) = mixed_fixture("conversion_rejected");
    let path = dir.join("notes/notes.cldb.bak");
    let bulk_id = {
        let manager =
            BackupManager::new(&path, true, DurabilityMode::Strict, RedbOptions::default())
                .unwrap();
        manager
            .write_bulk("notes", vec![("a".into(), 2), ("b".into(), 1)])
            .unwrap()
    };
    let contents = |path: &std::path::Path| {
        let db = redb::ReadOnlyDatabase::open(path).unwrap();
        let read = db.begin_read().unwrap();
        let records = read
            .open_table(NOTES)
            .unwrap()
            .iter()
            .unwrap()
            .map(|entry| {
                let (key, value) = entry.unwrap();
                (key.value().to_string(), value.value().to_vec())
            })
            .collect::<Vec<_>>();
        let counters = read
            .open_table(TableDefinition::<&str, u64>::new("notes_version"))
            .unwrap()
            .iter()
            .unwrap()
            .map(|entry| {
                let (key, value) = entry.unwrap();
                (key.value().to_string(), value.value())
            })
            .collect::<Vec<_>>();
        let bulk = read
            .open_table(TableDefinition::<&str, &[u8]>::new("notes_bulk"))
            .unwrap()
            .iter()
            .unwrap()
            .map(|entry| {
                let (key, value) = entry.unwrap();
                (key.value().to_string(), value.value().to_vec())
            })
            .collect::<Vec<_>>();
        (records, counters, bulk)
    };
    let original_contents = contents(&path);
    assert_eq!(original_contents.0.len(), 3);
    assert_eq!(original_contents.1, vec![("a".into(), 2), ("b".into(), 1)]);
    assert_eq!(original_contents.2.len(), 1);
    assert_eq!(original_contents.2[0].0, bulk_id);
    let original = std::fs::read(&path).unwrap();

    crate::upgrade::backup_normalize::fault::corrupt_next();
    let rejected = crate::upgrade::backup_normalize::eager_normalize(
        &path,
        &["notes".into()],
        true,
        DurabilityMode::Strict,
        RedbOptions::default(),
    )
    .unwrap();
    assert!(rejected
        .failure
        .as_ref()
        .unwrap()
        .contains("verification mismatch"));
    assert_eq!(
        std::fs::read(&path).unwrap(),
        original,
        "rejected conversion must preserve every original file byte before Storage opens"
    );
    assert!(!dir.join("notes/notes.cldb.bak.upgrading").exists());

    // Reject the build-time attempt too: reads must work before the next retry.
    crate::upgrade::backup_normalize::fault::corrupt_next();
    let storage = build(&dir);
    let manager = storage.db_manager("notes");
    let meta = manager.read_meta().unwrap().unwrap();
    assert_ne!(meta.backup_format, "json_wrapped_v2");
    assert!(
        meta.upgrade_log
            .iter()
            .any(|r| r.step == "backup_conversion_failed"
                && r.detail.as_ref().unwrap().contains("verification mismatch")),
        "{:?}",
        meta
    );
    for (key, bytes) in &records {
        let (id, version) = key.rsplit_once(':').unwrap();
        let before = crate::backup::codec::decode_record("notes", key, bytes).unwrap();
        let after = manager
            .get_by_version(NOTES, id, version.parse().unwrap())
            .unwrap();
        assert_eq!(before.data, after.data);
        if !before.date_from_migration {
            assert_eq!(before, after);
        }
    }
    assert_eq!(
        manager
            .backup_manager
            .as_ref()
            .unwrap()
            .list_bulk("notes")
            .unwrap()[0]
            .bulk_id,
        bulk_id
    );
    storage.close();
    drop(storage);
    // Writable redb handles may update allocator metadata; all stored content
    // must still match, including exact record and bulk bytes and every counter.
    assert_eq!(contents(&path), original_contents);
    assert!(!dir.join("notes/notes.cldb.bak.upgrading").exists());

    let storage = build(&dir);
    assert_eq!(
        storage
            .db_manager("notes")
            .read_meta()
            .unwrap()
            .unwrap()
            .backup_format,
        "json_wrapped_v2",
        "{:?}",
        storage.db_manager("notes").read_meta().unwrap()
    );
    storage.close();
    drop(storage);
    let converted = contents(&path);
    assert_eq!(converted.0.len(), original_contents.0.len());
    assert_eq!(converted.1, original_contents.1);
    assert_eq!(converted.2, original_contents.2);
}

#[cfg(feature = "crash-inject")]
#[test]
#[ignore = "child process for interruption tests"]
fn interrupted_child() {
    let Ok(dir) = std::env::var("CLOVE_TEST_DIR") else {
        return;
    };
    let dir = PathBuf::from(dir);
    let action = std::env::var("CLOVE_TEST_ACTION").unwrap();

    if action == "dirty-legacy" {
        let m = BackupManager::new(
            &dir.join("notes/notes.cldb.bak"),
            true,
            DurabilityMode::Strict,
            RedbOptions::default(),
        )
        .unwrap();
        let record = crate::backup::BackupRecord {
            version: 1,
            timestamp: 123,
            date: "before interruption".into(),
            operation: crate::backup::BackupOperation::Set,
            table: "notes".into(),
            key: "dirty".into(),
            data: Some(br#"{"id":"dirty"}"#.to_vec()),
            bulk_id: None,
            restored_version: None,
            date_from_migration: false,
        };
        let db = m.db().unwrap();
        let tx = db.begin_write().unwrap();
        {
            tx.open_table(NOTES)
                .unwrap()
                .insert("dirty:1", serde_json::to_vec(&record).unwrap().as_slice())
                .unwrap();
        }
        {
            tx.open_table(TableDefinition::<&str, u64>::new("notes_version"))
                .unwrap()
                .insert("dirty", 1)
                .unwrap();
        }
        tx.commit().unwrap();
        std::process::exit(99);
    }
    if action == "convert" {
        let _storage = build(&dir);
        return;
    }
    let storage = build(&dir);
    let manager = storage.db_manager("notes");
    if action == "record" {
        manager
            .backup_manager
            .as_ref()
            .unwrap()
            .record_set(NOTES, "notes", "new", b"{}".to_vec())
            .unwrap();
        return;
    }
    let writes: Vec<_> = (0..1000)
        .map(|i| ("notes".to_string(), format!("n{i}"), b"{}".to_vec()))
        .collect();
    if action == "atomic" {
        manager.commit_batch_atomic(&writes, &[]).unwrap();
    } else {
        manager.commit_batch(&writes, &[]).unwrap();
    }
}
#[cfg(feature = "crash-inject")]
fn interrupt(dir: &std::path::Path, action: &str, point: &str) {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "backup_tests::interrupted_child",
            "--exact",
            "--ignored",
            "--test-threads=1",
        ])
        .env("CLOVE_TEST_DIR", dir)
        .env("CLOVE_TEST_ACTION", action)
        .env("CLOVE_CRASH_POINT", point)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(99));
}
#[cfg(feature = "crash-inject")]
#[test]
fn interrupted_batches_keep_only_legacy_prefix_and_no_atomic_changes() {
    for (action, point, expected) in [
        ("legacy", "after_commit", 512),
        ("atomic", "before_commit", 0),
    ] {
        let dir = PathBuf::from("target/test_backup").join(format!("crash_batch_{action}"));
        let _ = std::fs::remove_dir_all(&dir);
        let storage = build(&dir);
        storage.close();
        drop(storage);
        interrupt(&dir, action, point);
        let storage = build(&dir);
        assert_eq!(
            storage.db_manager("notes").count_keys("notes").unwrap(),
            expected
        );
    }
}
#[cfg(feature = "crash-inject")]
#[test]
fn interrupted_record_allocation_leaves_no_version_gap() {
    let dir = PathBuf::from("target/test_backup/crash_version");
    let _ = std::fs::remove_dir_all(&dir);
    let storage = build(&dir);
    storage.close();
    drop(storage);
    interrupt(&dir, "record", "backup_after_version");
    let storage = build(&dir);
    let bm = storage.db_manager("notes").backup_manager.as_ref().unwrap();
    assert_eq!(bm.current_version("notes", "new").unwrap(), 0);
    assert!(bm.history(NOTES, "new").unwrap().is_empty());
    bm.record_set(NOTES, "notes", "new", b"{}".to_vec())
        .unwrap();
    assert_eq!(bm.current_version("notes", "new").unwrap(), 1);
}
#[cfg(feature = "crash-inject")]
#[test]
fn interrupted_conversion_retries_before_replace_and_only_marks_after_replace() {
    for point in ["backup_before_replace", "backup_after_replace"] {
        let (dir, _) = mixed_fixture(point);
        let path = dir.join("notes/notes.cldb.bak");
        let original = std::fs::read(&path).unwrap();
        interrupt(&dir, "convert", point);
        if point == "backup_before_replace" {
            assert!(
                std::fs::read(&path).unwrap() == original,
                "source changed before replacement"
            );
            assert!(dir.join("notes/notes.cldb.bak.upgrading").exists());
        }
        let storage = build(&dir);
        let meta = storage.db_manager("notes").read_meta().unwrap().unwrap();
        assert_eq!(meta.backup_format, "json_wrapped_v2");
        let log = meta
            .upgrade_log
            .iter()
            .rev()
            .find(|r| r.step == "backup_normalize")
            .unwrap()
            .detail
            .as_ref()
            .unwrap();
        assert_eq!(
            log,
            if point == "backup_after_replace" {
                "converted=0"
            } else {
                "converted=3"
            }
        );
        assert!(!dir.join("notes/notes.cldb.bak.upgrading").exists());
        assert_eq!(
            storage
                .db_manager("notes")
                .backup_manager
                .as_ref()
                .unwrap()
                .history(NOTES, "a")
                .unwrap()
                .len(),
            2
        );
    }
}

#[test]
fn rejected_converter_itself_leaves_every_original_byte_unchanged() {
    let (dir, _) = mixed_fixture("converter_exact_bytes");
    let path = dir.join("notes/notes.cldb.bak");
    let original = std::fs::read(&path).unwrap();
    crate::upgrade::backup_normalize::fault::corrupt_next();
    let result = crate::upgrade::backup_normalize::eager_normalize(
        &path,
        &["notes".into()],
        true,
        DurabilityMode::Strict,
        RedbOptions::default(),
    )
    .unwrap();
    assert!(
        result
            .failure
            .as_ref()
            .unwrap()
            .contains("verification mismatch")
    );
    assert!(
        std::fs::read(&path).unwrap() == original,
        "converter changed original bytes"
    );
    assert!(!dir.join("notes/notes.cldb.bak.upgrading").exists());
}

#[test]
fn renamed_history_keeps_counters_and_bulk_metadata_for_future_writes() {
    let m = manager("rename_auxiliary");
    m.record_set(NOTES, "notes", "a", b"{\"id\":\"a\",\"v\":1}".to_vec())
        .unwrap();
    m.record_set(NOTES, "notes", "a", b"{\"id\":\"a\",\"v\":2}".to_vec())
        .unwrap();
    let id = m.write_bulk("notes", vec![("a".into(), 1)]).unwrap();
    m.rewrite_table_name("notes", "articles").unwrap();
    assert_eq!(m.current_version("articles", "a").unwrap(), 2);
    assert_eq!(m.list_bulk("articles").unwrap()[0].bulk_id, id);
    let articles = TableDefinition::new("articles");
    m.record_set(articles, "articles", "a", b"{}".to_vec())
        .unwrap();
    assert_eq!(m.history(articles, "a").unwrap().len(), 3);
    assert_eq!(
        m.view_by_version(articles, "a", 1).unwrap(),
        Some(b"{\"id\":\"a\",\"v\":1}".to_vec())
    );
    let restored = m.restore_bulk(articles, "articles", &id).unwrap();
    assert_eq!(restored.len(), 1);
}

use crate::backup::view::HistoryDisplayMode;
use crate::migration::{MigrateOutcome, MigrateTo, migrate_value};
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct Article {
    id: String,
    title: String,
    body: String,
}
impl Entity for Article {
    fn entity_id(&self) -> &str {
        &self.id
    }
}
impl MigrateTo<Article> for Note {
    fn migrate_json(
        value: serde_json::Value,
    ) -> crate::units::Result<MigrateOutcome<serde_json::Value>> {
        let n: Note = serde_json::from_value(value)?;
        migrate_value(Article {
            id: n.id,
            title: n.title,
            body: "derived".into(),
        })
    }
}
fn normalized(storage: &Storage) -> Vec<crate::backup::view::RecordData> {
    let manager = storage.db_manager("notes");
    let index = manager.migration_index().unwrap();
    manager
        .history(NOTES, "a")
        .unwrap()
        .iter()
        .map(|r| {
            BackupManager::resolve_record(
                r,
                Some(&index),
                manager.migration_registry(),
                HistoryDisplayMode::Normalized,
            )
            .data
        })
        .collect()
}
#[test]
fn schema_migration_history_is_identical_before_and_after_wire_conversion() {
    let dir = PathBuf::from("target/test_backup/schema_conversion");
    let _ = std::fs::remove_dir_all(&dir);
    let storage = Storage::builder(StorageConfig::default().change_dir_path(dir.clone()))
        .migration_step::<Note, Article>()
        .add_database(
            DatabaseConfig::new("notes", "notes")
                .backup_enabled(true)
                .register::<Note>("notes"),
        )
        .build()
        .unwrap();
    storage
        .domain::<Note>()
        .repo()
        .set(
            "a",
            &Note {
                id: "a".into(),
                title: "current".into(),
            },
        )
        .unwrap();
    let manager = storage.db_manager("notes");
    let bm = manager.backup_manager.as_ref().unwrap();
    let raw = br#"{"title":"old","id":"a"}"#;
    insert(bm, "a:1", raw);
    let record = crate::backup::codec::raw_record("notes", "a:2", raw).unwrap();
    let mut dated = record;
    dated.timestamp = 123;
    dated.date = "original".into();
    dated.date_from_migration = false;
    insert(bm, "a:2", &serde_json::to_vec(&dated).unwrap());
    let db = bm.db().unwrap();
    let tx = db.begin_write().unwrap();
    {
        tx.open_table(TableDefinition::<&str, u64>::new("notes_version"))
            .unwrap()
            .insert("a", 2)
            .unwrap();
    }
    tx.commit().unwrap();
    drop(db);
    let mut meta = manager.read_meta().unwrap().unwrap();
    meta.backup_format = "json_wrapped_v1".into();
    manager.write_meta(&meta).unwrap();
    storage
        .migrate::<Note, Article>()
        .from_db("notes", "notes")
        .execute()
        .unwrap();
    let before = normalized(&storage);
    assert_eq!(before.len(), 2);
    assert!(
        before
            .iter()
            .all(|v| v.as_json().unwrap()["body"] == "derived")
    );
    storage.close();
    drop(storage);
    let storage = Storage::builder(StorageConfig::default().change_dir_path(dir))
        .migration_step::<Note, Article>()
        .add_database(
            DatabaseConfig::new("notes", "notes")
                .backup_enabled(true)
                .register::<Article>("notes"),
        )
        .build()
        .unwrap();
    assert_eq!(normalized(&storage), before);
    let manager = storage.db_manager("notes");
    manager.rewrite_backup_table("notes", "articles").unwrap();
    let renamed = manager
        .history(TableDefinition::new("articles"), "a")
        .unwrap();
    assert_eq!(renamed.len(), 2);
    assert!(renamed.iter().all(|r| r.table == "articles"));
    assert!(manager.history(NOTES, "a").unwrap().is_empty());
}

#[test]
fn repository_restore_paths_keep_v2_payload_bytes_and_delete_records() {
    let dir = PathBuf::from("target/test_backup/repository_v2_restore");
    let _ = std::fs::remove_dir_all(&dir);
    let storage = build(&dir);
    let m = storage.db_manager("notes");
    let payloads: [&[u8]; 3] = [
        b" {\"z\":1.00,\"id\":\"a\"} \n",
        b"[1, 2, 3]",
        &[0, 255, 128],
    ];
    for (i, payload) in payloads.iter().enumerate() {
        let key = format!("p{i}");
        m.set(NOTES, "notes", &key, payload.to_vec()).unwrap();
        m.set(NOTES, "notes", &key, b"changed".to_vec()).unwrap();
        assert_eq!(
            m.get_by_version(NOTES, &key, 1).unwrap().data.as_deref(),
            Some(*payload)
        );
        m.restore_by_version(NOTES, "notes", &key, 1).unwrap();
        assert_eq!(m.get_raw("notes", &key).unwrap().as_deref(), Some(*payload));
    }
    let bulk = m
        .set_bulk("notes", (0..3).map(|i| (format!("p{i}"), 1)).collect())
        .unwrap();
    for i in 0..3 {
        m.set(NOTES, "notes", &format!("p{i}"), b"changed again".to_vec())
            .unwrap();
    }
    m.restore_bulk(NOTES, "notes", &bulk).unwrap();
    for (i, payload) in payloads.iter().enumerate() {
        assert_eq!(
            m.get_raw("notes", &format!("p{i}")).unwrap().as_deref(),
            Some(*payload)
        );
    }
    m.delete(NOTES, "notes", "p0").unwrap();
    let version = m.current_version("notes", "p0").unwrap();
    let bdb = m.backup_manager.as_ref().unwrap().db().unwrap();
    let tx = bdb.begin_read().unwrap();
    let table = tx.open_table(NOTES).unwrap();
    let bytes = table
        .get(format!("p0:{version}").as_str())
        .unwrap()
        .unwrap()
        .value()
        .to_vec();
    drop(tx);
    drop(bdb);
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        json.get("data").is_none() && json.get("doc").is_none() && json.get("data_b64").is_none()
    );
    m.set(NOTES, "notes", "p0", b"new".to_vec()).unwrap();
    m.restore_by_version(NOTES, "notes", "p0", version).unwrap();
    assert!(m.get_raw("notes", "p0").unwrap().is_none());
}

#[test]
fn raw_entity_domain_fields_are_not_backup_metadata() {
    let bytes=br#"{"id":"a","version":1,"operation":"edit","timestamp":123,"date":"domain date","table":"domain","key":"domain"}"#;
    let row = crate::backup::codec::decode_record("notes", "a:7", bytes).unwrap();
    assert_eq!(row.version, 7);
    assert_eq!(row.data.as_deref(), Some(bytes.as_slice()));
}
#[test]
fn malformed_envelopes_are_errors_instead_of_raw_or_empty_sets() {
    for bytes in [
        br#"{"version":1,"timestamp":123,"date":"d","operation":"Set","table":"notes","key":"a"}"#.as_slice(),
        br#"{"version":1,"timestamp":123,"date":"d","table":"notes","key":"a","data":[123,125]}"#.as_slice(),
        br#"{"version":1,"timestamp":123,"date":"d","operation":"Set","table":"notes","key":"a","doc":{"x":1},"doc":{"x":2}}"#.as_slice(),
        br#"{"version":1,"timestamp":123,"date":"d","operation":"Set","table":"notes","key":"a","data_b64":"YQ==","data_b64":"Yg=="}"#.as_slice(),
    ] {
        assert!(crate::backup::codec::decode_record("notes","a:1",bytes).is_err(),"accepted damaged envelope: {}",String::from_utf8_lossy(bytes));
    }
}

#[test]
fn newly_created_v2_backup_is_already_marked_upgraded() {
    let dir = PathBuf::from("target/test_backup/new_v2_marker");
    let _ = std::fs::remove_dir_all(&dir);
    let storage = build(&dir);
    let meta = storage.db_manager("notes").read_meta().unwrap().unwrap();
    assert_eq!(meta.backup_format, "json_wrapped_v2");
    assert!(meta.backup_upgraded);
}

#[test]
fn restoring_a_restore_of_deletion_removes_the_current_row() {
    let dir = PathBuf::from("target/test_backup/restore_absence");
    let _ = std::fs::remove_dir_all(&dir);
    let storage = build(&dir);
    let m = storage.db_manager("notes");
    m.set(NOTES, "notes", "a", b"original".to_vec()).unwrap();
    m.delete(NOTES, "notes", "a").unwrap();
    m.restore_by_version(NOTES, "notes", "a", 2).unwrap();
    m.set(NOTES, "notes", "a", b"new".to_vec()).unwrap();
    m.restore_by_version(NOTES, "notes", "a", 3).unwrap();
    assert!(m.get_raw("notes", "a").unwrap().is_none());
    let bulk = m.set_bulk("notes", vec![("a".into(), 2)]).unwrap();
    m.restore_bulk(NOTES, "notes", &bulk).unwrap();
    let absent_version = m.current_version("notes", "a").unwrap();
    m.set(NOTES, "notes", "a", b"new again".to_vec()).unwrap();
    m.restore_by_version(NOTES, "notes", "a", absent_version)
        .unwrap();
    assert!(m.get_raw("notes", "a").unwrap().is_none());
}

#[test]
fn a_registered_history_table_with_auxiliary_suffix_is_still_converted() {
    let dir = PathBuf::from("target/test_backup/suffix_table");
    let _ = std::fs::remove_dir_all(&dir);
    let make = || {
        Storage::builder(StorageConfig::default().change_dir_path(dir.clone()))
            .add_database(
                DatabaseConfig::new("notes", "notes")
                    .backup_enabled(true)
                    .register::<Note>("notes_bulk"),
            )
            .build()
            .unwrap()
    };
    let storage = make();
    let m = storage.db_manager("notes");
    let bm = m.backup_manager.as_ref().unwrap();
    let table = TableDefinition::new("notes_bulk");
    bm.record_set(table, "notes_bulk", "a", b"{}".to_vec())
        .unwrap();
    let record = m.get_by_version(table, "a", 1).unwrap();
    {
        let db = bm.db().unwrap();
        let tx = db.begin_write().unwrap();
        {
            tx.open_table(table)
                .unwrap()
                .insert("a:1", serde_json::to_vec(&record).unwrap().as_slice())
                .unwrap();
        }
        tx.commit().unwrap();
    }
    let mut meta = m.read_meta().unwrap().unwrap();
    meta.backup_format = "json_wrapped_v1".into();
    m.write_meta(&meta).unwrap();
    storage.close();
    drop(storage);
    let storage = make();
    let meta = storage.db_manager("notes").read_meta().unwrap().unwrap();
    assert_eq!(
        meta.backup_format, "json_wrapped_v2",
        "{:?}",
        meta.upgrade_log
    );
    assert_eq!(
        storage
            .db_manager("notes")
            .get_by_version(table, "a", 1)
            .unwrap(),
        record
    );
    let db = storage
        .db_manager("notes")
        .backup_manager
        .as_ref()
        .unwrap()
        .db()
        .unwrap();
    let tx = db.begin_read().unwrap();
    let wire = tx
        .open_table(table)
        .unwrap()
        .get("a:1")
        .unwrap()
        .unwrap()
        .value()
        .to_vec();
    assert!(
        crate::backup::codec::is_v2(&wire).unwrap(),
        "history record was skipped because of the table suffix"
    );
}

#[cfg(feature = "crash-inject")]
#[test]
fn an_unclean_legacy_backup_is_repaired_only_on_the_copy_and_converted() {
    let (dir, _) = mixed_fixture("unclean_conversion");
    interrupt(&dir, "dirty-legacy", "unused");
    let storage = build(&dir);
    let meta = storage.db_manager("notes").read_meta().unwrap().unwrap();
    assert_eq!(
        meta.backup_format, "json_wrapped_v2",
        "{:?}",
        meta.upgrade_log
    );
    let row = storage
        .db_manager("notes")
        .get_by_version(NOTES, "dirty", 1)
        .unwrap();
    assert_eq!(row.data.as_deref(), Some(br#"{"id":"dirty"}"#.as_slice()));
    assert!(
        storage.open_report().iter().any(|r| r.format_check
            && r.repaired
            && r.path.to_string_lossy().ends_with(".upgrading"))
    );
    assert!(!dir.join("notes/notes.cldb.bak.upgrading").exists());
}

#[cfg(feature = "crash-inject")]
#[test]
fn rejecting_an_unclean_backup_conversion_keeps_the_original_bytes() {
    let (dir, _) = mixed_fixture("unclean_rejected");
    interrupt(&dir, "dirty-legacy", "unused");
    let path = dir.join("notes/notes.cldb.bak");
    let original = std::fs::read(&path).unwrap();
    crate::upgrade::backup_normalize::fault::corrupt_next();
    let result = crate::upgrade::backup_normalize::eager_normalize(
        &path,
        &["notes".into()],
        true,
        DurabilityMode::Strict,
        RedbOptions::default(),
    )
    .unwrap();
    assert!(
        result
            .failure
            .as_ref()
            .unwrap()
            .contains("verification mismatch")
    );
    assert!(
        std::fs::read(&path).unwrap() == original,
        "repair modified original instead of the copy"
    );
    assert!(!dir.join("notes/notes.cldb.bak.upgrading").exists());
}

#[test]
fn a_stale_counter_cannot_overwrite_an_existing_history_version() {
    let m = manager("stale_version_counter");
    m.record_set(NOTES, "notes", "a", b"old".to_vec()).unwrap();
    {
        let db = m.db().unwrap();
        let tx = db.begin_write().unwrap();
        {
            tx.open_table(TableDefinition::<&str, u64>::new("notes_version"))
                .unwrap()
                .insert("a", 0)
                .unwrap();
        }
        tx.commit().unwrap();
    }
    assert!(m.record_set(NOTES, "notes", "a", b"new".to_vec()).is_err());
    assert_eq!(
        m.view_by_version(NOTES, "a", 1).unwrap(),
        Some(b"old".to_vec())
    );
    assert_eq!(m.current_version("notes", "a").unwrap(), 0);
}

#[test]
fn canonical_raw_rewrite_supplies_a_fixed_conversion_date() {
    let raw = crate::upgrade::parse_backup_value("notes", "a:1", br#"{"id":"a"}"#).unwrap();
    let bytes = crate::upgrade::canonical_bytes(&raw).unwrap();
    let record = crate::upgrade::parse_backup_value("notes", "a:1", &bytes).unwrap();
    assert!(record.date_from_migration && record.timestamp > 0 && !record.date.is_empty());
    let again = crate::upgrade::canonical_bytes(&record).unwrap();
    assert_eq!(
        crate::upgrade::parse_backup_value("notes", "a:1", &again).unwrap(),
        record
    );
}

#[test]
fn rejected_conversion_remains_readable_and_retries_on_the_next_build() {
    let (dir, records) = mixed_fixture("failure_readable_retry");
    let expected: Vec<_> = records
        .iter()
        .map(|(key, bytes)| crate::backup::codec::decode_record("notes", key, bytes).unwrap())
        .collect();
    crate::upgrade::backup_normalize::fault::corrupt_next();
    let storage = build(&dir);
    let m = storage.db_manager("notes");
    let meta = m.read_meta().unwrap().unwrap();
    assert_eq!(meta.backup_format, "json_wrapped_v1");
    assert!(!meta.backup_upgraded);
    assert!(
        meta.upgrade_log
            .iter()
            .any(|entry| entry.step == "backup_conversion_failed")
    );
    for record in &expected {
        assert_eq!(
            m.get_by_version(NOTES, &record.key, record.version)
                .unwrap(),
            *record
        );
    }
    assert_eq!(
        m.backup_manager
            .as_ref()
            .unwrap()
            .current_version("notes", "a")
            .unwrap(),
        2
    );
    storage.close();
    drop(storage);
    assert!(!dir.join("notes/notes.cldb.bak.upgrading").exists());
    let storage = build(&dir);
    let m = storage.db_manager("notes");
    let meta = m.read_meta().unwrap().unwrap();
    assert_eq!(meta.backup_format, "json_wrapped_v2");
    assert!(meta.backup_upgraded);
    assert_eq!(
        meta.upgrade_log
            .iter()
            .rev()
            .find(|e| e.step == "backup_normalize")
            .unwrap()
            .detail
            .as_deref(),
        Some("converted=3")
    );
    for record in &expected {
        let current = m
            .get_by_version(NOTES, &record.key, record.version)
            .unwrap();
        assert_eq!(current.data, record.data);
        if !record.date_from_migration {
            assert_eq!(current, *record);
        }
    }
}
