use clove1db::{
    backup::{
        BackupManager, BackupOperation, BackupRecord,
        view::{HistoryDisplayMode, RecordData},
    },
    entity::Entity,
    migration::{MigrateOutcome, MigrateTo, migrate_value},
    storage::{DatabaseConfig, Storage, StorageConfig},
};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};
type DemoResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const NOTES: TableDefinition<&str, &[u8]> = TableDefinition::new("notes");
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Note {
    id: String,
    title: String,
    body: String,
}
impl Entity for Note {
    fn entity_id(&self) -> &str {
        &self.id
    }
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Article {
    id: String,
    title: String,
    body: String,
    reviewed: bool,
}
impl Entity for Article {
    fn entity_id(&self) -> &str {
        &self.id
    }
}
impl MigrateTo<Article> for Note {
    fn migrate_json(
        value: serde_json::Value,
    ) -> clove1db::units::Result<MigrateOutcome<serde_json::Value>> {
        let n: Note = serde_json::from_value(value)?;
        migrate_value(Article {
            id: n.id,
            title: n.title,
            body: n.body,
            reviewed: true,
        })
    }
}
fn build(dir: &Path) -> clove1db::units::Result<Storage> {
    Storage::builder(StorageConfig::default().change_dir_path(dir.to_path_buf()))
        .migration_step::<Note, Article>()
        .add_database(
            DatabaseConfig::new("notes", "notes")
                .backup_enabled(true)
                .register::<Note>("notes"),
        )
        .build()
}
fn build_article(dir: &Path) -> clove1db::units::Result<Storage> {
    Storage::builder(StorageConfig::default().change_dir_path(dir.to_path_buf()))
        .migration_step::<Note, Article>()
        .add_database(
            DatabaseConfig::new("notes", "notes")
                .backup_enabled(true)
                .register::<Article>("notes"),
        )
        .build()
}
fn backup(dir: &Path) -> PathBuf {
    dir.join("notes/notes.cldb.bak")
}
fn old_marker(storage: &Storage) -> DemoResult {
    let m = storage.db_manager("notes");
    let mut meta = m.read_meta().unwrap().unwrap();
    meta.backup_format = "json_wrapped_v1".into();
    meta.backup_upgraded = false;
    m.write_meta(&meta)?;
    Ok(())
}
fn v1(key: &str, version: u64, data: Vec<u8>) -> BackupRecord {
    BackupRecord {
        version,
        timestamp: 1_700_000_000_000,
        date: "2023-11-14 22:13:20.000".into(),
        operation: BackupOperation::Set,
        table: "notes".into(),
        key: key.into(),
        data: Some(data),
        bulk_id: None,
        restored_version: None,
        date_from_migration: false,
    }
}
fn put_backup(storage: &Storage, key: &str, bytes: &[u8]) -> DemoResult {
    let db = storage
        .db_manager("notes")
        .backup_manager
        .as_ref()
        .unwrap()
        .db()?;
    let tx = db.begin_write()?;
    {
        tx.open_table(NOTES)?.insert(key, bytes)?;
    }
    tx.commit()?;
    Ok(())
}
fn measure(dir: &Path, label: &str) -> DemoResult<u64> {
    let path = backup(dir);
    let db = redb::Database::open(&path)?;
    let tx = db.begin_read()?;
    let mut count = 0;
    let mut values = 0;
    let mut numeric = 0;
    for entry in tx.open_table(NOTES)?.iter()? {
        let (_, v) = entry?;
        count += 1;
        values += v.value().len();
        let json: serde_json::Value = serde_json::from_slice(v.value())?;
        if let Some(data) = json.get("data").filter(|d| !d.is_null()) {
            numeric += serde_json::to_vec(data)?.len();
        }
    }
    drop(tx);
    let stats = db.begin_write()?.stats()?;
    let bytes = fs::metadata(&path)?.len();
    let capacity_pages = bytes / stats.page_size() as u64;
    println!(
        "{label}: primary_bytes={} backup_bytes={bytes} history_versions={count} value_bytes={values} numeric_array_bytes={numeric} numeric_array_share={:.2}% allocated_pages={} unused_page_capacity={} page_size={}",
        fs::metadata(dir.join("notes/notes.cldb"))?.len(),
        numeric as f64 / values as f64 * 100.0,
        stats.allocated_pages(),
        capacity_pages.saturating_sub(stats.allocated_pages()),
        stats.page_size()
    );
    // Unused file capacity includes file-header/allocator overhead; redb exposes no exact free-page count.
    assert_eq!(count, 1000);
    Ok(bytes)
}
fn size_demo(dir: &Path) -> DemoResult {
    let storage = build(dir)?;
    old_marker(&storage)?;
    for revision in 0..5 {
        for i in 0..200 {
            let note = Note {
                id: format!("n{i:04}"),
                title: format!("Note {i} revision {revision}"),
                body: "A synthetic paragraph. ".repeat(100),
            };
            let bytes = serde_json::to_vec(&note)?;
            let m = storage.db_manager("notes");
            m.commit_batch_atomic(&[("notes".into(), note.id.clone(), bytes.clone())], &[])?;
            // Reproduce the previous writer: counter and numeric-array record in two commits.
            let db = m.backup_manager.as_ref().unwrap().db()?;
            let tx = db.begin_write()?;
            {
                tx.open_table(TableDefinition::<&str, u64>::new("notes_version"))?
                    .insert(note.id.as_str(), revision + 1)?;
            }
            tx.commit()?;
            drop(db);
            put_backup(
                &storage,
                &format!("{}:{}", note.id, revision + 1),
                &serde_json::to_vec(&v1(&note.id, revision + 1, bytes))?,
            )?;
        }
    }
    storage.close();
    drop(storage);
    println!("1. Size: 200 synthetic notes x 5 versions");
    let before = measure(dir, "v1")?;
    let start = Instant::now();
    let storage = build(dir)?;
    let conversion_ms = start.elapsed().as_millis();
    assert_eq!(
        storage
            .db_manager("notes")
            .read_meta()
            .unwrap()
            .unwrap()
            .backup_format,
        "json_wrapped_v2"
    );
    storage.close();
    drop(storage);
    let after = measure(dir, "v2 + compact")?;
    assert!(after < before);
    println!(
        "conversion_build_ms={conversion_ms} backup_reduction={:.2}%",
        (1.0 - after as f64 / before as f64) * 100.0
    );
    Ok(())
}
fn mixed_demo(dir: &Path) -> DemoResult {
    println!("2. Mixed raw, legacy JSON and v1");
    let storage = build(dir)?;
    old_marker(&storage)?;
    let raw = b" \n {\"title\":\"Raw\",\"id\":\"a\",\"body\":\"original\"} \t".to_vec();
    let legacy_data = b"[123, 34, 105]".to_vec();
    let binary = vec![0, 255, 128, 1];
    put_backup(&storage, "a:1", &raw)?;
    let legacy = serde_json::json!({"version":2,"timestamp":123,"date":"original date","operation":"Set","table":"notes","key":"a","data":legacy_data});
    put_backup(&storage, "a:2", &serde_json::to_vec(&legacy)?)?;
    put_backup(
        &storage,
        "b:1",
        &serde_json::to_vec(&v1("b", 1, binary.clone()))?,
    )?;
    let m = storage.db_manager("notes");
    let bulk = m
        .backup_manager
        .as_ref()
        .unwrap()
        .write_bulk("notes", vec![("a".into(), 2), ("b".into(), 1)])?;
    {
        let db = m.backup_manager.as_ref().unwrap().db()?;
        let tx = db.begin_write()?;
        {
            let mut counters = tx.open_table(TableDefinition::<&str, u64>::new("notes_version"))?;
            counters.insert("a", 2)?;
            counters.insert("b", 1)?;
        }
        tx.commit()?;
    }
    let expected = [("a", 1, raw), ("a", 2, legacy_data), ("b", 1, binary)];
    for (key, version, bytes) in &expected {
        assert_eq!(
            m.get_by_version(NOTES, key, *version)?.data.as_ref(),
            Some(bytes)
        );
    }
    storage.close();
    drop(storage);
    let storage = build(dir)?;
    let m = storage.db_manager("notes");
    for (key, version, bytes) in &expected {
        let record = m.get_by_version(NOTES, key, *version)?;
        assert_eq!(record.data.as_ref(), Some(bytes));
        println!(
            "{key}:{version} byte_exact=true date_from_migration={} timestamp={} date={}",
            record.date_from_migration, record.timestamp, record.date
        );
    }
    assert_eq!(
        m.backup_manager.as_ref().unwrap().list_bulk("notes")?[0].bulk_id,
        bulk
    );
    let raw_date = m.get_by_version(NOTES, "a", 1)?;
    assert!(raw_date.date_from_migration && raw_date.timestamp > 0);
    println!(
        "all three records converted; bulk metadata preserved; temporary_copy_exists={}",
        dir.join("notes/notes.cldb.bak.upgrading").exists()
    );
    storage.close();
    drop(storage);
    let storage = build(dir)?;
    assert_eq!(
        storage.db_manager("notes").get_by_version(NOTES, "a", 1)?,
        raw_date
    );
    Ok(())
}
fn normalized(storage: &Storage) -> clove1db::units::Result<Vec<RecordData>> {
    let m = storage.db_manager("notes");
    let index = m.migration_index()?;
    Ok(m.history(NOTES, "a")?
        .iter()
        .map(|r| {
            BackupManager::resolve_record(
                r,
                Some(&index),
                m.migration_registry(),
                HistoryDisplayMode::Normalized,
            )
            .data
        })
        .collect())
}
fn migration_demo(dir: &Path) -> DemoResult {
    println!("3. Schema history and table rename");
    let storage = build(dir)?;
    old_marker(&storage)?;
    let note = Note {
        id: "a".into(),
        title: "Earlier title".into(),
        body: "A paragraph".into(),
    };
    let bytes = serde_json::to_vec(&note)?;
    storage
        .db_manager("notes")
        .commit_batch_atomic(&[("notes".into(), "a".into(), bytes.clone())], &[])?;
    put_backup(&storage, "a:1", &bytes)?;
    put_backup(
        &storage,
        "a:2",
        &serde_json::to_vec(&v1("a", 2, bytes.clone()))?,
    )?;
    let db = storage
        .db_manager("notes")
        .backup_manager
        .as_ref()
        .unwrap()
        .db()?;
    let tx = db.begin_write()?;
    {
        tx.open_table(TableDefinition::<&str, u64>::new("notes_version"))?
            .insert("a", 2)?;
    }
    tx.commit()?;
    drop(db);
    storage
        .migrate::<Note, Article>()
        .from_db("notes", "notes")
        .execute()?;
    let before = normalized(&storage)?;
    assert!(
        before
            .iter()
            .all(|d| d.as_json().unwrap()["reviewed"] == true)
    );
    storage.close();
    drop(storage);
    let storage = build_article(dir)?;
    let after = normalized(&storage)?;
    assert_eq!(before, after);
    let m = storage.db_manager("notes");
    m.rewrite_backup_table("notes", "articles")?;
    let records = m.history(TableDefinition::new("articles"), "a")?;
    assert_eq!(records.len(), 2);
    assert!(m.history(NOTES, "a")?.is_empty());
    println!(
        "normalized_history_equal=true old_versions={} renamed_versions={} renamed_counter={}",
        before.len(),
        records.len(),
        m.backup_manager
            .as_ref()
            .unwrap()
            .current_version("articles", "a")?
    );
    Ok(())
}
fn report_demo(dir: &Path) -> DemoResult {
    println!("4. First and second build open report");
    let storage = build(dir)?;
    old_marker(&storage)?;
    put_backup(&storage, "a:1", br#"{"id":"a"}"#)?;
    storage.close();
    drop(storage);
    let storage = build(dir)?;
    let report = storage.open_report();
    let first = report.iter().filter(|r| r.format_check).count();
    assert!(first > 0);
    for row in report {
        println!(
            "first: path={} bytes={} open_us={} repaired={} format_check={}",
            row.path.display(),
            row.bytes,
            row.open_time.as_micros(),
            row.repaired,
            row.format_check
        );
    }
    storage.close();
    drop(storage);
    let storage = build(dir)?;
    let second = storage
        .open_report()
        .iter()
        .filter(|r| r.format_check)
        .count();
    assert_eq!(second, 0);
    println!("first_format_checks={first} second_format_checks={second}");
    Ok(())
}
fn batch_child(dir: &Path, action: &str) -> DemoResult {
    let storage = build(dir)?;
    let m = storage.db_manager("notes");
    let writes: Vec<_> = (0..1000)
        .map(|i| ("notes".into(), format!("n{i}"), b"{}".to_vec()))
        .collect();
    if action == "atomic" {
        m.commit_batch_atomic(&writes, &[])?;
    } else {
        m.commit_batch(&writes, &[])?;
    }
    Ok(())
}
fn batch_demo(dir: &Path) -> DemoResult {
    println!("5. Interruption of 1,000 raw batch writes");
    for (action, point, expected) in [
        ("legacy", "after_commit", 512),
        ("atomic", "before_commit", 0),
    ] {
        let path = dir.join(action);
        let storage = build(&path)?;
        storage.close();
        drop(storage);
        let status = Command::new(std::env::current_exe()?)
            .arg("--batch-child")
            .arg(&path)
            .arg(action)
            .env("CLOVE_CRASH_POINT", point)
            .status()?;
        assert_eq!(status.code(), Some(99));
        let storage = build(&path)?;
        let count = storage.db_manager("notes").count_keys("notes")?;
        assert_eq!(count, expected);
        println!("{action}: crash_point={point} persisted={count}/1000");
    }
    let path = dir.join("atomic_success");
    let storage = build(&path)?;
    let m = storage.db_manager("notes");
    let writes: Vec<_> = (0..1000)
        .map(|i| ("notes".into(), format!("n{i}"), b"{}".to_vec()))
        .collect();
    m.commit_batch_atomic(&writes, &[])?;
    assert_eq!(m.count_keys("notes")?, 1000);
    println!("atomic uninterrupted: persisted=1000/1000");
    Ok(())
}
fn main() -> DemoResult {
    let args: Vec<_> = std::env::args_os().collect();
    if args.get(1).is_some_and(|a| a == "--batch-child") {
        return batch_child(Path::new(&args[2]), &args[3].to_string_lossy());
    }
    // A fresh location per run; retained for inspection, with no destructive cleanup.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let base = PathBuf::from("target/demo14").join(format!("{}-{stamp}", std::process::id()));
    fs::create_dir_all(&base)?;
    println!("clove1db 0.0.126 demo; data={}", base.display());
    size_demo(&base.join("size"))?;
    mixed_demo(&base.join("mixed"))?;
    migration_demo(&base.join("migration"))?;
    report_demo(&base.join("report"))?;
    batch_demo(&base.join("batches"))?;
    println!("All assertions passed.");
    Ok(())
}
