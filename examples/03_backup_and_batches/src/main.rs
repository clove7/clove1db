//! # 03 — History, restore and batches
//!
//! With `backup_enabled(true)` every write and delete through the domain or the repository is kept
//! in a `.cldb.bak` file next to the database, forever. From it you can:
//!
//! - list the **history** of a row: every version, what was done, when;
//! - read a row **as it was** at a version, and **restore** it to that version (a restore is itself
//!   a new version, so nothing is lost);
//! - update many rows at once with one **bulk id**, and undo the whole bulk later.
//!
//! Raw batches are the other way to write, for imports and copies. They are outside the history:
//!
//! - `commit_batch_atomic(writes, deletes)` commits everything in **one transaction**, whatever
//!   its size: all or nothing;
//! - `commit_batch(writes, deletes)` splits a large batch into chunks of
//!   `max_commit_batch_entries` (512 by default). A failure in a later chunk leaves the earlier
//!   chunks committed.
//!
//! Run it with `cargo run` from this folder.

use clove1db::{
    CloveFields, Unique,
    backup::BackupOperation,
    backup::view::RecordData,
    dto::{InputDto, OutputDto},
    entity::Entity,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::{ClError, Result},
};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Document {
    id: String,
    title: String,
    body: String,
}

impl Entity for Document {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Deserialize)]
struct WriteDocument {
    id: String,
    title: String,
    body: String,
}

impl InputDto<Document> for WriteDocument {
    fn validate(&self) -> Result<()> {
        if self.title.trim().is_empty() {
            return Err(ClError::Validation("title is required".into()));
        }
        Ok(())
    }
    fn into_entity(self) -> Result<Document> {
        Ok(Document { id: self.id, title: self.title, body: self.body })
    }
}

#[derive(Debug, Serialize)]
struct DocumentView {
    id: String,
    title: String,
}

impl OutputDto<Document> for DocumentView {
    fn from_entity(e: Document) -> Self {
        Self { id: e.id, title: e.title }
    }
}

/// A device whose status is changed in bulk.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Device {
    id: String,
    status: String,
}

impl Entity for Device {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Deserialize)]
struct SetStatus {
    id: String,
    status: String,
}

impl InputDto<Device> for SetStatus {
    fn into_entity(self) -> Result<Device> {
        Ok(Device { id: self.id, status: self.status })
    }
}

#[derive(Debug, Serialize)]
struct DeviceView {
    status: String,
}

impl OutputDto<Device> for DeviceView {
    fn from_entity(e: Device) -> Self {
        Self { status: e.status }
    }
}

/// Rows written by raw batches. The unique `code` makes one row of a batch fail on purpose.
#[derive(Debug, Clone, Default, Serialize, Deserialize, CloveFields)]
struct Item {
    id: String,
    code: String,
}

impl Entity for Item {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn check(ok: bool, what: &str) -> Result<()> {
    if ok {
        println!("  ok  {what}");
        Ok(())
    } else {
        Err(ClError::Validation(format!("check failed: {what}")))
    }
}

fn open(root: &Path) -> Result<Storage> {
    Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("docs", "docs")
                .dir_path(root.to_path_buf())
                .backup_enabled(true)
                .register::<Document>("documents")
                .register::<Device>("devices"),
        )
        .add_database(
            DatabaseConfig::new("items", "items")
                .dir_path(root.to_path_buf())
                .has_cache(false)
                .max_commit_batch_entries(512)
                .register::<Item>("items")
                .unique::<Item>(Unique::on(Item::code)),
        )
        .build()
}

fn write(id: &str, title: &str, body: &str) -> WriteDocument {
    WriteDocument { id: id.into(), title: title.into(), body: body.into() }
}

fn history(storage: &Storage) -> Result<()> {
    let docs = storage.domain::<Document>();

    println!("\nfour versions of one document");
    docs.create::<WriteDocument, DocumentView>(write("doc-1", "Draft", "first ideas"))?;
    docs.update::<WriteDocument, DocumentView>("doc-1", write("doc-1", "Second draft", "more detail"))?;
    docs.update::<WriteDocument, DocumentView>("doc-1", write("doc-1", "Final", "polished"))?;
    docs.delete("doc-1")?;
    check(docs.get::<DocumentView>("doc-1").is_err(), "the deleted row is gone from the database")?;

    let versions = docs.history("doc-1")?;
    for r in &versions {
        let title = match &r.data {
            RecordData::Typed(json) | RecordData::Json(json) => {
                json.get("title").and_then(|v| v.as_str()).unwrap_or("?").to_string()
            }
            RecordData::None => "(no data: deleted)".into(),
        };
        println!("  v{} {:?} {} {}", r.version, r.operation, r.date, title);
    }
    check(versions.len() == 4, "the history kept all four versions")?;
    check(versions[3].operation == BackupOperation::Delete, "the last one is the delete")?;

    println!("\nread an old version, then restore it");
    let v2 = docs.get_by_version("doc-1", 2)?;
    let v2_title = v2.data.as_json().and_then(|j| j.get("title")).and_then(|t| t.as_str()).map(str::to_string);
    check(v2_title.as_deref() == Some("Second draft"), "version 2 reads as it was")?;
    docs.restore_by_version("doc-1", 1)?;
    check(docs.get::<DocumentView>("doc-1")?.title == "Draft", "after the restore the row is version 1 again")?;
    let after = docs.history("doc-1")?;
    let last = after.last().ok_or(ClError::Validation("no history".into()))?;
    check(
        after.len() == 5 && last.operation == BackupOperation::Restore && last.restored_version == Some(1),
        "the restore is a fifth version that says it came from version 1",
    )?;
    Ok(())
}

fn bulk(storage: &Storage) -> Result<()> {
    let devices = storage.domain::<Device>();
    println!("\na bulk update, and undoing it");
    for id in ["d1", "d2", "d3"] {
        devices.create::<SetStatus, DeviceView>(SetStatus { id: id.into(), status: "online".into() })?;
    }
    let payload = ["d1", "d2", "d3"]
        .iter()
        .map(|id| (id.to_string(), SetStatus { id: id.to_string(), status: "maintenance".into() }))
        .collect();
    let (_, bulk_id) = devices.update_bulk::<SetStatus, DeviceView>(payload)?;
    println!("  bulk id {bulk_id}");
    check(
        ["d1", "d2", "d3"].iter().all(|id| devices.get::<DeviceView>(id).map(|d| d.status == "maintenance").unwrap_or(false)),
        "all three are in maintenance",
    )?;
    devices.restore_bulk(&bulk_id)?;
    let statuses: Vec<String> = ["d1", "d2", "d3"]
        .iter()
        .map(|id| devices.get::<DeviceView>(id).map(|d| d.status))
        .collect::<Result<_>>()?;
    println!("  after restore_bulk: {statuses:?}");
    check(statuses.iter().all(|s| s == "online"), "restore_bulk put back what was there before the bulk")?;
    Ok(())
}

fn rows(range: std::ops::Range<usize>, duplicate_at: Option<usize>) -> Result<Vec<(String, String, Vec<u8>)>> {
    range
        .map(|i| {
            // One row repeats the code of row 0, so the unique constraint refuses it.
            let code = if Some(i) == duplicate_at { "code-000000".to_string() } else { format!("code-{i:06}") };
            let item = Item { id: format!("item-{i:06}"), code };
            Ok(("items".to_string(), item.id.clone(), serde_json::to_vec(&item)?))
        })
        .collect()
}

fn batches(storage: &Storage) -> Result<()> {
    let db = storage.db_manager("items");
    let items = storage.domain::<Item>();

    println!("\nan atomic batch of 1,000 rows");
    db.commit_batch_atomic(&rows(0..1_000, None)?, &[])?;
    check(items.query().count()? == 1_000, "all 1,000 rows were written")?;

    println!("\nan atomic batch that fails on its last row: all or nothing");
    let failed = db.commit_batch_atomic(&rows(1_000..2_000, Some(1_999))?, &[]);
    check(failed.is_err(), "the batch is refused")?;
    check(items.query().count()? == 1_000, "none of its 1,000 rows were written")?;

    println!("\na chunked batch that fails in its second chunk");
    let failed = db.commit_batch(&rows(1_000..2_000, Some(1_999))?, &[]);
    check(failed.is_err(), "the batch is refused")?;
    let count = items.query().count()?;
    println!("  rows now: {count}");
    check(count == 1_512, "the first chunk of 512 rows stayed committed")?;
    Ok(())
}

fn main() -> Result<()> {
    let root = std::env::temp_dir().join(format!("clove1db-example-03-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    println!("03 history, restore and batches — data in {}", root.display());

    let storage = open(&root)?;
    history(&storage)?;
    bulk(&storage)?;
    batches(&storage)?;
    storage.close();
    drop(storage);

    println!("\nthe history is a file of its own");
    let bak = root.join("docs").join("docs.cldb.bak");
    check(bak.is_file(), "docs.cldb.bak exists next to docs.cldb")?;
    let storage = open(&root)?;
    check(storage.domain::<Document>().history("doc-1")?.len() == 5, "and it is read again after reopening")?;
    storage.close();
    drop(storage);

    std::fs::remove_dir_all(&root)?;
    println!("\n03 history, restore and batches: all checks passed");
    Ok(())
}
