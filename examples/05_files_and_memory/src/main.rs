//! # 05 — Files and memory
//!
//! Three things that decide how much memory and disk a program uses.
//!
//! 1. **Attachments.** A table registered with `register_blob` keeps one file per row in a folder
//!    next to the database (`{db}.blobs`). The row holds the metadata; the file is written before
//!    the row commits and is read as a stream (`Read + Seek`), never loaded whole unless you ask.
//! 2. **The cache budget.** `cache_bytes(max_bytes, ttl, idle)` sizes the cache of decoded rows in
//!    **bytes**. `get_uncached` reads without filling it, for a walk over many rows read once.
//!    Expired entries are freed by `run_cache_maintenance()`; `cache_stats()` shows what is held.
//! 3. **Reading a large table.** `get_uncached_as::<Summary>` reads only the fields a smaller type
//!    names, and `list_map` turns each row into what you keep while the table is read, so the
//!    whole table is never held twice. `redb_cache_bytes` caps redb's own page cache per file.
//!
//! Run it with `cargo run --release` from this folder.

use clove1db::{
    dto::{InputDto, OutputDto},
    entity::Entity,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::{ClError, Result},
};
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::time::Instant;

// ── Attachments ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Attachment {
    id: String,
    filename: String,
    mime: String,
    size_bytes: usize, // filled in by the library when the file is stored
}

impl Entity for Attachment {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Deserialize)]
struct Upload {
    id: String,
    filename: String,
    mime: String,
}

impl InputDto<Attachment> for Upload {
    fn validate(&self) -> Result<()> {
        if self.filename.contains(['/', '\\']) {
            return Err(ClError::Validation("a file name, not a path".into()));
        }
        Ok(())
    }
    fn into_entity(self) -> Result<Attachment> {
        Ok(Attachment { id: self.id, filename: self.filename, mime: self.mime, size_bytes: 0 })
    }
}

#[derive(Debug, Serialize)]
struct AttachmentView {
    id: String,
    filename: String,
    size_bytes: usize,
}

impl OutputDto<Attachment> for AttachmentView {
    fn from_entity(e: Attachment) -> Self {
        Self { id: e.id, filename: e.filename, size_bytes: e.size_bytes }
    }
}

// ── Rows with a large field ───────────────────────────────────────────────────

/// An event with about 10 KB of payload.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Event {
    id: String,
    kind: String,
    at: u64,
    payload: String,
}

impl Entity for Event {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// The same row without its payload: serde skips the field without building it.
#[derive(Debug, Deserialize)]
struct Summary {
    id: String,
    kind: String,
}

fn check(ok: bool, what: &str) -> Result<()> {
    if ok {
        println!("  ok  {what}");
        Ok(())
    } else {
        Err(ClError::Validation(format!("check failed: {what}")))
    }
}

const ROWS: usize = 2_000;
const PAYLOAD: usize = 10_000;
const BUDGET: u64 = 2 * 1024 * 1024;

fn open(root: &Path) -> Result<Storage> {
    Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("files", "files")
                .dir_path(root.to_path_buf())
                .has_cache(false)
                .blob_enabled(true)
                .register_blob::<Attachment>("attachments"),
        )
        .add_database(
            DatabaseConfig::new("events", "events")
                .dir_path(root.to_path_buf())
                .cache_bytes(BUDGET, 300, 60) // 2 MiB of decoded rows
                .redb_cache_bytes(16 * 1024 * 1024) // 16 MiB of redb pages for this file
                .register::<Event>("events"),
        )
        .build()
}

fn file_bytes(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

fn attachments(storage: &Storage, root: &Path) -> Result<()> {
    println!("\nattachments");
    let files = storage.domain::<Attachment>();
    let content = file_bytes(7, 3 * 1024 * 1024 + 123);
    let stored = files.create_with_blob::<Upload, AttachmentView>(
        Upload { id: "report".into(), filename: "report.bin".into(), mime: "application/octet-stream".into() },
        content.clone(),
    )?;
    let meta = files.get::<AttachmentView>(&stored.id)?;
    println!("  stored {} ({} bytes)", meta.filename, meta.size_bytes);
    check(meta.size_bytes == content.len(), "the row records the file's size")?;
    check(root.join("files").join("files.blobs").is_dir(), "the file lives in files.blobs, not in the .cldb")?;

    let mut reader = files.open_blob("report")?;
    let mut chunk = vec![0u8; 64 * 1024];
    let mut read_back = Vec::with_capacity(content.len());
    loop {
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        read_back.extend_from_slice(&chunk[..n]);
    }
    check(read_back == content, "read in 64 KiB pieces, the file is byte for byte what was stored")?;

    let middle = 2 * 1024 * 1024;
    reader.seek(SeekFrom::Start(middle as u64))?;
    let mut sixteen = [0u8; 16];
    reader.read_exact(&mut sixteen)?;
    check(sixteen[..] == content[middle..middle + 16], "a seek reads from the middle without reading the start")?;
    drop(reader);

    files.delete("report")?;
    check(files.get::<AttachmentView>("report").is_err(), "deleting the row deletes the attachment with it")?;
    Ok(())
}

fn cache_budget(storage: &Storage) -> Result<()> {
    println!("\nthe cache budget: {ROWS} rows of about 10 KB, a budget of 2 MiB");
    let events = storage.domain::<Event>();
    let db = storage.db_manager("events");
    let rows = (0..ROWS)
        .map(|i| {
            let e = Event { id: format!("e{i:05}"), kind: ["open", "save", "close"][i % 3].into(), at: i as u64, payload: "p".repeat(PAYLOAD) };
            Ok(("events".to_string(), e.id.clone(), serde_json::to_vec(&e)?))
        })
        .collect::<Result<Vec<_>>>()?;
    db.commit_batch_atomic(&rows, &[])?;
    println!("  table: about {} MB of rows", ROWS * PAYLOAD / 1_000_000);

    for i in 0..ROWS {
        let _: Event = events.repo().get(&format!("e{i:05}"))?;
    }
    storage.run_cache_maintenance();
    let (bytes, entries) = db.cache_stats();
    println!("  after reading every row with get: {bytes} bytes in {entries} entries");
    check(bytes <= BUDGET, "the cache holds no more than its byte budget")?;
    check((entries as usize) < ROWS, "so it keeps only part of the table")?;

    db.clear_cache();
    for i in 0..ROWS {
        let _: Event = events.repo().get_uncached(&format!("e{i:05}"))?;
    }
    storage.run_cache_maintenance();
    let (bytes, entries) = db.cache_stats();
    println!("  after reading every row with get_uncached: {bytes} bytes in {entries} entries");
    check(bytes == 0 && entries == 0, "get_uncached leaves the cache empty")?;
    Ok(())
}

fn large_table(storage: &Storage) -> Result<()> {
    println!("\nreading the whole table");
    let events = storage.domain::<Event>();

    let started = Instant::now();
    let full = events.repo().list_map(|e: Event| e.payload.len())?;
    let full_time = started.elapsed();

    let started = Instant::now();
    let mut kinds = 0usize;
    for i in 0..ROWS {
        let s: Summary = events.repo().get_uncached_as(&format!("e{i:05}"))?;
        if s.kind == "save" && s.id.starts_with('e') {
            kinds += 1;
        }
    }
    let summary_time = started.elapsed();

    println!("  list_map over every row, whole rows: {:.1} ms", full_time.as_secs_f64() * 1e3);
    println!("  get_uncached_as::<Summary> for every row, no payload: {:.1} ms", summary_time.as_secs_f64() * 1e3);
    check(full.len() == ROWS && full.iter().all(|&n| n == PAYLOAD), "list_map saw every row and kept one number each")?;
    check(kinds == ROWS / 3 + usize::from(ROWS % 3 > 1), "the summaries are right without the payload")?;
    Ok(())
}

fn main() -> Result<()> {
    let root = std::env::temp_dir().join(format!("clove1db-example-05-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    println!("05 files and memory — data in {}", root.display());

    let storage = open(&root)?;
    attachments(&storage, &root)?;
    cache_budget(&storage)?;
    large_table(&storage)?;
    storage.close();
    drop(storage);

    std::fs::remove_dir_all(&root)?;
    println!("\n05 files and memory: all checks passed");
    Ok(())
}
