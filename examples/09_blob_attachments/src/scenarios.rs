use std::io::Read;
use std::path::{Path, PathBuf};

use clove1db::{
    inspect_cldb,
    migration::{
        ExternalFrom, KeyDecoder, MigrationTo, ValueDecoder,
    },
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::Result,
};
use redb::{Database, Durability, ReadableDatabase, TableDefinition};
use serde_json::json;

use crate::entities::{
    AttachmentMeta, AttachmentMetaResponse, ExternalAttachmentRow, LegacyAttachmentInline,
    UploadAttachmentDto,
};
use crate::log;

pub const BASE_DIR: &str = "./target/example_09_blob";

pub fn attachments_storage(dir: PathBuf) -> Result<Storage> {
    Storage::builder(StorageConfig::default())
        .migration_step::<LegacyAttachmentInline, AttachmentMeta>()
        .migration_step::<ExternalAttachmentRow, AttachmentMeta>()
        .add_database(
            DatabaseConfig::new("attachments", "attachments")
                .dir_path(dir)
                .backup_enabled(false)
                .has_cache(false)
                .blob_enabled(true)
                .register_blob::<AttachmentMeta>("files"),
        )
        .build()
}

pub fn legacy_inline_storage(dir: PathBuf) -> Result<Storage> {
    Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("legacy", "legacy")
                .dir_path(dir)
                .backup_enabled(false)
                .has_cache(false)
                .register::<LegacyAttachmentInline>("files"),
        )
        .build()
}

pub fn scenario_crud(base: &Path) -> Result<()> {
    log::banner("Scenario 1 — Blob CRUD + open_blob");
    let dir = base.join("crud");
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }

    let storage = attachments_storage(dir.clone())?;
    let domain = storage.domain::<AttachmentMeta>();

    let payload = b"hello blob sidecar world".to_vec();
    let meta = domain.create_with_blob::<UploadAttachmentDto, AttachmentMetaResponse>(
        UploadAttachmentDto {
            filename: "hello.txt".into(),
            account_id: 42,
            mime: "text/plain".into(),
        },
        payload.clone(),
    )?;
    let meta = domain.get::<AttachmentMetaResponse>(&meta.id)?;
    log::kv("created id", &meta.id);
    log::kv("size_bytes", meta.size_bytes);

    let fetched = domain.get::<AttachmentMetaResponse>(&meta.id)?;
    assert_eq!(fetched.filename, "hello.txt");

    let mut file = domain.open_blob(&meta.id)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    assert_eq!(buf, payload);
    log::ok("open_blob returned original payload");

    domain.delete(&meta.id)?;
    log::ok("deleted metadata + blob");

    drop(storage);

    let cldb = dir.join("attachments").join("attachments.cldb");
    let report = inspect_cldb(&cldb)?;
    log::kv("blob_enabled", report.blob_enabled);
    log::kv("table_storage modes", report.table_storage.len());
    log::ok("inspect_cldb reports blob sidecar config");
    Ok(())
}

pub fn scenario_scan(base: &Path) -> Result<()> {
    log::banner("Scenario 2 — Migration scan preview");
    let dir = base.join("scan");
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }

    let storage = Storage::builder(StorageConfig::default())
        .migration_step::<LegacyAttachmentInline, AttachmentMeta>()
        .add_database(
            DatabaseConfig::new("legacy", "legacy")
                .dir_path(dir.clone())
                .backup_enabled(false)
                .has_cache(false)
                .register::<LegacyAttachmentInline>("files"),
        )
        .add_database(
            DatabaseConfig::new("attachments", "attachments")
                .dir_path(dir.clone())
                .backup_enabled(false)
                .has_cache(false)
                .blob_enabled(true)
                .register_blob::<AttachmentMeta>("files"),
        )
        .build()?;

    let legacy = storage.domain::<LegacyAttachmentInline>();
    let inline = LegacyAttachmentInline {
        id: "inline-1".into(),
        filename: "scan-me.bin".into(),
        account_id: 7,
        data: vec![1, 2, 3, 4, 5],
        mime: "application/octet-stream".into(),
    };
    legacy.repo().set(&inline.id, &inline)?;

    let report = storage
        .migrate::<LegacyAttachmentInline, AttachmentMeta>()
        .from_db("legacy", "files")
        .to(clove1db::migration::MigrationTo::new("attachments").table("files"))
        .scan()?;
    log::kv("record_count", report.record_count);
    log::kv("inline_with_payload_hint", report.inline_with_payload_hint);
    log::ok("scan completed without writing target DB");
    Ok(())
}

pub fn scenario_external_migrate(base: &Path) -> Result<()> {
    log::banner("Scenario 3 — External 0xFB redb → blob (migrate_blob)");
    let dir = base.join("external");
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }

    let external_path = seed_external_redb(&dir)?;

    let storage = attachments_storage(dir.clone())?;
    let result = storage
        .migrate::<ExternalAttachmentRow, AttachmentMeta>()
        .from_external(ExternalFrom {
            path: external_path.clone(),
            table: "attachments".into(),
            key_decoder: KeyDecoder::U64AsString,
            value_decoder: ValueDecoder::BytesAsArray,
        })
        .to(
            clove1db::migration::MigrationTo::new("attachments")
                .table("files"),
        )
        .execute()?;
    log::kv("records_migrated", result.records_migrated);
    log::kv("blobs_written", result.report.blobs_written);

    let domain = storage.domain::<AttachmentMeta>();
    let listed = domain.list::<AttachmentMetaResponse>()?;
    for item in &listed {
        log::line(format!(
            "  [{}] {} ({} bytes, {})",
            &item.id[..8.min(item.id.len())],
            item.filename,
            item.size_bytes,
            item.mime
        ));
    }
    log::ok("external rows imported with blob sidecar");
    Ok(())
}

pub fn scenario_inline_to_blob(base: &Path) -> Result<()> {
    log::banner("Scenario 4 — Inline JSON+data → blob sidecar");
    let dir = base.join("inline_to_blob");
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }

    let storage = Storage::builder(StorageConfig::default())
        .migration_step::<LegacyAttachmentInline, AttachmentMeta>()
        .add_database(
            DatabaseConfig::new("legacy", "legacy")
                .dir_path(dir.clone())
                .backup_enabled(false)
                .has_cache(false)
                .register::<LegacyAttachmentInline>("files"),
        )
        .add_database(
            DatabaseConfig::new("attachments", "attachments")
                .dir_path(dir.clone())
                .backup_enabled(false)
                .has_cache(false)
                .blob_enabled(true)
                .register_blob::<AttachmentMeta>("files"),
        )
        .build()?;

    let legacy = storage.domain::<LegacyAttachmentInline>();
    let row = LegacyAttachmentInline {
        id: "doc-1".into(),
        filename: "notes.txt".into(),
        account_id: 99,
        data: b"inline payload moved to blob".to_vec(),
        mime: "text/plain".into(),
    };
    legacy.repo().set(&row.id, &row)?;

    let result = storage
        .migrate::<LegacyAttachmentInline, AttachmentMeta>()
        .from_db("legacy", "files")
        .to(
            clove1db::migration::MigrationTo::new("attachments")
                .table("files")
                .delete_source(true),
        )
        .execute()?;
    log::kv("records_migrated", result.records_migrated);
    log::kv("blobs_written", result.report.blobs_written);

    let domain = storage.domain::<AttachmentMeta>();
    let meta = domain.get::<AttachmentMetaResponse>("doc-1")?;
    log::kv("meta.size_bytes", meta.size_bytes);
    let mut f = domain.open_blob("doc-1")?;
    let mut buf = String::new();
    f.read_to_string(&mut buf)?;
    log::kv("blob text", &buf);
    log::ok("inline data split into blob file + metadata JSON");
    Ok(())
}

fn seed_external_redb(dir: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join("vendor.redb");
    let db = Database::create(&path).map_err(|e| clove1db::units::ClError::Database(e.into()))?;
    let mut header = vec![0xfb, 0x01, 0x00, 0x00];
    header.extend_from_slice(&1001u32.to_le_bytes());
    let mut png = header.clone();
    png.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    png.extend_from_slice(b"fakepng");
    let mut write_txn = db.begin_write()?;
    write_txn.set_durability(Durability::Immediate)?;
    {
        let table: TableDefinition<u64, &[u8]> = TableDefinition::new("attachments");
        let mut t = write_txn.open_table(table)?;
        t.insert(1u64, png.as_slice())?;
    }
    write_txn.commit()?;
    log::kv("seeded external redb", path.display());
    let _ = json!({"probe": true});
    Ok(path)
}
