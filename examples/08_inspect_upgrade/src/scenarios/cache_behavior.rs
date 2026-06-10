use clove1db::units::Result;

use crate::entities::{AttachmentFullResponse, AttachmentMetaResponse, ProductV1Response};
use crate::entities::seed_counts;
use crate::fixtures::SeedState;
use crate::log;
use crate::paths::{self, copy_dir_all};
use crate::storage::{attachments_storage, cache_off_storage, retail_v1_storage};

pub fn run(seed: &SeedState) -> Result<()> {
    log::step("Retail with cache ON (default) — double get + list");

    let storage = retail_v1_storage(paths::upgraded_042_dir(), "retail", "retail")?;
    let domain = storage.domain::<crate::entities::ProductV1>();
    let id = &seed.retail_042.products[0].0;
    log::kv("sample_product_id", log::short_id(id));

    let a = domain.get::<ProductV1Response>(id)?;
    let b = domain.get::<ProductV1Response>(id)?;
    log::line(format!("get #1: id={} name={}", log::short_id(&a.id), a.name));
    log::line(format!("get #2: id={} name={} (cache hit)", log::short_id(&b.id), b.name));

    if a.name != b.name || a.id != b.id {
        return Err(clove1db::units::ClError::Validation(
            "cached get mismatch".into(),
        ));
    }
    let listed = domain.list::<ProductV1Response>()?;
    log::kv("list.len()", listed.len());
    if listed.len() != seed_counts::PRODUCTS {
        return Err(clove1db::units::ClError::Validation("list with cache".into()));
    }
    log::ok("cache ON: identical reads, list count correct");
    drop(storage);

    log::step("Attachments — backup OFF, cache OFF, ~2 MiB blob");
    let attach_parent = paths::upgraded_attachments_dir();
    if attach_parent.exists() {
        std::fs::remove_dir_all(&attach_parent)?;
    }
    copy_dir_all(
        &paths::era_042_attachments_dir(),
        &attach_parent.join("attachments"),
    )?;
    log::path_entry("source", &paths::era_042_attachments_cldb());

    let attach_storage = attachments_storage(attach_parent.clone())?;
    let files = attach_storage.domain::<crate::entities::AttachmentV1>();

    let meta = files.get::<AttachmentMetaResponse>(&seed.attachment_id)?;
    log::line(format!(
        "AttachmentMetaResponse: id={} file={} size_bytes={}",
        log::short_id(&meta.id),
        meta.filename,
        meta.size_bytes
    ));

    let full = files.get::<AttachmentFullResponse>(&seed.attachment_id)?;
    log::kv("full payload len", full.data.len());
    if full.data.len() != seed_counts::ATTACHMENT_BYTES {
        return Err(clove1db::units::ClError::Validation(format!(
            "attachment size {}",
            full.data.len()
        )));
    }
    log::ok(format!(
        "binary integrity OK ({} bytes = 2 MiB)",
        seed_counts::ATTACHMENT_BYTES
    ));
    drop(attach_storage);

    log::step("Retail copy with explicit has_cache(false) after upgrade");
    let cache_off_parent = paths::cache_off_dir();
    if cache_off_parent.exists() {
        std::fs::remove_dir_all(&cache_off_parent)?;
    }
    copy_dir_all(
        &paths::era_042_retail_dir(),
        &cache_off_parent.join("retail"),
    )?;
    let off_storage = cache_off_storage(cache_off_parent)?;
    let off_domain = off_storage.domain::<crate::entities::ProductV1>();
    let count = off_domain.list::<ProductV1Response>()?.len();
    log::kv("list with cache OFF", count);
    if count != seed_counts::PRODUCTS {
        return Err(clove1db::units::ClError::Validation(
            "cache-off CRUD after upgrade".into(),
        ));
    }
    log::ok("CRUD works with cache disabled");

    Ok(())
}
