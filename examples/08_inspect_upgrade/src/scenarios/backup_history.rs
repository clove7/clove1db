use clove1db::{
    backup::view::{HistoryDisplayMode, RecordData},
    units::Result,
};

use clove1db::repository::BackupRecordRepository;

use crate::entities::{ProductV1, seed_counts};
use crate::fixtures::SeedState;
use crate::log;
use crate::paths;
use crate::storage::{retail_v1_storage, retail_v2_storage};
use crate::verify::{assert_backup_versions, assert_get_by_version_readable};

fn print_history_v1(label: &str, records: &[BackupRecordRepository<ProductV1>]) {
    log::subsection(label);
    for record in records {
        let title = match &record.data {
            RecordData::Typed(json) | RecordData::Json(json) => json
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string(),
            RecordData::None => "(deleted)".into(),
        };
        log::line(format!(
            "v{} | op={:?} | restorable={} | name={title}",
            record.version, record.operation, record.restorable
        ));
    }
}

pub fn run(seed: &SeedState) -> Result<()> {
    log::step("042 upgraded — backup history on history_product (≥3 versions)");

    let storage = retail_v1_storage(paths::upgraded_042_dir(), "retail", "retail")?;
    let pid = &seed.retail_042.history_product_id;
    log::kv("history_product_id", log::short_id(pid));

    assert_backup_versions(&storage, pid, seed_counts::MIN_PRODUCT_HISTORY)?;
    assert_get_by_version_readable(&storage, pid)?;

    let domain = storage.domain::<crate::entities::ProductV1>();
    let as_stored = domain.history_with_mode(pid, HistoryDisplayMode::AsStored)?;
    let normalized = domain.history_with_mode(pid, HistoryDisplayMode::Normalized)?;

    print_history_v1("HistoryDisplayMode::AsStored", &as_stored);
    print_history_v1("HistoryDisplayMode::Normalized", &normalized);

    if as_stored.is_empty() || normalized.is_empty() {
        return Err(clove1db::units::ClError::Validation(
            "history modes returned empty".into(),
        ));
    }
    log::ok(format!(
        "as_stored={} versions, normalized={} versions",
        as_stored.len(),
        normalized.len()
    ));

    let v1 = domain.get_by_version(pid, 1)?;
    log::subsection("get_by_version(product, 1)");
    match &v1.data {
        RecordData::Json(json) | RecordData::Typed(json) => {
            log::line(format!("RecordData JSON: {}", json));
        }
        RecordData::None => log::line("RecordData::None"),
    }

    drop(storage);

    log::step("049 upgraded — normalized history on migrated product");
    let storage_v2 = retail_v2_storage(paths::upgraded_049_dir(), "retail", "retail")?;
    let domain_v2 = storage_v2.domain::<crate::entities::ProductV2>();
    let pid49 = &seed.retail_049.history_product_id;
    log::kv("history_product_id", log::short_id(pid49));

    let hist = domain_v2.history_with_mode(pid49, HistoryDisplayMode::Normalized)?;
    log::subsection("049 Normalized (ProductV2 fields in history)");
    for record in &hist {
        let title = match &record.data {
            RecordData::Typed(json) | RecordData::Json(json) => json
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string(),
            RecordData::None => "(deleted)".into(),
        };
        let sku = match &record.data {
            RecordData::Typed(json) | RecordData::Json(json) => json
                .get("sku")
                .and_then(|v| v.as_str())
                .unwrap_or("-")
                .to_string(),
            RecordData::None => "-".into(),
        };
        log::line(format!(
            "v{} | op={:?} | name={title} | sku={sku} | schema={}",
            record.version, record.operation, record.schema_at_version
        ));
    }

    if hist.len() < seed_counts::MIN_PRODUCT_HISTORY {
        return Err(clove1db::units::ClError::Validation(format!(
            "049 history len {}",
            hist.len()
        )));
    }
    log::ok(format!("{} backup versions after V1→V2 migration", hist.len()));

    Ok(())
}
