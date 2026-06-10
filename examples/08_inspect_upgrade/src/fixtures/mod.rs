mod external_redb;
mod fake;
mod seed_042;
mod seed_049;
mod seed_056;

use crate::log;
use crate::paths;

pub struct RetailManifest {
    pub products: Vec<(String, String)>,
    pub history_product_id: String,
    pub buyers: Vec<(String, String, String)>,
    pub employees: Vec<(String, String, String)>,
}

pub struct SeedState {
    pub retail_042: RetailManifest,
    pub retail_049: RetailManifest,
    pub attachment_id: String,
}

fn map_seed_err(context: &str, err: impl std::fmt::Display) -> clove1db::units::ClError {
    clove1db::units::ClError::MigrationError(format!("{context}: {err}"))
}

pub fn seed_all() -> clove1db::units::Result<SeedState> {
    log::banner("Phase 1 — Seeding fixtures");
    std::fs::create_dir_all(paths::base())?;
    log::kv("data_dir", paths::BASE_DIR);

    log::step("fake — directory named .cldb (invalid file)");
    fake::create().map_err(|e| map_seed_err("fake", e))?;
    log::ok("created fake_shop.cldb/ as directory");

    log::step("external_redb — foreign inventory table");
    external_redb::create()?;
    log::ok("foreign.cldb with 5 inventory rows (non-entity JSON)");

    log::step("seed_042 — clove1db-v042 retail + attachments");
    let retail_042 = seed_042::create().map_err(|e| map_seed_err("seed_042", e))?;
    log::ok(format!(
        "{} products, {} buyers, {} employees; 1× ~2MiB attachment",
        retail_042.products.len(),
        retail_042.buyers.len(),
        retail_042.employees.len()
    ));

    log::step("seed_049 — clove1db-v049 + in-place RetailV1→RetailV2 migration");
    let retail_049 = seed_049::create().map_err(|e| map_seed_err("seed_049", e))?;
    log::ok(format!(
        "migration applied; {} products now V2 (sku + price_cents)",
        retail_049.products.len()
    ));

    log::step("seed_056 — current clove1db authenticated retail");
    seed_056::create()?;
    log::ok("era_056 retail.cldb with _clove_meta");

    let state = SeedState {
        retail_042,
        retail_049,
        attachment_id: seed_042::attachment_id(),
    };
    log::print_seed_summary(&state);
    Ok(state)
}
