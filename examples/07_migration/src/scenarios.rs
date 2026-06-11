use std::path::PathBuf;

use clove1db::{
    backup::view::{HistoryDisplayMode, RecordData},
    inspect_cldb, FileKind,
    migration::{
        redb_external::list_external_tables, ExternalFrom, KeyDecoder, MigrationTo,
        TargetConflictPolicy, ValueDecoder,
    },
    storage::Storage,
    units::{ClError, Result},
};

use crate::external::{
    ExternalCatalogRow, read_all_rows, seed_vendor_inventory, vendor_inventory_path, VENDOR_TABLE,
};
use crate::product::ProductV1;
use crate::log;
use crate::product::{
    format_price, ProductV1Dto, ProductV1Response, ProductV2Response, ProductV3Dto, ProductV3Response,
};
use crate::storage::{
    catalog_v2_storage, catalog_v3_storage, dual_db_storage, import_target_storage,
    legacy_catalog_storage, BASE_DIR,
};

pub struct CatalogSeed {
    pub laptop_id: String,
    pub mouse_id: String,
    pub hub_id: String,
}

/// Example 1 — Seed legacy catalog with backup history.
pub fn example_seed_legacy_catalog(base: &PathBuf) -> Result<(Storage, CatalogSeed)> {
    log::banner("Example 1 — Seed legacy catalog (ProductV1 + history)");

    let storage = legacy_catalog_storage(base)?;
    log::path_entry("catalog DB", &base.join("catalog").join("legacy.cldb"));
    log::kv("schema", "products@1");
    log::kv("table", "products");
    log::kv("backup", "enabled");

    let domain = storage.domain::<crate::product::ProductV1>();

    let laptop = domain.create::<ProductV1Dto, ProductV1Response>(ProductV1Dto {
        name: "Laptop Pro 15".into(),
    })?;
    let mouse = domain.create::<ProductV1Dto, ProductV1Response>(ProductV1Dto {
        name: "Wireless Mouse".into(),
    })?;
    let hub = domain.create::<ProductV1Dto, ProductV1Response>(ProductV1Dto {
        name: "USB-C Hub".into(),
    })?;

    domain.update::<ProductV1Dto, ProductV1Response>(
        &laptop.id,
        ProductV1Dto {
            name: "Laptop Pro 15 (2024)".into(),
        },
    )?;
    domain.update::<ProductV1Dto, ProductV1Response>(
        &mouse.id,
        ProductV1Dto {
            name: "Wireless Mouse v2".into(),
        },
    )?;

    log::subsection("Seeded products (ProductV1 JSON)");
    for (label, p) in [
        ("Laptop", &laptop),
        ("Mouse", &mouse),
        ("Hub", &hub),
    ] {
        log::line(format!(
            "{label} [{}] → {{\"id\":\"{}\",\"name\":\"{}\"}}",
            log::short_id(&p.id),
            p.id,
            p.name
        ));
    }

    let hist = domain.history(&laptop.id)?;
    log::kv("laptop backup versions", hist.len());
    for r in &hist {
        if let RecordData::Json(j) | RecordData::Typed(j) = &r.data {
            log::line(format!(
                "  v{} op={:?} name={}",
                r.version,
                r.operation,
                j.get("name").and_then(|v| v.as_str()).unwrap_or("?")
            ));
        }
    }
    log::ok("legacy catalog ready");

    Ok((
        storage,
        CatalogSeed {
            laptop_id: laptop.id,
            mouse_id: mouse.id,
            hub_id: hub.id,
        },
    ))
}

/// Example 2 — dry_run before V1 → V2.
pub fn example_dry_run_v1_to_v2(storage: &Storage) -> Result<()> {
    log::banner("Example 2 — dry_run: ProductV1 → ProductV2");

    log::step("migrate::<ProductV1, ProductV2>: InPlace products@1 → @2");
    let report = storage
        .migrate::<ProductV1, crate::product::ProductV2>()
        .from_db("legacy", "products")
        .dry_run()?;

    log::print_migration_report("dry_run report", &report);
    log::line("decoder adds: sku (from name slug), price_cents=9900");
    log::ok("dry_run complete — no writes");
    Ok(())
}

/// Example 3 — Execute V1 → V2 in-place.
pub fn example_migrate_v1_to_v2(storage: Storage, seed: &CatalogSeed) -> Result<Storage> {
    log::banner("Example 3 — Execute: ProductV1 → ProductV2");

    let result = storage
        .migrate::<ProductV1, crate::product::ProductV2>()
        .from_db("legacy", "products")
        .execute()?;

    log::kv("migration_id", &result.migration_id);
    log::kv("records_migrated", result.records_migrated);
    drop(storage);

    let storage = catalog_v2_storage(&PathBuf::from(BASE_DIR))?;
    let idx = storage.migration_index("legacy")?;
    if let Some(tc) = idx.tables.get("products") {
        log::kv("products schema_version", tc.current_version());
        log::kv("chain entries", tc.index.chain.len());
    }

    let domain = storage.domain::<crate::product::ProductV2>();
    log::subsection("Products after migration (ProductV2 JSON)");
    for (label, id) in [
        ("Laptop", &seed.laptop_id),
        ("Mouse", &seed.mouse_id),
        ("Hub", &seed.hub_id),
    ] {
        let p = domain.get::<ProductV2Response>(id)?;
        log::line(format!(
            "{label} → {{\"id\":\"{}\",\"name\":\"{}\",\"sku\":\"{}\",\"price_cents\":{}}}",
            p.id, p.name, p.sku, p.price_cents
        ));
        log::line(format!("         display: {} | {}", p.sku, format_price(p.price_cents)));
    }
    log::ok("in-place schema migration");
    Ok(storage)
}

/// Example 4 — History AsStored vs Normalized.
pub fn example_product_history_modes(storage: &Storage, laptop_id: &str) -> Result<()> {
    log::banner("Example 4 — History: AsStored vs Normalized");
    log::kv("product_id", log::short_id(laptop_id));

    let domain = storage.domain::<crate::product::ProductV2>();

    log::subsection("AsStored — JSON as written in each backup era");
    for r in domain.history_with_mode(laptop_id, HistoryDisplayMode::AsStored)? {
        if let RecordData::Json(json) | RecordData::Typed(json) = &r.data {
            let keys: Vec<_> = json
                .as_object()
                .map(|o| o.keys().cloned().collect())
                .unwrap_or_default();
            log::line(format!(
                "v{} schema={} restorable={} keys={keys:?}",
                r.version, r.schema_at_version, r.restorable
            ));
            log::line(format!("       body: {json}"));
        }
    }

    log::subsection("Normalized — decoded to current ProductV2 shape");
    for r in domain.history_with_mode(laptop_id, HistoryDisplayMode::Normalized)? {
        if let Some(json) = r.data.as_json() {
            log::line(format!(
                "v{} sku={} price_cents={}",
                r.version,
                json.get("sku").and_then(|v| v.as_str()).unwrap_or("-"),
                json.get("price_cents").and_then(|v| v.as_u64()).unwrap_or(0)
            ));
        }
    }
    log::ok("history modes demonstrated");
    Ok(())
}

/// Example 5 — Chained V2 → V3.
pub fn example_migrate_v2_to_v3(storage: Storage, seed: &CatalogSeed) -> Result<Storage> {
    log::banner("Example 5 — Chained migration: ProductV2 → ProductV3");

    let idx_before = storage.migration_index("legacy")?;
    if let Some(tc) = idx_before.tables.get("products") {
        log::kv(
            "chain before",
            format!("{} step(s) → products@{}", tc.index.chain.len(), tc.current_version()),
        );
    }

    let result = storage
        .migrate::<crate::product::ProductV2, crate::product::ProductV3>()
        .from_db("legacy", "products")
        .execute()?;

    log::kv("migration_id", &result.migration_id);
    log::kv("records_migrated", result.records_migrated);
    log::line("decoder adds: category (from name heuristics), stock=50");
    drop(storage);

    let storage = catalog_v3_storage(&PathBuf::from(BASE_DIR))?;
    let idx = storage.migration_index("legacy")?;
    if let Some(tc) = idx.tables.get("products") {
        log::kv(
            "chain after",
            format!("{} step(s) → products@{}", tc.index.chain.len(), tc.current_version()),
        );
    }

    let domain = storage.domain::<crate::product::ProductV3>();
    for (label, id) in [("Laptop", &seed.laptop_id), ("Mouse", &seed.mouse_id)] {
        let p = domain.get::<ProductV3Response>(id)?;
        log::line(format!(
            "{label}: {} | {} | category={} stock={} @ {}",
            p.name, p.sku, p.category, p.stock, format_price(p.price_cents)
        ));
    }
    log::ok("second migration in chain");
    Ok(storage)
}

/// Example 6 — Restore guards.
pub fn example_restore_guards(storage: &Storage, laptop_id: &str) -> Result<()> {
    log::banner("Example 6 — Restore guards on product history");
    log::kv("product_id", log::short_id(laptop_id));

    let domain = storage.domain::<crate::product::ProductV3>();

    log::step("Attempt restore v1 (pre-migration ProductV1 era) — expect NotRestorable");
    match domain.restore_by_version(laptop_id, 1) {
        Err(ClError::NotRestorable {
            version,
            schema_at_version,
            current_schema_version,
            migration_id,
        }) => {
            log::ok(format!(
                "v{version} blocked — schema_at_version={schema_at_version}, current={current_schema_version}, mig={migration_id}"
            ));
        }
        Ok(_) => log::line("⚠ v1 unexpectedly restored"),
        Err(e) => log::line(format!("⚠ {e}")),
    }

    log::step("Update then restore current version");
    domain.update::<ProductV3Dto, ProductV3Response>(
        laptop_id,
        ProductV3Dto {
            name: "Laptop Pro 15 — Sale".into(),
            sku: "SKU-laptop_pro_15".into(),
            price_cents: 8_499,
            category: "computers".into(),
            stock: 12,
        },
    )?;
    let post_v = domain.current_version(laptop_id)?;
    log::kv("new version after update", post_v);
    domain.restore_by_version(laptop_id, post_v)?;
    let restored = domain.get::<ProductV3Response>(laptop_id)?;
    log::ok(format!(
        "v{post_v} restored → {} @ {}",
        restored.name,
        format_price(restored.price_cents)
    ));
    Ok(())
}

/// Example 7 — Cross-DB warehouse → shop floor.
pub fn example_cross_db_product_move(base: &PathBuf) -> Result<()> {
    log::banner("Example 7 — Cross-DB: warehouse → shop floor");

    let wh_dir = base.join("cross_db");
    let _ = std::fs::remove_dir_all(&wh_dir);
    let storage = dual_db_storage(&wh_dir)?;
    log::kv("kind", "DataTransfer");
    log::line("source: legacy_wh / warehouse_products (ProductV1)");
    log::line("target: shop / floor_products (ProductV2)");

    let wh = storage.domain::<crate::product::ProductV1>();
    let p1 = wh.create::<ProductV1Dto, ProductV1Response>(ProductV1Dto {
        name: "Mechanical Keyboard".into(),
    })?;
    let p2 = wh.create::<ProductV1Dto, ProductV1Response>(ProductV1Dto {
        name: "Monitor 27".into(),
    })?;
    log::subsection("Warehouse stock");
    for p in [&p1, &p2] {
        log::line(format!("[{}] {}", log::short_id(&p.id), p.name));
    }

    let report = storage
        .migrate::<ProductV1, crate::product::ProductV2>()
        .from_db("legacy_wh", "warehouse_products")
        .to(
            MigrationTo::new("shop")
                .table("floor_products")
                .delete_source(true),
        )
        .on_target_conflict(TargetConflictPolicy::Overwrite)
        .execute()?;

    log::print_migration_report("cross-DB execute", &report.report);
    log::kv("delete_source", true);

    let shop = storage.domain::<crate::product::ProductV2>();
    log::subsection("Shop floor after move");
    for p in shop.list::<ProductV2Response>()? {
        log::line(format!(
            "[{}] {} | {} | {}",
            log::short_id(&p.id),
            p.name,
            p.sku,
            format_price(p.price_cents)
        ));
    }

    let wh_left = storage
        .db_manager("legacy_wh")
        .list_entries("warehouse_products")?;
    log::kv("warehouse remaining", wh_left.len());
    log::ok("products moved and source keys deleted");
    Ok(())
}

/// Example 8 — KeyConflictPolicy::Skip.
pub fn example_conflict_skip(base: &PathBuf) -> Result<()> {
    log::banner("Example 8 — Key conflict: Skip on cross-DB import");

    let dir = base.join("conflict_skip");
    let _ = std::fs::remove_dir_all(&dir);
    let storage = dual_db_storage(&dir)?;

    let wh = storage.domain::<crate::product::ProductV1>();
    let shop = storage.domain::<crate::product::ProductV2>();

    let imported = wh.create::<ProductV1Dto, ProductV1Response>(ProductV1Dto {
        name: "Webcam HD".into(),
    })?;
    shop.repo().set(
        &imported.id,
        &crate::product::ProductV2 {
            id: imported.id.clone(),
            name: "Webcam HD (floor display)".into(),
            sku: "SKU-floor-webcam".into(),
            price_cents: 4_500,
        },
    )?;
    log::kv("conflicting key", &imported.id);
    log::line("shop floor already owns this key with different ProductV2 JSON");

    let report = storage
        .migrate::<ProductV1, crate::product::ProductV2>()
        .from_db("legacy_wh", "warehouse_products")
        .to(MigrationTo::new("shop").table("floor_products"))
        .on_target_conflict(TargetConflictPolicy::Skip)
        .dry_run()?;

    log::print_migration_report("Skip policy dry_run", &report);

    let kept = shop.get::<ProductV2Response>(&imported.id)?;
    log::ok(format!(
        "floor keeps: {} @ {} (not overwritten)",
        kept.name,
        format_price(kept.price_cents)
    ));
    Ok(())
}

/// Example 9 — Import from external raw redb into clove1db.
pub fn example_external_redb_import(base: &PathBuf) -> Result<()> {
    log::banner("Example 9 — External redb → clove1db (ExternalImport)");

    log::step("Create third-party vendor_inventory.redb (NOT a .cldb file)");
    let ext_path = vendor_inventory_path(base);
    let seeded = seed_vendor_inventory(base)?;
    log::path_entry("external redb", &ext_path);
    log::kv("table", VENDOR_TABLE);
    log::kv("key_decoder", "Utf8String");
    log::kv("value_decoder", "JsonValidate");

    let tables = list_external_tables(&ext_path)?;
    log::kv("tables in file", tables.join(", "));

    log::subsection("Raw external rows (vendor JSON)");
    for (key, row) in read_all_rows(&ext_path)? {
        log::line(format!(
            "key={key} → {{\"id\":\"{}\",\"title\":\"{}\",\"price_usd\":{},\"vendor_code\":\"{}\"}}",
            row.id, row.title, row.price_usd, row.vendor_code
        ));
    }

    log::step("Open empty clove1db import target (ProductV2 / products)");
    let import_dir = base.join("external_import");
    let clove_sub = import_dir.join("import");
    if clove_sub.exists() {
        std::fs::remove_dir_all(&clove_sub)?;
        log::line("cleared previous import/imported.cldb only (keeps vendor_inventory.redb)");
    }
    let cldb = import_dir.join("import").join("imported.cldb");
    log::path_entry("clove target", &cldb);

    let storage = import_target_storage(base)?;
    log::kv("products before", storage.domain::<crate::product::ProductV2>().list::<ProductV2Response>()?.len());

    let external = ExternalFrom {
        path: ext_path.clone(),
        table: VENDOR_TABLE.to_string(),
        key_decoder: KeyDecoder::Utf8String,
        value_decoder: ValueDecoder::JsonValidate,
    };

    log::step("dry_run: migrate::<ExternalCatalogRow, ProductV2> from external redb");

    let dry = storage
        .migrate::<ExternalCatalogRow, crate::product::ProductV2>()
        .from_external(external.clone())
        .to(MigrationTo::new("imported").table("products"))
        .dry_run()?;
    log::print_migration_report("external dry_run", &dry);

    log::step("execute ExternalImport migration");
    let result = storage
        .migrate::<ExternalCatalogRow, crate::product::ProductV2>()
        .from_external(external)
        .to(MigrationTo::new("imported").table("products"))
        .execute()?;

    log::kv("migration_id", &result.migration_id);
    log::kv("records_migrated", result.records_migrated);

    let idx = storage.migration_index("imported")?;
    log::subsection("migration chain on import DB");
    if let Some(tc) = idx.tables.get("products") {
        log::kv("products schema_version", tc.current_version());
        if let Some(m) = tc.manifests.last() {
            log::kv("manifest.kind", format!("{:?}", m.kind));
            log::kv("manifest.from_layout_hash", &m.from_layout_hash);
            log::kv("manifest.to_layout_hash", &m.to_layout_hash);
            log::line(format!(
                "from: {}.{} @{}",
                m.from.db, m.from.table, m.from.schema_version
            ));
            log::line(format!(
                "to:   {}.{} @{}",
                m.to.db, m.to.table, m.to.schema_version
            ));
        }
    }

    log::subsection("Imported ProductV2 entities in clove1db");
    let domain = storage.domain::<crate::product::ProductV2>();
    let products = domain.list::<ProductV2Response>()?;
    log::kv("product count", products.len());

    for p in &products {
        log::line(format!(
            "[{}] {} | {} | {}",
            log::short_id(&p.id),
            p.name,
            p.sku,
            format_price(p.price_cents)
        ));
    }

    log::step("Verify external file unchanged (import reads only)");
    log::path_entry("external redb after", &ext_path);
    let ext_after = read_all_rows(&ext_path)?;
    log::kv("external row count", ext_after.len());
    assert_eq!(ext_after.len(), seeded.len());

    for row in &seeded {
        let imported = domain.get::<ProductV2Response>(&row.id)?;
        let expected_cents = (row.price_usd * 100.0).round() as u64;
        if imported.name != row.title
            || imported.sku != row.vendor_code
            || imported.price_cents != expected_cents
        {
            return Err(ClError::Validation(format!(
                "import mismatch for id {}",
                row.id
            )));
        }
    }
    log::ok("external redb → clove1db ProductV2 import verified");

    drop(storage);
    let after = inspect_cldb(&cldb)?;
    log::kv("inspect after import", format!("{:?}", after.kind));
    if after.kind != FileKind::Authenticated {
        log::line("(expected Authenticated once _clove_meta present)");
    }

    Ok(())
}
