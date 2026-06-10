use std::path::PathBuf;

use clove1db::{
    backup::view::{HistoryDisplayMode, RecordData},
    migration::{KeyConflictPolicy, MigrationKind},
    storage::Storage,
    units::{ClError, Result},
};

use crate::product::{
    ProductV1Dto, ProductV1Response, ProductV2Response, ProductV3Dto, ProductV3Response,
    format_price,
};
use crate::storage::{
    catalog_v2_storage, catalog_v3_storage, dual_db_storage, legacy_catalog_storage, BASE_DIR,
};

pub struct CatalogSeed {
    pub laptop_id: String,
    pub mouse_id: String,
    pub hub_id: String,
}

/// Example 1 — Seed a legacy product catalog with backup history.
pub fn example_seed_legacy_catalog(base: &PathBuf) -> Result<(Storage, CatalogSeed)> {
    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║  Example 1 — Seed legacy catalog (ProductV1 + history)   ║");
    println!("╚══════════════════════════════════════════════════════════╝");

    let storage = legacy_catalog_storage(base)?;
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

    println!("  📦 Seeded 3 products:");
    println!("     • {} [{}]", laptop.name, laptop.id);
    println!("     • {} (updated) [{}]", "Wireless Mouse v2", mouse.id);
    println!("     • {} [{}]", hub.name, hub.id);
    println!("  📜 Laptop has {} backup versions", domain.history(&laptop.id)?.len());

    Ok((
        storage,
        CatalogSeed {
            laptop_id: laptop.id,
            mouse_id: mouse.id,
            hub_id: hub.id,
        },
    ))
}

/// Example 2 — dry_run before migrating catalog schema V1 → V2.
pub fn example_dry_run_v1_to_v2(storage: &Storage) -> Result<()> {
    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║  Example 2 — dry_run: ProductV1 → ProductV2            ║");
    println!("╚══════════════════════════════════════════════════════════╝");

    let report = storage
        .migration_runner()
        .from_explicit("legacy", "products")
        .to_explicit("legacy", "products")
        .with_decoder("ProductV1_to_V2")
        .with_schema_names("ProductV1", "ProductV2")
        .kind(MigrationKind::SameDbRemapTable)
        .on_key_conflict(KeyConflictPolicy::Fail)
        .dry_run()?;

    println!("  🔍 dry_run id: {}", report.migration_id);
    println!("     source products: {}", report.source_count);
    println!("     would overwrite:  {}", report.would_overwrite);
    println!("     conflicts:        {}", report.conflicts.len());
    Ok(())
}

/// Example 3 — Execute in-place schema migration; products gain sku + price.
pub fn example_migrate_v1_to_v2(storage: Storage, seed: &CatalogSeed) -> Result<Storage> {
    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║  Example 3 — Execute: ProductV1 → ProductV2            ║");
    println!("╚══════════════════════════════════════════════════════════╝");

    let result = storage
        .migration_runner()
        .from_explicit("legacy", "products")
        .to_explicit("legacy", "products")
        .with_decoder("ProductV1_to_V2")
        .with_schema_names("ProductV1", "ProductV2")
        .kind(MigrationKind::SameDbRemapTable)
        .execute()?;

    println!(
        "  ✅ migration_id={} | migrated {} products",
        result.migration_id, result.records_migrated
    );

    drop(storage);

    let storage = catalog_v2_storage(&PathBuf::from(BASE_DIR))?;
    let domain = storage.domain::<crate::product::ProductV2>();

    for (label, id) in [
        ("Laptop", &seed.laptop_id),
        ("Mouse", &seed.mouse_id),
        ("Hub", &seed.hub_id),
    ] {
        let p = domain.get::<ProductV2Response>(id)?;
        println!(
            "  🏷️  {} → {} | {} | {}",
            label,
            p.name,
            p.sku,
            format_price(p.price_cents)
        );
    }

    Ok(storage)
}

/// Example 4 — Product history: AsStored (original shape) vs Normalized (current shape).
pub fn example_product_history_modes(storage: &Storage, laptop_id: &str) -> Result<()> {
    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║  Example 4 — History: AsStored vs Normalized             ║");
    println!("╚══════════════════════════════════════════════════════════╝");

    let domain = storage.domain::<crate::product::ProductV2>();

    println!("  📖 AsStored (original era JSON):");
    for r in domain.history_with_mode(laptop_id, HistoryDisplayMode::AsStored)? {
        if let RecordData::Json(json) | RecordData::Typed(json) = &r.data {
            let keys: Vec<_> = json
                .as_object()
                .map(|o| o.keys().cloned().collect())
                .unwrap_or_default();
            println!(
                "     v{} | schema={} | restorable={} | keys={:?}",
                r.version, r.schema_at_version, r.restorable, keys
            );
        }
    }

    println!("  📖 Normalized (current ProductV2 shape):");
    for r in domain.history_with_mode(laptop_id, HistoryDisplayMode::Normalized)? {
        if let Some(json) = r.data.as_json() {
            let has_sku = json.get("sku").is_some();
            let has_price = json.get("price_cents").is_some();
            println!(
                "     v{} | sku={} price={}",
                r.version, has_sku, has_price
            );
        }
    }

    Ok(())
}

/// Example 5 — Second chained migration V2 → V3 (category + stock).
pub fn example_migrate_v2_to_v3(storage: Storage, seed: &CatalogSeed) -> Result<Storage> {
    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║  Example 5 — Chained migration: ProductV2 → ProductV3    ║");
    println!("╚══════════════════════════════════════════════════════════╝");

    let chain_before = storage.migration_chain("legacy")?;
    println!(
        "  🔗 chain before: {} migration(s), schema={}",
        chain_before.index.chain.len(),
        chain_before.current_schema()
    );

    let result = storage
        .migration_runner()
        .from_explicit("legacy", "products")
        .to_explicit("legacy", "products")
        .with_decoder("ProductV2_to_V3")
        .with_schema_names("ProductV2", "ProductV3")
        .kind(MigrationKind::SameDbRemapTable)
        .execute()?;

    println!("  ✅ mig-2 id={} | migrated {}", result.migration_id, result.records_migrated);
    drop(storage);

    let storage = catalog_v3_storage(&PathBuf::from(BASE_DIR))?;
    let chain = storage.migration_chain("legacy")?;
    println!(
        "  🔗 chain after: {} migrations → {}",
        chain.index.chain.len(),
        chain.current_schema()
    );

    let domain = storage.domain::<crate::product::ProductV3>();
    let laptop = domain.get::<ProductV3Response>(&seed.laptop_id)?;
    let mouse = domain.get::<ProductV3Response>(&seed.mouse_id)?;
    println!(
        "  💻 Laptop: {} | {} | stock={} | {}",
        laptop.sku, laptop.category, laptop.stock, format_price(laptop.price_cents)
    );
    println!(
        "  🖱️  Mouse:  {} | {} | stock={}",
        mouse.sku, mouse.category, mouse.stock
    );

    Ok(storage)
}

/// Example 7 — Cross-DB move: warehouse → shop floor (different db + table).
pub fn example_cross_db_product_move(base: &PathBuf) -> Result<()> {
    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║  Example 7 — Cross-DB: warehouse → shop floor            ║");
    println!("╚══════════════════════════════════════════════════════════╝");

    let wh_dir = base.join("cross_db");
    let _ = std::fs::remove_dir_all(&wh_dir);
    let storage = dual_db_storage(&wh_dir)?;

    let wh = storage.domain::<crate::product::ProductV1>();
    let p1 = wh.create::<ProductV1Dto, ProductV1Response>(ProductV1Dto {
        name: "Mechanical Keyboard".into(),
    })?;
    let p2 = wh.create::<ProductV1Dto, ProductV1Response>(ProductV1Dto {
        name: "Monitor 27".into(),
    })?;
    println!("  🏭 Warehouse: {} + {}", p1.name, p2.name);

    let report = storage
        .migration_runner()
        .from_explicit("legacy_wh", "warehouse_products")
        .to_explicit("shop", "floor_products")
        .with_decoder("ProductV1_to_V2")
        .with_schema_names("ProductV1", "ProductV2")
        .kind(MigrationKind::CrossDbMove)
        .on_key_conflict(KeyConflictPolicy::Overwrite)
        .delete_old_source(true)
        .execute()?;

    println!(
        "  🚚 Moved {} products → shop floor (migration {})",
        report.records_migrated, report.migration_id
    );

    let shop = storage.domain::<crate::product::ProductV2>();
    let on_floor = shop.list::<ProductV2Response>()?;
    for p in &on_floor {
        println!(
            "  🛒 Floor: {} | {} | {}",
            p.name,
            p.sku,
            format_price(p.price_cents)
        );
    }

    let wh_left = storage
        .db_manager("legacy_wh")
        .list_entries("warehouse_products")?;
    println!("  🏭 Warehouse remaining: {} items", wh_left.len());

    Ok(())
}

/// Example 8 — KeyConflictPolicy::Skip when shop floor already stocks a product.
pub fn example_conflict_skip(base: &PathBuf) -> Result<()> {
    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║  Example 8 — Key conflict: Skip on cross-DB import       ║");
    println!("╚══════════════════════════════════════════════════════════╝");

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
    println!("  🛒 Shop floor already has product key: {}", imported.id);

    let report = storage
        .migration_runner()
        .from_explicit("legacy_wh", "warehouse_products")
        .to_explicit("shop", "floor_products")
        .with_decoder("ProductV1_to_V2")
        .with_schema_names("ProductV1", "ProductV2")
        .kind(MigrationKind::CrossDbMove)
        .on_key_conflict(KeyConflictPolicy::Skip)
        .dry_run()?;

    println!(
        "  ⏭️  Skip policy: would_skip={} would_insert={} conflicts={}",
        report.would_skip, report.would_insert, report.conflicts.len()
    );

    let kept = shop.get::<ProductV2Response>(&imported.id)?;
    println!(
        "  🏷️  Floor keeps its version: {} @ {}",
        kept.name,
        format_price(kept.price_cents)
    );
    Ok(())
}

/// Example 6 — Restore guards: pre-migration versions are read-only.
pub fn example_restore_guards(storage: &Storage, laptop_id: &str) -> Result<()> {
    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║  Example 6 — Restore guards on product history           ║");
    println!("╚══════════════════════════════════════════════════════════╝");

    let domain = storage.domain::<crate::product::ProductV3>();

    match domain.restore_by_version(laptop_id, 1) {
        Err(ClError::NotRestorable { version, schema_at_version, .. }) => {
            println!(
                "  🚫 v{} rejected (schema {} is read-only)",
                version, schema_at_version
            );
        }
        Ok(_) => println!("  ⚠️  v1 unexpectedly restored"),
        Err(e) => println!("  ⚠️  {:?}", e),
    }

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
    domain.restore_by_version(laptop_id, post_v)?;
    let restored = domain.get::<ProductV3Response>(laptop_id)?;
    println!(
        "  ✅ Post-migration v{} restored → {} @ {}",
        post_v,
        restored.name,
        format_price(restored.price_cents)
    );

    Ok(())
}
