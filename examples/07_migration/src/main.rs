mod external;
mod log;
mod product;
mod scenarios;
mod storage;

use std::path::PathBuf;

use clove1db::units::Result;

use storage::BASE_DIR;

fn main() -> Result<()> {
    let base = PathBuf::from(BASE_DIR);
    let _ = std::fs::remove_dir_all(&base);

    log::banner("clove1db — Product Migration Examples");
    log::line("Schema upgrades, cross-DB moves, external redb import, history & restore");
    log::kv("data_dir", BASE_DIR);
    log::kv("framework", "clove1db 0.0.56");

    // 1–3: Legacy catalog → ProductV2
    let (storage_v1, seed) = scenarios::example_seed_legacy_catalog(&base)?;
    scenarios::example_dry_run_v1_to_v2(&storage_v1)?;
    let storage_v2 = scenarios::example_migrate_v1_to_v2(storage_v1, &seed)?;

    // 4: History display modes
    scenarios::example_product_history_modes(&storage_v2, &seed.laptop_id)?;

    // 5–6: ProductV3 chain + restore guards
    let storage_v3 = scenarios::example_migrate_v2_to_v3(storage_v2, &seed)?;
    scenarios::example_restore_guards(&storage_v3, &seed.laptop_id)?;
    drop(storage_v3);

    // 7–8: Cross-DB scenarios
    scenarios::example_cross_db_product_move(&base)?;
    scenarios::example_conflict_skip(&base)?;

    // 9: External raw redb → clove1db
    scenarios::example_external_redb_import(&base)?;

    log::banner("All product migration examples completed");
    log::ok("Examples 1–9 passed");
    Ok(())
}
