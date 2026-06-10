mod product;
mod scenarios;
mod storage;

use std::path::PathBuf;

use clove1db::units::Result;

use storage::BASE_DIR;

fn main() -> Result<()> {
    let base = PathBuf::from(BASE_DIR);
    let _ = std::fs::remove_dir_all(&base);

    println!("═══════════════════════════════════════════════════════════");
    println!("  clove1db — Product Migration Examples");
    println!("  Catalog schema upgrades, cross-DB moves, history & restore");
    println!("═══════════════════════════════════════════════════════════");

    // 1–3: Legacy catalog → ProductV2
    let (storage_v1, seed) = scenarios::example_seed_legacy_catalog(&base)?;
    scenarios::example_dry_run_v1_to_v2(&storage_v1)?;
    let storage_v2 = scenarios::example_migrate_v1_to_v2(storage_v1, &seed)?;

    // 4: History display modes on a product
    scenarios::example_product_history_modes(&storage_v2, &seed.laptop_id)?;

    // 5: Second migration in chain → ProductV3
    let storage_v3 = scenarios::example_migrate_v2_to_v3(storage_v2, &seed)?;

    // 6: Restore guards (needs ProductV3 domain)
    scenarios::example_restore_guards(&storage_v3, &seed.laptop_id)?;
    drop(storage_v3);

    // 7: Cross-DB warehouse → shop floor
    scenarios::example_cross_db_product_move(&base)?;

    // 8: Conflict policy Skip demo
    scenarios::example_conflict_skip(&base)?;

    println!("\n═══════════════════════════════════════════════════════════");
    println!("  ✅ All product migration examples completed");
    println!("═══════════════════════════════════════════════════════════");

    Ok(())
}
