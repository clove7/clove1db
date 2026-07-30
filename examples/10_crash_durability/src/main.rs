mod entities;
mod log;
mod scenarios;

use std::env;
use std::path::PathBuf;
use std::time::Instant;

use scenarios::BASE_DIR;

fn main() -> clove1db::units::Result<()> {
    if let Ok(child) = env::var("CLOVE_CRASH_CHILD") {
        let base = PathBuf::from(env::var("CLOVE_BASE").unwrap_or_else(|_| BASE_DIR.into()));
        scenarios::run_child(&child, &base)?;
        return Ok(());
    }

    let wall = Instant::now();
    let base = PathBuf::from(BASE_DIR);
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base)?;

    log::banner("clove1db 0.0.98 — EXAMPLE 10 HEAVY CRASH / DURABILITY STRESS");
    log::summary_box(
        "Run profile",
        &[
            "Mode: DurabilityMode::Strict (default)".into(),
            format!("Data root: {BASE_DIR}"),
            format!("Heavy orders per big seed: {}", scenarios::HEAVY_ORDERS),
            format!("Blobs: {} × {}", scenarios::HEAVY_BLOBS, log::bytes_human(scenarios::BLOB_BYTES as u64)),
            format!(
                "Parallel: {} threads × {} creates",
                scenarios::PARALLEL_THREADS,
                scenarios::PARALLEL_PER_THREAD
            ),
            "Focus: diverse sensitive cafe-like rows, backup history, heavy migrate V1→V2→V3, crash inject".into(),
            "Every phase prints what it does — watch the terminal carefully.".into(),
        ],
    );

    let mut timings = Vec::new();

    timings.push((
        "01 index-write crash".into(),
        scenarios::scenario_01_kill_during_index_write(&base)?,
    ));
    timings.push((
        "02 NUL index recover".into(),
        scenarios::scenario_02_nul_index_recover(&base)?,
    ));
    timings.push((
        "03 multi-table crash".into(),
        scenarios::scenario_03_kill_multi_table_layout(&base)?,
    ));
    timings.push((
        "04 dense commit crash".into(),
        scenarios::scenario_04_kill_dense_commit(&base)?,
    ));
    timings.push((
        "05 blob crash".into(),
        scenarios::scenario_05_kill_blob_write(&base)?,
    ));
    timings.push((
        "06 RAM pressure".into(),
        scenarios::scenario_06_memory_pressure(&base)?,
    ));
    timings.push((
        "07 parallel crash".into(),
        scenarios::scenario_07_parallel_then_kill(&base)?,
    ));
    timings.push((
        "08 heavy migrate crash".into(),
        scenarios::scenario_08_kill_during_migrate(&base)?,
    ));
    timings.push((
        "09 multi-db crash".into(),
        scenarios::scenario_09_multi_db_kill(&base)?,
    ));
    timings.push((
        "10 compound worst".into(),
        scenarios::scenario_10_compound_worst(&base)?,
    ));

    log::final_report(wall.elapsed(), &timings);
    Ok(())
}
