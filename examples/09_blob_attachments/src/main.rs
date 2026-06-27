mod entities;
mod log;
mod scenarios;

use scenarios::BASE_DIR;
use std::path::PathBuf;

fn main() -> clove1db::units::Result<()> {
    let base = PathBuf::from(BASE_DIR);
    std::fs::create_dir_all(&base)?;

    log::banner("clove1db 0.0.84 — Blob Sidecar Example 09");

    scenarios::scenario_crud(&base)?;
    scenarios::scenario_scan(&base)?;
    scenarios::scenario_external_migrate(&base)?;
    scenarios::scenario_inline_to_blob(&base)?;

    log::banner("All 4 scenarios completed successfully");
    Ok(())
}
