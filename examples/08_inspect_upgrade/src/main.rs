mod entities;
mod fixtures;
mod log;
mod paths;
mod scenarios;
mod storage;
mod verify;

use std::path::PathBuf;

use clove1db::units::Result;

use paths::BASE_DIR;

struct Scenario {
    name: &'static str,
    result: Result<()>,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("\n❌ Example 08 failed: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let base = PathBuf::from(BASE_DIR);
    let _ = std::fs::remove_dir_all(&base);

    log::banner("Example 08 — Inspect, Upgrade & Era Fixtures");
    log::line("Lab for inspect_cldb, Storage::build() upgrade, backup normalize, cache, attachments.");
    log::kv("upgrade_target", "clove1db 0.0.63 (path ../..)");
    log::kv("era_seeders", "vendor/clove1db-v042 + vendor/clove1db-v049 (isolated snapshots)");

    let seed = fixtures::seed_all()?;

    let mut results = Vec::new();

    macro_rules! run_scenario {
        ($name:expr, $body:expr) => {{
            log::banner(concat!("Scenario: ", $name));
            let result = $body;
            match &result {
                Ok(()) => log::ok(concat!($name, " — PASS")),
                Err(e) => log::line(format!("✗ {} — FAIL: {e}", $name)),
            }
            results.push(Scenario {
                name: $name,
                result,
            });
        }};
    }

    run_scenario!("inspect_all", scenarios::inspect_all::run());
    run_scenario!("reject_invalid", scenarios::reject_invalid::run());
    run_scenario!("upgrade_eras", scenarios::upgrade_eras::run());
    run_scenario!("crud_verify", scenarios::crud_verify::run(&seed));
    run_scenario!("backup_history", scenarios::backup_history::run(&seed));
    run_scenario!("cache_behavior", scenarios::cache_behavior::run(&seed));
    run_scenario!("attachments_large", scenarios::attachments_large::run(&seed));

    log::banner("Final summary");
    let mut failed = 0usize;
    for s in &results {
        match &s.result {
            Ok(()) => log::line(format!("✅ PASS  {}", s.name)),
            Err(e) => {
                failed += 1;
                log::line(format!("❌ FAIL  {} — {e}", s.name));
            }
        }
    }

    if failed > 0 {
        return Err(clove1db::units::ClError::Validation(format!(
            "{failed} scenario(s) failed"
        )));
    }

    log::line("\n✅ All Example 08 scenarios passed.");
    Ok(())
}
