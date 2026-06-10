use clove1db::{
    inspect_cldb, FileKind,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::{ClError, Result},
};

use crate::entities::ProductV1;
use crate::log;
use crate::paths::{self, copy_dir_all};
use crate::storage::{retail_v1_storage, retail_v2_storage};

fn expect_err<T>(label: &str, result: Result<T>, matcher: fn(&ClError) -> bool) -> Result<()> {
    match result {
        Err(e) if matcher(&e) => {
            log::ok(format!("{label} — rejected as expected ({e})"));
            Ok(())
        }
        Err(e) => {
            log::line(format!("✗ {label} — unexpected error: {e}"));
            Err(e)
        }
        Ok(_) => Err(ClError::Validation(format!("{label} should have failed"))),
    }
}

pub fn run() -> Result<()> {
    log::step("build() on fake .cldb directory → NotCloveDatabase");
    let err = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("", "fake_shop")
                .dir_path(paths::base().join("fake"))
                .register::<ProductV1>("products"),
        )
        .build();
    expect_err("fake_shop", err, |e| matches!(e, ClError::NotCloveDatabase { .. }))?;

    log::step("build() on external redb → NotCloveDatabase");
    let err = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("", "foreign")
                .dir_path(paths::base().join("external"))
                .register::<ProductV1>("products"),
        )
        .build();
    expect_err("foreign redb", err, |e| matches!(e, ClError::NotCloveDatabase { .. }))?;

    log::step("build() with ProductV2 registration on V1-upgraded DB → LayoutMismatch");
    let layout_dir = paths::base().join("reject").join("layout_mismatch");
    if layout_dir.exists() {
        std::fs::remove_dir_all(&layout_dir)?;
    }
    copy_dir_all(&paths::era_042_retail_dir(), &layout_dir.join("retail"))?;
    log::path_entry("copy", &layout_dir.join("retail"));

    let storage_v1 = retail_v1_storage(layout_dir.clone(), "retail", "retail")?;
    drop(storage_v1);
    log::line("first build() registers ProductV1 layout at products@v1");

    let err = retail_v2_storage(layout_dir, "retail", "retail");
    expect_err(
        "layout mismatch",
        err,
        |e| matches!(e, ClError::LayoutMismatch { .. }),
    )?;

    log::step("era_042 source fixture unchanged after reject tests");
    let report = inspect_cldb(&paths::era_042_retail_cldb())?;
    log::kv("era_042 still", format!("{:?}", report.kind));
    if report.kind != FileKind::Legacy042 {
        return Err(ClError::Validation("era_042 should remain Legacy042".into()));
    }
    log::ok("source fixtures intact");

    Ok(())
}
