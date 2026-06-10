use clove1db::{metadata::FileEra, units::Result, FileKind};

use clove1db::metadata::inspect::pre_upgrade_path;
use crate::log;
use crate::paths::{self, copy_dir_all};
use crate::storage::{retail_v1_storage, retail_v2_storage};
use crate::verify::assert_meta;

fn table_version(meta: &clove1db::metadata::CloveMeta, table: &str) -> Option<u32> {
    meta.table_meta(table).map(|t| t.schema_version)
}

fn assert_table_schemas(
    report: &clove1db::InspectReport,
    expected: &[(&str, u32)],
    label: &str,
) -> Result<()> {
    for (table, version) in expected {
        let found = report
            .table_schemas
            .iter()
            .find(|(name, _)| name == *table)
            .map(|(_, v)| *v);
        log::line(format!(
            "{table}@v: {}",
            found.map(|v| v.to_string()).unwrap_or_else(|| "?".into())
        ));
        if found != Some(*version) {
            return Err(clove1db::units::ClError::Validation(format!(
                "{label}: {table} expected v{version}, inspect has {:?}",
                report.table_schemas
            )));
        }
    }
    Ok(())
}

pub fn run() -> Result<()> {
    log::step("042 → 056: copy era_042/retail → upgraded/retail_042, build with ProductV1");

    let dir_042 = paths::upgraded_042_dir();
    if dir_042.exists() {
        std::fs::remove_dir_all(&dir_042)?;
    }
    copy_dir_all(&paths::era_042_retail_dir(), &dir_042.join("retail"))?;
    log::path_entry("source", &paths::era_042_retail_dir());
    log::path_entry("dest", &dir_042.join("retail"));

    log::line("Running Storage::build() — pipeline writes _clove_meta, normalizes .bak");
    let storage_042 = retail_v1_storage(dir_042.clone(), "retail", "retail")?;
    drop(storage_042);

    let cldb_042 = dir_042.join("retail").join("retail.cldb");
    let bak_042 = dir_042.join("retail").join("retail.cldb.bak");
    log::print_meta(&cldb_042, "after 042 upgrade")?;
    assert_meta(&cldb_042, "042 upgrade", |m| {
        m.upgrade_complete
            && m.file_era == FileEra::Legacy042
            && m.backup_upgraded
            && table_version(m, "products") == Some(1)
            && table_version(m, "buyers") == Some(1)
            && table_version(m, "employees") == Some(1)
    })?;

    let report_042 = log::print_inspect("after 042 upgrade", &cldb_042)?;
    assert_table_schemas(
        &report_042,
        &[("products", 1), ("buyers", 1), ("employees", 1)],
        "042 upgrade",
    )?;

    let pre = pre_upgrade_path(&bak_042);
    log::path_entry(".pre-upgrade path", &pre);
    if pre.exists() {
        return Err(clove1db::units::ClError::Validation(
            ".pre-upgrade should be removed after success".into(),
        ));
    }
    log::ok("backup normalized; .pre-upgrade removed");

    let migration_index = dir_042
        .join("retail")
        .join("retail.migration")
        .join("index.json");
    log::subsection("retail.migration/index.json (created on 042 upgrade)");
    log::print_migration_index(&migration_index);
    if !migration_index.exists() {
        return Err(clove1db::units::ClError::Validation(
            "migration index should exist after 042 upgrade".into(),
        ));
    }

    log::step("049 → 056: copy era_049/retail → upgraded/retail_049, build with ProductV2");

    let dir_049 = paths::upgraded_049_dir();
    if dir_049.exists() {
        std::fs::remove_dir_all(&dir_049)?;
    }
    copy_dir_all(&paths::era_049_retail_dir(), &dir_049.join("retail"))?;

    let storage_049 = retail_v2_storage(dir_049.clone(), "retail", "retail")?;
    drop(storage_049);

    let cldb_049 = dir_049.join("retail").join("retail.cldb");
    log::print_meta(&cldb_049, "after 049 upgrade")?;
    assert_meta(&cldb_049, "049 upgrade", |m| {
        m.upgrade_complete
            && table_version(m, "products") == Some(2)
            && table_version(m, "buyers") == Some(1)
            && table_version(m, "employees") == Some(1)
    })?;

    let report_049 = log::print_inspect("after 049 upgrade", &cldb_049)?;
    assert_table_schemas(
        &report_049,
        &[("products", 2), ("buyers", 1), ("employees", 1)],
        "049 upgrade",
    )?;

    let chain = clove1db::migration::DbMigrationIndex::load(
        &dir_049.join("retail"),
        "retail",
        &["products", "buyers", "employees"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>(),
    )?;
    if let Some(products) = chain.tables.get("products") {
        log::kv("products.current_version", products.current_version());
        if products.current_version() != 2 {
            return Err(clove1db::units::ClError::Validation(format!(
                "products chain version={}",
                products.current_version()
            )));
        }
    } else {
        return Err(clove1db::units::ClError::Validation(
            "products migration chain missing".into(),
        ));
    }
    log::kv("migration tables", chain.tables.len());

    log::step("Idempotent: second build() on upgraded/retail_049");
    let storage_idem = retail_v2_storage(dir_049.clone(), "retail", "retail")?;
    drop(storage_idem);
    let report = log::print_inspect("idempotent 049", &cldb_049)?;
    if report.kind != FileKind::Authenticated {
        return Err(clove1db::units::ClError::Validation(format!(
            "idempotent inspect: {:?}",
            report.kind
        )));
    }
    assert_table_schemas(
        &report,
        &[("products", 2), ("buyers", 1), ("employees", 1)],
        "idempotent 049",
    )?;
    log::ok("second build succeeded; inspect → Authenticated");

    Ok(())
}
