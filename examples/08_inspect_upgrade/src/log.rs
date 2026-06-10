use std::fmt::Display;
use std::path::Path;

use clove1db::{
    inspect_cldb, metadata::read_meta, InspectReport,
};
use redb::Database;

use crate::fixtures::{RetailManifest, SeedState};

pub fn banner(title: &str) {
    println!("\n═══════════════════════════════════════════════════════════");
    println!("  {title}");
    println!("═══════════════════════════════════════════════════════════");
}

pub fn subsection(title: &str) {
    println!("\n  ── {title} ──");
}

pub fn step(msg: impl Display) {
    println!("\n  ▶ {msg}");
}

pub fn line(msg: impl Display) {
    println!("      {msg}");
}

pub fn kv(key: &str, value: impl Display) {
    println!("      {key}: {value}");
}

pub fn ok(msg: impl Display) {
    println!("      ✓ {msg}");
}

pub fn path_entry(label: &str, path: &Path) {
    kv(label, path.display());
    if path.exists() {
        if path.is_dir() {
            kv(&format!("{label} (type)"), "directory");
        } else if let Ok(meta) = std::fs::metadata(path) {
            kv(&format!("{label} (size)"), format!("{} bytes", meta.len()));
        }
    } else {
        kv(&format!("{label} (exists)"), "false");
    }
}

pub fn short_id(id: &str) -> String {
    if id.len() > 8 {
        format!("{}…", &id[..8])
    } else {
        id.to_string()
    }
}

pub fn print_inspect(label: &str, path: &Path) -> clove1db::units::Result<InspectReport> {
    subsection(&format!("inspect_cldb — {label}"));
    path_entry("path", path);
    let report = inspect_cldb(path)?;
    kv("FileKind", format!("{:?}", report.kind));
    if let Some(era) = report.file_era {
        kv("file_era", format!("{era:?}"));
    }
    kv("backup_exists", report.backup_exists);
    kv("backup_upgraded", report.backup_upgraded);
    kv("migration_exists", report.migration_exists);
    if let Some(v) = &report.framework_version {
        kv("framework_version", v);
    }
    if !report.table_schemas.is_empty() {
        for (table, version) in &report.table_schemas {
            kv(&format!("{table}@v"), *version);
        }
    }
    if !report.tables.is_empty() {
        kv("tables", report.tables.join(", "));
    }
    if let Some(bak) = &report.backup_path {
        path_entry("backup_path", bak);
    }
    Ok(report)
}

pub fn print_meta(path: &Path, label: &str) -> clove1db::units::Result<()> {
    subsection(&format!("_clove_meta — {label}"));
    path_entry("primary", path);
    let db = Database::open(path).map_err(|e| clove1db::units::ClError::Database(e.into()))?;
    let Some(meta) = read_meta(&db)? else {
        line("(no _clove_meta yet)");
        return Ok(());
    };
    kv("framework", &meta.framework);
    kv("framework_version", &meta.framework_version);
    kv("file_era", format!("{:?}", meta.file_era));
    kv("db_name", &meta.db_name);
    kv("backup_enabled", meta.backup_enabled);
    kv("backup_format", &meta.backup_format);
    kv("backup_upgraded", meta.backup_upgraded);
    kv("upgrade_complete", meta.upgrade_complete);
    if !meta.tables.is_empty() {
        for t in &meta.tables {
            line(format!(
                "table {} → v{} ({})",
                t.name, t.schema_version, t.layout_hash
            ));
        }
    }
    if !meta.upgrade_log.is_empty() {
        kv("upgrade_log_entries", meta.upgrade_log.len());
        for entry in meta.upgrade_log.iter().take(5) {
            line(format!(
                "log: {} @ {} {:?}",
                entry.step, entry.at, entry.detail
            ));
        }
    }
    Ok(())
}

pub fn print_retail_manifest(label: &str, manifest: &RetailManifest) {
    subsection(label);
    kv("products", manifest.products.len());
    for (id, name) in &manifest.products {
        line(format!("product [{}] {}", short_id(id), name));
    }
    kv("history_product_id", short_id(&manifest.history_product_id));
    kv("buyers", manifest.buyers.len());
    for (id, name, email) in &manifest.buyers {
        line(format!("buyer [{}] {name} <{email}>", short_id(id)));
    }
    kv("employees", manifest.employees.len());
    for (id, name, role) in &manifest.employees {
        line(format!("employee [{}] {name} ({role})", short_id(id)));
    }
}

pub fn print_seed_summary(seed: &SeedState) {
    banner("Fixture seed summary");
    step("fake_shop.cldb (directory, not a redb file)");
    path_entry("path", &crate::paths::fake_shop_dir());

    step("foreign.cldb (raw redb, non-clove JSON)");
    path_entry("path", &crate::paths::foreign_cldb());
    line("table: inventory — keys item-0..4, values {\"qty\", \"label\"}");

    step("era_042 — clove1db-v042 retail + attachments");
    path_entry("retail primary", &crate::paths::era_042_retail_cldb());
    path_entry("attachments primary", &crate::paths::era_042_attachments_cldb());
    print_retail_manifest("retail_042 manifest", &seed.retail_042);
    kv(
        "attachment_id",
        format!("{} (~2 MiB blob)", short_id(&seed.attachment_id)),
    );

    step("era_049 — clove1db-v049 retail + RetailV1→V2 migration");
    path_entry("retail primary", &crate::paths::era_049_retail_cldb());
    print_retail_manifest("retail_049 manifest (products at V1 names, stored as V2)", &seed.retail_049);

    step("era_056 — current clove1db (pre-authenticated)");
    path_entry("retail primary", &crate::paths::era_056_retail_cldb());
    line("5 products, 3 buyers, 2 employees — schema RetailV1");
}

pub fn print_migration_index(path: &Path) {
    if path.exists() {
        if let Ok(text) = std::fs::read_to_string(path) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                kv("db_name", v["db_name"].as_str().unwrap_or("?"));
                if let Some(tables) = v["tables"].as_object() {
                    kv("migration_tables", tables.len());
                }
                if let Some(chain) = v["chain"].as_array() {
                    kv("migration_chain_len", chain.len());
                }
            }
        }
    }
}
