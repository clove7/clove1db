use std::fmt::Display;
use std::path::Path;

use clove1db::migration::report::MigrationReport;

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
    if id.len() > 10 {
        format!("{}…", &id[..10])
    } else {
        id.to_string()
    }
}

pub fn print_migration_report(label: &str, report: &MigrationReport) {
    subsection(label);
    kv("migration_id", &report.migration_id);
    kv("dry_run", report.dry_run);
    kv("source_count", report.source_count);
    kv("would_insert", report.would_insert);
    kv("would_overwrite", report.would_overwrite);
    kv("would_skip", report.would_skip);
    kv("conflicts", report.conflicts.len());
    for c in &report.conflicts {
        line(format!(
            "conflict table={} key={} policy={:?}",
            c.table, c.key, c.policy
        ));
    }
    for err in &report.errors {
        line(format!("error: {err}"));
    }
}

