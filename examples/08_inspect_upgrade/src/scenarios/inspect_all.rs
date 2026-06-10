use clove1db::{units::Result, FileKind};

use crate::log;
use crate::paths;
use crate::verify::assert_kind;

struct Case {
    path: std::path::PathBuf,
    kind: FileKind,
    label: &'static str,
    expect_backup: Option<bool>,
    expect_migration: Option<bool>,
}

pub fn run() -> Result<()> {
    log::step("Classify every fixture via inspect_cldb (before upgrade)");

    let cases = [
        Case {
            path: paths::fake_shop_dir(),
            kind: FileKind::Invalid,
            label: "fake dir",
            expect_backup: None,
            expect_migration: None,
        },
        Case {
            path: paths::foreign_cldb(),
            kind: FileKind::ExternalRedb,
            label: "foreign redb",
            expect_backup: Some(false),
            expect_migration: Some(false),
        },
        Case {
            path: paths::era_042_retail_cldb(),
            kind: FileKind::Legacy042,
            label: "era_042 retail",
            expect_backup: Some(true),
            expect_migration: Some(false),
        },
        Case {
            path: paths::era_042_attachments_cldb(),
            kind: FileKind::Legacy042,
            label: "era_042 attachments (no backup)",
            expect_backup: Some(false),
            expect_migration: Some(false),
        },
        Case {
            path: paths::era_049_retail_cldb(),
            kind: FileKind::Clove049,
            label: "era_049 retail",
            expect_backup: Some(true),
            expect_migration: Some(true),
        },
        Case {
            path: paths::era_056_retail_cldb(),
            kind: FileKind::Authenticated,
            label: "era_056 retail",
            expect_backup: Some(true),
            expect_migration: None,
        },
    ];

    for case in cases {
        let report = log::print_inspect(case.label, &case.path)?;
        assert_kind(&report, case.kind, case.label)?;

        if let Some(want) = case.expect_backup {
            log::kv("check backup_exists", want);
            if report.backup_exists != want {
                return Err(clove1db::units::ClError::Validation(format!(
                    "{}: backup_exists expected {want}",
                    case.label
                )));
            }
        }
        if let Some(want) = case.expect_migration {
            log::kv("check migration_exists", want);
            if report.migration_exists != want {
                return Err(clove1db::units::ClError::Validation(format!(
                    "{}: migration_exists expected {want}",
                    case.label
                )));
            }
        }
        log::ok(format!("{} → {:?}", case.label, case.kind));
    }

    Ok(())
}
