use std::collections::HashMap;
use std::fs;
use std::path::Path;

use redb::Database;

use crate::metadata::inspect::{inspect_database, pre_upgrade_path, FileKind};
use crate::metadata::store::{ensure_meta_table, read_meta, write_meta};
use crate::metadata::types::{BackupFormat, CloveMeta, FileEra, TableMeta, BACKUP_FORMAT_JSON};
use crate::migration::chain::DbMigrationIndex;
use crate::migration::layout::FieldLayout;
use crate::metadata::types::TableStorageMode;
use crate::migration::types::migration_dir_name;
use crate::durability::DurabilityMode;
use crate::upgrade::backup_normalize::eager_normalize;
use crate::upgrade::migration_refs::upgrade_migration_refs_with_durability;
use crate::units::{ClError, Result};

pub struct TableRegistration {
    pub name: String,
    pub layout: FieldLayout,
    pub storage: TableStorageMode,
}

pub struct UpgradeInput<'a> {
    pub dir_path: &'a Path,
    pub backup_dir_path: Option<&'a Path>,
    pub dir_name: &'a str,
    pub db_name: &'a str,
    pub tables: &'a [TableRegistration],
    pub backup_enabled: bool,
    pub blob_enabled: bool,
    pub has_cache: bool,
    pub durability: DurabilityMode,
}

pub struct UpgradeOutput {
    pub meta: CloveMeta,
    pub table_layouts: HashMap<String, FieldLayout>,
}

pub struct OpenUpgradePipeline;

impl OpenUpgradePipeline {
    pub fn run(input: &UpgradeInput<'_>) -> Result<UpgradeOutput> {
        let db_dir = input.dir_path.join(input.dir_name);
        fs::create_dir_all(&db_dir)?;
        if let Some(backup_root) = input.backup_dir_path {
            let backup_parent = backup_root.join(input.dir_name);
            fs::create_dir_all(&backup_parent)?;
        }

        let primary_path = db_dir.join(format!("{}.cldb", input.db_name));
        let backup_path = input.backup_dir_path.map(|bp| {
            bp.join(input.dir_name)
                .join(format!("{}.cldb.bak", input.db_name))
        });
        let migration_dir = db_dir.join(migration_dir_name(input.db_name));

        let inspection = inspect_database(
            &primary_path,
            backup_path.as_deref(),
            &migration_dir,
        )?;

        match inspection.kind {
            FileKind::Invalid | FileKind::ExternalRedb => {
                return Err(ClError::NotCloveDatabase {
                    path: primary_path.display().to_string(),
                });
            }
            _ => {}
        }

        if inspection.kind != FileKind::New {
            validate_tables(
                &input.tables.iter().map(|t| t.name.clone()).collect::<Vec<_>>(),
                &inspection.tables,
            )?;
        }

        let file_era = resolve_file_era(&inspection);
        let mut meta = build_meta(input, file_era);

        if inspection.kind == FileKind::Authenticated {
            if let Ok(db) = Database::open(&primary_path) {
                if let Ok(Some(existing)) = read_meta(&db) {
                    if existing.meta_version == crate::metadata::types::META_VERSION {
                        meta = existing;
                        meta.framework_version = env!("CARGO_PKG_VERSION").to_string();
                    }
                }
            }
        }

        if let Some(ref bp) = backup_path {
            if bp.exists() && input.backup_enabled && !meta.backup_upgraded {
                let table_names: Vec<String> =
                    input.tables.iter().map(|t| t.name.to_string()).collect();
                let result = eager_normalize(bp, &table_names, input.has_cache, input.durability)?;
                if let Some(pre) = backup_path.as_ref().map(|p| pre_upgrade_path(p.as_path())) {
                    if pre.exists() && result.pre_upgrade_removed {
                        meta.backup_pre_upgrade_path = None;
                    } else if pre.exists() {
                        meta.backup_pre_upgrade_path = pre.to_str().map(|s| s.to_string());
                    }
                }
                meta.push_log(
                    "backup_normalize",
                    Some(format!(
                        "converted={} skipped={} pre_upgrade_removed={}",
                        result.entries_converted,
                        result.entries_skipped,
                        result.pre_upgrade_removed
                    )),
                );
                meta.backup_upgraded = true;
                meta.backup_format = BACKUP_FORMAT_JSON.to_string();
            }
        }

        let refs_upgraded =
            upgrade_migration_refs_with_durability(&migration_dir, input.durability)?;
        if refs_upgraded > 0 {
            meta.push_log(
                "migration_refs_upgrade",
                Some(format!("files_updated={refs_upgraded}")),
            );
        }

        let table_names: Vec<String> = input.tables.iter().map(|t| t.name.clone()).collect();
        let mut migration_index = DbMigrationIndex::load_with_durability(
            &db_dir,
            input.db_name,
            &table_names,
            input.durability,
        )?;

        let mut table_layouts = HashMap::new();
        for reg in input.tables {
            migration_index.ensure_table(&reg.name, &reg.layout)?;
            table_layouts.insert(reg.name.clone(), reg.layout.clone());

            let chain = migration_index.table_chain(&reg.name)?;
            if let Some(tm) = meta.tables.iter_mut().find(|t| t.name == reg.name) {
                tm.schema_id = reg.name.clone();
                tm.schema_version = chain.current_version();
                tm.layout_hash = reg.layout.layout_hash.clone();
            }

            if inspection.kind != FileKind::New {
                let stored = chain
                    .dir
                    .join("layouts")
                    .join(format!("v{}.json", chain.current_version()));
                if stored.exists() {
                    let on_disk: FieldLayout = serde_json::from_str(&fs::read_to_string(stored)?)?;
                    if on_disk.layout_hash != reg.layout.layout_hash
                        && chain.manifests.is_empty()
                    {
                        return Err(ClError::LayoutMismatch {
                            table: reg.name.clone(),
                            registered: reg.layout.layout_hash.clone(),
                            chain_version: chain.current_version(),
                        });
                    }
                }
            }
        }

        let db = Database::create(&primary_path)
            .map_err(|e| ClError::Database(redb::Error::from(e)))?;
        ensure_meta_table(&db)?;

        meta.upgrade_complete = true;
        meta.framework_version = env!("CARGO_PKG_VERSION").to_string();
        meta.push_log("upgrade_complete", None);
        write_meta(&db, &meta)?;

        Ok(UpgradeOutput {
            meta,
            table_layouts,
        })
    }
}

fn resolve_file_era(inspection: &crate::metadata::DatabaseInspection) -> FileEra {
    inspection.file_era.unwrap_or_else(|| {
        if inspection.migration_exists {
            FileEra::Clove049
        } else if inspection.primary_exists {
            FileEra::Legacy042
        } else {
            FileEra::Current
        }
    })
}

fn build_meta(input: &UpgradeInput<'_>, file_era: FileEra) -> CloveMeta {
    let tables: Vec<TableMeta> = input
        .tables
        .iter()
        .map(|reg| TableMeta {
            name: reg.name.clone(),
            schema_id: reg.name.clone(),
            schema_version: 1,
            layout_hash: reg.layout.layout_hash.clone(),
            storage: reg.storage,
        })
        .collect();

    let mut meta = CloveMeta::new(
        input.db_name,
        file_era,
        input.backup_enabled,
        input.blob_enabled,
        tables,
    );

    if input.backup_enabled {
        meta.backup_format = BackupFormat::JsonWrappedV1.as_str().to_string();
        meta.backup_upgraded = false;
    }

    meta
}

fn validate_tables(expected: &[String], found: &[String]) -> Result<()> {
    if found.is_empty() {
        return Ok(());
    }
    let missing: Vec<String> = expected
        .iter()
        .filter(|t| !found.contains(t))
        .cloned()
        .collect();
    if !missing.is_empty() {
        return Err(ClError::TableMismatch {
            expected: expected.to_vec(),
            found: found.to_vec(),
        });
    }
    Ok(())
}
