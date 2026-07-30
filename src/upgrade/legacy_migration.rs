use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use serde_json::Value;

use crate::durability::DurabilityMode;
use crate::fsutil::write_atomic_json;
use crate::migration::layout::FieldLayout;
use crate::migration::types::{
    layout_path, migration_dir_name, table_chain_dir, DbMigrationRootIndex, MigrationIndexEntry,
    MigrationKind, MigrationManifest, MIGRATION_INDEX_VERSION, SchemaRef, TableChainIndex,
    TableChainSummary, TargetConflictPolicy, VersionScope,
};
use crate::units::{ClError, Result};

#[derive(Debug, Deserialize)]
struct LegacyRootIndex {
    db_name: String,
    current_schema: String,
    initial_schema: String,
    chain: Vec<MigrationIndexEntry>,
}

#[derive(Debug, Deserialize)]
struct LegacySchemaRef {
    db: String,
    table: String,
    #[allow(dead_code)]
    schema: String,
}

#[derive(Debug, Deserialize)]
struct LegacyVersionScope {
    backup_versions_from: u64,
    backup_versions_to: u64,
    primary_snapshot_ref: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LegacyManifest {
    migration_id: String,
    parent_migration_id: Option<String>,
    timestamp: i64,
    kind: String,
    from: LegacySchemaRef,
    to: LegacySchemaRef,
    version_scope: LegacyVersionScope,
    #[allow(dead_code)]
    decoder: String,
    key_conflict_policy: Option<String>,
    target_conflict_policy: Option<String>,
}

pub fn is_legacy_root_index(data: &str) -> bool {
    serde_json::from_str::<Value>(data)
        .ok()
        .is_some_and(|v| v.get("index_version").is_none() && v.get("current_schema").is_some())
}

/// Converts v0.0.49 single-root migration layout into per-table `tables/{name}/` chains.
pub fn upgrade_legacy_migration_index(
    db_dir: &Path,
    db_name: &str,
    registered_tables: &[String],
    durability: DurabilityMode,
) -> Result<()> {
    let migration_dir = db_dir.join(migration_dir_name(db_name));
    let root_path = migration_dir.join("index.json");
    if !root_path.exists() {
        return Ok(());
    }

    let data = fs::read_to_string(&root_path)?;
    if !is_legacy_root_index(&data) {
        return Ok(());
    }

    let legacy: LegacyRootIndex = serde_json::from_str(&data)?;
    let mut table_versions: HashMap<String, u32> = registered_tables
        .iter()
        .map(|t| (t.clone(), 1u32))
        .collect();

    let mut table_chains: HashMap<String, TableChainIndex> = registered_tables
        .iter()
        .map(|t| {
            (
                t.clone(),
                TableChainIndex {
                    schema_id: t.clone(),
                    current_version: 1,
                    initial_version: 1,
                    chain: Vec::new(),
                },
            )
        })
        .collect();

    let mut chain_entries = legacy.chain;
    chain_entries.sort_by_key(|e| e.order);

    for entry in chain_entries {
        let old_mig_dir = migration_dir.join(&entry.migration_id);
        if !old_mig_dir.is_dir() {
            return Err(ClError::MigrationError(format!(
                "legacy migration dir missing: {}",
                old_mig_dir.display()
            )));
        }

        let manifest_data = fs::read_to_string(old_mig_dir.join("manifest.json"))?;
        let legacy_manifest: LegacyManifest = serde_json::from_str(&manifest_data)?;
        let table = legacy_manifest.from.table.clone();

        let from_version = *table_versions.get(&table).unwrap_or(&1);
        let to_version = from_version + 1;
        table_versions.insert(table.clone(), to_version);

        let table_dir = table_chain_dir(&migration_dir, &table);
        let new_manifest = convert_manifest(
            &legacy_manifest,
            from_version,
            to_version,
            &table_dir,
        )?;
        let new_mig_dir = table_chain_dir(&migration_dir, &table).join(&entry.migration_id);
        fs::create_dir_all(new_mig_dir.parent().unwrap())?;
        if new_mig_dir.exists() {
            fs::remove_dir_all(&new_mig_dir)?;
        }
        fs::rename(&old_mig_dir, &new_mig_dir)?;
        write_atomic_json(
            &new_mig_dir.join("manifest.json"),
            &new_manifest,
            durability,
        )?;

        let chain = table_chains.get_mut(&table).ok_or_else(|| {
            ClError::MigrationError(format!(
                "legacy migration targets unregistered table '{table}'"
            ))
        })?;
        chain.chain.push(MigrationIndexEntry {
            migration_id: entry.migration_id,
            order: entry.order,
        });
        chain.current_version = to_version;
    }

    let _ = (&legacy.initial_schema, &legacy.current_schema);

    fs::create_dir_all(migration_dir.join("tables"))?;
    for table in registered_tables {
        let chain = table_chains.get(table).unwrap();
        let table_dir = table_chain_dir(&migration_dir, table);
        fs::create_dir_all(&table_dir)?;
        write_atomic_json(&table_dir.join("index.json"), chain, durability)?;
    }

    let mut summaries = HashMap::new();
    for table in registered_tables {
        let chain = table_chains.get(table).unwrap();
        summaries.insert(
            table.clone(),
            TableChainSummary {
                schema_id: table.clone(),
                current_version: chain.current_version,
                initial_version: chain.initial_version,
            },
        );
    }

    let root = DbMigrationRootIndex {
        index_version: MIGRATION_INDEX_VERSION,
        db_name: legacy.db_name,
        tables: summaries,
    };
    write_atomic_json(&root_path, &root, durability)?;
    Ok(())
}

fn layout_hash_at(table_dir: &Path, version: u32) -> String {
    let path = layout_path(table_dir, version);
    if path.exists() {
        if let Ok(data) = fs::read_to_string(&path) {
            if let Ok(layout) = serde_json::from_str::<FieldLayout>(&data) {
                return layout.layout_hash;
            }
        }
    }
    format!("unknown-v{version}")
}

fn convert_manifest(
    legacy: &LegacyManifest,
    from_version: u32,
    to_version: u32,
    table_dir: &Path,
) -> Result<MigrationManifest> {
    let kind = match legacy.kind.as_str() {
        "SameDbRemapTable" => MigrationKind::InPlaceEvolve,
        "CrossDbMove" => MigrationKind::DataTransfer,
        "ExternalImport" => MigrationKind::ExternalImport,
        other => {
            return Err(ClError::MigrationError(format!(
                "unknown legacy migration kind: {other}"
            )));
        }
    };

    let policy = legacy
        .target_conflict_policy
        .as_deref()
        .or(legacy.key_conflict_policy.as_deref())
        .map(parse_conflict_policy)
        .transpose()?
        .unwrap_or(TargetConflictPolicy::Fail);

    Ok(MigrationManifest {
        migration_id: legacy.migration_id.clone(),
        parent_migration_id: legacy.parent_migration_id.clone(),
        timestamp: legacy.timestamp,
        kind,
        from: SchemaRef {
            db: legacy.from.db.clone(),
            table: legacy.from.table.clone(),
            schema_id: legacy.from.table.clone(),
            schema_version: from_version,
        },
        to: SchemaRef {
            db: legacy.to.db.clone(),
            table: legacy.to.table.clone(),
            schema_id: legacy.to.table.clone(),
            schema_version: to_version,
        },
        version_scope: VersionScope {
            backup_versions_from: legacy.version_scope.backup_versions_from,
            backup_versions_to: legacy.version_scope.backup_versions_to,
            scope_table: legacy.from.table.clone(),
            primary_snapshot_ref: legacy.version_scope.primary_snapshot_ref.clone(),
        },
        from_layout_hash: layout_hash_at(table_dir, from_version),
        to_layout_hash: layout_hash_at(table_dir, to_version),
        target_conflict_policy: policy,
        table_rename: None,
        field_diff: None,
    })
}

fn parse_conflict_policy(s: &str) -> Result<TargetConflictPolicy> {
    match s {
        "Fail" => Ok(TargetConflictPolicy::Fail),
        "Skip" => Ok(TargetConflictPolicy::Skip),
        "Overwrite" => Ok(TargetConflictPolicy::Overwrite),
        "OverwriteIfCompatible" => Ok(TargetConflictPolicy::OverwriteIfCompatible),
        other => Err(ClError::MigrationError(format!(
            "unknown legacy conflict policy: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrades_v049_root_index_to_per_table() {
        let tmp = std::env::temp_dir().join(format!(
            "clove_legacy_mig_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&tmp);
        let mig = tmp.join("retail.migration");
        fs::create_dir_all(mig.join("mig-test").join("refs")).unwrap();
        fs::write(
            mig.join("index.json"),
            r#"{
  "db_name": "retail",
  "current_schema": "RetailV2",
  "initial_schema": "RetailV1",
  "chain": [{"migration_id": "mig-test", "order": 1}]
}"#,
        )
        .unwrap();
        fs::write(
            mig.join("mig-test/manifest.json"),
            r#"{
  "migration_id": "mig-test",
  "parent_migration_id": null,
  "timestamp": 1,
  "kind": "SameDbRemapTable",
  "from": {"db": "retail", "table": "products", "schema": "RetailV1"},
  "to": {"db": "retail", "table": "products", "schema": "RetailV2"},
  "version_scope": {
    "backup_versions_from": 1,
    "backup_versions_to": 3,
    "primary_snapshot_ref": "primary_before_mig-test"
  },
  "decoder": "RetailV1_to_V2",
  "key_conflict_policy": "Fail"
}"#,
        )
        .unwrap();

        upgrade_legacy_migration_index(
            &tmp,
            "retail",
            &["products".into(), "buyers".into()],
            DurabilityMode::Strict,
        )
        .unwrap();

        let root: DbMigrationRootIndex =
            serde_json::from_str(&fs::read_to_string(mig.join("index.json")).unwrap()).unwrap();
        assert_eq!(root.index_version, MIGRATION_INDEX_VERSION);
        assert_eq!(root.tables.get("products").unwrap().current_version, 2);
        assert_eq!(root.tables.get("buyers").unwrap().current_version, 1);

        let products_index: TableChainIndex = serde_json::from_str(
            &fs::read_to_string(mig.join("tables/products/index.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(products_index.current_version, 2);
        assert!(mig.join("tables/products/mig-test/manifest.json").exists());
        assert!(!mig.join("mig-test").exists());

        let _ = fs::remove_dir_all(&tmp);
    }
}
