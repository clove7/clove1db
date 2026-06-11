use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::backup::view::HistoryDisplayMode;
use crate::migration::step_registry::MigrationStepRegistry;
use crate::migration::layout::FieldLayout;
use crate::upgrade::legacy_migration::{is_legacy_root_index, upgrade_legacy_migration_index};
use crate::migration::types::{
    DbMigrationRootIndex, MigrationIndexEntry, MigrationManifest, TableChainIndex,
    TableChainSummary, layout_path, migration_dir_name, table_chain_dir, MIGRATION_INDEX_VERSION,
};
use crate::units::{ClError, Result};

#[derive(Debug, Clone)]
pub struct TableMigrationChain {
    pub table: String,
    pub dir: PathBuf,
    pub index: TableChainIndex,
    pub manifests: Vec<MigrationManifest>,
}

#[derive(Debug, Clone)]
pub struct DbMigrationIndex {
    pub dir: PathBuf,
    pub db_name: String,
    pub root: DbMigrationRootIndex,
    pub tables: HashMap<String, TableMigrationChain>,
}

impl DbMigrationIndex {
    pub fn migration_path(db_dir: &Path, db_name: &str) -> PathBuf {
        db_dir.join(migration_dir_name(db_name))
    }

    pub fn load(db_dir: &Path, db_name: &str, registered_tables: &[String]) -> Result<Self> {
        let dir = Self::migration_path(db_dir, db_name);
        if !dir.exists() {
            return Ok(Self::empty(dir, db_name, registered_tables));
        }

        let root_path = dir.join("index.json");
        if root_path.exists() {
            let data = fs::read_to_string(&root_path)?;
            if is_legacy_root_index(&data) {
                upgrade_legacy_migration_index(db_dir, db_name, registered_tables)?;
            }
        } else if !dir.join("tables").exists() {
            return Err(ClError::LegacyMigrationFormat {
                path: root_path.display().to_string(),
            });
        }

        let root: DbMigrationRootIndex = if root_path.exists() {
            let data = fs::read_to_string(&root_path)?;
            let parsed: DbMigrationRootIndex = serde_json::from_str(&data)?;
            if parsed.index_version != MIGRATION_INDEX_VERSION {
                return Err(ClError::LegacyMigrationFormat {
                    path: root_path.display().to_string(),
                });
            }
            parsed
        } else {
            DbMigrationRootIndex {
                index_version: MIGRATION_INDEX_VERSION,
                db_name: db_name.to_string(),
                tables: HashMap::new(),
            }
        };

        let mut tables = HashMap::new();
        for table in registered_tables {
            let chain = Self::load_table_chain(&dir, table)?;
            tables.insert(table.clone(), chain);
        }

        Ok(Self {
            dir,
            db_name: db_name.to_string(),
            root,
            tables,
        })
    }

    fn load_table_chain(migration_dir: &Path, table: &str) -> Result<TableMigrationChain> {
        let table_dir = table_chain_dir(migration_dir, table);
        let index_path = table_dir.join("index.json");

        let index: TableChainIndex = if index_path.exists() {
            serde_json::from_str(&fs::read_to_string(&index_path)?)?
        } else {
            TableChainIndex {
                schema_id: table.to_string(),
                current_version: 1,
                initial_version: 1,
                chain: Vec::new(),
            }
        };

        let mut manifests = Vec::new();
        for entry in &index.chain {
            let manifest_path = table_dir
                .join(&entry.migration_id)
                .join("manifest.json");
            if manifest_path.exists() {
                manifests.push(serde_json::from_str(&fs::read_to_string(&manifest_path)?)?);
            }
        }

        Ok(TableMigrationChain {
            table: table.to_string(),
            dir: table_dir,
            index,
            manifests,
        })
    }

    fn empty(dir: PathBuf, db_name: &str, tables: &[String]) -> Self {
        let mut table_map = HashMap::new();
        let mut summaries = HashMap::new();
        for t in tables {
            summaries.insert(
                t.clone(),
                TableChainSummary {
                    schema_id: t.clone(),
                    current_version: 1,
                    initial_version: 1,
                },
            );
            table_map.insert(
                t.clone(),
                TableMigrationChain {
                    table: t.clone(),
                    dir: table_chain_dir(&dir, t),
                    index: TableChainIndex {
                        schema_id: t.clone(),
                        current_version: 1,
                        initial_version: 1,
                        chain: Vec::new(),
                    },
                    manifests: Vec::new(),
                },
            );
        }
        Self {
            dir,
            db_name: db_name.to_string(),
            root: DbMigrationRootIndex {
                index_version: MIGRATION_INDEX_VERSION,
                db_name: db_name.to_string(),
                tables: summaries,
            },
            tables: table_map,
        }
    }

    pub fn ensure_table(&mut self, table: &str, layout: &FieldLayout) -> Result<()> {
        if !self.tables.contains_key(table) {
            let chain = TableMigrationChain {
                table: table.to_string(),
                dir: table_chain_dir(&self.dir, table),
                index: TableChainIndex {
                    schema_id: table.to_string(),
                    current_version: 1,
                    initial_version: 1,
                    chain: Vec::new(),
                },
                manifests: Vec::new(),
            };
            self.tables.insert(table.to_string(), chain);
            self.root.tables.insert(
                table.to_string(),
                TableChainSummary {
                    schema_id: table.to_string(),
                    current_version: 1,
                    initial_version: 1,
                },
            );
        }
        {
            let chain = self.tables.get_mut(table).unwrap();
            chain.ensure_layout(1, layout)?;
        }
        self.persist_root()?;
        Ok(())
    }

    pub fn table_chain(&self, table: &str) -> Result<&TableMigrationChain> {
        self.tables
            .get(table)
            .ok_or_else(|| ClError::MigrationError(format!("table chain '{table}' not found")))
    }

    pub fn table_chain_mut(&mut self, table: &str) -> Result<&mut TableMigrationChain> {
        self.tables
            .get_mut(table)
            .ok_or_else(|| ClError::MigrationError(format!("table chain '{table}' not found")))
    }

    pub fn persist_root(&mut self) -> Result<()> {
        fs::create_dir_all(&self.dir)?;
        for (name, chain) in &self.tables {
            self.root.tables.insert(
                name.clone(),
                TableChainSummary {
                    schema_id: chain.index.schema_id.clone(),
                    current_version: chain.index.current_version,
                    initial_version: chain.index.initial_version,
                },
            );
        }
        fs::write(
            self.dir.join("index.json"),
            serde_json::to_string_pretty(&self.root)?,
        )?;
        Ok(())
    }

    pub fn append_manifest(
        &mut self,
        table: &str,
        manifest: MigrationManifest,
        snapshot: Option<&[(String, Vec<u8>)]>,
        new_layout: Option<&FieldLayout>,
    ) -> Result<()> {
        let chain = self.table_chain_mut(table)?;
        chain.append(manifest, snapshot)?;
        if let Some(layout) = new_layout {
            chain.ensure_layout(chain.index.current_version, layout)?;
        }
        self.persist_root()?;
        Ok(())
    }
}

impl TableMigrationChain {
    pub fn current_version(&self) -> u32 {
        self.index.current_version
    }

    pub fn schema_id(&self) -> &str {
        &self.index.schema_id
    }

    pub fn ensure_layout(&self, version: u32, layout: &FieldLayout) -> Result<()> {
        fs::create_dir_all(self.dir.join("layouts"))?;
        let path = layout_path(&self.dir, version);
        if !path.exists() {
            fs::write(path, serde_json::to_string_pretty(layout)?)?;
        }
        fs::create_dir_all(&self.dir)?;
        fs::write(
            self.dir.join("index.json"),
            serde_json::to_string_pretty(&self.index)?,
        )?;
        Ok(())
    }

    pub fn schema_version_for_backup(&self, backup_version: u64) -> u32 {
        for manifest in &self.manifests {
            if backup_version <= manifest.version_scope.backup_versions_to {
                return manifest.from.schema_version;
            }
        }
        self.index.current_version
    }

    pub fn migration_id_for_version(&self, backup_version: u64) -> Option<&str> {
        for manifest in &self.manifests {
            if backup_version <= manifest.version_scope.backup_versions_to {
                return Some(&manifest.migration_id);
            }
        }
        None
    }

    pub fn is_restorable(&self, backup_version: u64) -> bool {
        self.schema_version_for_backup(backup_version) == self.index.current_version
    }

    pub fn decode_to_json(
        &self,
        bytes: &[u8],
        backup_version: u64,
        mode: HistoryDisplayMode,
        registry: &MigrationStepRegistry,
    ) -> Result<(Value, Vec<String>)> {
        let era_version = self.schema_version_for_backup(backup_version);
        let mut decode_path = vec!(format!("{}@{}", self.index.schema_id, era_version));

        match mode {
            HistoryDisplayMode::AsStored => {
                let json = serde_json::from_slice(bytes)?;
                Ok((json, decode_path))
            }
            HistoryDisplayMode::Normalized => {
                let mut current_bytes = bytes.to_vec();
                let mut current_ver = era_version;

                for manifest in &self.manifests {
                    if current_ver == manifest.from.schema_version {
                        let decoder = registry
                            .get_by_layout(&manifest.from_layout_hash, &manifest.to_layout_hash)
                            .map_err(|_| ClError::DecoderNotFound {
                                from_layout_hash: manifest.from_layout_hash.clone(),
                                to_layout_hash: manifest.to_layout_hash.clone(),
                                migration_id: manifest.migration_id.clone(),
                            })?;
                        current_bytes = decoder.migrate_bytes(&current_bytes)?;
                        current_ver = manifest.to.schema_version;
                        decode_path.push(format!("{}@{}", self.index.schema_id, current_ver));
                    }
                    if current_ver == self.index.current_version {
                        break;
                    }
                }

                let json = serde_json::from_slice(&current_bytes)?;
                Ok((json, decode_path))
            }
        }
    }

    pub fn append(
        &mut self,
        manifest: MigrationManifest,
        snapshot: Option<&[(String, Vec<u8>)]>,
    ) -> Result<()> {
        let mig_dir = self.dir.join(&manifest.migration_id);
        fs::create_dir_all(mig_dir.join("refs"))?;

        if let Some(entries) = snapshot {
            let ref_name = manifest
                .version_scope
                .primary_snapshot_ref
                .clone()
                .unwrap_or_else(|| format!("primary_before_{}", manifest.migration_id));
            let ref_path = mig_dir.join("refs").join(format!("{ref_name}.json"));
            let snapshot_data: Vec<(String, String)> = entries
                .iter()
                .map(|(k, v)| (k.clone(), hex_encode(v)))
                .collect();
            fs::write(ref_path, serde_json::to_string_pretty(&snapshot_data)?)?;
        }

        fs::write(
            mig_dir.join("manifest.json"),
            serde_json::to_string_pretty(&manifest)?,
        )?;

        let order = (self.index.chain.len() + 1) as u32;
        self.index.chain.push(MigrationIndexEntry {
            migration_id: manifest.migration_id.clone(),
            order,
        });
        self.index.current_version = manifest.to.schema_version;
        self.manifests.push(manifest);

        fs::create_dir_all(&self.dir)?;
        fs::write(
            self.dir.join("index.json"),
            serde_json::to_string_pretty(&self.index)?,
        )?;
        Ok(())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{:02x}", b);
        s
    })
}

/// Legacy alias for compatibility during transition.
pub type MigrationChain = DbMigrationIndex;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::types::{
        MigrationKind, SchemaRef, TargetConflictPolicy, VersionScope,
    };

    #[test]
    fn schema_version_for_backup_respects_chain() {
        let chain = TableMigrationChain {
            table: "products".into(),
            dir: PathBuf::from("/tmp"),
            index: TableChainIndex {
                schema_id: "products".into(),
                current_version: 3,
                initial_version: 1,
                chain: vec![],
            },
            manifests: vec![
                MigrationManifest {
                    migration_id: "mig-001".into(),
                    parent_migration_id: None,
                    timestamp: 1,
                    kind: MigrationKind::InPlaceEvolve,
                    from: SchemaRef {
                        db: "d".into(),
                        table: "products".into(),
                        schema_id: "products".into(),
                        schema_version: 1,
                    },
                    to: SchemaRef {
                        db: "d".into(),
                        table: "products".into(),
                        schema_id: "products".into(),
                        schema_version: 2,
                    },
                    version_scope: VersionScope {
                        backup_versions_from: 1,
                        backup_versions_to: 10,
                        scope_table: "products".into(),
                        primary_snapshot_ref: None,
                    },
                    from_layout_hash: "hash-v1".into(),
                    to_layout_hash: "hash-v2".into(),
                    target_conflict_policy: TargetConflictPolicy::Fail,
                    table_rename: None,
                    field_diff: None,
                },
                MigrationManifest {
                    migration_id: "mig-002".into(),
                    parent_migration_id: Some("mig-001".into()),
                    timestamp: 2,
                    kind: MigrationKind::InPlaceEvolve,
                    from: SchemaRef {
                        db: "d".into(),
                        table: "products".into(),
                        schema_id: "products".into(),
                        schema_version: 2,
                    },
                    to: SchemaRef {
                        db: "d".into(),
                        table: "products".into(),
                        schema_id: "products".into(),
                        schema_version: 3,
                    },
                    version_scope: VersionScope {
                        backup_versions_from: 11,
                        backup_versions_to: 20,
                        scope_table: "products".into(),
                        primary_snapshot_ref: None,
                    },
                    from_layout_hash: "hash-v2".into(),
                    to_layout_hash: "hash-v3".into(),
                    target_conflict_policy: TargetConflictPolicy::Fail,
                    table_rename: None,
                    field_diff: None,
                },
            ],
        };

        assert_eq!(chain.schema_version_for_backup(5), 1);
        assert_eq!(chain.schema_version_for_backup(15), 2);
        assert_eq!(chain.schema_version_for_backup(25), 3);
        assert!(!chain.is_restorable(5));
        assert!(chain.is_restorable(25));
    }
}
