use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::backup::view::HistoryDisplayMode;
use crate::migration::decoder::SchemaDecoderRegistry;
use crate::migration::types::{
    MigrationIndex, MigrationManifest, migration_dir_name,
};
use crate::units::{ClError, Result};

#[derive(Debug, Clone)]
pub struct MigrationChain {
    pub dir: PathBuf,
    pub index: MigrationIndex,
    pub manifests: Vec<MigrationManifest>,
}

impl MigrationChain {
    pub fn migration_path(db_dir: &Path, db_name: &str) -> PathBuf {
        db_dir.join(migration_dir_name(db_name))
    }

    pub fn load(db_dir: &Path, db_name: &str, initial_schema: &str) -> Result<Self> {
        let dir = Self::migration_path(db_dir, db_name);
        if !dir.exists() {
            return Ok(Self::empty(dir, db_name, initial_schema));
        }

        let index_path = dir.join("index.json");
        let index: MigrationIndex = if index_path.exists() {
            let data = fs::read_to_string(&index_path)?;
            serde_json::from_str(&data)?
        } else {
            return Ok(Self::empty(dir, db_name, initial_schema));
        };

        let mut manifests = Vec::new();
        for entry in &index.chain {
            let manifest_path = dir.join(&entry.migration_id).join("manifest.json");
            if manifest_path.exists() {
                let data = fs::read_to_string(&manifest_path)?;
                manifests.push(serde_json::from_str(&data)?);
            }
        }

        Ok(Self {
            dir,
            index,
            manifests,
        })
    }

    fn empty(dir: PathBuf, db_name: &str, initial_schema: &str) -> Self {
        Self {
            dir,
            index: MigrationIndex {
                db_name: db_name.to_string(),
                current_schema: initial_schema.to_string(),
                initial_schema: initial_schema.to_string(),
                chain: Vec::new(),
            },
            manifests: Vec::new(),
        }
    }

    pub fn current_schema(&self) -> &str {
        &self.index.current_schema
    }

    pub fn schema_for_version(&self, version: u64) -> &str {
        for manifest in &self.manifests {
            if version <= manifest.version_scope.backup_versions_to {
                return &manifest.from.schema;
            }
        }
        &self.index.current_schema
    }

    pub fn migration_id_for_version(&self, version: u64) -> Option<&str> {
        for manifest in &self.manifests {
            if version <= manifest.version_scope.backup_versions_to {
                return Some(&manifest.migration_id);
            }
        }
        None
    }

    pub fn is_restorable(&self, version: u64) -> bool {
        self.schema_for_version(version) == self.index.current_schema
    }

    pub fn decode_path_for_version(&self, version: u64) -> Vec<String> {
        let mut path = Vec::new();
        let target = self.schema_for_version(version);
        path.push(target.to_string());
        path
    }

    pub fn decode_to_json(
        &self,
        bytes: &[u8],
        version: u64,
        mode: HistoryDisplayMode,
        registry: &SchemaDecoderRegistry,
    ) -> Result<(Value, Vec<String>)> {
        let era_schema = self.schema_for_version(version).to_string();
        let mut decode_path = vec![era_schema.clone()];

        match mode {
            HistoryDisplayMode::AsStored => {
                let json = self.decode_era_json(bytes, &era_schema, version, registry)?;
                Ok((json, decode_path))
            }
            HistoryDisplayMode::Normalized => {
                let mut current_bytes = bytes.to_vec();
                let mut current_schema = era_schema.clone();

                for manifest in &self.manifests {
                    if current_schema == manifest.from.schema {
                        let decoder = registry.get(&manifest.decoder).map_err(|_| {
                            ClError::DecoderNotFound {
                                schema: manifest.decoder.clone(),
                                migration_id: manifest.migration_id.clone(),
                            }
                        })?;
                        current_bytes = decoder.migrate_bytes(&current_bytes)?;
                        current_schema = manifest.to.schema.clone();
                        decode_path.push(current_schema.clone());
                    }
                    if current_schema == self.index.current_schema {
                        break;
                    }
                }

                let json = registry
                    .decode_to_json(&self.index.current_schema, &current_bytes)
                    .or_else(|_| {
                        serde_json::from_slice(&current_bytes).map_err(ClError::Serialization)
                    })?;
                Ok((json, decode_path))
            }
        }
    }

    fn decode_era_json(
        &self,
        bytes: &[u8],
        era_schema: &str,
        version: u64,
        registry: &SchemaDecoderRegistry,
    ) -> Result<Value> {
        if let Ok(decoder_name) = self.decoder_for_era(era_schema, version) {
            if let Ok(decoder) = registry.get(&decoder_name) {
                return decoder.decode_to_json(bytes);
            }
        }
        Ok(serde_json::from_slice(bytes)?)
    }

    fn decoder_for_era(&self, era_schema: &str, version: u64) -> Result<String> {
        for manifest in &self.manifests {
            if version <= manifest.version_scope.backup_versions_to
                && manifest.from.schema == era_schema
            {
                return Ok(manifest.decoder.clone());
            }
        }
        Err(ClError::DecoderNotFound {
            schema: era_schema.to_string(),
            migration_id: String::new(),
        })
    }

    pub fn append(&mut self, manifest: MigrationManifest, snapshot: Option<&[(String, Vec<u8>)]>) -> Result<()> {
        let mig_dir = self.dir.join(&manifest.migration_id);
        fs::create_dir_all(&mig_dir)?;
        fs::create_dir_all(mig_dir.join("refs"))?;

        if let Some(entries) = snapshot {
            let ref_name = manifest
                .version_scope
                .primary_snapshot_ref
                .clone()
                .unwrap_or_else(|| format!("primary_before_{}", manifest.migration_id));
            let ref_path = mig_dir.join("refs").join(format!("{}.json", ref_name));
            let snapshot_data: Vec<(String, String)> = entries
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        base64_encode(v),
                    )
                })
                .collect();
            fs::write(ref_path, serde_json::to_string_pretty(&snapshot_data)?)?;
        }

        let manifest_path = mig_dir.join("manifest.json");
        fs::write(manifest_path, serde_json::to_string_pretty(&manifest)?)?;

        let order = (self.index.chain.len() + 1) as u32;
        self.index.chain.push(crate::migration::types::MigrationIndexEntry {
            migration_id: manifest.migration_id.clone(),
            order,
        });
        self.index.current_schema = manifest.to.schema.clone();

        self.manifests.push(manifest);

        fs::create_dir_all(&self.dir)?;
        fs::write(
            self.dir.join("index.json"),
            serde_json::to_string_pretty(&self.index)?,
        )?;

        Ok(())
    }
}

fn base64_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{:02x}", b);
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::types::{MigrationKind, SchemaRef, VersionScope, KeyConflictPolicy};

    #[test]
    fn schema_for_version_respects_chain() {
        let chain = MigrationChain {
            dir: PathBuf::from("/tmp"),
            index: MigrationIndex {
                db_name: "users".into(),
                current_schema: "UserV3".into(),
                initial_schema: "UserV1".into(),
                chain: vec![],
            },
            manifests: vec![
                MigrationManifest {
                    migration_id: "mig-001".into(),
                    parent_migration_id: None,
                    timestamp: 1,
                    kind: MigrationKind::SameDbRemapTable,
                    from: SchemaRef { db: "u".into(), table: "users".into(), schema: "UserV1".into() },
                    to: SchemaRef { db: "u".into(), table: "users".into(), schema: "UserV2".into() },
                    version_scope: VersionScope { backup_versions_from: 1, backup_versions_to: 10, primary_snapshot_ref: None },
                    decoder: "v1_v2".into(),
                    key_conflict_policy: KeyConflictPolicy::Fail,
                },
                MigrationManifest {
                    migration_id: "mig-002".into(),
                    parent_migration_id: Some("mig-001".into()),
                    timestamp: 2,
                    kind: MigrationKind::SameDbRemapTable,
                    from: SchemaRef { db: "u".into(), table: "users".into(), schema: "UserV2".into() },
                    to: SchemaRef { db: "u".into(), table: "users".into(), schema: "UserV3".into() },
                    version_scope: VersionScope { backup_versions_from: 11, backup_versions_to: 20, primary_snapshot_ref: None },
                    decoder: "v2_v3".into(),
                    key_conflict_policy: KeyConflictPolicy::Fail,
                },
            ],
        };

        assert_eq!(chain.schema_for_version(5), "UserV1");
        assert_eq!(chain.schema_for_version(15), "UserV2");
        assert_eq!(chain.schema_for_version(25), "UserV3");
        assert!(!chain.is_restorable(5));
        assert!(chain.is_restorable(25));
    }
}
