use std::path::PathBuf;
use chrono::Local;
use uuid::Uuid;

use crate::migration::batch::MigrationBatch;
use crate::migration::clove::read_clove_table;
use crate::migration::decoder::SchemaDecoderRegistry;
use crate::migration::redb_external::read_external_table;
use crate::migration::report::{MigrationReport, MigrationResult};
use crate::migration::types::{
    KeyConflictPolicy, MigrationKind, MigrationManifest, MigrationSourceRef,
    MigrationTargetRef, SchemaRef, VersionScope,
};
use crate::repository::DatabaseManager;
use crate::storage::Storage;
use crate::units::{ClError, Result};

pub struct MigrationRunner {
    storage: Storage,
    registry: SchemaDecoderRegistry,
    source: Option<MigrationSourceRef>,
    target: Option<MigrationTargetRef>,
    decoder_name: Option<String>,
    from_schema: Option<String>,
    to_schema: Option<String>,
    kind: MigrationKind,
    conflict_policy: KeyConflictPolicy,
    delete_old: bool,
}

impl MigrationRunner {
    pub fn new(storage: Storage, registry: SchemaDecoderRegistry) -> Self {
        Self {
            storage,
            registry,
            source: None,
            target: None,
            decoder_name: None,
            from_schema: None,
            to_schema: None,
            kind: MigrationKind::SameDbRemapTable,
            conflict_policy: KeyConflictPolicy::Fail,
            delete_old: false,
        }
    }

    pub fn from_clove(mut self, path: PathBuf, table: impl Into<String>) -> Self {
        self.source = Some(MigrationSourceRef::CloveDb {
            path,
            table: table.into(),
        });
        self
    }

    pub fn from_explicit(mut self, db_name: impl Into<String>, table: impl Into<String>) -> Self {
        self.source = Some(MigrationSourceRef::Explicit {
            db_name: db_name.into(),
            table: table.into(),
        });
        self
    }

    pub fn from_external_redb(
        mut self,
        path: PathBuf,
        spec: crate::migration::types::RedbTableSpec,
    ) -> Self {
        self.source = Some(MigrationSourceRef::ExternalRedb { path, spec });
        self.kind = MigrationKind::ExternalImport;
        self
    }

    pub fn to_explicit(mut self, db_name: impl Into<String>, table: impl Into<String>) -> Self {
        self.target = Some(MigrationTargetRef::Explicit {
            db_name: db_name.into(),
            table: table.into(),
        });
        self
    }

    pub fn with_decoder(mut self, name: impl Into<String>) -> Self {
        self.decoder_name = Some(name.into());
        self
    }

    pub fn with_schema_names(
        mut self,
        from: impl Into<String>,
        to: impl Into<String>,
    ) -> Self {
        self.from_schema = Some(from.into());
        self.to_schema = Some(to.into());
        self
    }

    pub fn kind(mut self, kind: MigrationKind) -> Self {
        self.kind = kind;
        self
    }

    pub fn on_key_conflict(mut self, policy: KeyConflictPolicy) -> Self {
        self.conflict_policy = policy;
        self
    }

    pub fn delete_old_source(mut self, delete: bool) -> Self {
        self.delete_old = delete;
        self
    }

    pub fn dry_run(&self) -> Result<MigrationReport> {
        self.run(true)
    }

    pub fn execute(&self) -> Result<MigrationResult> {
        let report = self.run(false)?;
        Ok(MigrationResult {
            migration_id: report.migration_id.clone(),
            records_migrated: report.would_insert + report.would_overwrite,
            report,
        })
    }

    fn run(&self, dry_run: bool) -> Result<MigrationReport> {
        let migration_id = format!("mig-{}", &Uuid::new_v4().to_string()[..8]);
        let mut report = MigrationReport::new(migration_id.clone(), dry_run);

        let source = self
            .source
            .as_ref()
            .ok_or_else(|| ClError::MigrationError("migration source not set".into()))?;
        let target = self
            .target
            .as_ref()
            .ok_or_else(|| ClError::MigrationError("migration target not set".into()))?;
        let decoder_name = self
            .decoder_name
            .as_ref()
            .ok_or_else(|| ClError::MigrationError("decoder not set".into()))?;
        let from_schema = self
            .from_schema
            .as_ref()
            .ok_or_else(|| ClError::MigrationError("from_schema not set".into()))?;
        let to_schema = self
            .to_schema
            .as_ref()
            .ok_or_else(|| ClError::MigrationError("to_schema not set".into()))?;

        self.registry.get(decoder_name).map_err(|_| ClError::DecoderNotFound {
            schema: decoder_name.clone(),
            migration_id: migration_id.clone(),
        })?;

        let (source_db_name, source_table, entries) = self.read_source(source)?;

        let MigrationTargetRef::Explicit {
            db_name: target_db_name,
            table: target_table,
        } = target;

        let target_db = self.storage.db_manager(target_db_name).clone();
        let decoder = self.registry.get(decoder_name)?;

        let in_place = source_table == *target_table && source_db_name == *target_db_name;

        let mut batch = MigrationBatch::new();
        let mut snapshot = Vec::new();

        report.source_count = entries.len();

        for (key, bytes) in &entries {
            let migrated = decoder.migrate_bytes(bytes)?;
            let exists = target_db
                .get_raw(target_table, key)?
                .is_some();

            if exists {
                if in_place {
                    report.would_overwrite += 1;
                } else {
                    match self.conflict_policy {
                        KeyConflictPolicy::Fail => {
                            report.conflicts.push(crate::migration::report::ConflictEntry {
                                table: target_table.clone(),
                                key: key.clone(),
                                policy: self.conflict_policy,
                            });
                            continue;
                        }
                        KeyConflictPolicy::Skip => {
                            report.would_skip += 1;
                            continue;
                        }
                        KeyConflictPolicy::Overwrite => {
                            report.would_overwrite += 1;
                        }
                    }
                }
            } else {
                report.would_insert += 1;
            }

            if !dry_run {
                snapshot.push((key.clone(), bytes.clone()));
            }
            batch.stage_write(target_table, key, migrated);
        }

        if !report.conflicts.is_empty() && matches!(self.conflict_policy, KeyConflictPolicy::Fail) {
            return Ok(report);
        }

        if batch.write_count() == 0 && report.would_skip == report.source_count {
            report
                .errors
                .push("no records to migrate after conflict resolution".into());
            return Ok(report);
        }

        if dry_run {
            report.would_delete_old_db = self.delete_old;
            return Ok(report);
        }

        batch.commit(&target_db)?;

        let keys: Vec<String> = entries.iter().map(|(k, _)| k.clone()).collect();
        let max_version = self.max_backup_version(&target_db, target_table, &keys)?;

        let manifest = MigrationManifest {
            migration_id: migration_id.clone(),
            parent_migration_id: target_db
                .migration_chain()
                .ok()
                .and_then(|c| c.manifests.last().map(|m| m.migration_id.clone())),
            timestamp: Local::now().timestamp_millis(),
            kind: self.kind,
            from: SchemaRef {
                db: source_db_name,
                table: source_table.clone(),
                schema: from_schema.clone(),
            },
            to: SchemaRef {
                db: target_db_name.clone(),
                table: target_table.clone(),
                schema: to_schema.clone(),
            },
            version_scope: VersionScope {
                backup_versions_from: 1,
                backup_versions_to: max_version,
                primary_snapshot_ref: Some(format!("primary_before_{}", migration_id)),
            },
            decoder: decoder_name.clone(),
            key_conflict_policy: self.conflict_policy,
        };

        target_db.append_migration(manifest, Some(&snapshot))?;

        if self.delete_old && source_table != *target_table {
            if let MigrationSourceRef::Explicit { db_name, table } = source {
                let source_db = self.storage.db_manager(db_name).clone();
                for (key, _) in &entries {
                    source_db.delete_raw(table, key)?;
                }
            }
        }

        report.would_delete_old_db = self.delete_old;
        Ok(report)
    }

    fn read_source(
        &self,
        source: &MigrationSourceRef,
    ) -> Result<(String, String, Vec<(String, Vec<u8>)>)> {
        match source {
            MigrationSourceRef::CloveDb { path, table } => {
                let entries = read_clove_table(path, table)?;
                Ok(("external".into(), table.clone(), entries))
            }
            MigrationSourceRef::Explicit { db_name, table } => {
                let db = self.storage.db_manager(db_name);
                let entries = db.list_entries(table)?;
                Ok((db_name.clone(), table.clone(), entries))
            }
            MigrationSourceRef::ExternalRedb { path, spec } => {
                let entries = read_external_table(path, spec)?;
                Ok(("external".into(), spec.source_table.clone(), entries))
            }
        }
    }

    fn max_backup_version(
        &self,
        db: &DatabaseManager,
        table: &str,
        keys: &[String],
    ) -> Result<u64> {
        let mut max = 0u64;
        for key in keys {
            if let Ok(v) = db.current_version(table, key) {
                max = max.max(v);
            }
        }
        if max > 0 {
            return Ok(max);
        }
        if let Ok(chain) = db.migration_chain() {
            if let Some(last) = chain.manifests.last() {
                return Ok(last.version_scope.backup_versions_to);
            }
        }
        Ok(0)
    }
}

pub fn default_registry() -> SchemaDecoderRegistry {
    let mut registry = SchemaDecoderRegistry::new();
    registry.register("passthrough", crate::migration::decoder::JsonPassthroughDecoder);
    registry
}
