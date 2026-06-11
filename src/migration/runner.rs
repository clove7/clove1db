use chrono::Local;
use std::marker::PhantomData;
use std::sync::Arc;
use uuid::Uuid;

use crate::migration::batch::MigrationBatch;
use crate::migration::guard::{assert_target_available, check_compatible_overwrite};
use crate::migration::layout::FieldLayout;
use crate::migration::migrate_to::{MigrateTo, MigrationSourceType, MigrationTargetType};
use crate::migration::plan::{MigrationSource, resolve_plan};
use crate::migration::redb_external::read_external_table;
use crate::migration::report::{ConflictEntry, MigrationReport, MigrationResult};
use crate::migration::step_registry::MigrationStepRegistry;
use crate::migration::types::{
    ExternalFrom, MigrationFrom, MigrationKind, MigrationManifest, MigrationTo,
    RedbTableSpec, SchemaRef, TableRenameInfo, TargetConflictPolicy, VersionScope,
};
use crate::repository::DatabaseManager;
use crate::storage::Storage;
use crate::units::{ClError, Result};

pub struct MigrationRun<'a, F, T> {
    storage: Storage,
    registry: Arc<MigrationStepRegistry>,
    source: Option<MigrationSource>,
    target: Option<MigrationTo>,
    conflict_policy: TargetConflictPolicy,
    _from: PhantomData<F>,
    _to: PhantomData<T>,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a, F, T> MigrationRun<'a, F, T>
where
    F: MigrationSourceType,
    T: MigrationTargetType,
    F: MigrateTo<T>,
{
    pub(crate) fn new(storage: Storage, registry: Arc<MigrationStepRegistry>) -> Self {
        let _ = registry.register::<F, T>();
        Self {
            storage,
            registry,
            source: None,
            target: None,
            conflict_policy: TargetConflictPolicy::Fail,
            _from: PhantomData,
            _to: PhantomData,
            _lifetime: PhantomData,
        }
    }

    pub fn from(self, from: MigrationFrom) -> Self {
        Self {
            source: Some(MigrationSource::Clove(from)),
            ..self
        }
    }

    pub fn from_db(self, db: impl Into<String>, table: impl Into<String>) -> Self {
        self.from(MigrationFrom {
            db: db.into(),
            table: table.into(),
        })
    }

    pub fn from_external(self, external: ExternalFrom) -> Self {
        Self {
            source: Some(MigrationSource::External(external)),
            ..self
        }
    }

    pub fn to(self, target: MigrationTo) -> Self {
        Self { target: Some(target), ..self }
    }

    pub fn on_target_conflict(self, policy: TargetConflictPolicy) -> Self {
        Self {
            conflict_policy: policy,
            ..self
        }
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
        let source = self
            .source
            .as_ref()
            .ok_or_else(|| ClError::MigrationError("migration source not set".into()))?;

        let plan = resolve_plan(source, self.target.as_ref())?;
        let migration_id = format!("mig-{}", &Uuid::new_v4().to_string()[..8]);
        let mut report = MigrationReport::new(migration_id.clone(), dry_run);

        let target_db = self.storage.db_manager(&plan.to.db).clone();
        assert_target_available(&plan, &target_db, self.conflict_policy)?;

        let entries = self.read_source(source)?;
        report.source_count = entries.len();

        let from_version = self.resolve_from_version(&plan)?;
        let to_version = if plan.kind == MigrationKind::ExternalImport && from_version == 0 {
            1
        } else {
            from_version + 1
        };

        let (from_layout_hash, to_layout_hash) = MigrationStepRegistry::layout_pair::<F, T>()?;
        let decoder = self
            .registry
            .get_by_layout(&from_layout_hash, &to_layout_hash)?;

        let in_place = plan.kind == MigrationKind::InPlaceEvolve;
        let target_layout = target_db.table_layout(&plan.to.table)?;

        let mut batch = MigrationBatch::new();
        let mut snapshot = Vec::new();

        for (key, bytes) in &entries {
            let migrated = decoder.migrate_bytes(bytes)?;
            let exists = target_db.get_raw(&plan.to.table, key)?.is_some();

            if exists && !in_place {
                match self.conflict_policy {
                    TargetConflictPolicy::Fail => {
                        report.conflicts.push(ConflictEntry {
                            table: plan.to.table.clone(),
                            key: key.clone(),
                            policy: self.conflict_policy,
                        });
                        continue;
                    }
                    TargetConflictPolicy::Skip => {
                        report.would_skip += 1;
                        continue;
                    }
                    TargetConflictPolicy::Overwrite => {
                        report.would_overwrite += 1;
                    }
                    TargetConflictPolicy::OverwriteIfCompatible => {
                        let existing = target_db
                            .get_raw(&plan.to.table, key)?
                            .unwrap_or_default();
                        if !check_compatible_overwrite(&existing, &migrated, &target_layout)? {
                            report.conflicts.push(ConflictEntry {
                                table: plan.to.table.clone(),
                                key: key.clone(),
                                policy: self.conflict_policy,
                            });
                            continue;
                        }
                        report.would_overwrite += 1;
                    }
                }
            } else if exists {
                report.would_overwrite += 1;
            } else {
                report.would_insert += 1;
            }

            if !dry_run {
                snapshot.push((key.clone(), bytes.clone()));
            }
            batch.stage_write(&plan.to.table, key, migrated);
        }

        if !report.conflicts.is_empty()
            && matches!(self.conflict_policy, TargetConflictPolicy::Fail)
        {
            return Ok(report);
        }

        if batch.write_count() == 0 && report.would_skip == report.source_count {
            report
                .errors
                .push("no records to migrate after conflict resolution".into());
            return Ok(report);
        }

        if dry_run {
            report.would_delete_old_db = plan.effective_delete_source;
            return Ok(report);
        }

        batch.commit(&target_db)?;

        let keys: Vec<String> = entries.iter().map(|(k, _)| k.clone()).collect();
        let max_version = self.max_backup_version(&target_db, &plan.to.table, &keys)?;

        let table_rename = if plan.from.table != plan.to.table && plan.from.db == plan.to.db {
            Some(TableRenameInfo {
                from_table: plan.from.table.clone(),
                to_table: plan.to.table.clone(),
                backup_rewrite: true,
            })
        } else {
            None
        };

        let manifest = MigrationManifest {
            migration_id: migration_id.clone(),
            parent_migration_id: target_db.migration_index().ok().and_then(|i| {
                i.tables
                    .get(&plan.to.table)
                    .and_then(|c| c.manifests.last().map(|m| m.migration_id.clone()))
            }),
            timestamp: Local::now().timestamp_millis(),
            kind: plan.kind,
            from: SchemaRef {
                db: plan.from.db.clone(),
                table: plan.from.table.clone(),
                schema_id: plan.from.table.clone(),
                schema_version: from_version,
            },
            to: SchemaRef {
                db: plan.to.db.clone(),
                table: plan.to.table.clone(),
                schema_id: plan.to.table.clone(),
                schema_version: to_version,
            },
            version_scope: VersionScope {
                backup_versions_from: 1,
                backup_versions_to: max_version,
                scope_table: plan.from.table.clone(),
                primary_snapshot_ref: Some(format!("primary_before_{migration_id}")),
            },
            from_layout_hash,
            to_layout_hash,
            target_conflict_policy: self.conflict_policy,
            table_rename,
            field_diff: None,
        };

        let new_layout = snapshot
            .first()
            .and_then(|(_, bytes)| FieldLayout::capture_from_sample_json(bytes).ok())
            .or_else(|| FieldLayout::capture_from_sample_json(&[]).ok());

        target_db.append_migration(
            &plan.to.table,
            manifest,
            Some(&snapshot),
            new_layout.as_ref(),
        )?;

        if plan.effective_delete_source {
            let source_db = self.storage.db_manager(&plan.from.db).clone();
            for (key, _) in &entries {
                source_db.delete_raw(&plan.from.table, key)?;
            }
            if plan.from.table != plan.to.table && plan.from.db == plan.to.db {
                target_db.rewrite_backup_table(&plan.from.table, &plan.to.table)?;
            }
        }

        report.would_delete_old_db = plan.effective_delete_source;
        Ok(report)
    }

    fn resolve_from_version(&self, plan: &crate::migration::plan::MigrationPlan) -> Result<u32> {
        if plan.kind == MigrationKind::ExternalImport {
            let index = self.storage.db_manager(&plan.to.db).migration_index()?;
            return Ok(index
                .table_chain(&plan.to.table)
                .map(|c| c.current_version())
                .unwrap_or(0));
        }
        let source_db = self.storage.db_manager(&plan.from.db);
        let index = source_db.migration_index()?;
        Ok(index.table_chain(&plan.from.table)?.current_version())
    }

    fn read_source(&self, source: &MigrationSource) -> Result<Vec<(String, Vec<u8>)>> {
        match source {
            MigrationSource::Clove(from) => {
                let db = self.storage.db_manager(&from.db);
                db.list_entries(&from.table)
            }
            MigrationSource::External(ext) => {
                let spec = RedbTableSpec {
                    source_table: ext.table.clone(),
                    key_decoder: ext.key_decoder,
                    value_decoder: ext.value_decoder,
                };
                read_external_table(&ext.path, &spec)
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
        if let Ok(index) = db.migration_index() {
            if let Ok(chain) = index.table_chain(table) {
                if let Some(last) = chain.manifests.last() {
                    return Ok(last.version_scope.backup_versions_to);
                }
            }
        }
        Ok(0)
    }
}
