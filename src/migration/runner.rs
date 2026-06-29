use chrono::Local;
use std::marker::PhantomData;
use std::sync::Arc;
use uuid::Uuid;

use crate::migration::batch::MigrationBatch;
use crate::migration::decoder::{
    storage_key_for_metadata, MigrationRecordContext, MigrationRecordResult,
};
use crate::migration::guard::{assert_target_available, check_compatible_overwrite};
use crate::migration::layout::FieldLayout;
use crate::migration::migrate_to::{MigrateTo, MigrationSourceType, MigrationTargetType};
use crate::migration::plan::{MigrationPlan, MigrationSource, resolve_plan};
use crate::migration::redb_external::read_external_table;
use crate::migration::report::{ConflictEntry, MigrationReport, MigrationResult, SkippedEntry};
use crate::migration::scan::{scan_record, MigrationScanReport};
use crate::migration::step_registry::MigrationStepRegistry;
use crate::migration::types::{
    BlobMigrationPolicy, ExternalFrom, MigrationFrom, MigrationKind, MigrationManifest,
    MigrationTo, RedbTableSpec, SchemaRef, TableRenameInfo, TableStorageMode,
    TargetConflictPolicy, VersionScope,
};
use crate::repository::DatabaseManager;
use crate::storage::Storage;
use crate::units::{ClError, Result};

/// One row staged during [`MigrationRun::dry_run`] and committed by [`MigrationRun::execute`].
struct StagedRecord {
    source_key: String,
    storage_key: String,
    metadata_bytes: Vec<u8>,
    blob: Option<Vec<u8>>,
    blob_sidecar_copy: bool,
}

/// Cached migration plan produced by `dry_run` and replayed by the next `execute`.
struct PreparedMigration {
    migration_id: String,
    plan: MigrationPlan,
    report: MigrationReport,
    staged: Vec<StagedRecord>,
    snapshot: Vec<(String, Vec<u8>)>,
    storage_keys: Vec<String>,
    source_entries: Vec<(String, Vec<u8>)>,
    from_version: u32,
    to_version: u32,
    from_layout_hash: String,
    to_layout_hash: String,
}

impl PreparedMigration {
    fn is_executable(&self) -> bool {
        self.report.errors.is_empty()
            && self.report.conflicts.is_empty()
            && !self.staged.is_empty()
    }
}

pub struct MigrationRun<'a, F, T> {
    storage: Storage,
    registry: Arc<MigrationStepRegistry>,
    source: Option<MigrationSource>,
    target: Option<MigrationTo>,
    conflict_policy: TargetConflictPolicy,
    blob_policy: BlobMigrationPolicy,
    prepared: Option<PreparedMigration>,
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
            blob_policy: BlobMigrationPolicy::default(),
            prepared: None,
            _from: PhantomData,
            _to: PhantomData,
            _lifetime: PhantomData,
        }
    }

    pub fn from(self, from: MigrationFrom) -> Self {
        Self {
            source: Some(MigrationSource::Clove(from)),
            prepared: None,
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
            prepared: None,
            ..self
        }
    }

    pub fn to(self, target: MigrationTo) -> Self {
        Self {
            target: Some(target),
            prepared: None,
            ..self
        }
    }

    pub fn on_target_conflict(self, policy: TargetConflictPolicy) -> Self {
        Self {
            conflict_policy: policy,
            prepared: None,
            ..self
        }
    }

    pub fn blob_policy(self, policy: BlobMigrationPolicy) -> Self {
        Self {
            blob_policy: policy,
            prepared: None,
            ..self
        }
    }

    pub fn scan(&self) -> Result<MigrationScanReport> {
        let source = self
            .source
            .as_ref()
            .ok_or_else(|| ClError::MigrationError("migration source not set".into()))?;
        let mut plan = resolve_plan(source, self.target.as_ref())?;
        self.enrich_plan_storage(&mut plan);

        let mut report = MigrationScanReport::new(&plan.from.table, &plan.to.table);
        report.from_storage = plan.from.storage;
        report.to_storage = plan.to.storage;

        let entries = self.read_source(source)?;
        for (key, bytes) in entries {
            scan_record(
                &mut report,
                &key,
                &bytes,
                plan.from.storage,
                plan.to.storage,
            )?;
        }
        Ok(report)
    }

    /// Simulates the migration, caches staged rows, and returns a report.
    ///
    /// The next [`execute`](Self::execute) on the **same** [`MigrationRun`] commits the cached
    /// rows without re-reading the source or re-running transforms.
    pub fn dry_run(&mut self) -> Result<MigrationReport> {
        let prepared = self.prepare()?;
        let report = prepared.report.clone();
        if prepared.is_executable() {
            self.prepared = Some(prepared);
        }
        Ok(report)
    }

    /// Commits the migration. Reuses rows staged by [`dry_run`](Self::dry_run) when present;
    /// otherwise reads the source and migrates in one pass.
    pub fn execute(&mut self) -> Result<MigrationResult> {
        let report = if let Some(prepared) = self.prepared.take() {
            if !prepared.is_executable() {
                return Err(ClError::MigrationError(
                    "cached dry_run cannot be executed (conflicts or errors)".into(),
                ));
            }
            self.commit_prepared(prepared)?
        } else {
            let prepared = self.prepare()?;
            if !prepared.is_executable() {
                return Ok(MigrationResult {
                    migration_id: prepared.migration_id,
                    records_migrated: 0,
                    report: prepared.report,
                });
            }
            self.commit_prepared(prepared)?
        };
        Ok(MigrationResult {
            migration_id: report.migration_id.clone(),
            records_migrated: report.would_insert + report.would_overwrite,
            report,
        })
    }

    fn enrich_plan_storage(&self, plan: &mut MigrationPlan) {
        if plan.from.db != "external" {
            let db = self.storage.db_manager(&plan.from.db);
            plan.from.storage = db.table_storage_mode(&plan.from.table);
        } else {
            plan.from.storage = TableStorageMode::InlineJson;
        }
        let target_db = self.storage.db_manager(&plan.to.db);
        plan.to.storage = target_db.table_storage_mode(&plan.to.table);
    }

    fn prepare(&self) -> Result<PreparedMigration> {
        let source = self
            .source
            .as_ref()
            .ok_or_else(|| ClError::MigrationError("migration source not set".into()))?;

        let mut plan = resolve_plan(source, self.target.as_ref())?;
        self.enrich_plan_storage(&mut plan);
        let migration_id = format!("mig-{}", &Uuid::new_v4().to_string()[..8]);
        let mut report = MigrationReport::new(migration_id.clone(), true);
        report.from_storage = Some(plan.from.storage);
        report.to_storage = Some(plan.to.storage);

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

        let is_external = plan.external.is_some();
        let value_decoder = plan
            .external
            .as_ref()
            .map(|e| e.value_decoder)
            .unwrap_or(crate::migration::types::ValueDecoder::JsonValidate);

        let mut staged = Vec::new();
        let mut snapshot = Vec::new();
        let mut storage_keys = Vec::new();

        for (key, bytes) in &entries {
            let ctx = MigrationRecordContext {
                key: key.clone(),
                from_storage: plan.from.storage,
                to_storage: plan.to.storage,
                is_external,
                value_decoder,
            };
            let record_result = decoder.migrate_record(&ctx, bytes)?;
            let migrated = match record_result {
                MigrationRecordResult::Skip { reason } => {
                    report.source_skipped += 1;
                    report.skipped_entries.push(SkippedEntry {
                        key: key.clone(),
                        reason,
                    });
                    continue;
                }
                MigrationRecordResult::Migrated(migrated) => migrated,
            };
            let storage_key = storage_key_for_metadata(&migrated.metadata_bytes, key);

            let exists = target_db.get_raw(&plan.to.table, &storage_key)?.is_some();

            if exists && !in_place {
                match self.conflict_policy {
                    TargetConflictPolicy::Fail => {
                        report.conflicts.push(ConflictEntry {
                            table: plan.to.table.clone(),
                            key: storage_key.clone(),
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
                            .get_raw(&plan.to.table, &storage_key)?
                            .unwrap_or_default();
                        if !check_compatible_overwrite(
                            &existing,
                            &migrated.metadata_bytes,
                            &target_layout,
                        )? {
                            report.conflicts.push(ConflictEntry {
                                table: plan.to.table.clone(),
                                key: storage_key.clone(),
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

            snapshot.push((storage_key.clone(), migrated.metadata_bytes.clone()));
            storage_keys.push(storage_key.clone());

            let blob_sidecar_copy = plan.from.storage == TableStorageMode::BlobSidecar
                && plan.to.storage == TableStorageMode::BlobSidecar;
            if blob_sidecar_copy {
                report.blobs_copied += 1;
            } else if plan.to.storage == TableStorageMode::BlobSidecar {
                if migrated.blob.is_some() {
                    report.blobs_written += 1;
                }
            }

            staged.push(StagedRecord {
                source_key: key.clone(),
                storage_key,
                metadata_bytes: migrated.metadata_bytes,
                blob: migrated.blob,
                blob_sidecar_copy,
            });
        }

        if !report.conflicts.is_empty()
            && matches!(self.conflict_policy, TargetConflictPolicy::Fail)
        {
            report.would_delete_old_db = plan.effective_delete_source;
            return Ok(PreparedMigration {
                migration_id,
                plan,
                report,
                staged,
                snapshot,
                storage_keys,
                source_entries: entries,
                from_version,
                to_version,
                from_layout_hash,
                to_layout_hash,
            });
        }

        if staged.is_empty() && report.would_skip == report.source_count {
            report
                .errors
                .push("no records to migrate after conflict resolution".into());
        }

        report.would_delete_old_db = plan.effective_delete_source;
        Ok(PreparedMigration {
            migration_id,
            plan,
            report,
            staged,
            snapshot,
            storage_keys,
            source_entries: entries,
            from_version,
            to_version,
            from_layout_hash,
            to_layout_hash,
        })
    }

    fn commit_prepared(&self, mut prepared: PreparedMigration) -> Result<MigrationReport> {
        if prepared.staged.is_empty() {
            prepared.report.dry_run = false;
            return Ok(prepared.report);
        }

        let plan = &prepared.plan;
        let target_db = self.storage.db_manager(&plan.to.db).clone();
        let source_db = if plan.from.db != "external" {
            Some(self.storage.db_manager(&plan.from.db).clone())
        } else {
            None
        };

        let mut batch = MigrationBatch::new();
        let mut pending_blobs: Vec<(String, Vec<u8>)> = Vec::new();
        let mut pending_copies: Vec<(String, String)> = Vec::new();

        for record in &prepared.staged {
            batch.stage_write(
                &plan.to.table,
                &record.storage_key,
                record.metadata_bytes.clone(),
            );
            if record.blob_sidecar_copy {
                pending_copies.push((record.source_key.clone(), record.storage_key.clone()));
            } else if let Some(blob) = &record.blob {
                pending_blobs.push((record.storage_key.clone(), blob.clone()));
            }

            if batch.write_count() >= self.blob_policy.batch_size {
                Self::flush_batch(
                    &mut batch,
                    &target_db,
                    source_db.as_ref(),
                    plan,
                    &mut pending_blobs,
                    &mut pending_copies,
                )?;
            }
        }

        if batch.write_count() > 0 {
            Self::flush_batch(
                &mut batch,
                &target_db,
                source_db.as_ref(),
                plan,
                &mut pending_blobs,
                &mut pending_copies,
            )?;
        }

        let max_version = self.max_backup_version(
            &target_db,
            &plan.to.table,
            &prepared.storage_keys,
        )?;

        let table_rename = if plan.from.table != plan.to.table && plan.from.db == plan.to.db {
            Some(TableRenameInfo {
                from_table: plan.from.table.clone(),
                to_table: plan.to.table.clone(),
                backup_rewrite: true,
            })
        } else {
            None
        };

        let migration_id = prepared.migration_id.clone();
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
                schema_version: prepared.from_version,
            },
            to: SchemaRef {
                db: plan.to.db.clone(),
                table: plan.to.table.clone(),
                schema_id: plan.to.table.clone(),
                schema_version: prepared.to_version,
            },
            version_scope: VersionScope {
                backup_versions_from: 1,
                backup_versions_to: max_version,
                scope_table: plan.from.table.clone(),
                primary_snapshot_ref: Some(format!("primary_before_{migration_id}")),
            },
            from_layout_hash: prepared.from_layout_hash.clone(),
            to_layout_hash: prepared.to_layout_hash.clone(),
            target_conflict_policy: self.conflict_policy,
            table_rename,
            field_diff: None,
        };

        let new_layout = prepared
            .snapshot
            .first()
            .and_then(|(_, bytes)| FieldLayout::capture_from_sample_json(bytes).ok())
            .or_else(|| FieldLayout::capture_from_sample_json(&[]).ok());

        target_db.append_migration(
            &plan.to.table,
            manifest,
            Some(&prepared.snapshot),
            new_layout.as_ref(),
        )?;

        if plan.effective_delete_source {
            if let Some(source_db) = source_db {
                for (key, _) in &prepared.source_entries {
                    if self.blob_policy.delete_source_blobs
                        && plan.from.storage == TableStorageMode::BlobSidecar
                    {
                        let _ = source_db.delete_blob(&plan.from.table, key);
                    }
                    source_db.delete_raw(&plan.from.table, key)?;
                }
                if plan.from.table != plan.to.table && plan.from.db == plan.to.db {
                    target_db.rewrite_backup_table(&plan.from.table, &plan.to.table)?;
                }
            }
        }

        prepared.report.dry_run = false;
        prepared.report.would_delete_old_db = plan.effective_delete_source;
        Ok(prepared.report)
    }

    fn resolve_from_version(&self, plan: &MigrationPlan) -> Result<u32> {
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

    fn flush_batch(
        batch: &mut MigrationBatch,
        target_db: &DatabaseManager,
        source_db: Option<&DatabaseManager>,
        plan: &MigrationPlan,
        pending_blobs: &mut Vec<(String, Vec<u8>)>,
        pending_copies: &mut Vec<(String, String)>,
    ) -> Result<()> {
        if batch.write_count() == 0 {
            return Ok(());
        }
        batch.commit(target_db)?;
        batch.clear();
        for (key, blob) in pending_blobs.drain(..) {
            target_db.write_blob(&plan.to.table, &key, &blob)?;
        }
        if let Some(src_db) = source_db {
            for (src_key, dest_key) in pending_copies.drain(..) {
                src_db.copy_blob(
                    &plan.from.table,
                    &src_key,
                    target_db,
                    &plan.to.table,
                    &dest_key,
                )?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::Entity;
    use crate::migration::migrate_to::{migrate_value, MigrateOutcome, MigrateTo};
    use crate::storage::{DatabaseConfig, Storage, StorageConfig};
    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    use std::path::PathBuf;

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    struct LegacyWalletRow {
        profit: f64,
    }

    impl Entity for LegacyWalletRow {
        fn entity_id(&self) -> &str {
            "legacy"
        }
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    struct WalletRow {
        id: String,
        product_id: String,
        profit: f64,
    }

    impl Entity for WalletRow {
        fn entity_id(&self) -> &str {
            &self.id
        }
    }

    impl MigrateTo<WalletRow> for LegacyWalletRow {
        fn migrate_json(value: Value) -> Result<MigrateOutcome<Value>> {
            let row: LegacyWalletRow = serde_json::from_value(value)?;
            migrate_value(WalletRow {
                id: "30657".into(),
                product_id: "13152".into(),
                profit: row.profit,
            })
        }
    }

    /// Regression: migration must write under entity `id`, not the legacy source key.
    #[test]
    fn migration_uses_entity_id_as_storage_key() {
        let dir = PathBuf::from("./target/test_migration_storage_key");
        let _ = std::fs::remove_dir_all(&dir);

        let storage = Storage::builder(StorageConfig::default())
            .migration_step::<LegacyWalletRow, WalletRow>()
            .add_database(
                DatabaseConfig::new("legacy", "legacy")
                    .dir_path(dir.join("legacy"))
                    .has_cache(false)
                    .register::<LegacyWalletRow>("products"),
            )
            .add_database(
                DatabaseConfig::new("wallets", "wallets")
                    .dir_path(dir.join("wallets"))
                    .has_cache(false)
                    .register::<WalletRow>("wallets"),
            )
            .build()
            .unwrap();

        let legacy_db = storage.db_manager("legacy");
        let legacy_bytes =
            serde_json::to_vec(&LegacyWalletRow { profit: 945.0 }).unwrap();
        legacy_db
            .commit_batch(
                &[(
                    "products".to_string(),
                    "13152".to_string(),
                    legacy_bytes,
                )],
                &[],
            )
            .unwrap();

        let mut run = storage
            .migrate::<LegacyWalletRow, WalletRow>()
            .from_db("legacy", "products")
            .to(MigrationTo::new("wallets").table("wallets"))
            .on_target_conflict(TargetConflictPolicy::Skip);

        run.dry_run().unwrap();
        run.execute().unwrap();

        let wallets_db = storage.db_manager("wallets");
        assert!(
            wallets_db.get_raw("wallets", "30657").unwrap().is_some(),
            "row must be stored under wallet.id"
        );
        assert!(
            wallets_db.get_raw("wallets", "13152").unwrap().is_none(),
            "legacy product_id must not be used as redb key"
        );

        let entries = wallets_db.list_entries("wallets").unwrap();
        assert_eq!(entries.len(), 1);
        let meta: WalletRow = serde_json::from_slice(&entries[0].1).unwrap();
        assert_eq!(meta.id, "30657");
        assert_eq!(entries[0].0, "30657");

        storage
            .domain::<WalletRow>()
            .repo()
            .set(
                "30657",
                &WalletRow {
                    id: "30657".into(),
                    product_id: "13152".into(),
                    profit: 0.0,
                },
            )
            .unwrap();

        let entries = wallets_db.list_entries("wallets").unwrap();
        assert_eq!(entries.len(), 1, "update must replace in place, not duplicate");
    }

    #[test]
    fn dry_run_then_execute_reuses_same_migration_id() {
        let dir = PathBuf::from("./target/test_migration_dry_run_execute");
        let _ = std::fs::remove_dir_all(&dir);

        let storage = Storage::builder(StorageConfig::default())
            .migration_step::<LegacyWalletRow, WalletRow>()
            .add_database(
                DatabaseConfig::new("legacy", "legacy")
                    .dir_path(dir.join("legacy"))
                    .has_cache(false)
                    .register::<LegacyWalletRow>("products"),
            )
            .add_database(
                DatabaseConfig::new("wallets", "wallets")
                    .dir_path(dir.join("wallets"))
                    .has_cache(false)
                    .register::<WalletRow>("wallets"),
            )
            .build()
            .unwrap();

        let legacy_db = storage.db_manager("legacy");
        legacy_db
            .commit_batch(
                &[(
                    "products".to_string(),
                    "13152".to_string(),
                    serde_json::to_vec(&LegacyWalletRow { profit: 1.0 }).unwrap(),
                )],
                &[],
            )
            .unwrap();

        let mut run = storage
            .migrate::<LegacyWalletRow, WalletRow>()
            .from_db("legacy", "products")
            .to(MigrationTo::new("wallets").table("wallets"))
            .on_target_conflict(TargetConflictPolicy::Skip);

        let dry = run.dry_run().unwrap();
        assert!(dry.dry_run);
        assert_eq!(dry.would_insert, 1);

        let result = run.execute().unwrap();
        assert_eq!(result.migration_id, dry.migration_id);
        assert!(!result.report.dry_run);
        assert_eq!(result.records_migrated, 1);
    }
}
