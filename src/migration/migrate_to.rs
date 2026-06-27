use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

use crate::entity::Entity;
use crate::migration::decoder::merge_defaults;
use crate::units::{ClError, Result};

/// Per-record result from [`MigrateTo::migrate_json`] / [`MigrateTo::migrate_blob`].
///
/// - [`Migrate`](Self::Migrate) — write the transformed row.
/// - [`Skip`](Self::Skip) — omit this source row and continue (not a fatal error).
///
/// `Err` from the migration methods remains a hard failure that stops the run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrateOutcome<T> {
    Migrate(T),
    Skip(Option<String>),
}

/// Transform source rows into a target schema shape.
///
/// Implement **one** of:
/// - [`migrate_json`](Self::migrate_json) — metadata / inline JSON transforms
/// - [`migrate_blob`](Self::migrate_blob) — raw or inline rows with binary payload
///
/// The other method has a default: `migrate_blob` delegates to `migrate_json` with an
/// empty payload; `migrate_json` returns an error if not overridden.
pub trait MigrateTo<T> {
    fn migrate_json(value: Value) -> Result<MigrateOutcome<Value>> {
        let _ = value;
        Err(ClError::MigrationError(
            "migrate_json not implemented; use migrate_blob for raw/binary sources".into(),
        ))
    }

    fn migrate_blob(value: Value) -> Result<MigrateOutcome<(Vec<u8>, Option<Value>)>> {
        match Self::migrate_json(value)? {
            MigrateOutcome::Migrate(meta) => Ok(MigrateOutcome::Migrate((Vec::new(), Some(meta)))),
            MigrateOutcome::Skip(reason) => Ok(MigrateOutcome::Skip(reason)),
        }
    }
}

/// Source type for `migrate::<F, T>()` — external rows or in-db legacy shapes.
pub trait MigrationSourceType: DeserializeOwned + Serialize + Default + Send + Sync + 'static {}

impl<T> MigrationSourceType for T where T: DeserializeOwned + Serialize + Default + Send + Sync + 'static {}

/// Target entity type for `migrate::<F, T>()`.
pub trait MigrationTargetType: Entity + Serialize + Default + Send + Sync + 'static {}

impl<T> MigrationTargetType for T where T: Entity + Serialize + Default + Send + Sync + 'static {}

/// Wrap a successfully transformed JSON value.
pub fn migrate_value<T: Serialize>(value: T) -> Result<MigrateOutcome<Value>> {
    Ok(MigrateOutcome::Migrate(serde_json::to_value(value)?))
}

/// Skip the current source row with an optional reason recorded in the migration report.
pub fn skip_record(reason: impl Into<String>) -> Result<MigrateOutcome<Value>> {
    Ok(MigrateOutcome::Skip(Some(reason.into())))
}

/// Skip the current source row without recording a reason.
pub fn skip_record_silent() -> Result<MigrateOutcome<Value>> {
    Ok(MigrateOutcome::Skip(None))
}

/// Register a migration step in the global registry (idempotent).
pub fn register_step<F, T>() -> Result<()>
where
    F: MigrationSourceType,
    T: MigrationTargetType,
    F: MigrateTo<T>,
{
    crate::migration::step_registry::MigrationStepRegistry::global()
        .register::<F, T>()
        .map(|_| ())
}

/// Merge missing fields from `T::default()` into deserialized `F` JSON (additive-only migrations).
pub fn auto_migrate_json<F, T>(value: Value) -> Result<MigrateOutcome<Value>>
where
    F: DeserializeOwned,
    T: Serialize + Default + DeserializeOwned,
{
    let _from: F = serde_json::from_value(value.clone())?;
    let mut out = value;
    let template = serde_json::to_value(T::default())?;
    merge_defaults(&mut out, &template);
    Ok(MigrateOutcome::Migrate(out))
}
