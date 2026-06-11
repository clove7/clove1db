use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

use crate::entity::Entity;
use crate::migration::decoder::merge_defaults;
use crate::units::Result;

/// Transform JSON from a source schema shape into a target schema shape.
pub trait MigrateTo<T> {
    fn migrate_json(value: Value) -> Result<Value>;
}

/// Source type for `migrate::<F, T>()` — external rows or in-db legacy shapes.
pub trait MigrationSourceType: DeserializeOwned + Serialize + Default + Send + Sync + 'static {}

impl<T> MigrationSourceType for T where T: DeserializeOwned + Serialize + Default + Send + Sync + 'static {}

/// Target entity type for `migrate::<F, T>()`.
pub trait MigrationTargetType: Entity + Serialize + Default + Send + Sync + 'static {}

impl<T> MigrationTargetType for T where T: Entity + Serialize + Default + Send + Sync + 'static {}

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
pub fn auto_migrate_json<F, T>(value: Value) -> Result<Value>
where
    F: DeserializeOwned,
    T: Serialize + Default + DeserializeOwned,
{
    let _from: F = serde_json::from_value(value.clone())?;
    let mut out = value;
    let template = serde_json::to_value(T::default())?;
    merge_defaults(&mut out, &template);
    Ok(out)
}
