pub mod backup_normalize;
pub mod legacy_migration;
pub mod legacy_record;
pub mod migration_refs;
pub mod pipeline;

#[cfg(test)]
mod pipeline_tests;

pub use backup_normalize::{eager_normalize, BackupNormalizeResult};
pub use legacy_migration::upgrade_legacy_migration_index;
pub use legacy_record::{canonical_bytes, from_raw_entity, parse_backup_value};
pub use migration_refs::upgrade_migration_refs;
pub use pipeline::{OpenUpgradePipeline, TableRegistration, UpgradeInput, UpgradeOutput};
