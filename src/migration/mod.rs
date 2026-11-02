pub mod batch;
pub mod chain;
pub mod clove;
pub mod decoder;
#[allow(dead_code)] // used by the migration entry points as they are added
#[cfg(feature = "encryption")]
pub(crate) mod encrypted;
pub mod guard;
pub mod layout;
pub mod migrate_to;
pub mod plan;
pub mod redb_external;
pub mod report;
pub mod runner;
pub mod scan;
pub mod step_registry;
pub mod stream_external;
pub mod types;

pub use batch::MigrationBatch;
#[cfg(feature = "encryption")]
pub use encrypted::{
    run::{ChangeDone, ChangeProtection, ChangeReport, TableReport},
    fields::api::{ChangeFields, FieldChangeDone, FieldChangeReport, FieldReport, TableChange},
    space::Available,
};
pub use chain::{DbMigrationIndex, MigrationChain, TableMigrationChain};
pub use decoder::{
    row_bytes_to_value, MigratedRecord, MigrationRecordContext, MigrationRecordResult,
    SchemaDecoder,
};
pub use layout::{FieldLayout, LayoutDiff, LayoutDiffKind};
pub use migrate_to::{
    auto_migrate_json, migrate_value, register_step, skip_record, skip_record_silent, MigrateOutcome,
    MigrateTo, MigrationSourceType, MigrationTargetType,
};
pub use plan::{MigrationPlan, MigrationSource, ResolvedEndpoint, resolve_plan};
pub use report::{ConflictEntry, MigrationReport, MigrationResult, SkippedEntry};
pub use redb_external::{list_external_tables, read_external_table, scan_external_table};
pub use runner::MigrationRun;
pub use scan::{scan_record, MigrationScanReport};
pub use step_registry::{MigrationStepKey, MigrationStepRegistry};
pub use types::{
    DbMigrationRootIndex, ExternalFrom, FieldDiffEntry, KeyDecoder,
    MigrationFrom, MigrationKind, MigrationManifest, MigrationTo, RedbTableSpec, SchemaRef,
    TableChainIndex, TableStorageMode, TargetConflictPolicy, ValueDecoder,
};
