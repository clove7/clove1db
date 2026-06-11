pub mod batch;
pub mod chain;
pub mod clove;
pub mod decoder;
pub mod guard;
pub mod layout;
pub mod migrate_to;
pub mod plan;
pub mod redb_external;
pub mod report;
pub mod runner;
pub mod step_registry;
pub mod types;

pub use batch::MigrationBatch;
pub use chain::{DbMigrationIndex, MigrationChain, TableMigrationChain};
pub use layout::{FieldLayout, LayoutDiff, LayoutDiffKind};
pub use migrate_to::{auto_migrate_json, register_step, MigrateTo, MigrationSourceType, MigrationTargetType};
pub use plan::{MigrationPlan, MigrationSource, resolve_plan};
pub use report::{ConflictEntry, MigrationReport, MigrationResult};
pub use redb_external::{list_external_tables, read_external_table};
pub use runner::MigrationRun;
pub use step_registry::{MigrationStepKey, MigrationStepRegistry};
pub use types::{
    DbMigrationRootIndex, ExternalFrom, FieldDiffEntry, KeyDecoder, MigrationFrom, MigrationKind,
    MigrationManifest, MigrationTo, RedbTableSpec, SchemaRef, TableChainIndex,
    TargetConflictPolicy, ValueDecoder,
};
