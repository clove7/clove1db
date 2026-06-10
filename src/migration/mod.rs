pub mod batch;
pub mod chain;
pub mod clove;
pub mod decoder;
pub mod field_map;
pub mod guard;
pub mod layout;
pub mod plan;
pub mod redb_external;
pub mod report;
pub mod runner;
pub mod types;

pub use batch::MigrationBatch;
pub use chain::{DbMigrationIndex, MigrationChain, TableMigrationChain};
pub use decoder::{AutoAdditiveDecoder, JsonPassthroughDecoder, SchemaDecoder, SchemaDecoderRegistry};
pub use field_map::{FieldMap, FieldTransform};
pub use layout::{FieldLayout, LayoutDiff, LayoutDiffKind};
pub use plan::{MigrationPlan, MigrationSource, resolve_plan};
pub use report::{ConflictEntry, MigrationReport, MigrationResult};
pub use redb_external::{list_external_tables, read_external_table};
pub use runner::{MigrationRunner, default_registry};
pub use types::{
    DbMigrationRootIndex, ExternalFrom, FieldDiffEntry, KeyDecoder, MigrationFrom, MigrationKind,
    MigrationManifest, MigrationTo, RedbTableSpec, SchemaRef, TableChainIndex,
    TargetConflictPolicy, ValueDecoder,
};
