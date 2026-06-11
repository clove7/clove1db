use std::path::PathBuf;

use clove1db::{
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::Result,
};

use crate::external::ExternalCatalogRow;
use crate::product::{ProductV1, ProductV2, ProductV3};

pub const BASE_DIR: &str = "./examples_data/07_migration";

pub fn builder() -> clove1db::storage::StorageBuilder {
    Storage::builder(StorageConfig::default())
}

pub fn legacy_catalog_storage(base: &PathBuf) -> Result<Storage> {
    builder()
        .add_database(
            DatabaseConfig::new("catalog", "legacy")
                .dir_path(base.clone())
                .backup_enabled(true)
                .register::<ProductV1>("products"),
        )
        .build()
}

pub fn catalog_v2_storage(base: &PathBuf) -> Result<Storage> {
    builder()
        .migration_step::<ProductV1, ProductV2>()
        .add_database(
            DatabaseConfig::new("catalog", "legacy")
                .dir_path(base.clone())
                .backup_enabled(true)
                .register::<ProductV2>("products"),
        )
        .build()
}

pub fn catalog_v3_storage(base: &PathBuf) -> Result<Storage> {
    builder()
        .migration_step::<ProductV1, ProductV2>()
        .migration_step::<ProductV2, ProductV3>()
        .add_database(
            DatabaseConfig::new("catalog", "legacy")
                .dir_path(base.clone())
                .backup_enabled(true)
                .register::<ProductV3>("products"),
        )
        .build()
}

pub fn dual_db_storage(base: &PathBuf) -> Result<Storage> {
    builder()
        .migration_step::<ProductV1, ProductV2>()
        .add_database(
            DatabaseConfig::new("warehouse", "legacy_wh")
                .dir_path(base.clone())
                .backup_enabled(true)
                .register::<ProductV1>("warehouse_products"),
        )
        .add_database(
            DatabaseConfig::new("shop_floor", "shop")
                .dir_path(base.clone())
                .backup_enabled(true)
                .register::<ProductV2>("floor_products"),
        )
        .build()
}

pub fn import_target_storage(base: &PathBuf) -> Result<Storage> {
    builder()
        .migration_step::<ExternalCatalogRow, ProductV2>()
        .add_database(
            DatabaseConfig::new("import", "imported")
                .dir_path(base.join("external_import"))
                .backup_enabled(true)
                .register::<ProductV2>("products"),
        )
        .build()
}
