use std::path::PathBuf;

use clove1db::{
    migration::{SchemaDecoderRegistry, default_registry},
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::Result,
};

use crate::product::{
    ExternalCatalogToProductV2Decoder, ProductV1, ProductV2, ProductV3, ProductV1ToV2Decoder,
    ProductV2ToV3Decoder,
};

pub const BASE_DIR: &str = "./examples_data/07_migration";

pub fn decoders() -> SchemaDecoderRegistry {
    let mut r = default_registry();
    r.register("ProductV1_to_V2", ProductV1ToV2Decoder);
    r.register("ProductV2_to_V3", ProductV2ToV3Decoder);
    r.register("ExternalCatalog_to_ProductV2", ExternalCatalogToProductV2Decoder);
    r
}

pub fn builder() -> clove1db::storage::StorageBuilder {
    Storage::builder(StorageConfig::default()).decoder_registry(decoders())
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
        .add_database(
            DatabaseConfig::new("import", "imported")
                .dir_path(base.join("external_import"))
                .backup_enabled(true)
                .register::<ProductV2>("products"),
        )
        .build()
}
