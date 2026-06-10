use std::path::PathBuf;

use clove1db::{
    migration::{default_registry, SchemaDecoderRegistry},
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::Result,
};

use crate::entities::{
    AttachmentV1, BuyerV1, EmployeeV1, ProductV1, ProductV2, RetailV1ToV2Decoder,
};

fn decoders() -> SchemaDecoderRegistry {
    let mut r = default_registry();
    r.register("RetailV1_to_V2", RetailV1ToV2Decoder);
    r
}

pub fn retail_v1_storage(dir: PathBuf, db_logical: &str, db_file: &str) -> Result<Storage> {
    Storage::builder(StorageConfig::default())
        .decoder_registry(decoders())
        .add_database(
            DatabaseConfig::new(db_logical, db_file)
                .dir_path(dir)
                .backup_enabled(true)
                .register::<ProductV1>("products")
                .register::<BuyerV1>("buyers")
                .register::<EmployeeV1>("employees"),
        )
        .build()
}

pub fn retail_v2_storage(dir: PathBuf, db_logical: &str, db_file: &str) -> Result<Storage> {
    Storage::builder(StorageConfig::default())
        .decoder_registry(decoders())
        .add_database(
            DatabaseConfig::new(db_logical, db_file)
                .dir_path(dir)
                .backup_enabled(true)
                .register::<ProductV2>("products")
                .register::<BuyerV1>("buyers")
                .register::<EmployeeV1>("employees"),
        )
        .build()
}

pub fn attachments_storage(dir: PathBuf) -> Result<Storage> {
    Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("attachments", "attachments")
                .dir_path(dir)
                .backup_enabled(false)
                .has_cache(false)
                .register::<AttachmentV1>("files"),
        )
        .build()
}

pub fn cache_off_storage(dir: PathBuf) -> Result<Storage> {
    Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("retail", "retail")
                .dir_path(dir)
                .backup_enabled(true)
                .has_cache(false)
                .register::<ProductV1>("products")
                .register::<BuyerV1>("buyers")
                .register::<EmployeeV1>("employees"),
        )
        .build()
}
