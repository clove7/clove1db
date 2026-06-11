use std::path::PathBuf;

use clove1db::{
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::Result,
};

use crate::entities::{AttachmentV1, BuyerV1, EmployeeV1, ProductV1, ProductV2};

pub fn retail_v1_storage(dir: PathBuf, db_logical: &str, db_file: &str) -> Result<Storage> {
    Storage::builder(StorageConfig::default())
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
        .migration_step::<ProductV1, ProductV2>()
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
