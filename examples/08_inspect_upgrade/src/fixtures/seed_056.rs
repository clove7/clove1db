use clove1db::{
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::Result,
};

use crate::entities::{
    BuyerDto, BuyerResponse, BuyerV1, EmployeeDto, EmployeeResponse, EmployeeV1, ProductV1,
    ProductV1Dto, ProductV1Response, ProductV2,
};
use crate::entities::seed_counts;
use crate::paths;

pub fn create() -> Result<()> {
    let retail_parent = paths::era_056_retail_dir().parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&retail_parent)?;

    let storage = Storage::builder(StorageConfig::default())
        .migration_step::<ProductV1, ProductV2>()
        .add_database(
            DatabaseConfig::new("retail", "retail")
                .dir_path(retail_parent)
                .backup_enabled(true)
                .register::<ProductV1>("products")
                .register::<BuyerV1>("buyers")
                .register::<EmployeeV1>("employees"),
        )
        .build()?;

    let products = storage.domain::<ProductV1>();
    let buyers = storage.domain::<BuyerV1>();
    let employees = storage.domain::<EmployeeV1>();

    for i in 0..seed_counts::PRODUCTS {
        products.create::<ProductV1Dto, ProductV1Response>(ProductV1Dto {
            name: format!("Auth product {i}"),
        })?;
    }
    for i in 0..seed_counts::BUYERS {
        buyers.create::<BuyerDto, BuyerResponse>(BuyerDto {
            name: format!("Buyer {i}"),
            email: format!("buyer{i}@056.test"),
        })?;
    }
    for i in 0..seed_counts::EMPLOYEES {
        employees.create::<EmployeeDto, EmployeeResponse>(EmployeeDto {
            name: format!("Employee {i}"),
            role: "staff".into(),
        })?;
    }

    Ok(())
}
