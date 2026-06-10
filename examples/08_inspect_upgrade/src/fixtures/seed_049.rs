use clove1db_v049::{
    dto::{InputDto, OutputDto},
    entity::Entity,
    migration::{default_registry, KeyConflictPolicy, MigrationKind, SchemaDecoder, SchemaDecoderRegistry},
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::Result,
};
use serde::{Deserialize, Serialize};

use crate::entities::seed_counts;
use crate::fixtures::RetailManifest;
use crate::paths;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProductV1 {
    id: String,
    name: String,
}

impl Entity for ProductV1 {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProductV2 {
    id: String,
    name: String,
    sku: String,
    price_cents: u64,
}

impl Entity for ProductV2 {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Buyer {
    id: String,
    name: String,
    email: String,
}

impl Entity for Buyer {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Employee {
    id: String,
    name: String,
    role: String,
}

impl Entity for Employee {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Deserialize)]
struct NameDto {
    name: String,
}

impl InputDto<ProductV1> for NameDto {
    fn into_entity(self) -> Result<ProductV1> {
        Ok(ProductV1 {
            id: uuid::Uuid::new_v4().to_string(),
            name: self.name,
        })
    }
}

#[derive(Debug, Serialize)]
struct ProductOut {
    id: String,
    name: String,
}

impl OutputDto<ProductV1> for ProductOut {
    fn from_entity(e: ProductV1) -> Self {
        Self {
            id: e.id,
            name: e.name,
        }
    }
}

#[derive(Debug, Deserialize)]
struct BuyerDto {
    name: String,
    email: String,
}

impl InputDto<Buyer> for BuyerDto {
    fn into_entity(self) -> Result<Buyer> {
        Ok(Buyer {
            id: uuid::Uuid::new_v4().to_string(),
            name: self.name,
            email: self.email,
        })
    }
}

#[derive(Debug, Serialize)]
struct BuyerOut {
    id: String,
    name: String,
    email: String,
}

impl OutputDto<Buyer> for BuyerOut {
    fn from_entity(e: Buyer) -> Self {
        Self {
            id: e.id,
            name: e.name,
            email: e.email,
        }
    }
}

#[derive(Debug, Deserialize)]
struct EmployeeDto {
    name: String,
    role: String,
}

impl InputDto<Employee> for EmployeeDto {
    fn into_entity(self) -> Result<Employee> {
        Ok(Employee {
            id: uuid::Uuid::new_v4().to_string(),
            name: self.name,
            role: self.role,
        })
    }
}

#[derive(Debug, Serialize)]
struct EmployeeOut {
    id: String,
    name: String,
    role: String,
}

impl OutputDto<Employee> for EmployeeOut {
    fn from_entity(e: Employee) -> Self {
        Self {
            id: e.id,
            name: e.name,
            role: e.role,
        }
    }
}

struct RetailV1ToV2Decoder;

impl SchemaDecoder for RetailV1ToV2Decoder {
    fn decode_to_json(&self, bytes: &[u8]) -> Result<serde_json::Value> {
        Ok(serde_json::from_slice(bytes)?)
    }

    fn migrate_bytes(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        let v1: ProductV1 = serde_json::from_slice(bytes)?;
        let sku = format!("SKU-{}", &v1.id[..8.min(v1.id.len())]);
        let v2 = ProductV2 {
            id: v1.id,
            name: v1.name,
            sku,
            price_cents: 1000,
        };
        Ok(serde_json::to_vec(&v2)?)
    }
}

fn decoders() -> SchemaDecoderRegistry {
    let mut r = default_registry();
    r.register("RetailV1_to_V2", RetailV1ToV2Decoder);
    r
}

pub fn create() -> Result<RetailManifest> {
    let retail_parent = paths::era_049_retail_dir().parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&retail_parent)?;

    let storage = Storage::builder(StorageConfig::default())
        .decoder_registry(decoders())
        .add_database(
            DatabaseConfig::new("retail", "retail")
                .dir_path(retail_parent.clone())
                .schema_name("RetailV1")
                .backup_enabled(true)
                .register::<ProductV1>("products")
                .register::<Buyer>("buyers")
                .register::<Employee>("employees"),
        )
        .build()?;

    let products = storage.domain::<ProductV1>();
    let buyers = storage.domain::<Buyer>();
    let employees = storage.domain::<Employee>();

    let names = [
        "Retail49-A",
        "Retail49-B",
        "Retail49-C",
        "Retail49-D",
        "Retail49-E",
    ];
    let mut product_rows = Vec::new();
    for name in names {
        let p = products.create::<NameDto, ProductOut>(NameDto {
            name: name.into(),
        })?;
        product_rows.push((p.id.clone(), p.name));
    }

    let history_id = product_rows[1].0.clone();
    products.update::<NameDto, ProductOut>(
        &history_id,
        NameDto {
            name: "Retail49-B v2".into(),
        },
    )?;
    products.update::<NameDto, ProductOut>(
        &history_id,
        NameDto {
            name: "Retail49-B v3".into(),
        },
    )?;
    if let Some(row) = product_rows.get_mut(1) {
        row.1 = "Retail49-B v3".into();
    }

    let buyer_inputs = [
        ("Dana", "dana@049.test"),
        ("Eli", "eli@049.test"),
        ("Fay", "fay@049.test"),
    ];
    let mut buyer_rows = Vec::new();
    for (name, email) in buyer_inputs {
        let b = buyers.create::<BuyerDto, BuyerOut>(BuyerDto {
            name: name.into(),
            email: email.into(),
        })?;
        buyer_rows.push((b.id, b.name, b.email));
    }

    let employee_inputs = [("Gus", "lead"), ("Hal", "clerk")];
    let mut employee_rows = Vec::new();
    for (name, role) in employee_inputs {
        let e = employees.create::<EmployeeDto, EmployeeOut>(EmployeeDto {
            name: name.into(),
            role: role.into(),
        })?;
        employee_rows.push((e.id, e.name, e.role));
    }

    storage
        .migration_runner()
        .from_explicit("retail", "products")
        .to_explicit("retail", "products")
        .with_decoder("RetailV1_to_V2")
        .with_schema_names("RetailV1", "RetailV2")
        .kind(MigrationKind::SameDbRemapTable)
        .on_key_conflict(KeyConflictPolicy::Fail)
        .execute()?;

    drop(storage);

    assert_eq!(product_rows.len(), seed_counts::PRODUCTS);

    Ok(RetailManifest {
        products: product_rows,
        history_product_id: history_id,
        buyers: buyer_rows,
        employees: employee_rows,
    })
}
