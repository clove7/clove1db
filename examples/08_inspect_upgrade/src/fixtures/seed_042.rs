use clove1db_v042::{
    dto::{InputDto, OutputDto},
    entity::Entity,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::Result,
};
use serde::{Deserialize, Serialize};

use crate::entities::seed_counts;
use crate::fixtures::RetailManifest;
use crate::paths;

static ATTACHMENT_ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();

pub fn attachment_id() -> String {
    ATTACHMENT_ID.get().expect("seed_042 not run").clone()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Product {
    id: String,
    name: String,
}

impl Entity for Product {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Attachment {
    id: String,
    filename: String,
    data: Vec<u8>,
}

impl Entity for Attachment {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Deserialize)]
struct NameDto {
    name: String,
}

impl InputDto<Product> for NameDto {
    fn into_entity(self) -> Result<Product> {
        Ok(Product {
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

impl OutputDto<Product> for ProductOut {
    fn from_entity(e: Product) -> Self {
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

#[derive(Debug, Deserialize)]
struct UploadDto {
    filename: String,
    data: Vec<u8>,
}

impl InputDto<Attachment> for UploadDto {
    fn into_entity(self) -> Result<Attachment> {
        Ok(Attachment {
            id: uuid::Uuid::new_v4().to_string(),
            filename: self.filename,
            data: self.data,
        })
    }
}

#[derive(Debug, Serialize)]
struct AttachmentOut {
    id: String,
    filename: String,
}

impl OutputDto<Attachment> for AttachmentOut {
    fn from_entity(e: Attachment) -> Self {
        Self {
            id: e.id,
            filename: e.filename,
        }
    }
}

pub fn create() -> Result<RetailManifest> {
    let retail_dir = paths::era_042_retail_dir().parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&retail_dir)?;

    let storage = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("retail", "retail")
                .dir_path(retail_dir.clone())
                .backup_enabled(true)
                .register::<Product>("products")
                .register::<Buyer>("buyers")
                .register::<Employee>("employees"),
        )
        .build()?;

    let products = storage.domain::<Product>();
    let buyers = storage.domain::<Buyer>();
    let employees = storage.domain::<Employee>();

    let names = [
        "Widget A",
        "Widget B",
        "Gadget C",
        "Gadget D",
        "Tool E",
    ];
    let mut product_rows = Vec::new();
    for name in names {
        let p = products.create::<NameDto, ProductOut>(NameDto {
            name: name.into(),
        })?;
        product_rows.push((p.id.clone(), p.name));
    }

    let history_id = product_rows[0].0.clone();
    products.update::<NameDto, ProductOut>(
        &history_id,
        NameDto {
            name: "Widget A v2".into(),
        },
    )?;
    products.update::<NameDto, ProductOut>(
        &history_id,
        NameDto {
            name: "Widget A v3".into(),
        },
    )?;
    if let Some(row) = product_rows.first_mut() {
        row.1 = "Widget A v3".into();
    }

    let buyer_inputs = [
        ("Alice", "alice@shop.test"),
        ("Bob", "bob@shop.test"),
        ("Carol", "carol@shop.test"),
    ];
    let mut buyer_rows = Vec::new();
    for (name, email) in buyer_inputs {
        let b = buyers.create::<BuyerDto, BuyerOut>(BuyerDto {
            name: name.into(),
            email: email.into(),
        })?;
        buyer_rows.push((b.id, b.name, b.email));
    }

    let employee_inputs = [("Eve", "manager"), ("Dan", "cashier")];
    let mut employee_rows = Vec::new();
    for (name, role) in employee_inputs {
        let e = employees.create::<EmployeeDto, EmployeeOut>(EmployeeDto {
            name: name.into(),
            role: role.into(),
        })?;
        employee_rows.push((e.id, e.name, e.role));
    }

    drop(storage);

    let attach_parent = paths::era_042_attachments_dir()
        .parent()
        .unwrap()
        .to_path_buf();
    let attach_storage = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("attachments", "attachments")
                .dir_path(attach_parent)
                .backup_enabled(false)
                .has_cache(false)
                .register::<Attachment>("files"),
        )
        .build()?;

    let files = attach_storage.domain::<Attachment>();
    let blob = vec![0xABu8; seed_counts::ATTACHMENT_BYTES];
    let meta = files.create::<UploadDto, AttachmentOut>(UploadDto {
        filename: "large_blob.bin".into(),
        data: blob,
    })?;
    let _ = ATTACHMENT_ID.set(meta.id.clone());

    Ok(RetailManifest {
        products: product_rows,
        history_product_id: history_id,
        buyers: buyer_rows,
        employees: employee_rows,
    })
}
