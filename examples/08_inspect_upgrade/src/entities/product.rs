use clove1db::{
    dto::{InputDto, OutputDto},
    entity::Entity,
    migration::{migrate_value, MigrateOutcome, MigrateTo},
    units::Result,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ProductV1 {
    pub id: String,
    pub name: String,
}

impl Entity for ProductV1 {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ProductV2 {
    pub id: String,
    pub name: String,
    pub sku: String,
    pub price_cents: u64,
}

impl Entity for ProductV2 {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Deserialize)]
pub struct ProductV1Dto {
    pub name: String,
}

impl InputDto<ProductV1> for ProductV1Dto {
    fn into_entity(self) -> Result<ProductV1> {
        Ok(ProductV1 {
            id: uuid::Uuid::new_v4().to_string(),
            name: self.name,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct ProductV1Response {
    pub id: String,
    pub name: String,
}

impl OutputDto<ProductV1> for ProductV1Response {
    fn from_entity(e: ProductV1) -> Self {
        Self {
            id: e.id,
            name: e.name,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ProductV2Response {
    pub id: String,
    pub name: String,
    pub sku: String,
    pub price_cents: u64,
}

impl OutputDto<ProductV2> for ProductV2Response {
    fn from_entity(e: ProductV2) -> Self {
        Self {
            id: e.id,
            name: e.name,
            sku: e.sku,
            price_cents: e.price_cents,
        }
    }
}

impl MigrateTo<ProductV2> for ProductV1 {
    fn migrate_json(value: Value) -> Result<MigrateOutcome<Value>> {
        let v1: ProductV1 = serde_json::from_value(value)?;
        let sku = format!("SKU-{}", &v1.id[..8.min(v1.id.len())]);
        migrate_value(ProductV2 {
            id: v1.id,
            name: v1.name,
            sku,
            price_cents: 1000,
        })
    }
}
