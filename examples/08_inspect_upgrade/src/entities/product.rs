use clove1db::{
    dto::{InputDto, OutputDto},
    entity::Entity,
    migration::SchemaDecoder,
    units::Result,
};
use serde::{Deserialize, Serialize};

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

pub struct RetailV1ToV2Decoder;

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
