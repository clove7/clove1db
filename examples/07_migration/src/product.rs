use serde::{Deserialize, Serialize};
use serde_json::Value;

use clove1db::{
    dto::{InputDto, OutputDto},
    entity::Entity,
    migration::SchemaDecoder,
    units::Result,
};

// ── Product schema generations ───────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProductV1 {
    pub id: String,
    pub name: String,
}

impl Entity for ProductV1 {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProductV3 {
    pub id: String,
    pub name: String,
    pub sku: String,
    pub price_cents: u64,
    pub category: String,
    pub stock: u32,
}

impl Entity for ProductV3 {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

// ── DTOs ─────────────────────────────────────────────────────────────────────

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

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct ProductV2Dto {
    pub name: String,
    pub sku: String,
    pub price_cents: u64,
}

impl InputDto<ProductV2> for ProductV2Dto {
    fn into_entity(self) -> Result<ProductV2> {
        Ok(ProductV2 {
            id: uuid::Uuid::new_v4().to_string(),
            name: self.name,
            sku: self.sku,
            price_cents: self.price_cents,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct ProductV3Dto {
    pub name: String,
    pub sku: String,
    pub price_cents: u64,
    pub category: String,
    pub stock: u32,
}

impl InputDto<ProductV3> for ProductV3Dto {
    fn into_entity(self) -> Result<ProductV3> {
        Ok(ProductV3 {
            id: uuid::Uuid::new_v4().to_string(),
            name: self.name,
            sku: self.sku,
            price_cents: self.price_cents,
            category: self.category,
            stock: self.stock,
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

#[derive(Debug, Serialize)]
pub struct ProductV3Response {
    pub id: String,
    pub name: String,
    pub sku: String,
    pub price_cents: u64,
    pub category: String,
    pub stock: u32,
}

impl OutputDto<ProductV3> for ProductV3Response {
    fn from_entity(e: ProductV3) -> Self {
        Self {
            id: e.id,
            name: e.name,
            sku: e.sku,
            price_cents: e.price_cents,
            category: e.category,
            stock: e.stock,
        }
    }
}

// ── Decoders ─────────────────────────────────────────────────────────────────

fn slug(name: &str) -> String {
    name.to_lowercase()
        .replace([' ', '-'], "_")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

pub struct ProductV1ToV2Decoder;

impl SchemaDecoder for ProductV1ToV2Decoder {
    fn decode_to_json(&self, bytes: &[u8]) -> Result<Value> {
        Ok(serde_json::from_slice(bytes)?)
    }

    fn migrate_bytes(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        let v1: ProductV1 = serde_json::from_slice(bytes)?;
        let v2 = ProductV2 {
            id: v1.id,
            name: v1.name.clone(),
            sku: format!("SKU-{}", slug(&v1.name)),
            price_cents: 9_900,
        };
        Ok(serde_json::to_vec(&v2)?)
    }
}

/// Maps external vendor_catalog JSON → ProductV2 entity bytes for clove1db.
pub struct ExternalCatalogToProductV2Decoder;

#[derive(Debug, Deserialize)]
struct ExternalCatalogRow {
    id: String,
    title: String,
    price_usd: f64,
    vendor_code: String,
}

impl SchemaDecoder for ExternalCatalogToProductV2Decoder {
    fn decode_to_json(&self, bytes: &[u8]) -> Result<Value> {
        Ok(serde_json::from_slice(bytes)?)
    }

    fn migrate_bytes(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        let row: ExternalCatalogRow = serde_json::from_slice(bytes)?;
        let price_cents = (row.price_usd * 100.0).round() as u64;
        let v2 = ProductV2 {
            id: row.id,
            name: row.title,
            sku: row.vendor_code,
            price_cents,
        };
        Ok(serde_json::to_vec(&v2)?)
    }
}

pub struct ProductV2ToV3Decoder;

impl SchemaDecoder for ProductV2ToV3Decoder {
    fn decode_to_json(&self, bytes: &[u8]) -> Result<Value> {
        Ok(serde_json::from_slice(bytes)?)
    }

    fn migrate_bytes(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        let v2: ProductV2 = serde_json::from_slice(bytes)?;
        let category = if v2.name.to_lowercase().contains("mouse") {
            "peripherals"
        } else if v2.name.to_lowercase().contains("laptop") {
            "computers"
        } else {
            "accessories"
        };
        let v3 = ProductV3 {
            id: v2.id,
            name: v2.name,
            sku: v2.sku,
            price_cents: v2.price_cents,
            category: category.into(),
            stock: 50,
        };
        Ok(serde_json::to_vec(&v3)?)
    }
}

pub fn format_price(cents: u64) -> String {
    format!("${}.{:02}", cents / 100, cents % 100)
}
