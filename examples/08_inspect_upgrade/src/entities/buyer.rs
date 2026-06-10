use clove1db::{
    dto::{InputDto, OutputDto},
    entity::Entity,
    units::Result,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct BuyerV1 {
    pub id: String,
    pub name: String,
    pub email: String,
}

impl Entity for BuyerV1 {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Deserialize)]
pub struct BuyerDto {
    pub name: String,
    pub email: String,
}

impl InputDto<BuyerV1> for BuyerDto {
    fn into_entity(self) -> Result<BuyerV1> {
        Ok(BuyerV1 {
            id: uuid::Uuid::new_v4().to_string(),
            name: self.name,
            email: self.email,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct BuyerResponse {
    pub id: String,
    pub name: String,
    pub email: String,
}

impl OutputDto<BuyerV1> for BuyerResponse {
    fn from_entity(e: BuyerV1) -> Self {
        Self {
            id: e.id,
            name: e.name,
            email: e.email,
        }
    }
}
