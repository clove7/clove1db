use clove1db::{
    dto::{InputDto, OutputDto},
    entity::Entity,
    units::Result,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct EmployeeV1 {
    pub id: String,
    pub name: String,
    pub role: String,
}

impl Entity for EmployeeV1 {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Deserialize)]
pub struct EmployeeDto {
    pub name: String,
    pub role: String,
}

impl InputDto<EmployeeV1> for EmployeeDto {
    fn into_entity(self) -> Result<EmployeeV1> {
        Ok(EmployeeV1 {
            id: uuid::Uuid::new_v4().to_string(),
            name: self.name,
            role: self.role,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct EmployeeResponse {
    pub id: String,
    pub name: String,
    pub role: String,
}

impl OutputDto<EmployeeV1> for EmployeeResponse {
    fn from_entity(e: EmployeeV1) -> Self {
        Self {
            id: e.id,
            name: e.name,
            role: e.role,
        }
    }
}
