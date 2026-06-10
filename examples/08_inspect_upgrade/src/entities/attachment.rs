use clove1db::{
    dto::{InputDto, OutputDto},
    entity::Entity,
    units::Result,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AttachmentV1 {
    pub id: String,
    pub filename: String,
    pub data: Vec<u8>,
}

impl Entity for AttachmentV1 {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Deserialize)]
pub struct UploadAttachmentDto {
    pub filename: String,
    pub data: Vec<u8>,
}

impl InputDto<AttachmentV1> for UploadAttachmentDto {
    fn into_entity(self) -> Result<AttachmentV1> {
        Ok(AttachmentV1 {
            id: uuid::Uuid::new_v4().to_string(),
            filename: self.filename,
            data: self.data,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct AttachmentMetaResponse {
    pub id: String,
    pub filename: String,
    pub size_bytes: usize,
}

impl OutputDto<AttachmentV1> for AttachmentMetaResponse {
    fn from_entity(e: AttachmentV1) -> Self {
        Self {
            id: e.id,
            filename: e.filename,
            size_bytes: e.data.len(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AttachmentFullResponse {
    pub id: String,
    pub filename: String,
    pub data: Vec<u8>,
}

impl OutputDto<AttachmentV1> for AttachmentFullResponse {
    fn from_entity(e: AttachmentV1) -> Self {
        Self {
            id: e.id,
            filename: e.filename,
            data: e.data,
        }
    }
}
