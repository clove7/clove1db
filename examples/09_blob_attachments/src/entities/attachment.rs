use clove1db::{
    dto::{InputDto, OutputDto},
    entity::Entity,
    migration::MigrateTo,
    units::{ClError, Result},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttachmentMeta {
    pub id: String,
    pub filename: String,
    pub account_id: u64,
    pub size_bytes: usize,
    pub mime: String,
}

impl Entity for AttachmentMeta {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Deserialize)]
pub struct UploadAttachmentDto {
    pub filename: String,
    pub account_id: u64,
    pub mime: String,
}

impl InputDto<AttachmentMeta> for UploadAttachmentDto {
    fn into_entity(self) -> Result<AttachmentMeta> {
        Ok(AttachmentMeta {
            id: uuid::Uuid::new_v4().to_string(),
            filename: self.filename,
            account_id: self.account_id,
            size_bytes: 0,
            mime: self.mime,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct AttachmentMetaResponse {
    pub id: String,
    pub filename: String,
    pub account_id: u64,
    pub size_bytes: usize,
    pub mime: String,
}

impl OutputDto<AttachmentMeta> for AttachmentMetaResponse {
    fn from_entity(e: AttachmentMeta) -> Self {
        Self {
            id: e.id,
            filename: e.filename,
            account_id: e.account_id,
            size_bytes: e.size_bytes,
            mime: e.mime,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LegacyAttachmentInline {
    pub id: String,
    pub filename: String,
    pub account_id: u64,
    pub data: Vec<u8>,
    pub mime: String,
}

impl Entity for LegacyAttachmentInline {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

impl MigrateTo<AttachmentMeta> for LegacyAttachmentInline {
    fn migrate_json(value: Value) -> Result<Value> {
        let inline: LegacyAttachmentInline = serde_json::from_value(value)?;
        Ok(serde_json::to_value(AttachmentMeta {
            id: inline.id,
            filename: inline.filename,
            account_id: inline.account_id,
            size_bytes: inline.data.len(),
            mime: inline.mime,
        })?)
    }

    fn migrate_blob(value: Value) -> Result<(Vec<u8>, Option<Value>)> {
        let inline: LegacyAttachmentInline = serde_json::from_value(value)?;
        let payload = inline.data;
        let meta = AttachmentMeta {
            id: inline.id,
            filename: inline.filename,
            account_id: inline.account_id,
            size_bytes: payload.len(),
            mime: inline.mime,
        };
        Ok((payload, Some(serde_json::to_value(meta)?)))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExternalAttachmentRow;

impl MigrateTo<AttachmentMeta> for ExternalAttachmentRow {
    fn migrate_blob(value: Value) -> Result<(Vec<u8>, Option<Value>)> {
        let raw = value_from_external(&value)?;
        let (account_id, payload) = extract_fb_payload(&raw)?;
        let mime = infer_mime(&payload);
        let meta = json!({
            "id": uuid::Uuid::new_v4().to_string(),
            "filename": format!("import-{}.{}", account_id, ext_for_mime(&mime)),
            "account_id": account_id,
            "size_bytes": payload.len(),
            "mime": mime,
        });
        Ok((payload, Some(meta)))
    }
}

fn value_from_external(value: &Value) -> Result<Vec<u8>> {
    match value {
        Value::Array(arr) => arr
            .iter()
            .map(|v| {
                v.as_u64()
                    .map(|n| n as u8)
                    .ok_or_else(|| ClError::MigrationError("invalid byte array".into()))
            })
            .collect(),
        Value::String(s) => Ok(s.as_bytes().to_vec()),
        _ => Err(ClError::MigrationError(
            "external row must be byte array Value".into(),
        )),
    }
}

fn extract_fb_payload(raw: &[u8]) -> Result<(u64, Vec<u8>)> {
    if raw.len() < 8 || raw[0] != 0xfb {
        return Err(ClError::MigrationError("expected 0xFB header".into()));
    }
    let account = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]) as u64;
    let offset = find_payload_offset(raw).unwrap_or(8);
    Ok((account, raw[offset..].to_vec()))
}

fn find_payload_offset(raw: &[u8]) -> Option<usize> {
    const SIGS: &[&[u8]] = &[
        b"RIFF", b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF8", b"%PDF", b"PK\x03\x04",
    ];
    for sig in SIGS {
        if let Some(pos) = raw.windows(sig.len()).position(|w| w == *sig) {
            return Some(pos);
        }
    }
    None
}

fn infer_mime(payload: &[u8]) -> String {
    if payload.starts_with(b"\x89PNG") {
        "image/png".into()
    } else if payload.starts_with(b"\xff\xd8\xff") {
        "image/jpeg".into()
    } else if payload.starts_with(b"GIF8") {
        "image/gif".into()
    } else if payload.starts_with(b"%PDF") {
        "application/pdf".into()
    } else {
        "application/octet-stream".into()
    }
}

fn ext_for_mime(mime: &str) -> &str {
    match mime {
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/gif" => "gif",
        "application/pdf" => "pdf",
        _ => "bin",
    }
}
