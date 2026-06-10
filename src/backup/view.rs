use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::backup::BackupOperation;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HistoryDisplayMode {
    #[default]
    AsStored,
    Normalized,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RecordData {
    Typed(Value),
    Json(Value),
    None,
}

impl RecordData {
    pub fn as_json(&self) -> Option<&Value> {
        match self {
            RecordData::Typed(v) | RecordData::Json(v) => Some(v),
            RecordData::None => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BackupRecordView {
    pub version: u64,
    pub timestamp: i64,
    pub date: String,
    pub operation: BackupOperation,
    pub table: String,
    pub key: String,
    pub data: RecordData,
    pub schema_at_version: String,
    pub migration_id: Option<String>,
    pub readable: bool,
    pub restorable: bool,
    pub decode_path: Vec<String>,
    pub bulk_id: Option<String>,
    pub restored_version: Option<u64>,
}
