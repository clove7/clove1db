use std::collections::HashMap;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

use crate::metadata::types::TableStorageMode;
use crate::migration::types::ValueDecoder;
use crate::units::{ClError, Result};

#[derive(Debug, Clone)]
pub struct MigratedRecord {
    pub metadata_bytes: Vec<u8>,
    pub blob: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub enum MigrationRecordResult {
    Migrated(MigratedRecord),
    Skip { reason: Option<String> },
}

#[derive(Debug, Clone)]
pub struct MigrationRecordContext {
    pub key: String,
    pub from_storage: TableStorageMode,
    pub to_storage: TableStorageMode,
    pub is_external: bool,
    pub value_decoder: ValueDecoder,
}

pub trait SchemaDecoder: Send + Sync {
    fn decode_to_json(&self, bytes: &[u8]) -> Result<Value>;
    fn migrate_bytes(&self, bytes: &[u8]) -> Result<Vec<u8>>;

    fn migrate_record(
        &self,
        _ctx: &MigrationRecordContext,
        bytes: &[u8],
    ) -> Result<MigrationRecordResult> {
        let metadata_bytes = self.migrate_bytes(bytes)?;
        Ok(MigrationRecordResult::Migrated(MigratedRecord {
            metadata_bytes,
            blob: None,
        }))
    }
}

pub fn row_bytes_to_value(
    bytes: &[u8],
    is_external: bool,
    decoder: ValueDecoder,
) -> Result<Value> {
    if !is_external {
        return Ok(serde_json::from_slice(bytes)?);
    }
    match decoder {
        ValueDecoder::RawPassthrough | ValueDecoder::BytesAsArray => {
            let arr: Vec<Value> = bytes
                .iter()
                .map(|b| Value::Number((*b as u64).into()))
                .collect();
            Ok(Value::Array(arr))
        }
        ValueDecoder::Utf8String | ValueDecoder::Base64String => {
            let s = std::str::from_utf8(bytes).map_err(|e| ClError::Utf8Error(e.to_string()))?;
            Ok(Value::String(s.to_string()))
        }
        ValueDecoder::JsonValidate | ValueDecoder::JsonString | ValueDecoder::JsonValue => {
            Ok(serde_json::from_slice(bytes)?)
        }
    }
}

pub(crate) fn ensure_meta_id(mut meta: Value, key: &str) -> Value {
    if let Value::Object(obj) = &mut meta {
        if !obj.contains_key("id") {
            obj.insert("id".to_string(), Value::String(key.to_string()));
        }
    }
    meta
}

pub struct JsonPassthroughDecoder;

impl SchemaDecoder for JsonPassthroughDecoder {
    fn decode_to_json(&self, bytes: &[u8]) -> Result<Value> {
        Ok(serde_json::from_slice(bytes)?)
    }

    fn migrate_bytes(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        Ok(bytes.to_vec())
    }
}

pub struct AutoAdditiveDecoder {
    target_template: Value,
}

impl AutoAdditiveDecoder {
    pub fn new<T: Serialize>(template: &T) -> Result<Self> {
        Ok(Self {
            target_template: serde_json::to_value(template)?,
        })
    }

    pub fn from_json(template: Value) -> Self {
        Self {
            target_template: template,
        }
    }
}

impl SchemaDecoder for AutoAdditiveDecoder {
    fn decode_to_json(&self, bytes: &[u8]) -> Result<Value> {
        let mut base: Value = serde_json::from_slice(bytes)?;
        merge_defaults(&mut base, &self.target_template);
        Ok(base)
    }

    fn migrate_bytes(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&self.decode_to_json(bytes)?)?)
    }
}

pub(crate) fn merge_defaults(target: &mut Value, template: &Value) {
    let (Value::Object(tgt), Value::Object(tpl)) = (target, template) else {
        return;
    };
    for (k, v) in tpl {
        tgt.entry(k.clone()).or_insert_with(|| v.clone());
    }
}

pub struct TypedDecoder<T: DeserializeOwned + Serialize + Send + Sync + 'static> {
    _marker: std::marker::PhantomData<T>,
}

impl<T: DeserializeOwned + Serialize + Send + Sync + 'static> TypedDecoder<T> {
    pub fn new() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }
}

impl<T: DeserializeOwned + Serialize + Send + Sync + 'static> SchemaDecoder for TypedDecoder<T> {
    fn decode_to_json(&self, bytes: &[u8]) -> Result<Value> {
        let v: T = serde_json::from_slice(bytes)?;
        Ok(serde_json::to_value(&v)?)
    }

    fn migrate_bytes(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        Ok(bytes.to_vec())
    }
}

#[derive(Clone, Default)]
pub struct SchemaDecoderRegistry {
    decoders: HashMap<String, Arc<dyn SchemaDecoder>>,
}

impl std::fmt::Debug for SchemaDecoderRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SchemaDecoderRegistry")
            .field("decoders", &self.decoders.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl SchemaDecoderRegistry {
    pub fn new() -> Self {
        Self {
            decoders: HashMap::new(),
        }
    }

    pub fn register<D: SchemaDecoder + 'static>(&mut self, name: impl Into<String>, decoder: D) {
        self.decoders.insert(name.into(), Arc::new(decoder));
    }

    pub fn get(&self, name: &str) -> Result<Arc<dyn SchemaDecoder>> {
        self.decoders
            .get(name)
            .cloned()
            .ok_or_else(|| ClError::DecoderNotFound {
                from_layout_hash: name.to_string(),
                to_layout_hash: String::new(),
                migration_id: String::new(),
            })
    }

    pub fn decode_to_json(&self, name: &str, bytes: &[u8]) -> Result<Value> {
        self.get(name)?.decode_to_json(bytes)
    }

    pub fn migrate_bytes(&self, name: &str, bytes: &[u8]) -> Result<Vec<u8>> {
        self.get(name)?.migrate_bytes(bytes)
    }
}
