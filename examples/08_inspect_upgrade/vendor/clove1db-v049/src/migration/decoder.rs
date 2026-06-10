use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;

use crate::units::{ClError, Result};

pub trait SchemaDecoder: Send + Sync {
    fn decode_to_json(&self, bytes: &[u8]) -> Result<Value>;
    fn migrate_bytes(&self, bytes: &[u8]) -> Result<Vec<u8>>;
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
                schema: name.to_string(),
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
