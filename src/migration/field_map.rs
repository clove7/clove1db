use std::collections::HashMap;

use serde_json::{Map, Value};

use crate::migration::decoder::SchemaDecoder;
use crate::units::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldTransform {
    Identity,
    UsdToCents,
}

#[derive(Debug, Clone)]
pub struct FieldMap {
    renames: HashMap<String, String>,
    transforms: HashMap<String, FieldTransform>,
}

impl FieldMap {
    pub fn new() -> Self {
        Self {
            renames: HashMap::new(),
            transforms: HashMap::new(),
        }
    }

    pub fn rename(mut self, from: impl Into<String>, to: impl Into<String>) -> Self {
        self.renames.insert(from.into(), to.into());
        self
    }

    pub fn transform(
        mut self,
        from: impl Into<String>,
        to: impl Into<String>,
        rule: FieldTransform,
    ) -> Self {
        let from = from.into();
        let to = to.into();
        self.renames.insert(from.clone(), to.clone());
        self.transforms.insert(from, rule);
        self
    }

    pub fn build_decoder(&self) -> FieldMapDecoder {
        FieldMapDecoder {
            renames: self.renames.clone(),
            transforms: self.transforms.clone(),
        }
    }
}

impl Default for FieldMap {
    fn default() -> Self {
        Self::new()
    }
}

pub struct FieldMapDecoder {
    renames: HashMap<String, String>,
    transforms: HashMap<String, FieldTransform>,
}

impl SchemaDecoder for FieldMapDecoder {
    fn decode_to_json(&self, bytes: &[u8]) -> Result<Value> {
        let v: Value = serde_json::from_slice(bytes)?;
        Ok(self.apply_map(v))
    }

    fn migrate_bytes(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        let v: Value = serde_json::from_slice(bytes)?;
        Ok(serde_json::to_vec(&self.apply_map(v))?)
    }
}

impl FieldMapDecoder {
    fn apply_map(&self, value: Value) -> Value {
        let Some(obj) = value.as_object() else {
            return value;
        };
        let mut out = Map::new();
        for (k, v) in obj {
            let target_key = self.renames.get(k).cloned().unwrap_or_else(|| k.clone());
            let transformed = if let Some(rule) = self.transforms.get(k) {
                apply_transform(*rule, v)
            } else {
                v.clone()
            };
            out.insert(target_key, transformed);
        }
        Value::Object(out)
    }
}

fn apply_transform(rule: FieldTransform, v: &Value) -> Value {
    match rule {
        FieldTransform::Identity => v.clone(),
        FieldTransform::UsdToCents => {
            let cents = v
                .as_f64()
                .map(|f| (f * 100.0).round() as u64)
                .or_else(|| v.as_u64())
                .unwrap_or(0);
            Value::Number(cents.into())
        }
    }
}
