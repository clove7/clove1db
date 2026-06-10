use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::units::Result;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldSpec {
    pub name: String,
    pub json_type: String,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldLayout {
    pub fields: Vec<FieldSpec>,
    pub layout_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutDiffKind {
    Identical,
    AutoSafe,
    RequiresDecoder,
    Breaking,
}

#[derive(Debug, Clone)]
pub struct LayoutDiff {
    pub kind: LayoutDiffKind,
    pub added_fields: Vec<String>,
    pub removed_fields: Vec<String>,
    pub type_changes: Vec<(String, String, String)>,
}

impl FieldLayout {
    pub fn from_json_value(value: &Value) -> Self {
        let mut fields = Vec::new();
        if let Some(obj) = value.as_object() {
            for (name, v) in obj {
                fields.push(FieldSpec {
                    name: name.clone(),
                    json_type: json_type_name(v),
                    required: true,
                });
            }
        }
        fields.sort_by(|a, b| a.name.cmp(&b.name));
        let layout_hash = compute_hash(&fields);
        Self { fields, layout_hash }
    }

    pub fn capture_from_sample_json(bytes: &[u8]) -> Result<Self> {
        let value: Value = serde_json::from_slice(bytes)?;
        Ok(Self::from_json_value(&value))
    }

    pub fn capture_from_entity_json<T: serde::Serialize>(entity: &T) -> Result<Self> {
        let value = serde_json::to_value(entity)?;
        Ok(Self::from_json_value(&value))
    }

    pub fn diff(&self, other: &Self) -> LayoutDiff {
        let self_map: BTreeMap<_, _> = self.fields.iter().map(|f| (&f.name, f)).collect();
        let other_map: BTreeMap<_, _> = other.fields.iter().map(|f| (&f.name, f)).collect();

        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut type_changes = Vec::new();

        for (name, f) in &other_map {
            if let Some(old) = self_map.get(name) {
                if old.json_type != f.json_type {
                    type_changes.push((
                        (*name).clone(),
                        old.json_type.clone(),
                        f.json_type.clone(),
                    ));
                }
            } else {
                added.push((*name).clone());
            }
        }
        for name in self_map.keys() {
            if !other_map.contains_key(name) {
                removed.push((*name).clone());
            }
        }

        let kind = if self.layout_hash == other.layout_hash {
            LayoutDiffKind::Identical
        } else if !removed.is_empty() || !type_changes.is_empty() {
            LayoutDiffKind::Breaking
        } else if !added.is_empty() {
            LayoutDiffKind::AutoSafe
        } else {
            LayoutDiffKind::RequiresDecoder
        };

        LayoutDiff {
            kind,
            added_fields: added,
            removed_fields: removed,
            type_changes,
        }
    }
}

fn json_type_name(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(_) => "bool".into(),
        Value::Number(n) => {
            if n.is_u64() || n.is_i64() {
                "integer".into()
            } else {
                "number".into()
            }
        }
        Value::String(_) => "string".into(),
        Value::Array(_) => "array".into(),
        Value::Object(_) => "object".into(),
    }
}

fn compute_hash(fields: &[FieldSpec]) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for f in fields {
        f.name.hash(&mut hasher);
        f.json_type.hash(&mut hasher);
        f.required.hash(&mut hasher);
    }
    format!("{:016x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_safe_on_added_fields() {
        let v1 = FieldLayout::from_json_value(&serde_json::json!({"id": "a", "name": "x"}));
        let v2 = FieldLayout::from_json_value(
            &serde_json::json!({"id": "a", "name": "x", "sku": "s"}),
        );
        assert_eq!(v1.diff(&v2).kind, LayoutDiffKind::AutoSafe);
    }

    #[test]
    fn breaking_on_removed_field() {
        let v1 = FieldLayout::from_json_value(&serde_json::json!({"id": "a", "name": "x"}));
        let v2 = FieldLayout::from_json_value(&serde_json::json!({"id": "a"}));
        assert_eq!(v1.diff(&v2).kind, LayoutDiffKind::Breaking);
    }
}
