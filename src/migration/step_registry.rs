use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex, OnceLock};

use serde_json::Value;

use crate::metadata::types::TableStorageMode;
use crate::migration::decoder::{
    ensure_meta_id, row_bytes_to_value, MigratedRecord, MigrationRecordContext, SchemaDecoder,
};
use crate::migration::layout::FieldLayout;
use crate::migration::migrate_to::{MigrateTo, MigrationSourceType, MigrationTargetType};
use crate::units::{ClError, Result};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MigrationStepKey {
    pub from_layout_hash: String,
    pub to_layout_hash: String,
}

pub struct MigrationStepRegistry {
    steps: Mutex<HashMap<MigrationStepKey, Arc<dyn SchemaDecoder>>>,
}

impl std::fmt::Debug for MigrationStepRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let guard = self.steps.lock().ok();
        let keys: Vec<_> = guard
            .as_ref()
            .map(|g| g.keys().cloned().collect())
            .unwrap_or_default();
        f.debug_struct("MigrationStepRegistry")
            .field("steps", &keys)
            .finish()
    }
}

impl MigrationStepRegistry {
    pub fn new() -> Self {
        Self {
            steps: Mutex::new(HashMap::new()),
        }
    }

    pub fn global() -> Arc<Self> {
        static REG: OnceLock<Arc<MigrationStepRegistry>> = OnceLock::new();
        Arc::clone(REG.get_or_init(|| Arc::new(MigrationStepRegistry::new())))
    }

    pub fn layout_pair<F, T>() -> Result<(String, String)>
    where
        F: MigrationSourceType,
        T: MigrationTargetType,
    {
        let from = FieldLayout::capture_from_entity_json(&F::default())?.layout_hash;
        let to = FieldLayout::capture_from_entity_json(&T::default())?.layout_hash;
        Ok((from, to))
    }

    pub fn register<F, T>(&self) -> Result<MigrationStepKey>
    where
        F: MigrationSourceType,
        T: MigrationTargetType,
        F: MigrateTo<T>,
    {
        let (from_hash, to_hash) = Self::layout_pair::<F, T>()?;
        let key = MigrationStepKey {
            from_layout_hash: from_hash.clone(),
            to_layout_hash: to_hash.clone(),
        };
        let mut guard = self.steps.lock().map_err(|e| {
            ClError::MigrationError(format!("migration registry lock poisoned: {e}"))
        })?;
        guard
            .entry(key.clone())
            .or_insert_with(|| Arc::new(TypedMigrationStep::<F, T>::new()));
        Ok(key)
    }

    pub fn get_by_layout(&self, from_hash: &str, to_hash: &str) -> Result<Arc<dyn SchemaDecoder>> {
        let key = MigrationStepKey {
            from_layout_hash: from_hash.to_string(),
            to_layout_hash: to_hash.to_string(),
        };
        let guard = self.steps.lock().map_err(|e| {
            ClError::MigrationError(format!("migration registry lock poisoned: {e}"))
        })?;
        guard.get(&key).cloned().ok_or_else(|| ClError::DecoderNotFound {
            from_layout_hash: from_hash.to_string(),
            to_layout_hash: to_hash.to_string(),
            migration_id: String::new(),
        })
    }
}

impl Default for MigrationStepRegistry {
    fn default() -> Self {
        Self::new()
    }
}

struct TypedMigrationStep<F, T> {
    _marker: PhantomData<(F, T)>,
}

impl<F, T> TypedMigrationStep<F, T> {
    fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<F, T> SchemaDecoder for TypedMigrationStep<F, T>
where
    F: MigrationSourceType,
    T: MigrationTargetType,
    F: MigrateTo<T>,
{
    fn decode_to_json(&self, bytes: &[u8]) -> Result<Value> {
        Ok(serde_json::from_slice(bytes)?)
    }

    fn migrate_bytes(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        let value: Value = serde_json::from_slice(bytes)?;
        let migrated = F::migrate_json(value)?;
        Ok(serde_json::to_vec(&migrated)?)
    }

    fn migrate_record(
        &self,
        ctx: &MigrationRecordContext,
        bytes: &[u8],
    ) -> Result<MigratedRecord> {
        use TableStorageMode::*;

        let use_json_path = ctx.from_storage == BlobSidecar && !ctx.is_external;

        if use_json_path {
            let value: Value = serde_json::from_slice(bytes)?;
            let migrated = F::migrate_json(value)?;
            let meta = ensure_meta_id(migrated, &ctx.key);
            return Ok(MigratedRecord {
                metadata_bytes: serde_json::to_vec(&meta)?,
                blob: None,
            });
        }

        let value = row_bytes_to_value(bytes, ctx.is_external, ctx.value_decoder)?;
        let (payload, meta_opt) = F::migrate_blob(value)?;
        let meta = meta_opt.ok_or_else(|| {
            ClError::MigrationError("migrate_blob returned None metadata".into())
        })?;
        let meta = ensure_meta_id(meta, &ctx.key);
        let blob = if payload.is_empty() {
            None
        } else {
            Some(payload)
        };
        Ok(MigratedRecord {
            metadata_bytes: serde_json::to_vec(&meta)?,
            blob,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::Entity;
    use crate::migration::migrate_to::auto_migrate_json;
    use crate::migration::types::ValueDecoder;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    struct V1 {
        id: String,
        name: String,
    }

    impl Entity for V1 {
        fn entity_id(&self) -> &str {
            &self.id
        }
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    struct V2 {
        id: String,
        name: String,
        sku: String,
    }

    impl Entity for V2 {
        fn entity_id(&self) -> &str {
            &self.id
        }
    }

    impl MigrateTo<V2> for V1 {
        fn migrate_json(value: Value) -> Result<Value> {
            auto_migrate_json::<V1, V2>(value)
        }
    }

    #[test]
    fn register_and_migrate_by_layout_hash() {
        let reg = MigrationStepRegistry::new();
        let key = reg.register::<V1, V2>().unwrap();
        let decoder = reg
            .get_by_layout(&key.from_layout_hash, &key.to_layout_hash)
            .unwrap();
        let input = serde_json::json!({"id":"1","name":"test"});
        let out = decoder.migrate_bytes(&serde_json::to_vec(&input).unwrap()).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["sku"], "");
    }

    #[test]
    fn migrate_record_inline_path() {
        let reg = MigrationStepRegistry::new();
        let key = reg.register::<V1, V2>().unwrap();
        let decoder = reg
            .get_by_layout(&key.from_layout_hash, &key.to_layout_hash)
            .unwrap();
        let ctx = MigrationRecordContext {
            key: "1".into(),
            from_storage: TableStorageMode::InlineJson,
            to_storage: TableStorageMode::InlineJson,
            is_external: false,
            value_decoder: ValueDecoder::JsonValidate,
        };
        let input = serde_json::json!({"id":"1","name":"test"});
        let rec = decoder
            .migrate_record(&ctx, &serde_json::to_vec(&input).unwrap())
            .unwrap();
        assert!(rec.blob.is_none());
        let v: serde_json::Value = serde_json::from_slice(&rec.metadata_bytes).unwrap();
        assert_eq!(v["sku"], "");
    }
}
