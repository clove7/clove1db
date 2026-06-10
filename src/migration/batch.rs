use std::collections::HashMap;

use crate::repository::DatabaseManager;
use crate::units::Result;

#[derive(Debug, Default)]
pub struct MigrationBatch {
    writes: HashMap<String, Vec<(String, Vec<u8>)>>,
    deletes: Vec<(String, String)>,
}

impl MigrationBatch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stage_write(&mut self, table: impl Into<String>, key: impl Into<String>, value: Vec<u8>) {
        self.writes
            .entry(table.into())
            .or_default()
            .push((key.into(), value));
    }

    pub fn stage_delete(&mut self, table: impl Into<String>, key: impl Into<String>) {
        self.deletes.push((table.into(), key.into()));
    }

    pub fn write_count(&self) -> usize {
        self.writes.values().map(|v| v.len()).sum()
    }

    pub fn commit(&self, db: &DatabaseManager) -> Result<()> {
        let mut flat_writes = Vec::new();
        for (table, entries) in &self.writes {
            for (key, value) in entries {
                flat_writes.push((table.clone(), key.clone(), value.clone()));
            }
        }
        db.commit_batch(&flat_writes, &self.deletes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::decoder::SchemaDecoderRegistry;
    use crate::storage::{DatabaseConfig, Storage, StorageConfig};
    use serde::{Deserialize, Serialize};
    use crate::entity::Entity;
    use std::path::PathBuf;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct Item {
        id: String,
        v: u32,
    }
    impl Entity for Item {
        fn entity_id(&self) -> &str {
            &self.id
        }
    }

    #[test]
    fn commit_batch_writes_all() {
        let dir = PathBuf::from("./target/test_migration_batch");
        let _ = std::fs::remove_dir_all(&dir);
        let storage = Storage::builder(StorageConfig::default())
            .decoder_registry(SchemaDecoderRegistry::new())
            .add_database(
                DatabaseConfig::new("t", "items")
                    .dir_path(dir.clone())
                    .schema_name("Item")
                    .register::<Item>("items"),
            )
            .build()
            .unwrap();

        let db = storage.db_manager("items").clone();
        let batch = MigrationBatch::new();
        let b1 = serde_json::to_vec(&Item { id: "a".into(), v: 1 }).unwrap();
        let b2 = serde_json::to_vec(&Item { id: "b".into(), v: 2 }).unwrap();
        let mut batch = batch;
        batch.stage_write("items", "a", b1);
        batch.stage_write("items", "b", b2);
        batch.commit(&db).unwrap();

        assert!(db.get_raw("items", "a").unwrap().is_some());
        assert!(db.get_raw("items", "b").unwrap().is_some());
    }
}
