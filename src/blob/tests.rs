#[cfg(test)]
mod blob_tests {
    use std::io::Read;
    use std::path::PathBuf;

    use serde::{Deserialize, Serialize};

    use crate::blob::BlobStore;
    use crate::entity::Entity;
    use crate::metadata::types::TableStorageMode;
    use crate::migration::decoder::{row_bytes_to_value, MigrationRecordContext, MigrationRecordResult};
    use crate::migration::migrate_to::MigrateTo;
    use crate::migration::step_registry::MigrationStepRegistry;
    use crate::migration::types::ValueDecoder;
    use crate::storage::{DatabaseConfig, Storage, StorageConfig};
    use serde_json::Value;

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    struct DocMeta {
        id: String,
        title: String,
        size_bytes: usize,
    }

    impl Entity for DocMeta {
        fn entity_id(&self) -> &str {
            &self.id
        }
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    struct DocInline {
        id: String,
        title: String,
        data: Vec<u8>,
    }

    impl Entity for DocInline {
        fn entity_id(&self) -> &str {
            &self.id
        }
    }

    impl MigrateTo<DocMeta> for DocInline {
        fn migrate_json(value: Value) -> crate::units::Result<crate::migration::MigrateOutcome<Value>> {
            let row: DocInline = serde_json::from_value(value)?;
            Ok(crate::migration::MigrateOutcome::Migrate(serde_json::to_value(DocMeta {
                id: row.id,
                title: row.title,
                size_bytes: row.data.len(),
            })?))
        }

        fn migrate_blob(value: Value) -> crate::units::Result<crate::migration::MigrateOutcome<(Vec<u8>, Option<Value>)>> {
            let mut v = value;
            let data = v["data"].take();
            let payload: Vec<u8> = serde_json::from_value(data)?;
            if let Some(obj) = v.as_object_mut() {
                obj.remove("data");
            }
            Ok(crate::migration::MigrateOutcome::Migrate((payload, Some(v))))
        }
    }

    #[test]
    fn blob_store_write_read_delete() {
        let dir = PathBuf::from("./target/test_blob_store");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let store = BlobStore::new(&dir, "docs");
        store.write_atomic("files", "a1", b"hello blob").unwrap();
        assert!(store.path("files", "a1").exists());

        let mut f = store.open_read("files", "a1").unwrap();
        let mut buf = String::new();
        f.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "hello blob");

        assert!(store.delete("files", "a1").unwrap());
        assert!(!store.path("files", "a1").exists());
    }

    #[test]
    fn blob_table_crud_via_storage() {
        let dir = PathBuf::from("./target/test_blob_crud");
        let _ = std::fs::remove_dir_all(&dir);

        let storage = Storage::builder(StorageConfig::default().change_dir_path(dir.clone()))
            .add_database(
                DatabaseConfig::new("d", "docs")
                    .dir_path(dir.clone())
                    .backup_enabled(false)
                    .has_cache(false)
                    .blob_enabled(true)
                    .register_blob::<DocMeta>("files"),
            )
            .build()
            .unwrap();

        let domain = storage.domain::<DocMeta>();
        let meta = DocMeta {
            id: "x1".into(),
            title: "test".into(),
            size_bytes: 5,
        };
        domain.set_with_blob("x1", &meta, b"12345").unwrap();

        let mut f = domain.open_blob("x1").unwrap();
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"12345");

        domain.delete("x1").unwrap();
        assert!(domain.open_blob("x1").is_err());
    }

    #[test]
    fn migrate_blob_splits_inline_data() {
        let reg = MigrationStepRegistry::new();
        reg.register::<DocInline, DocMeta>().unwrap();
        let (from, to) = MigrationStepRegistry::layout_pair::<DocInline, DocMeta>().unwrap();
        let decoder = reg.get_by_layout(&from, &to).unwrap();

        let inline = serde_json::json!({
            "id": "1",
            "title": "doc",
            "data": [10u8, 20, 30]
        });
        let ctx = MigrationRecordContext {
            key: "1".into(),
            from_storage: TableStorageMode::InlineJson,
            to_storage: TableStorageMode::BlobSidecar,
            is_external: false,
            value_decoder: ValueDecoder::JsonValidate,
        };
        let out = decoder
            .migrate_record(&ctx, &serde_json::to_vec(&inline).unwrap())
            .unwrap();
        let migrated = match out {
            MigrationRecordResult::Migrated(m) => m,
            MigrationRecordResult::Skip { .. } => panic!("unexpected skip"),
        };
        assert_eq!(migrated.blob, Some(vec![10, 20, 30]));
        let meta: serde_json::Value = serde_json::from_slice(&migrated.metadata_bytes).unwrap();
        assert!(meta.get("data").is_none());
    }

    #[test]
    fn row_bytes_to_value_bytes_as_array() {
        let raw = b"abc";
        let value =
            row_bytes_to_value(raw, true, ValueDecoder::BytesAsArray).unwrap();
        assert_eq!(value, serde_json::json!([97, 98, 99]));
    }
}
