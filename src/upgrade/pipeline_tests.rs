#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::entity::Entity;
    use crate::metadata::inspect::{FileKind, inspect_database};
    use crate::metadata::store::read_meta;
    use crate::metadata::types::TableStorageMode;
    use crate::migration::layout::FieldLayout;
    use crate::storage::{DatabaseConfig, Storage, StorageConfig};
    use crate::upgrade::{OpenUpgradePipeline, TableRegistration, UpgradeInput};
    use redb::Database;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    struct User {
        id: String,
        name: String,
    }

    impl Entity for User {
        fn entity_id(&self) -> &str {
            &self.id
        }
    }

    #[test]
    fn build_requires_register() {
        let dir = PathBuf::from("./target/test_register_required");
        let _ = std::fs::remove_dir_all(&dir);
        let result = Storage::builder(StorageConfig::default())
            .add_database(DatabaseConfig::new("t", "users").dir_path(dir))
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn pipeline_writes_meta_on_new_db() {
        let dir = PathBuf::from("./target/test_pipeline_new");
        let _ = std::fs::remove_dir_all(&dir);
        let layout = FieldLayout::capture_from_entity_json(&User::default()).unwrap();
        let tables = vec![TableRegistration {
            name: "users".to_string(),
            layout,
            storage: TableStorageMode::InlineJson,
        }];
        let out = OpenUpgradePipeline::run(&UpgradeInput {
            dir_path: &dir,
            backup_dir_path: None,
            dir_name: "t",
            db_name: "users",
            tables: &tables,
            backup_enabled: false,
            blob_enabled: false,
            has_cache: true,
            durability: crate::durability::DurabilityMode::Strict,
        })
        .unwrap();

        assert!(out.meta.upgrade_complete);
        assert_eq!(out.meta.tables[0].schema_id, "users");
        assert_eq!(out.meta.tables[0].schema_version, 1);

        let primary = dir.join("t").join("users.cldb");
        let db = Database::open(&primary).unwrap();
        let meta = read_meta(&db).unwrap().unwrap();
        assert_eq!(meta.framework, "clove1db");
        assert!(meta.upgrade_complete);
    }

    #[test]
    fn inspect_new_database() {
        let dir = PathBuf::from("./target/test_inspect_new");
        let primary = dir.join("t").join("users.cldb");
        let migration = dir.join("t").join("users.migration");
        let report = inspect_database(&primary, None, &migration).unwrap();
        assert_eq!(report.kind, FileKind::New);
    }

    #[test]
    fn reopen_empty_authenticated_db_without_entity_rows() {
        let dir = PathBuf::from("./target/test_reopen_empty_auth");
        let _ = std::fs::remove_dir_all(&dir);

        let storage = Storage::builder(StorageConfig::default().change_dir_path(dir.clone()))
            .add_database(
                DatabaseConfig::new("bots", "bots")
                    .dir_path(dir.clone())
                    .backup_enabled(true)
                    .register::<User>("bots"),
            )
            .build()
            .unwrap();
        drop(storage);

        let primary = dir.join("bots").join("bots.cldb");
        let migration = dir.join("bots").join("bots.migration");
        let report = inspect_database(&primary, None, &migration).unwrap();
        assert_eq!(
            report.kind,
            FileKind::Authenticated,
            "empty entity tables must still inspect as Authenticated when _clove_meta exists"
        );

        Storage::builder(StorageConfig::default().change_dir_path(dir.clone()))
            .add_database(
                DatabaseConfig::new("bots", "bots")
                    .dir_path(dir.clone())
                    .backup_enabled(true)
                    .register::<User>("bots"),
            )
            .build()
            .expect("second build must succeed for empty authenticated db");
    }
}
