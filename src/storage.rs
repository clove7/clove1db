// storage.rs

use std::any::{Any, TypeId};

use std::collections::HashMap;

use std::env;

use std::marker::PhantomData;

use std::path::PathBuf;

use std::sync::Arc;



use crate::{
    domain::Domain,
    durability::{DurabilityMode, DEFAULT_MAX_COMMIT_BATCH_ENTRIES},
    entity::Entity,
    metadata::types::TableStorageMode,

    migration::chain::DbMigrationIndex,

    migration::layout::FieldLayout,

    migration::migrate_to::{MigrateTo, MigrationSourceType, MigrationTargetType},

    migration::runner::MigrationRun,

    migration::step_registry::MigrationStepRegistry,

    repository::DatabaseManager,

    repository::Repository,

    units::{ClError, Result},

    upgrade::{OpenUpgradePipeline, TableRegistration, UpgradeInput},

};



const DEFAULT_CACHE_CAPACITY: u64 = 10_000;

const DEFAULT_CACHE_TTL: u64 = 300;

const DEFAULT_CACHE_IDLE: u64 = 60;

const LOG_CHANNEL_CAPACITY: usize = 1024;



struct StorageInner {

    domains: HashMap<TypeId, Box<dyn Any + Send + Sync>>,

    database_managers: HashMap<String, DatabaseManager>,

    migration_registry: Arc<MigrationStepRegistry>,

}



#[derive(Clone)]

pub struct Storage(Arc<StorageInner>);



impl Storage {

    pub fn builder(config: StorageConfig) -> StorageBuilder {

        StorageBuilder::new(config)

    }



    pub fn domain<E: Entity>(&self) -> &Domain<E> {

        self.0

            .domains

            .get(&TypeId::of::<E>())

            .and_then(|b| b.downcast_ref::<Domain<E>>())

            .unwrap_or_else(|| {

                panic!(

                    "[Storage] Domain<{}> not registered",

                    std::any::type_name::<E>()

                )

            })

    }



    pub fn db_manager(&self, name: &str) -> &DatabaseManager {

        self.0

            .database_managers

            .get(name)

            .unwrap_or_else(|| panic!("[Storage] DatabaseManager '{}' not found", name))

    }



    pub fn db_list(&self) -> Vec<&DatabaseManager> {

        self.0.database_managers.values().collect()

    }



    pub fn db_list_names(&self) -> Vec<String> {

        self.0

            .database_managers

            .keys()

            .map(|k| k.to_string())

            .collect()

    }



    pub fn migrate<F, T>(&self) -> MigrationRun<'_, F, T>
    where
        F: MigrationSourceType,
        T: MigrationTargetType,
        F: MigrateTo<T>,
    {
        MigrationRun::new(self.clone(), self.0.migration_registry.clone())
    }

    pub fn migration_index(&self, db_name: &str) -> Result<DbMigrationIndex> {
        let db = self.db_manager(db_name);
        Ok(db.migration_index()?.clone())
    }

    pub fn migration_registry(&self) -> Arc<MigrationStepRegistry> {
        self.0.migration_registry.clone()
    }

}



trait DomainFactory: Send + Sync {
    fn table_name(&self) -> &'static str;
    fn layout(&self) -> FieldLayout;
    fn storage(&self) -> TableStorageMode;
    fn build(&self, database_manager: &DatabaseManager) -> (TypeId, Box<dyn Any + Send + Sync>);
}

struct TypedFactory<E: Entity + serde::Serialize + Default> {
    table: &'static str,
    layout: FieldLayout,
    storage: TableStorageMode,
    _marker: PhantomData<fn() -> E>,
}

impl<E: Entity + serde::Serialize + Default> DomainFactory for TypedFactory<E> {
    fn table_name(&self) -> &'static str {
        self.table
    }

    fn layout(&self) -> FieldLayout {
        self.layout.clone()
    }

    fn storage(&self) -> TableStorageMode {
        self.storage
    }

    fn build(&self, database_manager: &DatabaseManager) -> (TypeId, Box<dyn Any + Send + Sync>) {
        let repo = Repository::<E>::new(self.table, database_manager.clone());
        let domain = Domain::new(repo);
        (TypeId::of::<E>(), Box::new(domain))
    }
}



pub struct DatabaseConfig {

    has_cache: bool,

    dir_path: PathBuf,

    backup_dir_path: Option<PathBuf>,

    dir_name: String,

    db_name: String,

    cache_capacity: u64,

    cache_ttl: u64,

    cache_idle: u64,

    factories: Vec<Box<dyn DomainFactory>>,

    backup_enabled: bool,

    blob_enabled: bool,

    /// `None` means inherit from [`StorageConfig::durability`] at `add_database` time.
    durability: Option<DurabilityMode>,

    max_commit_batch_entries: usize,
}



impl DatabaseConfig {

    pub fn new(dir_name: &str, db_name: &str) -> Self {

        Self {

            has_cache: true,

            dir_path: PathBuf::from(""),

            backup_dir_path: None,

            dir_name: dir_name.to_string(),

            db_name: db_name.to_string(),

            cache_capacity: DEFAULT_CACHE_CAPACITY,

            cache_ttl: DEFAULT_CACHE_TTL,

            cache_idle: DEFAULT_CACHE_IDLE,

            factories: Vec::new(),

            backup_enabled: false,

            blob_enabled: false,

            durability: None,

            max_commit_batch_entries: DEFAULT_MAX_COMMIT_BATCH_ENTRIES,

        }

    }



    pub fn has_cache(mut self, has_cache: bool) -> Self {

        self.has_cache = has_cache;
        if has_cache {
            self.blob_enabled = false;
        }

        self

    }

    pub fn durability(mut self, mode: DurabilityMode) -> Self {
        self.durability = Some(mode);
        self
    }

    pub fn max_commit_batch_entries(mut self, max: usize) -> Self {
        self.max_commit_batch_entries = max.max(1);
        self
    }



    pub fn dir_path(mut self, path: PathBuf) -> Self {

        self.dir_path = path;

        self

    }



    pub fn backup_dir(mut self, path: PathBuf) -> Self {

        self.backup_enabled = true;
        self.blob_enabled = false;

        self.backup_dir_path = Some(path);

        self

    }



    pub fn backup_enabled(mut self, enabled: bool) -> Self {

        self.backup_enabled = enabled;
        if enabled {
            self.blob_enabled = false;
        }

        self

    }

    pub fn blob_enabled(mut self, enabled: bool) -> Self {
        self.blob_enabled = enabled;
        if enabled {
            self.backup_enabled = false;
            self.has_cache = false;
        }
        self
    }



    pub fn cache(mut self, capacity: u64, ttl_secs: u64, idle_secs: u64) -> Self {

        self.cache_capacity = capacity;

        self.cache_ttl = ttl_secs;

        self.cache_idle = idle_secs;

        self.has_cache = true;
        self.blob_enabled = false;

        self

    }



    pub fn register<E: Entity + serde::Serialize + Default>(self, table: &'static str) -> Self {
        self.register_with_storage::<E>(table, TableStorageMode::InlineJson)
    }

    pub fn register_blob<E: Entity + serde::Serialize + Default>(self, table: &'static str) -> Self {
        self.register_with_storage::<E>(table, TableStorageMode::BlobSidecar)
    }

    fn register_with_storage<E: Entity + serde::Serialize + Default>(
        mut self,
        table: &'static str,
        storage: TableStorageMode,
    ) -> Self {
        let layout =
            FieldLayout::capture_from_entity_json(&E::default()).unwrap_or_else(|_| {
                FieldLayout::from_json_value(&serde_json::json!({}))
            });
        self.factories.push(Box::new(TypedFactory::<E> {
            table,
            layout,
            storage,
            _marker: PhantomData,
        }));
        self
    }

}



#[derive(Clone)]

pub struct StorageConfig {

    log_channel_capacity: usize,

    name: String,

    dir_path: PathBuf,

    durability: DurabilityMode,

}



impl StorageConfig {

    pub fn default() -> Self {

        let dir_path = env::current_exe()

            .ok()

            .and_then(|p| p.parent().map(|p| p.to_path_buf()))

            .unwrap_or_else(|| PathBuf::from("."));



        Self {

            log_channel_capacity: LOG_CHANNEL_CAPACITY,

            name: "storage".to_string(),

            dir_path,

            durability: DurabilityMode::Strict,

        }

    }



    pub fn change_log_channel_capacity(mut self, capacity: usize) -> Self {

        self.log_channel_capacity = capacity;

        self

    }



    pub fn change_name(mut self, name: &str) -> Self {

        self.name = name.to_string();

        self

    }



    pub fn change_dir_path(mut self, path: PathBuf) -> Self {

        self.dir_path = path;

        self

    }

    pub fn durability(mut self, mode: DurabilityMode) -> Self {
        self.durability = mode;
        self
    }

}



pub struct StorageBuilder {

    database_configs: Vec<DatabaseConfig>,

    storage_config: StorageConfig,

    migration_registry: Arc<MigrationStepRegistry>,

    migration_steps: Vec<fn(&MigrationStepRegistry) -> crate::units::Result<()>>,

}



impl StorageBuilder {

    fn new(config: StorageConfig) -> Self {

        Self {

            database_configs: Vec::new(),

            storage_config: config,

            migration_registry: MigrationStepRegistry::global(),

            migration_steps: Vec::new(),

        }

    }

    /// Pre-register a typed migration step (for backup history replay without running migrate).
    pub fn migration_step<F, T>(mut self) -> Self
    where
        F: MigrationSourceType,
        T: MigrationTargetType,
        F: MigrateTo<T>,
    {
        fn register_step<F, T>(reg: &MigrationStepRegistry) -> Result<()>
        where
            F: MigrationSourceType,
            T: MigrationTargetType,
            F: MigrateTo<T>,
        {
            reg.register::<F, T>().map(|_| ())
        }
        self.migration_steps.push(register_step::<F, T>);
        self
    }



    pub fn add_database(mut self, config: DatabaseConfig) -> Self {

        let mut config = config;

        if (config.dir_path.to_str().is_some() && config.dir_path.to_str().unwrap().is_empty())

            || config.dir_path.to_str().is_none()

        {

            config.dir_path = self.storage_config.dir_path.clone();

        }

        if config.backup_enabled && config.backup_dir_path.is_none() {

            config.backup_dir_path = Some(config.dir_path.clone());

        }

        if config.durability.is_none() {
            config.durability = Some(self.storage_config.durability);
        }

        self.database_configs.push(config);

        self

    }



    pub fn build(self) -> Result<Storage> {

        let mut domains: HashMap<TypeId, Box<dyn Any + Send + Sync>> = HashMap::new();

        let mut database_managers: HashMap<String, DatabaseManager> = HashMap::new();

        let migration_registry = self.migration_registry.clone();
        for register in &self.migration_steps {
            register(&migration_registry)?;
        }

        for config in self.database_configs {

            if config.factories.is_empty() {

                return Err(ClError::Validation(

                    "DatabaseConfig must register at least one table".into(),

                ));

            }

            let has_blob_table = config
                .factories
                .iter()
                .any(|f| f.storage() == TableStorageMode::BlobSidecar);
            if has_blob_table && !config.blob_enabled {
                return Err(ClError::Validation(
                    "register_blob requires blob_enabled(true) on DatabaseConfig".into(),
                ));
            }

            let table_regs: Vec<TableRegistration> = config

                .factories

                .iter()

                .map(|f| TableRegistration {

                    name: f.table_name().to_string(),

                    layout: f.layout(),

                    storage: f.storage(),

                })

                .collect();



            let upgrade = OpenUpgradePipeline::run(&UpgradeInput {

                dir_path: &config.dir_path,

                backup_dir_path: config

                    .backup_dir_path

                    .as_ref()

                    .map(|p| p.as_path()),

                dir_name: &config.dir_name,

                db_name: &config.db_name,

                tables: &table_regs,

                backup_enabled: config.backup_enabled,

                blob_enabled: config.blob_enabled,

                has_cache: config.has_cache,

                durability: config.durability.unwrap_or(DurabilityMode::Strict),

            })?;



            let tables: Vec<String> = config

                .factories

                .iter()

                .map(|f| f.table_name().to_string())

                .collect();

            let table_storage: std::collections::HashMap<String, TableStorageMode> = config
                .factories
                .iter()
                .map(|f| (f.table_name().to_string(), f.storage()))
                .collect();

            let durability = config.durability.unwrap_or(DurabilityMode::Strict);

            let db_manager = DatabaseManager::open(

                &config.dir_path,

                config.backup_dir_path.as_ref(),

                &config.dir_name,

                &config.db_name,

                tables,

                config.cache_capacity,

                config.cache_ttl,

                config.cache_idle,

                config.has_cache,

                config.blob_enabled,

                table_storage,

                upgrade.table_layouts,

                migration_registry.clone(),

                durability,

                config.max_commit_batch_entries,

            )?;



            for factory in &config.factories {

                let (type_id, domain) = factory.build(&db_manager);

                domains.insert(type_id, domain);

            }



            database_managers.insert(config.db_name.clone(), db_manager);

        }



        Ok(Storage(Arc::new(StorageInner {

            domains,

            database_managers,

            migration_registry,

        })))

    }

}


