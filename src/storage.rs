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
    handle::RedbOptions,
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



/// Default cache budget, in **bytes**.
///
/// This was `10_000` and meant *entries*, which is a number that cannot bound
/// memory: the value is a `Vec<u8>` of whatever the caller stored, and 10,000
/// rows of 10 KB each are 100 MiB. 32 MiB is a budget an operator can reason
/// about without knowing how big a row happens to be.
const DEFAULT_CACHE_BYTES: u64 = 32 * 1024 * 1024;

const DEFAULT_CACHE_TTL: u64 = 300;

const DEFAULT_CACHE_IDLE: u64 = 60;

const LOG_CHANNEL_CAPACITY: usize = 1024;



struct StorageInner {
    index_worker:crate::indexes::Worker,

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



    /// Value-free snapshot of index diagnostics; does not build or refresh usage.
    pub fn index_report(&self)->Vec<crate::indexes::IndexReport> {self.db_list().into_iter().flat_map(|db|db.indexes.reports()).collect()}
    #[cfg(any(test,feature="crash-inject"))]
    #[doc(hidden)]
    pub fn test_advance_index_clock(&self,duration:std::time::Duration) {for db in self.db_list(){db.indexes.advance_clock(duration.as_millis() as u64);}}
    #[cfg(any(test,feature="crash-inject"))]
    #[doc(hidden)]
    pub fn test_request_index_compaction(&self){for db in self.db_list(){db.indexes.request_compact();}}
    pub fn db_list(&self) -> Vec<&DatabaseManager> {

        self.0.database_managers.values().collect()

    }


    /// Close every database, so the next open needs no repair.
    ///
    /// redb closes a file cleanly only when it is dropped, and a `Storage`
    /// kept in a `static` is never dropped — not even on a clean Ctrl+C — so
    /// without this every run leaves every file to be repaired on the next
    /// boot, a walk of the whole file. Call it once, on the way out.
    ///
    /// Waits for operations already running, then closes each `.cldb` and
    /// `.cldb.bak`. `Storage` is shared, so any clone used afterwards gets
    /// [`ClError::Closed`] instead of writing to a file that is gone. It does
    /// not cover a kill or a crash; [`DatabaseConfig::quick_repair`] does.
    pub fn close(&self) {
        self.0.index_worker.stop();
        for db in self.db_list() {db.indexes.clear();}

        for db in self.db_list() {

            db.close();

        }

    }


    /// Reclaim expired cache entries across every database.
    ///
    /// `moka` expires entries on a clock but frees them during maintenance, and
    /// maintenance runs when a cache is *used*. A database nobody has read since
    /// its entries expired therefore still holds them, hours past their TTL,
    /// until the next read happens to trigger housekeeping.
    ///
    /// Call this from an idle tick, a maintenance job, or before reporting
    /// process memory, when "expired" should mean "gone".
    pub fn run_cache_maintenance(&self) {

        for db in self.db_list() {

            db.run_cache_maintenance();

        }

    }



    /// Total `(bytes, entries)` cached across every database.
    ///
    /// Call [`Self::run_cache_maintenance`] first for a figure that excludes
    /// entries which have expired but not yet been reclaimed.
    pub fn cache_stats(&self) -> (u64, u64) {

        self.db_list().iter().fold((0, 0), |(b, e), db| {

            let (db_b, db_e) = db.cache_stats();

            (b + db_b, e + db_e)

        })

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

    /// How every file this `Storage` serves was opened by [`StorageBuilder::build`]:
    /// one line per `.cldb`, followed by its `.cldb.bak` when backup is enabled,
    /// sorted by database name.
    ///
    /// Always recorded, never printed: reading it is up to the caller. It costs
    /// a clock read and a file-size lookup per open, and nothing afterwards.
    ///
    /// Only the opens the storage keeps are listed. A `.cldb.bak` not yet marked
    /// upgraded — an old one, or one created by the previous build — is first
    /// opened once more for a one-time format check; that open, and a repair
    /// it may have done, is not in the report.
    pub fn open_report(&self) -> Vec<OpenReport> {
        let mut dbs: Vec<&DatabaseManager> = self.db_list();
        dbs.sort_by(|a, b| a.db_name.cmp(&b.db_name));
        dbs.into_iter()
            .flat_map(|db| {
                db.opened_files().into_iter().map(|file| OpenReport {
                    database: db.db_name.clone(),
                    path: file.path.clone(),
                    bytes: file.bytes,
                    open_time: file.open_time,
                    repaired: file.repaired,
                    format_check: file.format_check,
                })
            })
            .collect()
    }

}

/// How one file was opened. See [`Storage::open_report`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenReport {
    /// The database's name, as given to [`DatabaseConfig::new`].
    pub database: String,
    /// The primary, backup, or temporary conversion file.
    pub path: PathBuf,
    /// The file's size right after the open.
    pub bytes: u64,
    /// How long redb took to open (or create) the file.
    pub open_time: std::time::Duration,
    /// redb walked the whole file to rebuild its allocator state: the last
    /// process to write it ended without closing it, and its last commit did
    /// not save that state (see [`DatabaseConfig::quick_repair`]).
    pub repaired: bool,
    /// This open belongs to one-time backup format inspection or conversion.
    pub format_check: bool,
}

trait DomainFactory: Send + Sync {
    fn table_name(&self) -> &'static str;
    fn entity_type(&self)->TypeId;
    fn id_path(&self)->Option<crate::fields::Path>;
    fn layout(&self) -> FieldLayout;
    fn storage(&self) -> TableStorageMode;
    /// The protected fields the entity declares.
    fn sealed(&self) -> &'static [crate::field_crypto::SealedSpec];
    fn build(
        &self,
        database_manager: &DatabaseManager,
        seal: &SealEnv<'_>,
    ) -> Result<(TypeId, Box<dyn Any + Send + Sync>)>;
}

/// What a table with protected fields needs when its repository is made.
struct SealEnv<'a> {
    /// The keys of the database, when it has any.
    keys: Option<Arc<crate::field_crypto::FieldKeys>>,
    /// The identity recorded for each table that has protected fields.
    table_ids: &'a HashMap<String, String>,
}

struct TypedFactory<E: Entity + serde::Serialize + Default> {
    table: &'static str,
    layout: FieldLayout,
    storage: TableStorageMode,
    sealed: &'static [crate::field_crypto::SealedSpec],
    /// Set by `register_sealed`: how to encode and bind a row of this entity.
    kit: Option<crate::field_crypto::SealedKit<E>>,
    _marker: PhantomData<fn() -> E>,
}

impl<E: Entity + serde::Serialize + Default> DomainFactory for TypedFactory<E> {
    fn entity_type(&self)->TypeId {TypeId::of::<E>()}
    fn id_path(&self)->Option<crate::fields::Path> {E::id_field().map(|f|f.path())}
    fn table_name(&self) -> &'static str {
        self.table
    }

    fn layout(&self) -> FieldLayout {
        self.layout.clone()
    }

    fn storage(&self) -> TableStorageMode {
        self.storage
    }

    fn sealed(&self) -> &'static [crate::field_crypto::SealedSpec] {
        self.sealed
    }

    fn build(
        &self,
        database_manager: &DatabaseManager,
        seal: &SealEnv<'_>,
    ) -> Result<(TypeId, Box<dyn Any + Send + Sync>)> {
        let repo = match self.kit {
            Some(kit) => {
                let keys = seal.keys.clone().ok_or_else(|| {
                    ClError::Validation(
                        "a table with protected fields needs encryption keys: set `DatabaseConfig::encryption`".into(),
                    )
                })?;
                let table_id = seal.table_ids.get(self.table).ok_or_else(|| {
                    ClError::Validation("the table has no recorded identity".into())
                })?;
                let hooks = Arc::new(crate::field_crypto::SealedHooks::new(self.table, table_id, self.sealed, keys, kit));
                Repository::<E>::new_sealed(self.table, database_manager.clone(), hooks)
            }
            None => Repository::<E>::new(self.table, database_manager.clone()),
        };
        let domain = Domain::new(repo);
        Ok((TypeId::of::<E>(), Box::new(domain)))
    }
}



/// The size from which [`Prefetch::Auto`] reads a `.cldb` before opening it: 64 MiB (included).
pub const PREFETCH_AUTO_BYTES: u64 = 64 * 1024 * 1024;

/// The size above which [`Prefetch::Auto`] no longer reads a `.cldb` before opening it: 1 GiB (itself still read).
pub const PREFETCH_AUTO_MAX_BYTES: u64 = 1024 * 1024 * 1024;

/// Whether the `.cldb` is read once, front to back, before it is opened. See [`DatabaseConfig::prefetch`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Prefetch {
    /// Read it when the file is from [`PREFETCH_AUTO_BYTES`] up to and including [`PREFETCH_AUTO_MAX_BYTES`]
    /// (64 MiB to 1 GiB). The default.
    #[default]
    Auto,
    /// Always read it, whatever its size.
    Always,
    /// Never read it.
    Never,
}

impl Prefetch {
    /// Whether a file of `file_bytes` (0 when it does not exist yet) is read before it is opened.
    pub fn reads(self, file_bytes: u64) -> bool {
        match self {
            Prefetch::Auto => (PREFETCH_AUTO_BYTES..=PREFETCH_AUTO_MAX_BYTES).contains(&file_bytes),
            Prefetch::Always => true,
            Prefetch::Never => false,
        }
    }
}

/// `true` is [`Prefetch::Always`] and `false` is [`Prefetch::Never`], so `.prefetch(true)` and `.prefetch(false)` keep working.
impl From<bool> for Prefetch {
    fn from(on: bool) -> Self {
        if on { Prefetch::Always } else { Prefetch::Never }
    }
}

pub struct DatabaseConfig {

    has_cache: bool,

    dir_path: PathBuf,

    backup_dir_path: Option<PathBuf>,

    dir_name: String,

    db_name: String,

    cache_bytes: u64,

    cache_ttl: u64,

    cache_idle: u64,

    factories: Vec<Box<dyn DomainFactory>>,

    backup_enabled: bool,

    blob_enabled: bool,

    /// `None` means inherit from [`StorageConfig::durability`] at `add_database` time.
    durability: Option<DurabilityMode>,

    max_commit_batch_entries: usize,

    redb: RedbOptions,
    prefetch: Prefetch,
    journal_retention:crate::journal::Retention,
    unique:Vec<(TypeId,Vec<crate::Unique>)>,
    field_encryption: Option<Arc<crate::encrypted_store::EncryptionConfig>>,
    field_keys_file: Option<PathBuf>,
}



impl DatabaseConfig {

    pub fn new(dir_name: &str, db_name: &str) -> Self {

        Self {

            has_cache: true,

            dir_path: PathBuf::from(""),

            backup_dir_path: None,

            dir_name: dir_name.to_string(),

            db_name: db_name.to_string(),

            cache_bytes: DEFAULT_CACHE_BYTES,

            cache_ttl: DEFAULT_CACHE_TTL,

            cache_idle: DEFAULT_CACHE_IDLE,

            factories: Vec::new(),

            backup_enabled: false,

            blob_enabled: false,

            durability: None,

            max_commit_batch_entries: DEFAULT_MAX_COMMIT_BATCH_ENTRIES,

            redb: {
                #[allow(unused_mut)]
                let mut redb = RedbOptions::default();
                // Test builds only (`--cfg clove_test_encrypt_all`): every database is encrypted with a fixed test key.
                #[cfg(clove_test_encrypt_all)]
                {
                    redb.encryption = Some(crate::encrypted_store::EncryptionHandle::new(crate::encrypted_store::test_encrypt_all_config()));
                }
                redb
            },
            prefetch: Prefetch::Auto,
            journal_retention:crate::journal::Retention::Default,
            unique:Vec::new(),
            field_encryption: None,
            field_keys_file: None,

        }

    }



    /// Test builds only: keep this database plain under `--cfg clove_test_encrypt_all`.
    #[cfg(clove_test_encrypt_all)]
    #[doc(hidden)]
    pub fn plain(mut self) -> Self {
        self.redb.encryption = None;
        self
    }

    pub fn unique<E:Entity>(mut self,constraint:crate::Unique<E>)->Self {
        let constraint=constraint.erase();
        let id=TypeId::of::<E>();
        if let Some((_,v))=self.unique.iter_mut().find(|(i,_)|*i==id){v.push(constraint)}else{self.unique.push((id,vec![constraint]));}self
    }
    /// Size-only budget for the durable change journal, independent of history.
    pub fn journal_retention(mut self,retention:crate::journal::Retention)->Self {self.journal_retention=retention;self}

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

    /// Cap redb's page cache for this database's files, in **bytes**.
    ///
    /// This is redb's cache, underneath [`Self::cache_bytes`] — that one holds
    /// decoded rows, this one holds file pages. Without a cap redb allows 1 GiB
    /// per file, and pages read once stay resident: a full scan of a large
    /// table leaves about as much of it behind as it read, where a 64 MiB cap
    /// leaves 64 MiB at the same scan speed. It also bounds the peak of a
    /// repair after an unclean exit.
    ///
    /// The `.cldb` and the `.cldb.bak` each get this much.
    pub fn redb_cache_bytes(mut self, max_bytes: usize) -> Self {
        self.redb.cache_bytes = Some(max_bytes);
        self
    }

    /// Encrypt every file of this database (the `.cldb`, its `.cldb.bak`, its `.inx`) with keys the
    /// caller holds. The database must not exist yet: an existing unencrypted database is converted
    /// by a migration, and opening one with a key is the single "could not be opened" error.
    ///
    /// Every commit of an encrypted file is two-phase and saves redb's allocator state.
    ///
    /// The cipher is AES-256-GCM-SIV unless the configuration says otherwise (`EncryptionConfig::new` uses it; `with_suite`
    /// picks another, for example XChaCha20-Poly1305).
    ///
    /// The settings are checked at the start of `build()`, before any file is touched: only
    /// AES-256-GCM-SIV and XChaCha20-Poly1305 are accepted, the read key is always required, and a
    /// new database needs the search key too; each refusal is `ClError::Validation` saying what is
    /// missing. A wrong key or an unencrypted file is the single "could not be opened" error.
    ///
    /// Limits: a block put back from an older copy of its own file has a valid seal and is found
    /// only by [`DatabaseConfig::encryption_verify_on_open`] or, on closed files,
    /// `encrypted_store::verify_encrypted_files`; the whole file put back to an older state cannot
    /// be told; the number of files and their sizes are visible. Nothing converts a plain database
    /// in place: use a migration.
    pub fn encryption(mut self, config: crate::encrypted_store::EncryptionConfig) -> Self {
        self.redb.encryption = Some(crate::encrypted_store::EncryptionHandle::new(config));
        self
    }

    /// Keys for the protected fields (`Sealed`, `Hashed`, `SearchPrint`) of a database that is not
    /// encrypted as a whole. Use either this or [`DatabaseConfig::encryption`], not both: with
    /// whole-database encryption the protected fields use the keys of the database.
    ///
    /// A new database needs both the read key and the search key; an existing one opens with the
    /// read key, or with the search key alone (it can then read rows but neither write nor open a
    /// protected value). The data key is made at creation and stored locked in the main file, with
    /// a copy in the small keys file `{db}.keys` next to it (written only when it changes: a new
    /// protected table). The cipher is not stored, and only AES-256-GCM-SIV and XChaCha20-Poly1305
    /// are accepted. A wrong key is the single "could not be opened" error.
    ///
    /// The keys file is as safe as the programmer's keys: the data key in it is sealed under them,
    /// and a weak password can be guessed off the machine (the password is stretched, which only
    /// slows that down).
    pub fn field_encryption(mut self, config: crate::encrypted_store::EncryptionConfig) -> Self {
        self.field_encryption = Some(Arc::new(config));
        self
    }

    /// With [`DatabaseConfig::field_encryption`]: keep the sealed data key in this file **only**, and
    /// none in the main file. The main file then cannot open the protected fields by itself, and a
    /// copy of it taken alone is useless; the file must be kept somewhere else and backed up. If it
    /// is missing, or does not belong to this database, the library refuses to start, before it
    /// touches any file. **If this file is lost, the protected fields are lost for good.**
    pub fn field_keys_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.field_keys_file = Some(path.into());
        self
    }

    /// Speed settings of the encryption layer (call it after [`DatabaseConfig::encryption`]; without encryption it does nothing).
    /// Parallel sealing of a commit is on by default; see [`crate::EncryptionTuning`]. A database written
    /// with any setting opens with any other.
    pub fn encryption_tuning(mut self, tuning: crate::encrypted_store::EncryptionTuning) -> Self {
        if let Some(handle) = self.redb.encryption.take() {
            self.redb.encryption = Some(handle.with_tuning(tuning));
        }
        self
    }

    /// With [`DatabaseConfig::encryption`]: read and check every block of each file at open, so
    /// a block put back from an older copy of the file is found before any data is used. A full
    /// read of each file at every open.
    pub fn encryption_verify_on_open(mut self, enabled: bool) -> Self {
        self.redb.verify_on_open = enabled;
        self
    }

    /// Make every commit save redb's allocator state, so reopening after a
    /// kill or crash is near-instant instead of a full repair.
    ///
    /// Without it, a process that exits without closing — killed, crashed, or
    /// simply never dropping a `Storage` held in a `static` — leaves each file
    /// needing a repair that walks all of it, in time and memory that grow with
    /// the file; with this on, the same open takes milliseconds. The price is
    /// on every commit: 0.94 → 2.02 ms measured. Applies to the `.cldb.bak` too.
    ///
    /// [`Storage::open_report`] says, per file, whether the last open repaired it.
    ///
    /// For the clean path, see [`Storage::close`], which needs no option.
    pub fn quick_repair(mut self, enabled: bool) -> Self {
        self.redb.quick_repair = enabled;
        self
    }

    /// Read the `.cldb` once, front to back, before opening it, so that the first queries do not
    /// pay for the file's pages one at a time.
    ///
    /// When the operating system has not got the file cached (the first start after a reboot, or
    /// after other programs pushed it out), a scan reaches its pages in key order, which is not
    /// their order in the file: a 349 MB catalog took 9.1 s to answer its first count that way
    /// and 0.3 s once cached. One sequential read costs 0.18 s from cold and brings that to 0.5 s
    /// in total. When the file is already cached the read is wasted time: 0.06 s for the same file.
    /// The default is [`Prefetch::Auto`]: the read happens when the file is between
    /// [`PREFETCH_AUTO_BYTES`] (64 MiB) and [`PREFETCH_AUTO_MAX_BYTES`] (1 GiB), both included.
    /// The read happens at every open, so it has a price: from 64 MiB up, a cold start costs
    /// seconds and the read of an already cached file costs tens of milliseconds; below that the
    /// pages come one at a time in well under a second and the read is skipped. A file larger than
    /// the memory the system can give the cache does not benefit from being read ahead, and its
    /// read would take longer each time, so above 1 GiB it is skipped too.
    /// `prefetch(false)` ([`Prefetch::Never`]) turns it off whatever the size, and `prefetch(true)`
    /// ([`Prefetch::Always`]) turns it on whatever the size.
    /// It only reads: nothing is written, a failure to read is ignored, and a database that another
    /// program has open is still reported as [`ClError::DatabaseInUse`].
    pub fn prefetch(mut self, mode: impl Into<Prefetch>) -> Self {
        self.prefetch = mode.into();
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



    /// Cache this database, with a budget in **bytes**.
    ///
    /// Renamed from `cache(capacity, ..)`, which took a number of *entries*.
    /// That rename is the point: the two arguments look identical at a call
    /// site, so leaving the old name would have turned every `cache(10_000, ..)`
    /// into a 10 KB cache without a word from the compiler. This way each call
    /// site has to say what it meant.
    ///
    /// An entry count cannot bound memory. `10_000` entries of an unknown size
    /// is an unknown — 100 MiB of rows read once during a range scan and never
    /// again, if each row is 10 KB.
    ///
    /// `ttl_secs` and `idle_secs` decide when an entry *expires*. They do not
    /// decide when its memory comes back — see
    /// [`DatabaseManager::run_cache_maintenance`].
    pub fn cache_bytes(mut self, max_bytes: u64, ttl_secs: u64, idle_secs: u64) -> Self {

        self.cache_bytes = max_bytes;

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

    /// Registers an entity that has protected fields (`Sealed`, `Hashed`, `SearchPrint`).
    ///
    /// The protected fields are fixed when the table is created: opening an existing table with a
    /// different declaration is an error that writes nothing.
    pub fn register_sealed<E>(self, table: &'static str) -> Self
    where
        E: Entity + serde::Serialize + Default + crate::field_crypto::SealedFields,
    {
        self.register_with_storage_and_sealed::<E>(
            table,
            TableStorageMode::InlineJson,
            E::SEALED,
            Some(crate::field_crypto::SealedKit::<E>::new()),
        )
    }

    /// [`Self::register_sealed`] for a table that also keeps one attachment per row (it needs
    /// `blob_enabled(true)`). The attachment of a row is sealed in chunks with the keys of the
    /// protected fields, whatever the database itself is encrypted with, and is bound to the table,
    /// to the place of the attachment and to the row; the names of its folder and file are
    /// fingerprints that show neither the table nor the row.
    pub fn register_sealed_blob<E>(self, table: &'static str) -> Self
    where
        E: Entity + serde::Serialize + Default + crate::field_crypto::SealedFields,
    {
        self.register_with_storage_and_sealed::<E>(
            table,
            TableStorageMode::BlobSidecar,
            E::SEALED,
            Some(crate::field_crypto::SealedKit::<E>::new()),
        )
    }

    fn register_with_storage<E: Entity + serde::Serialize + Default>(
        self,
        table: &'static str,
        storage: TableStorageMode,
    ) -> Self {
        self.register_with_storage_and_sealed::<E>(table, storage, &[], None)
    }

    fn register_with_storage_and_sealed<E: Entity + serde::Serialize + Default>(
        mut self,
        table: &'static str,
        storage: TableStorageMode,
        sealed: &'static [crate::field_crypto::SealedSpec],
        kit: Option<crate::field_crypto::SealedKit<E>>,
    ) -> Self {
        // A default entity holds new protected values, which serialize only inside this step.
        let scope = (!sealed.is_empty()).then(crate::field_crypto::SealScope::enter);
        let mut layout =
            FieldLayout::capture_from_entity_json(&E::default()).unwrap_or_else(|_| {
                FieldLayout::from_json_value(&serde_json::json!({}))
            });
        drop(scope);
        // A protected field is stored as text whatever it holds.
        for spec in sealed {
            layout.set_json_type(spec.key, "string");
        }
        self.factories.push(Box::new(TypedFactory::<E> {
            table,
            layout,
            storage,
            sealed,
            kit,
            _marker: PhantomData,
        }));
        self
    }

}



#[derive(Clone)]

pub struct StorageConfig {

    log_channel_capacity: usize,
    event_sink:crate::events::EventSink,
    slow_query_threshold:std::time::Duration,

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
            event_sink:Default::default(),
            slow_query_threshold:std::time::Duration::from_millis(50),

            name: "storage".to_string(),

            dir_path,

            durability: DurabilityMode::Strict,

        }

    }



    pub fn event_sink(mut self,sink:impl Fn(&crate::LibraryEvent)+Send+Sync+'static)->Self {
        self.event_sink=crate::events::EventSink(Some(Arc::new(sink)));self
    }
    pub fn slow_query_threshold(mut self,threshold:std::time::Duration)->Self {
        self.slow_query_threshold=threshold;self
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
        let events = self.storage_config.event_sink.clone();
        let mut created = Vec::new();
        match self.build_files(&mut created) {
            Ok(storage) => Ok(storage),
            Err(error) => {
                // everything the failed build opened is closed by now (its handles were dropped)
                for c in created {
                    CreatedByThisCall::remove(c, &events);
                }
                Err(error)
            }
        }
    }

    fn build_files(self, created: &mut Vec<CreatedByThisCall>) -> Result<Storage> {
        // A change of a database's files that a crash cut short is settled before anything else is
        // looked at: in the middle of it the main file may be missing (moved aside, its new version
        // waiting), which would be taken for a new database; and the list of what this call makes
        // must not include files that the settling puts in place. If any database is being changed
        // right now (its marker is locked) the build fails before it touches any of them.
        {
            use crate::migration::encrypted::marker::{Migration, Places};
            let places_of = |config: &DatabaseConfig| {
                let dir = config.dir_path.join(&config.dir_name);
                let backup = config.backup_dir_path.as_ref().map(|b| b.join(&config.dir_name)).unwrap_or_else(|| dir.clone());
                (dir, backup)
            };
            for config in &self.database_configs {
                let (dir, backup) = places_of(config);
                Migration::check_free(Places { main: &dir, backup: &backup }, &config.db_name)?;
            }
            for config in &self.database_configs {
                let (dir, backup) = places_of(config);
                Migration::recover(Places { main: &dir, backup: &backup }, &config.db_name)?;
            }
        }
        // The shape of the encryption settings is checked before any file or folder is touched.
        for config in &self.database_configs {
            if let Some(encryption) = &config.redb.encryption {
                let is_new = main_file_is_new(&config.dir_path.join(&config.dir_name).join(format!("{}.cldb", config.db_name)));
                encryption.check_settings(is_new).map_err(|why| ClError::Validation(why.into()))?;
            }
        }

        let mut domains: HashMap<TypeId, Box<dyn Any + Send + Sync>> = HashMap::new();

        let mut database_managers: HashMap<String, DatabaseManager> = HashMap::new();

        let migration_registry = self.migration_registry.clone();
        for register in &self.migration_steps {
            register(&migration_registry)?;
        }

        for config in self.database_configs {

            let mut note = CreatedByThisCall::default();
            note.note(&config);
            created.push(note);

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

            if config.redb.encryption.is_some() && config.field_encryption.is_some() {
                return Err(ClError::Validation(
                    "set either `DatabaseConfig::encryption` or `DatabaseConfig::field_encryption`, not both".into(),
                ));
            }
            if config.redb.encryption.is_none()
                && config.field_encryption.is_none()
                && config.factories.iter().any(|f| !f.sealed().is_empty())
            {
                return Err(ClError::Validation(
                    "a table with protected fields needs encryption keys: set `DatabaseConfig::encryption` or `DatabaseConfig::field_encryption`".into(),
                ));
            }
            if let Some(keys) = &config.field_encryption
                && !crate::encrypted_store::cipher_allowed(keys.suite.cipher)
            {
                return Err(ClError::Validation("this cipher is not allowed for protected fields".into()));
            }
            // A keys file kept apart from the main file: it must be there for a database that exists,
            // and must not be there for one that does not. Decided before any file is touched.
            if let Some(path) = &config.field_keys_file {
                if config.redb.encryption.is_some() {
                    return Err(ClError::Validation(
                        "`DatabaseConfig::field_keys_file` is not available for a database encrypted as a whole: its lock stays in its file header (the keys file next to the database keeps a copy)".into(),
                    ));
                }
                if config.field_encryption.is_none() {
                    return Err(ClError::Validation(
                        "`DatabaseConfig::field_keys_file` needs `DatabaseConfig::field_encryption`".into(),
                    ));
                }
                if config.factories.iter().any(|f| !f.sealed().is_empty()) {
                    let main = config.dir_path.join(&config.dir_name).join(format!("{}.cldb", config.db_name));
                    let existing = !main_file_is_new(&main);
                    if existing && !path.is_file() {
                        return Err(ClError::Validation(format!(
                            "the keys file {} is missing: the protected fields of this database cannot be opened without it; nothing was opened",
                            path.display()
                        )));
                    }
                    if !existing && path.exists() {
                        return Err(ClError::Validation(format!(
                            "the keys file {} exists but the database does not: it belongs to another database or to one that was lost; nothing was opened",
                            path.display()
                        )));
                    }
                }
            }

            // A unique constraint compares stored values; a protected field stores sealed text.
            for (entity, definitions) in &config.unique {
                let Some(factory) = config.factories.iter().find(|f| f.entity_type() == *entity) else {
                    continue;
                };
                for definition in definitions {
                    for path in &definition.paths {
                        if let Some(crate::fields::Step::Key(first)) = path.steps.first()
                            && factory.sealed().iter().any(|spec| {
                                spec.key == first.as_str()
                                    && crate::field_crypto::print_steps(spec).as_deref() != Some(path.steps.as_slice())
                            })
                        {
                            return Err(ClError::Validation(format!(
                                "`{first}` is a protected field: a unique constraint cannot use it"
                            )));
                        }
                    }
                }
            }

            let table_regs: Vec<TableRegistration> = config

                .factories

                .iter()

                .map(|f| TableRegistration {

                    name: f.table_name().to_string(),

                    layout: f.layout(),

                    storage: f.storage(),

                    sealed: f.sealed(),

                })

                .collect();



            {
                let file = config.dir_path.join(&config.dir_name).join(format!("{}.cldb", config.db_name));
                let bytes = std::fs::metadata(&file).map(|m| m.len()).unwrap_or(0);
                if config.prefetch.reads(bytes) {
                    crate::handle::prefetch_file(&file);
                }
            }
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

                redb: config.redb.clone(),

                event_sink: self.storage_config.event_sink.clone(),

                field_encryption: config.field_encryption.clone(),

                field_keys_file: config.field_keys_file.clone(),

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

            // Tables with protected fields: their identities (recorded in the description) and the
            // keys of the database. Without keys such a table cannot be built.
            let table_ids: HashMap<String, String> = upgrade
                .meta
                .tables
                .iter()
                .filter_map(|t| t.table_id.clone().map(|id| (t.name.clone(), id)))
                .collect();
            let sealed_tables: std::collections::HashSet<String> = config
                .factories
                .iter()
                .filter(|f| !f.sealed().is_empty())
                .map(|f| f.table_name().to_string())
                .collect();
            let field_keys: Option<Arc<crate::field_crypto::FieldKeys>> = if sealed_tables.is_empty() {
                None
            } else if let Some(keys) = upgrade.field_keys.clone() {
                Some(keys)
            } else {
                config
                    .redb
                    .encryption
                    .as_ref()
                    .and_then(|e| e.context().cloned())
                    .map(crate::field_crypto::FieldKeys::with_context)
                    .transpose()?
                    .map(Arc::new)
            };

            // Attachments of tables that have protected fields are sealed with those fields' keys.
            let protected_attachments = field_keys.as_ref().and_then(|keys| {
                let ids: HashMap<String, String> = config
                    .factories
                    .iter()
                    .filter(|f| !f.sealed().is_empty() && f.storage() == TableStorageMode::BlobSidecar)
                    .filter_map(|f| table_ids.get(f.table_name()).map(|id| (f.table_name().to_string(), id.clone())))
                    .collect();
                (!ids.is_empty()).then(|| (keys.clone(), Arc::new(ids)))
            });

            #[cfg(test)]
            let encrypted_here = config.redb.encryption.is_some() && config.db_name == "hooked";
            let mut db_manager = DatabaseManager::open_with_attachments(
                upgrade.db,

                &config.dir_path,

                config.backup_dir_path.as_ref(),

                &config.dir_name,

                &config.db_name,

                tables,

                config.cache_bytes,

                config.cache_ttl,

                config.cache_idle,

                config.has_cache,

                config.blob_enabled,

                table_storage,

                upgrade.table_layouts,

                migration_registry.clone(),

                durability,

                config.max_commit_batch_entries,

                config.redb,

                protected_attachments,

            )?;

            #[cfg(test)]
            if encrypted_here && FAIL_AFTER_OPEN.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(ClError::Validation("injected failure after the database opened".into()));
            }
            db_manager.event_sink=self.storage_config.event_sink.clone();
            db_manager.slow_query_threshold=self.storage_config.slow_query_threshold;
            let constraints=config.unique.iter().map(|(id,defs)| {
                let table=config.factories.iter().find(|f|f.entity_type()==*id).ok_or_else(||ClError::Validation("unique entity not registered".into()))?.table_name().to_owned();
                Ok((table,defs.clone()))
            }).collect::<Result<Vec<_>>>()?;
            let ids=config.factories.iter().filter_map(|f|f.id_path().map(|p|(f.table_name().to_owned(),p))).collect::<Vec<_>>();
            db_manager.journal_write(|tx,_| {crate::id_contract::configure(tx,&ids)?;crate::unique::configure(tx,&constraints)})?;
            db_manager.set_journal_retention(config.journal_retention)?;
            db_manager.format_opens = upgrade.format_opens;
            db_manager.sealed_tables = Arc::new(sealed_tables);
            db_manager.field_keys = field_keys.clone();
            let seal_env = SealEnv { keys: field_keys, table_ids: &table_ids };
            for factory in &config.factories {
                let (type_id, domain) = factory.build(&db_manager, &seal_env)?;

                domains.insert(type_id, domain);

            }



            database_managers.insert(config.db_name.clone(), db_manager);

        }



        let index_worker=crate::indexes::boot(&mut database_managers)?;
        Ok(Storage(Arc::new(StorageInner {
            index_worker,

            domains,

            database_managers,

            migration_registry,

        })))

    }

}

/// What one `build` call created for a new encrypted database. If the build then fails, all of it
/// is removed again, so a failed first try never leaves files behind that refuse the next try
/// (an empty encrypted file made with a mistyped password, for example). Only paths that did not
/// exist when the call started are listed; nothing that was there before is ever touched.
/// Same rule as `EncryptionHandle::open_file`: a main file of zero length is a database that does not exist yet.
fn main_file_is_new(path: &std::path::Path) -> bool {
    !path.exists() || (path.is_file() && std::fs::metadata(path).map(|m| m.len() == 0).unwrap_or(false))
}

#[derive(Default)]
struct CreatedByThisCall {
    /// (path, is a folder, which kind of file for the event)
    items: Vec<(PathBuf, bool, &'static str)>,
    /// The database folder, when this call made it: removed last, and only if it is empty.
    folder: Option<PathBuf>,
}

impl CreatedByThisCall {
    fn note(&mut self, config: &DatabaseConfig) {
        let dir = config.dir_path.join(&config.dir_name);
        // Only a database that this call makes is removed again when the build fails: one that was
        // there before is never touched.
        if dir.join(format!("{}.cldb", config.db_name)).exists() {
            return;
        }
        if !dir.exists() {
            self.folder = Some(dir.clone());
        }
        let backup_dir = match &config.backup_dir_path {
            Some(b) => b.join(&config.dir_name),
            None => dir.clone(),
        };
        let mut candidates = vec![
            (dir.join(format!("{}.cldb", config.db_name)), false, "main"),
            (backup_dir.join(format!("{}.cldb.bak", config.db_name)), false, "bak"),
            (dir.join(format!("{}.inx", config.db_name)), false, "index"),
            (dir.join(format!("{}.keys", config.db_name)), false, "sidecar"),
            (crate::migration::chain::DbMigrationIndex::migration_path(&dir, &config.db_name), true, "sidecar"),
            (crate::blob::blob_root(&dir, &config.db_name), true, "sidecar"),
            (crate::blob::protected_blob_root(&dir, &config.db_name), true, "sidecar"),
        ];
        // the keys file kept apart from the database, when this call makes it
        if let Some(path) = &config.field_keys_file {
            candidates.push((path.clone(), false, "sidecar"));
        }
        for (path, is_dir, kind) in candidates {
            if !path.exists() {
                self.items.push((path, is_dir, kind));
            }
        }
    }

    fn remove(self, events: &crate::events::EventSink) {
        for (path, is_dir, kind) in self.items {
            let result = if is_dir { std::fs::remove_dir_all(&path) } else { std::fs::remove_file(&path) };
            if let Err(e) = result {
                if e.kind() != std::io::ErrorKind::NotFound {
                    events.emit(&crate::LibraryEvent::Encryption { event: "encryption/cleanup_failed", file: kind });
                }
            }
        }
        if let Some(folder) = self.folder {
            let _ = std::fs::remove_dir(&folder); // only when empty
        }
    }
}

/// Test hook: make the build fail after the database manager opened (files for the backup, the
/// migration folder and the attachment folder exist by then).
#[cfg(test)]
pub(crate) static FAIL_AFTER_OPEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
