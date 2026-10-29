//! The public side of changing how the fields of a table are protected: what to change, the keys,
//! the options, and `dry_run` that says what would happen without writing anything.
#![allow(dead_code)] // `execute` is written next
use super::{
    analyze::{self, Analysis, Paths},
    plan::StepKind,
};
use crate::{
    LibraryEvent,
    encrypted_store::{EncryptionConfig, EncryptionHandle},
    events::EventSink,
    field_crypto::{Method, SealedFields, SealedSpec},
    migration::encrypted::{
        marker::{Places, Root},
        space::{self, Available},
    },
    units::Result,
};
use std::{path::PathBuf, sync::Arc, time::Duration};

/// How the keys of the fields are held.
pub(crate) enum KeyMode {
    /// None given: only a change that needs no key can be made.
    None,
    /// The database is encrypted as a whole (and its fields use the same keys). This change does not
    /// change that.
    Whole(EncryptionHandle),
    /// The database is plain but for the protected fields, which have keys of their own; the data
    /// key is made when the database has none and the change needs one.
    Field(EncryptionConfig),
}

/// What a field becomes, for a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldReport {
    pub field: String,
    pub id: u32,
    /// `kept`, `sealed`, `hashed`, `fingerprint only`, `fingerprints added`, `fingerprints made again`,
    /// `fingerprints removed`, `opened`, `opened and hashed` or `opened and fingerprint only`.
    pub change: &'static str,
    /// The original value is lost for good.
    pub one_way: bool,
}

/// What a change does to one table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableChange {
    pub table: String,
    pub rows: u64,
    /// Saved versions in the history file (a deletion has none).
    pub versions: u64,
    pub fields: Vec<FieldReport>,
    /// Whether any row of the table is written again.
    pub rewrites_rows: bool,
}

/// What a change would do. Nothing was written to make it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldChangeReport {
    pub tables: Vec<TableChange>,
    /// Values that get a verification hash (rows and saved versions).
    pub hash_values: u64,
    /// The time those hashes take, from one hash timed here with the settings of the code. `None`
    /// when nothing is hashed.
    pub estimated_hash_time: Option<Duration>,
    /// Memory one hash needs while it runs.
    pub hash_memory_bytes: u64,
    /// Saved versions that hold no value for a field and were allowed to stay so, by (table, field, count).
    pub old_versions_without: Vec<(String, String, u64)>,
    /// A data key is made for the fields of this database (it had none).
    pub makes_data_key: bool,
    /// Extra disk space needed in the database folder, and in the backup folder when it is another.
    pub required_bytes: u64,
    pub required_bytes_backup: Option<u64>,
    /// The files and folders that are replaced or removed.
    pub replaces: Vec<String>,
}

/// What a change did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FieldChangeDone {
    /// Rows copied into the new main file.
    pub rows: u64,
    /// Saved versions in the new history file.
    pub versions: u64,
    pub files_replaced: u32,
    /// Attachments sealed again or taken back because their table gained its first protected field
    /// or lost its last, and their bytes.
    pub attachments_moved: u64,
    pub attachment_bytes_moved: u64,
}

/// A change of how the protected fields of a closed database are held: sealed, given or stripped of
/// fingerprints, opened, or made a hash or a fingerprint that does not keep the value.
pub struct ChangeFields {
    pub(crate) dir_path: PathBuf,
    pub(crate) dir_name: String,
    pub(crate) db_name: String,
    pub(crate) backup_dir_path: Option<PathBuf>,
    pub(crate) keys: KeyMode,
    pub(crate) tables: Vec<(String, &'static [SealedSpec])>,
    pub(crate) one_way_confirmed: bool,
    pub(crate) allow_without: Vec<String>,
    pub(crate) wipe_originals: bool,
    pub(crate) available: Available,
    pub(crate) events: EventSink,
}

impl ChangeFields {
    /// The database `{dir_path}/{dir_name}/{db_name}.cldb`. Name the tables to change, and the keys.
    pub fn new(dir_path: impl Into<PathBuf>, dir_name: &str, db_name: &str) -> Self {
        Self {
            dir_path: dir_path.into(),
            dir_name: dir_name.to_string(),
            db_name: db_name.to_string(),
            backup_dir_path: None,
            keys: KeyMode::None,
            tables: Vec::new(),
            one_way_confirmed: false,
            allow_without: Vec::new(),
            wipe_originals: false,
            available: Available::default(),
            events: EventSink::default(),
        }
    }

    /// The folder of the backup file, when it is not the database's own.
    pub fn backup_dir_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.backup_dir_path = Some(path.into());
        self
    }

    /// The database is encrypted as a whole under these keys, and its fields use them too. This
    /// change leaves that as it is.
    pub fn whole_database_keys(mut self, keys: EncryptionConfig) -> Self {
        self.keys = KeyMode::Whole(EncryptionHandle::new(keys));
        self
    }

    /// The database has keys for its protected fields only. When it has none yet, they are made
    /// from these (a new data key), if the change needs a key.
    pub fn field_keys(mut self, keys: EncryptionConfig) -> Self {
        self.keys = KeyMode::Field(keys);
        self
    }

    /// The protected fields of `table` from now on are those `E` declares. The stored description is
    /// read from the file; no number of a field is written by hand.
    pub fn table<E: SealedFields>(mut self, table: &str) -> Self {
        self.tables.push((table.to_string(), E::SEALED));
        self
    }

    /// `table` has no protected field from now on.
    pub fn table_without_protected_fields(mut self, table: &str) -> Self {
        self.tables.push((table.to_string(), &[]));
        self
    }

    /// Say that the change may lose a value for good (a hash, or a fingerprint that does not keep the
    /// value). Without this such a change is refused and nothing is touched.
    pub fn confirm_one_way(mut self) -> Self {
        self.one_way_confirmed = true;
        self
    }

    /// Saved versions that were written before the field existed hold no value for it. They stay as
    /// they are when the field is named here (and the name is in the report). Never for a hash.
    pub fn allow_old_versions_without(mut self, field: &str) -> Self {
        self.allow_without.push(field.to_string());
        self
    }

    /// Overwrite each old file with random bytes, and flush it, before it is removed.
    pub fn wipe_originals(mut self, on: bool) -> Self {
        self.wipe_originals = on;
        self
    }

    /// How much room the program says is free: when it is less than the change needs, it is refused
    /// before anything is written.
    pub fn available_bytes(mut self, available: Available) -> Self {
        self.available = available;
        self
    }

    /// Receive the stages of the change (names and counts, never a value).
    pub fn on_event(mut self, sink: impl Fn(&LibraryEvent) + Send + Sync + 'static) -> Self {
        self.events = EventSink(Some(Arc::new(sink)));
        self
    }

    pub(crate) fn paths(&self) -> Paths {
        let dir = self.dir_path.join(&self.dir_name);
        let backup_dir = match &self.backup_dir_path {
            Some(b) => b.join(&self.dir_name),
            None => dir.clone(),
        };
        Paths {
            main: dir.join(format!("{}.cldb", self.db_name)),
            backup: backup_dir.join(format!("{}.cldb.bak", self.db_name)),
            dir,
            backup_dir,
        }
    }

    /// What the change would do, and how much room it needs. Nothing is written.
    pub fn dry_run(&self) -> Result<FieldChangeReport> {
        let analysis = analyze::analyze(self)?;
        self.report(&analysis)
    }

    pub(crate) fn report(&self, a: &Analysis) -> Result<FieldChangeReport> {
        let files: Vec<(Root, &str)> = a.targets.iter().filter(|t| t.replace).map(|t| (t.root, t.name.as_str())).collect();
        let places = Places { main: &a.paths.dir, backup: &a.paths.backup_dir };
        let need = space::required(places, &files, false);
        let need = space::Required { main: need.main.saturating_add(a.attach_bytes), backup: need.backup };
        space::check(need, self.available)?;
        let tables = a
            .plans
            .iter()
            .zip(&a.counts)
            .map(|(plan, count)| TableChange {
                table: plan.table.clone(),
                rows: count.rows,
                versions: count.versions,
                rewrites_rows: plan.changes_rows(),
                fields: plan
                    .steps
                    .iter()
                    .map(|s| FieldReport { field: s.key.clone(), id: s.id, change: label(s.kind), one_way: s.kind.one_way() })
                    .collect(),
            })
            .collect();
        // One hash is timed with the settings of the code; the rest is that time, once for each value.
        let estimated_hash_time = if a.hash_values > 0 { self.time_one_hash(a)?.map(|one| one.saturating_mul(a.hash_values.min(u32::MAX as u64) as u32)) } else { None };
        Ok(FieldChangeReport {
            tables,
            hash_values: a.hash_values,
            estimated_hash_time,
            hash_memory_bytes: if a.hash_values > 0 { 64 * 1024 * 1024 } else { 0 },
            old_versions_without: a.allowed_versions_without.clone(),
            makes_data_key: a.made_keys.is_some(),
            required_bytes: need.main,
            required_bytes_backup: need.backup,
            replaces: a.targets.iter().map(|t| t.name.clone()).collect(),
        })
    }

    /// The time of one hash of a value, made with the first hash field the change makes.
    fn time_one_hash(&self, a: &Analysis) -> Result<Option<Duration>> {
        let Some(keys) = &a.keys else { return Ok(None) };
        let spec = a.plans.iter().flat_map(|p| p.steps.iter()).filter(|s| s.kind.one_way()).filter_map(|s| s.to).find(|t| t.method == Method::Hash);
        let Some(spec) = spec else { return Ok(None) };
        let started = std::time::Instant::now();
        crate::field_crypto::hash_plain(keys, "00000000000000000000000000000000", &spec, "probe", b"\"probe\"")?;
        Ok(Some(started.elapsed()))
    }
}

fn label(kind: StepKind) -> &'static str {
    match kind {
        StepKind::Keep => "kept",
        StepKind::Seal => "sealed",
        StepKind::Hash => "hashed",
        StepKind::PrintOnly => "fingerprint only",
        StepKind::AddPrints => "fingerprints added",
        StepKind::RemakePrints => "fingerprints made again",
        StepKind::DropPrints => "fingerprints removed",
        StepKind::Open => "opened",
        StepKind::OpenToHash => "opened and hashed",
        StepKind::OpenToPrintOnly => "opened and fingerprint only",
    }
}
