//! Changing how a whole database is protected after it was made: from plain files to files
//! encrypted as a whole, back, or under other keys or another cipher.
//!
//! The database must be closed. Every file is written again, complete, next to the old one; the
//! new files are checked against the old ones; and only then are they put in place, by one
//! decision that a crash cannot split (see the marker files). Until that decision the old files are
//! the database and nothing of them has been touched. A key that does not open the database, or a
//! database another program has open, is refused before anything is written.
use super::{
    attachments,
    convert,
    history,
    rekey,
    marker::{Migration, Places, Root, Target},
    rows::BatchLimits,
    sidecars::{self, Form},
    space::{self, Available},
};
use crate::{
    LibraryEvent,
    encrypted_store::{EncryptionConfig, EncryptionHandle},
    events::EventSink,
    field_crypto::FieldKeys,
    fsutil::maybe_crash,
    handle::{DbOrRo, RedbOptions},
    metadata::store::read_meta,
    units::{ClError, Result},
};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// redb's own file signature: an encrypted file never starts with it.
const PLAIN_SIGNATURE: [u8; 9] = [b'r', b'e', b'd', b'b', 0x1A, 0x0A, 0xA9, 0x0D, 0x0A];

/// What a table or file becomes, for a dry run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableReport {
    pub name: String,
    /// `copied`, `rebuilt` or `written again`.
    pub how: &'static str,
    pub entries: u64,
}

/// What a migration would do. Nothing was written to make it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeReport {
    /// Every table of the main file and what happens to it.
    pub tables: Vec<TableReport>,
    /// Every table of the backup history, all versions of which are copied.
    pub history_tables: Vec<TableReport>,
    /// Attachments that rows refer to, and their bytes.
    pub attachments: u64,
    pub attachment_bytes: u64,
    /// Files in the attachment folder that no row refers to: they are not copied, and go.
    pub unused_attachment_files: usize,
    /// Migration records that are rewritten.
    pub records: u64,
    /// Extra disk space needed in the database folder, and in the backup folder when it is another.
    pub required_bytes: u64,
    pub required_bytes_backup: Option<u64>,
    /// The files and folders that are replaced.
    pub replaces: Vec<String>,
}

/// What a migration did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeDone {
    pub rows: u64,
    pub files_replaced: u32,
    pub attachments: u64,
    pub attachment_bytes: u64,
    /// Files of the old attachment folder that no row referred to: they were not copied, and went
    /// with the old folder.
    pub unused_attachment_files: usize,
}

/// A change of how a closed database is protected as a whole.
pub struct ChangeProtection {
    dir_path: PathBuf,
    dir_name: String,
    db_name: String,
    backup_dir_path: Option<PathBuf>,
    from: Option<EncryptionHandle>,
    to: Option<EncryptionHandle>,
    wipe_originals: bool,
    available: Available,
    limits: BatchLimits,
    events: EventSink,
    declared: Vec<rekey::Declared>,
    /// The protected fields have keys of their own (the file is plain), before and after.
    from_fields: Option<EncryptionConfig>,
    to_fields: Option<EncryptionConfig>,
}

struct Paths {
    dir: PathBuf,
    backup_dir: PathBuf,
    main: PathBuf,
    backup: PathBuf,
    blobs: PathBuf,
    records: PathBuf,
}

/// Everything read from the old files, the plans, and the folders' forms.
struct Source {
    main: DbOrRo,
    backup: Option<DbOrRo>,
    main_plan: convert::Plan,
    history_plan: Option<history::Plan>,
    blobs: Vec<sidecars::Blob>,
    records: Vec<sidecars::Parts>,
    from_form: Form,
    unused_blobs: usize,
    /// The database has tables with protected fields.
    protected: bool,
    /// Those tables: (name, identity).
    protected_tables: Vec<(String, String)>,
    /// The keys of the protected fields of the old file.
    old_keys: Option<Arc<FieldKeys>>,
}

fn bad(why: impl Into<String>) -> ClError {
    ClError::MigrationError(why.into())
}

fn io(e: std::io::Error) -> ClError {
    ClError::IoError(e.to_string())
}

fn sync_path(path: &Path) {
    if path.is_dir() {
        if let Ok(rd) = fs::read_dir(path) {
            for e in rd.filter_map(|e| e.ok()) {
                sync_path(&e.path());
            }
        }
    } else if let Ok(f) = fs::OpenOptions::new().write(true).open(path) {
        let _ = f.sync_all();
    }
}

impl ChangeProtection {
    /// The database `{dir_path}/{dir_name}/{db_name}.cldb`, as it is plain and as it is to become.
    /// Both sides start as plain; set at least one of them to a whole-database encryption.
    pub fn new(dir_path: impl Into<PathBuf>, dir_name: &str, db_name: &str) -> Self {
        Self {
            dir_path: dir_path.into(),
            dir_name: dir_name.to_string(),
            db_name: db_name.to_string(),
            backup_dir_path: None,
            from: None,
            to: None,
            wipe_originals: false,
            available: Available::default(),
            limits: BatchLimits::DEFAULT,
            events: EventSink::default(),
            declared: Vec::new(),
            from_fields: None,
            to_fields: None,
        }
    }

    /// The database is plain, and its protected fields have keys of their own (they were made with
    /// `field_encryption`), under these keys.
    pub fn from_field_keys(mut self, keys: EncryptionConfig) -> Self {
        self.from = None;
        self.from_fields = Some(keys);
        self
    }

    /// The database is to be plain, and its protected fields to have keys of their own, under these
    /// keys (a new data key is made).
    pub fn to_field_keys(mut self, keys: EncryptionConfig) -> Self {
        self.to = None;
        self.to_fields = Some(keys);
        self
    }

    /// Say that the table `table` is the one of the entity `T`, which has protected fields. Every
    /// table of the database that has protected fields has to be named this way: their values are
    /// sealed again with the new keys, and a table that is not named is refused, before anything is
    /// written.
    pub fn protected_table<T: crate::field_crypto::SealedFields>(mut self, table: &str) -> Self {
        self.declared.push(rekey::declare::<T>(table));
        self
    }

    /// The folder of the backup file, when it is not the database's own.
    pub fn backup_dir_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.backup_dir_path = Some(path.into());
        self
    }

    pub fn from_plain(mut self) -> Self {
        self.from = None;
        self.from_fields = None;
        self
    }

    /// The database is encrypted as a whole now, under these keys.
    pub fn from_whole_database(mut self, keys: EncryptionConfig) -> Self {
        self.from = Some(EncryptionHandle::new(keys));
        self.from_fields = None;
        self
    }

    pub fn to_plain(mut self) -> Self {
        self.to = None;
        self.to_fields = None;
        self
    }

    /// The database is to be encrypted as a whole, under these keys (a new data key is made).
    pub fn to_whole_database(mut self, keys: EncryptionConfig) -> Self {
        self.to = Some(EncryptionHandle::new(keys));
        self.to_fields = None;
        self
    }

    /// Overwrite each old file with random bytes, and flush it, before it is removed. This costs
    /// one more write of every old file. It does not reach what the file system keeps elsewhere
    /// (snapshots, a flash drive that moves data when it is rewritten), so it is no guarantee.
    pub fn wipe_originals(mut self, on: bool) -> Self {
        self.wipe_originals = on;
        self
    }

    /// How much room the program says is free: when it is less than the migration needs, it is
    /// refused before anything is written. The library does not ask the system.
    pub fn available_bytes(mut self, available: Available) -> Self {
        self.available = available;
        self
    }

    /// Receive the stages of the migration (names and counts, never a value).
    pub fn on_event(mut self, sink: impl Fn(&LibraryEvent) + Send + Sync + 'static) -> Self {
        self.events = EventSink(Some(Arc::new(sink)));
        self
    }

    #[cfg(test)]
    pub(crate) fn batch_limits(mut self, limits: BatchLimits) -> Self {
        self.limits = limits;
        self
    }

    fn paths(&self) -> Paths {
        let dir = self.dir_path.join(&self.dir_name);
        let backup_dir = match &self.backup_dir_path {
            Some(b) => b.join(&self.dir_name),
            None => dir.clone(),
        };
        Paths {
            main: dir.join(format!("{}.cldb", self.db_name)),
            backup: backup_dir.join(format!("{}.cldb.bak", self.db_name)),
            blobs: crate::blob::blob_root(&dir, &self.db_name),
            records: crate::migration::chain::DbMigrationIndex::migration_path(&dir, &self.db_name),
            dir,
            backup_dir,
        }
    }

    fn emit(&self, event: &'static str, files: u32, rows: u64) {
        self.events.emit(&LibraryEvent::Migration { event, files, rows });
    }

    fn opener(handle: &Option<EncryptionHandle>) -> RedbOptions {
        RedbOptions { encryption: handle.clone(), cache_bytes: Some(super::rows::PAGE_CACHE_BYTES), ..RedbOptions::default() }
    }

    /// Open the old files with the old keys (a wrong key, or a database another program holds,
    /// is refused here), read them, and plan. Writes nothing.
    fn open_source(&self, paths: &Paths) -> Result<Source> {
        if self.from.is_none() && self.to.is_none() && self.from_fields.is_none() && self.to_fields.is_none() {
            return Err(ClError::Validation("the database is plain and is to stay plain: set the keys of one side".into()));
        }
        if !paths.main.is_file() {
            return Err(ClError::Validation(format!("there is no database at {}", paths.main.display())));
        }
        // a database another program has open is refused first (reading its file would fail on
        // Windows with a lock error, not an answer)
        crate::handle::guard_open(&paths.main, false)?;
        let mut head = [0u8; 9];
        let n = fs::File::open(&paths.main).map_err(io)?.read(&mut head).map_err(io)?;
        let plain_file = n == 9 && head == PLAIN_SIGNATURE;
        match (&self.from, plain_file) {
            (None, false) => return Err(ClError::EncryptedOpenFailed),
            (Some(_), true) => {
                return Err(ClError::Validation("the database is not encrypted: start from plain".into()));
            }
            _ => {}
        }
        // the old files are opened to be read only: nothing is written to them, not even what a
        // normal open writes. A file that needs repair has to be opened normally once first.
        let opener = Self::opener(&self.from);
        let main = opener.open_read_only_timed(&paths.main, "main").0?;
        let from_form = match &self.from {
            Some(handle) => Form::Sealed(handle.context().cloned().ok_or(ClError::EncryptedOpenFailed)?),
            None => Form::Plain,
        };
        let protected_tables = rekey::check(&main, &self.declared)?;
        let protected = !protected_tables.is_empty();
        let keyed = |whole: &Option<EncryptionHandle>, fields: &Option<EncryptionConfig>| whole.is_some() || fields.is_some();
        if protected && !(keyed(&self.from, &self.from_fields) && keyed(&self.to, &self.to_fields)) {
            return Err(bad(
                "this database has protected fields: it can be changed from one protection of its keys to another, not to or from plain files with no keys; nothing was changed",
            ));
        }
        if !protected && (self.from_fields.is_some() || self.to_fields.is_some()) {
            return Err(ClError::Validation("this database has no protected fields: there are no field keys to change".into()));
        }
        // the keys of the old file, tried now: a key that does not open it is refused before anything is written
        let old_keys = if protected { Some(self.old_keys(&main, paths)?) } else { None };
        let main_plan = convert::plan_main_with(&main, protected)?;
        let (backup, history_plan) = if paths.backup.is_file() {
            let db = opener.open_read_only_timed(&paths.backup, "bak").0?;
            let plan = history::plan_history(&db)?;
            (Some(db), Some(plan))
        } else {
            (None, None)
        };
        // the attachments of tables with protected fields are kept apart (`{db}.pblobs`), bound to
        // their table, row and file; they are moved by `attachments`
        let mut blobs = sidecars::plan_blobs(&main)?;
        blobs.retain(|b| !protected_tables.iter().any(|(name, _)| *name == b.table));
        let unused_blobs = match &from_form {
            Form::Plain => sidecars::unused_plain_blobs(&paths.blobs, &blobs)?,
            Form::Sealed(_) => 0,
        };
        let records = if paths.records.is_dir() {
            sidecars::plan_records(&from_form, &paths.records, &main_plan.user_tables)?
        } else {
            Vec::new()
        };
        Ok(Source { main, backup, main_plan, history_plan, blobs, records, from_form, unused_blobs, protected, protected_tables, old_keys })
    }

    /// The files and folders that are replaced: (folder, name, a new file takes its place).
    fn targets(&self, paths: &Paths, source: &Source) -> Vec<Target> {
        let mut targets = vec![Target::new(Root::Main, &format!("{}.cldb", self.db_name), true)];
        if source.backup.is_some() {
            targets.push(Target::new(Root::Backup, &format!("{}.cldb.bak", self.db_name), true));
        }
        // the index file is built again from the catalog when the database opens
        let index = format!("{}.inx", self.db_name);
        if paths.dir.join(&index).exists() {
            targets.push(Target::new(Root::Main, &index, false));
        }
        if let Ok(rd) = fs::read_dir(&paths.dir) {
            let mut stale: Vec<String> = rd
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with(&format!("{index}.build-")))
                .collect();
            stale.sort();
            targets.extend(stale.iter().map(|n| Target::new(Root::Main, n, false)));
        }
        if paths.blobs.is_dir() {
            targets.push(Target::new(Root::Main, &format!("{}.blobs", self.db_name), true));
        }
        if paths.records.is_dir() {
            targets.push(Target::new(Root::Main, &format!("{}.migration", self.db_name), true));
        }
        // the copy of the lock of the data key, with the table identities, that a database with
        // protected fields keeps beside it
        if source.protected && self.key_file(paths).is_file() {
            let name = self.key_file(paths).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            targets.push(Target::new(Root::Main, &name, true));
        }
        if source.protected && self.pblobs(paths).is_dir() {
            targets.push(Target::new(Root::Main, &format!("{}.pblobs", self.db_name), true));
        }
        targets
    }

    fn pblobs(&self, paths: &Paths) -> PathBuf {
        crate::blob::protected_blob_root(&paths.dir, &self.db_name)
    }

    /// The attachments of the tables with protected fields, as they are kept now.
    fn protected_place(&self, root: PathBuf, keys: Arc<FieldKeys>, protected: &[(String, String)]) -> attachments::Place {
        let ids: std::collections::HashMap<String, String> = protected.iter().cloned().collect();
        attachments::Place::Protected { root, keys: keys as Arc<dyn crate::encrypted_store::FileKeys>, ids: Arc::new(ids) }
    }

    fn key_file(&self, paths: &Paths) -> PathBuf {
        crate::field_crypto::keyfile::default_path(&paths.dir, &self.db_name)
    }

    /// The keys of the protected fields of the old file, opened with the keys given for it.
    fn old_keys(&self, main: &impl redb::ReadableDatabase, paths: &Paths) -> Result<Arc<FieldKeys>> {
        if let Some(handle) = &self.from {
            let context = handle.context().cloned().ok_or(ClError::EncryptedOpenFailed)?;
            return Ok(Arc::new(FieldKeys::with_context(context)?));
        }
        let config = self.from_fields.as_ref().ok_or(ClError::EncryptedOpenFailed)?;
        self.field_keys_of(config, main)
    }

    /// Open the keys of a database whose protected fields have keys of their own: the lock is in
    /// the main file. A database that keeps it only in a keys file elsewhere (`field_keys_file`) is
    /// refused, before anything is changed: a new data key made for it would not open its fields.
    fn field_keys_of(&self, config: &EncryptionConfig, main: &impl redb::ReadableDatabase) -> Result<Arc<FieldKeys>> {
        let locked = rekey::read_locked(main)?.ok_or_else(|| {
            ClError::Validation(
                "this database keeps the lock of its field keys outside the main file (`field_keys_file`), which this version does not change; nothing was changed".into(),
            )
        })?;
        crate::field_crypto::keystore::open(config, &locked)
    }

    /// The keys of the new file and the lock they are kept under. A new data key is made for keys of
    /// their own; for a whole-database encryption they are the ones the new file was just made with.
    fn new_keys(&self) -> Result<(Arc<FieldKeys>, rekey::NewLock)> {
        if let Some(handle) = &self.to {
            let context = handle.context().cloned().ok_or(ClError::EncryptedOpenFailed)?;
            let locked = context.locked_data_key().clone();
            return Ok((Arc::new(FieldKeys::with_context(context)?), rekey::NewLock { locked, in_main: false }));
        }
        let config = self.to_fields.as_ref().ok_or(ClError::EncryptedOpenFailed)?;
        let (locked, keys) = crate::field_crypto::keystore::create(config)?;
        Ok((keys, rekey::NewLock { locked, in_main: true }))
    }

    /// The keys file of the new keys, next to the old one under its temporary name.
    fn write_key_file(&self, paths: &Paths, source: &Source, rekey: &rekey::Rekey) -> Result<()> {
        let old = self.key_file(paths);
        if !old.is_file() {
            return Ok(());
        }
        let meta = read_meta(&source.main)?.ok_or_else(|| bad("the old main file has no description of its tables"))?;
        let ids: Vec<(String, String)> =
            meta.tables.iter().filter_map(|t| t.table_id.clone().map(|id| (t.name.clone(), id))).collect();
        let bytes = crate::field_crypto::keyfile::encode(&rekey.lock().locked, &ids, rekey.new_keys())?;
        let mut name = old.as_os_str().to_os_string();
        name.push(super::marker::NEW_SUFFIX);
        fs::write(PathBuf::from(name), bytes).map_err(io)
    }

    fn report(&self, paths: &Paths, source: &Source, targets: &[Target]) -> ChangeReport {
        let files: Vec<(Root, &str)> = targets.iter().filter(|t| t.replace).map(|t| (t.root, t.name.as_str())).collect();
        let places = Places { main: &paths.dir, backup: &paths.backup_dir };
        let need = space::required(places, &files, false);
        ChangeReport {
            tables: convert::describe(&source.main_plan)
                .into_iter()
                .map(|(name, how, entries)| TableReport { name, how, entries })
                .collect(),
            history_tables: source
                .history_plan
                .iter()
                .flat_map(|p| p.items.iter())
                .map(|i| TableReport { name: i.name.clone(), how: "copied", entries: i.entries })
                .collect(),
            attachments: source.blobs.len() as u64,
            attachment_bytes: source.blobs.iter().map(|b| b.size).sum(),
            unused_attachment_files: source.unused_blobs,
            records: source.records.len() as u64,
            required_bytes: need.main,
            required_bytes_backup: need.backup,
            replaces: targets.iter().map(|t| t.name.clone()).collect(),
        }
    }

    /// What the migration would do, and how much room it needs. Nothing is written.
    pub fn dry_run(&self) -> Result<ChangeReport> {
        let paths = self.paths();
        let source = self.open_source(&paths)?;
        let targets = self.targets(&paths, &source);
        Ok(self.report(&paths, &source, &targets))
    }

    /// Change the protection. On any failure before the decision the old files are the database,
    /// exactly as they were.
    pub fn execute(&self) -> Result<ChangeDone> {
        let paths = self.paths();
        let places = Places { main: &paths.dir, backup: &paths.backup_dir };
        // a change that a crash cut short is settled first
        Migration::recover(places, &self.db_name)?;
        let source = self.open_source(&paths)?;
        let targets = self.targets(&paths, &source);
        let report = self.report(&paths, &source, &targets);
        space::check(
            space::Required { main: report.required_bytes, backup: report.required_bytes_backup },
            self.available,
        )?;
        let files = targets.len() as u32;
        let user_tables = source.main_plan.user_tables.clone();
        let protected_tables = source.protected_tables.clone();
        let migration = Migration::begin_with(places, &self.db_name, targets, self.wipe_originals)?;
        self.emit("migration/started", files, 0);
        let made = self.write_new_files(&paths, source);
        let mut done = match made {
            Ok(done) => done,
            Err(e) => {
                self.undo(&paths, &migration);
                self.emit("migration/rolled_back", files, 0);
                return Err(e);
            }
        };
        done.files_replaced = files;
        done.unused_attachment_files = report.unused_attachment_files;
        // the decision, then the swap, then a look at what is in place
        let placed = (|| -> Result<()> {
            migration.commit()?;
            self.emit("migration/committed", files, done.rows);
            migration.swap()?;
            maybe_crash("migration_after_swap");
            self.check_in_place(&paths, &user_tables, &protected_tables)
        })();
        if let Err(e) = placed {
            self.undo(&paths, &migration);
            self.emit("migration/rolled_back", files, 0);
            return Err(e);
        }
        if let Err(e) = migration.finish() {
            // the new files are in place; the next open finishes the cleanup
            self.emit("migration/finished", files, done.rows);
            return Err(bad(format!("the database was changed, but cleaning up failed ({e}): open it to finish")));
        }
        self.emit("migration/finished", files, done.rows);
        Ok(done)
    }

    /// Put things back and remove what the attempt made (also what a failed encrypted creation
    /// leaves under its temporary name).
    fn undo(&self, paths: &Paths, migration: &Migration<'_>) {
        let _ = migration.roll_back();
        for base in [&paths.main, &paths.backup] {
            let mut creating = base.as_os_str().to_os_string();
            creating.push(".mig-new.creating");
            let _ = fs::remove_file(PathBuf::from(creating));
        }
    }

    fn write_new_files(&self, paths: &Paths, source: Source) -> Result<ChangeDone> {
        let new_opener = Self::opener(&self.to);
        let mut done = ChangeDone::default();
        let new_name = |p: &Path| -> PathBuf {
            let mut s = p.as_os_str().to_os_string();
            s.push(super::marker::NEW_SUFFIX);
            PathBuf::from(s)
        };
        // the main file first: it is what makes the new data key
        let new_main = new_name(&paths.main);
        let (to_main, _) = new_opener.open_timed(&new_main, true, "main")?;
        let to_form = match &self.to {
            Some(handle) => Form::Sealed(handle.context().cloned().ok_or(ClError::EncryptedOpenFailed)?),
            None => Form::Plain,
        };
        // the protected fields: the keys the old file has and the ones the new file was just made with
        let mut rekey = if source.protected { Some(self.rekey(&source)?) } else { None };
        let moved = match rekey.as_mut() {
            Some(r) => convert::copy_main_with(&source.main, &to_main, &source.main_plan, self.limits, r)?,
            None => convert::copy_main(&source.main, &to_main, &source.main_plan, self.limits)?,
        };
        match rekey.as_mut() {
            Some(r) => convert::verify_main_with(&source.main, &to_main, &source.main_plan, r)?,
            None => convert::verify_main(&source.main, &to_main, &source.main_plan)?,
        }
        done.rows += moved.copied.iter().map(|(_, n)| n).sum::<u64>();
        drop(to_main);
        if let Some(r) = rekey.as_ref() {
            self.write_key_file(paths, &source, r)?;
        }
        maybe_crash("migration_after_main_written");
        if let (Some(from), Some(plan)) = (&source.backup, &source.history_plan) {
            let new_backup = new_name(&paths.backup);
            let (to_backup, _) = new_opener.open_timed(&new_backup, true, "bak")?;
            match rekey.as_ref() {
                Some(r) => {
                    history::copy_history_with(from, &to_backup, plan, self.limits, &mut r.history())?;
                    history::verify_history_with(from, &to_backup, plan, &mut r.history())?;
                }
                None => {
                    history::copy_history(from, &to_backup, plan, self.limits)?;
                    history::verify_history(from, &to_backup, plan)?;
                }
            }
            done.rows += plan.items.iter().map(|i| i.entries).sum::<u64>();
            drop(to_backup);
            maybe_crash("migration_after_history_written");
        }
        if paths.blobs.is_dir() {
            let new_blobs = new_name(&paths.blobs);
            done.attachment_bytes = sidecars::copy_blobs(&source.blobs, &source.from_form, &paths.blobs, &to_form, &new_blobs, true)?;
            sidecars::verify_blobs(&source.blobs, &source.from_form, &paths.blobs, &to_form, &new_blobs)?;
            done.attachments = source.blobs.len() as u64;
            maybe_crash("migration_after_attachments_written");
        }
        if let (Some(r), true) = (rekey.as_ref(), self.pblobs(paths).is_dir()) {
            // sealed again, never copied as they are: the new roots change the key of every file and
            // the name it is kept under
            let (old_keys, new_keys) = r.both_keys();
            let from = self.protected_place(self.pblobs(paths), old_keys, &source.protected_tables);
            let to = self.protected_place(new_name(&self.pblobs(paths)), new_keys, &source.protected_tables);
            let names: Vec<String> = source.protected_tables.iter().map(|(n, _)| n.clone()).collect();
            let copied = attachments::copy_all(&source.main, Some(&names), &from, &to, &mut |_| {})?;
            done.attachments += copied.files;
            done.attachment_bytes += copied.bytes;
            maybe_crash("migration_after_protected_attachments_written");
        }
        if paths.records.is_dir() {
            let new_records = new_name(&paths.records);
            sidecars::copy_records(&source.records, &source.from_form, &paths.records, &to_form, &new_records, true)?;
            sidecars::verify_records(&source.records, &source.from_form, &paths.records, &to_form, &new_records)?;
            maybe_crash("migration_after_records_written");
        }
        // the old files are closed before anything is replaced, and every new file is on disk
        drop(source);
        sync_path(&new_main);
        sync_path(&new_name(&paths.backup));
        sync_path(&new_name(&paths.blobs));
        sync_path(&new_name(&paths.records));
        sync_path(&new_name(&self.key_file(paths)));
        sync_path(&new_name(&self.pblobs(paths)));
        Ok(done)
    }

    /// The change of the keys of the protected fields, from the keys of the old file to the ones the
    /// new file was made with.
    fn rekey(&self, source: &Source) -> Result<rekey::Rekey> {
        let old = source.old_keys.clone().ok_or(ClError::EncryptedOpenFailed)?;
        let (new, lock) = self.new_keys()?;
        rekey::Rekey::plan(&source.main, &self.declared, old, new, lock)
    }

    /// After the swap: the files that are in place open with the new keys and describe the same
    /// tables.
    fn check_in_place(&self, paths: &Paths, tables: &[String], protected: &[(String, String)]) -> Result<()> {
        let (db, _) = Self::opener(&self.to).open_timed(&paths.main, false, "main")?;
        let meta = read_meta(&db)?.ok_or_else(|| bad("the new main file has no description"))?;
        let found: Vec<String> = meta.tables.iter().map(|t| t.name.clone()).collect();
        if &found != tables {
            return Err(bad("the new main file does not describe the tables the old one did"));
        }
        // every attachment of a table with protected fields opens in place, under its new name
        if !protected.is_empty() && self.pblobs(paths).is_dir() {
            let keys = match (&self.to, &self.to_fields) {
                (Some(handle), _) => {
                    let context = handle.context().cloned().ok_or(ClError::EncryptedOpenFailed)?;
                    Arc::new(FieldKeys::with_context(context)?)
                }
                (None, Some(config)) => self.field_keys_of(config, &db)?,
                _ => return Err(ClError::EncryptedOpenFailed),
            };
            let place = self.protected_place(self.pblobs(paths), keys, protected);
            let names: Vec<String> = protected.iter().map(|(n, _)| n.clone()).collect();
            attachments::check_after_swap(&db, &place, Some(&names))?;
        }
        Ok(())
    }
}
