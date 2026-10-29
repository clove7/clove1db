//! Replacing the files of a database with new ones, so that after any crash the database is either
//! exactly as it was or exactly as it is meant to become.
//!
//! The new files are written next to the old ones under the name `{file}.mig-new`. Nothing is
//! replaced until every new file is complete. The decision is one file: `{db}.migrating.commit`,
//! made in one step and flushed. Without it the old files are the database; with it the new ones
//! are. A file cannot be replaced in one step on every system (on Windows the replace is a move
//! aside and a move in), so each file goes through its own sequence, and the state of every file is
//! told by which of its three names exist (`file`, `file.mig-new`, `file.mig-old`). Every step can
//! be run again.
//!
//! `{db}.migrating` lists the files and is written first. The folder is flushed after each
//! rename and each removal.
use crate::fsutil::maybe_crash;
use crate::units::{ClError, Result};
use crate::upgrade::pipeline::sync_folder;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) const NEW_SUFFIX: &str = ".mig-new";
pub(crate) const OLD_SUFFIX: &str = ".mig-old";
const INTENT_SUFFIX: &str = ".migrating";
const COMMIT_SUFFIX: &str = ".migrating.commit";

/// `fs::rename`, tried a few times on Windows: a program that has just opened the file without
/// allowing deletion (a virus scanner, a search indexer, a program that watches the folder) makes the
/// move fail for a moment with "access denied".
fn rename(from: &Path, to: &Path) -> std::io::Result<()> {
    const TRIES: u32 = 12;
    let mut attempt = 0;
    loop {
        match fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) if cfg!(windows) && e.kind() == std::io::ErrorKind::PermissionDenied && attempt + 1 < TRIES => {
                attempt += 1;
                std::thread::sleep(std::time::Duration::from_millis(10 * u64::from(attempt)));
            }
            Err(e) => return Err(e),
        }
    }
}

/// Which folder a file lives in: the database folder, or the folder of the backup file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) enum Root {
    Main,
    Backup,
}

/// One file or folder that the migration replaces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Target {
    pub root: Root,
    /// A single name, no path.
    pub name: String,
    /// `true` when a new file takes its place; `false` when it is only removed (it is made again
    /// by the library when needed).
    pub replace: bool,
    /// Set when the migration begins: whether the file was there. Putting things back needs it.
    #[serde(default)]
    pub existed: bool,
}

impl Target {
    pub(crate) fn new(root: Root, name: &str, replace: bool) -> Self {
        Self { root, name: name.to_string(), replace, existed: false }
    }
}

#[derive(Serialize, Deserialize)]
struct Intent {
    version: u8,
    targets: Vec<Target>,
    #[serde(default)]
    wipe: bool,
}

/// What `recover` found and did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Recovery {
    /// No migration was under way.
    Nothing,
    /// The commit had not been made: the old files stay, everything of the attempt is removed.
    RolledBack,
    /// The commit had been made: the new files are in place and the old ones are removed.
    RolledForward,
}

/// The two folders. The same path twice when the backup file lives next to the database.
#[derive(Clone, Copy)]
pub(crate) struct Places<'a> {
    pub main: &'a Path,
    pub backup: &'a Path,
}

pub(crate) struct Migration<'a> {
    places: Places<'a>,
    db_name: &'a str,
    targets: Vec<Target>,
    /// Overwrite each old file with random bytes, and flush it, before it is removed.
    wipe: bool,
    /// The marker file, locked for as long as the migration lives. Another program that opens the
    /// database finds the marker locked and is refused; when this process dies the system frees the
    /// lock and the next open settles what is left.
    _lock: Option<fs::File>,
}

/// Take the exclusive lock of a marker file without waiting: held by someone alive is
/// [`ClError::DatabaseInUse`].
fn lock_or_busy(file: &fs::File, path: &Path) -> Result<()> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(fs::TryLockError::WouldBlock) => Err(ClError::DatabaseInUse { path: path.display().to_string() }),
        Err(fs::TryLockError::Error(e)) => Err(e.into()),
    }
}

/// Overwrite a file (or every file in a folder) with random bytes and flush it. The length does
/// not change. This does not reach copies the file system keeps (snapshots, a flash drive that
/// moves data when it is rewritten).
fn wipe_path(path: &Path) -> Result<()> {
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            wipe_path(&entry?.path())?;
        }
        return Ok(());
    }
    let mut file = fs::OpenOptions::new().write(true).open(path)?;
    let mut left = file.metadata()?.len();
    let mut buf = vec![0u8; 1 << 20];
    while left > 0 {
        let n = left.min(buf.len() as u64) as usize;
        crate::crypto::random_bytes(&mut buf[..n]).map_err(|_| bad("no random source"))?;
        std::io::Write::write_all(&mut file, &buf[..n])?;
        left -= n as u64;
    }
    file.sync_all()?;
    Ok(())
}

fn bad(why: &str) -> ClError {
    ClError::MigrationError(why.to_string())
}

fn remove_any(path: &Path) -> Result<()> {
    let result = if path.is_dir() { fs::remove_dir_all(path) } else { fs::remove_file(path) };
    match result {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

fn check_targets(targets: &[Target]) -> Result<()> {
    for t in targets {
        let n = t.name.as_str();
        if n.is_empty() || n == "." || n == ".." || n.contains(['/', '\\']) || n.ends_with(NEW_SUFFIX) || n.ends_with(OLD_SUFFIX) {
            return Err(bad("a file name of the migration is not valid"));
        }
    }
    let mut seen = std::collections::HashSet::new();
    if !targets.iter().all(|t| seen.insert((t.root, t.name.clone()))) {
        return Err(bad("a file is listed twice in the migration"));
    }
    Ok(())
}

impl<'a> Migration<'a> {
    fn intent_path(places: &Places<'_>, db_name: &str) -> PathBuf {
        places.main.join(format!("{db_name}{INTENT_SUFFIX}"))
    }

    fn commit_path(places: &Places<'_>, db_name: &str) -> PathBuf {
        places.main.join(format!("{db_name}{COMMIT_SUFFIX}"))
    }

    /// The name the marker has while it is being made.
    fn begin_path(places: &Places<'_>, db_name: &str) -> PathBuf {
        places.main.join(format!("{db_name}{INTENT_SUFFIX}.begin"))
    }

    fn path(&self, t: &Target, suffix: &str) -> PathBuf {
        let base = match t.root {
            Root::Main => self.places.main,
            Root::Backup => self.places.backup,
        };
        base.join(format!("{}{suffix}", t.name))
    }

    fn flush(&self) {
        // best effort: not every system lets a folder be flushed
        let _ = sync_folder(self.places.main);
        if self.places.backup != self.places.main {
            let _ = sync_folder(self.places.backup);
        }
    }

    /// Start a migration of `targets`. Refuses when one is already under way (or was cut short and
    /// has not been recovered yet): nothing is written then.
    pub(crate) fn begin(places: Places<'a>, db_name: &'a str, targets: Vec<Target>) -> Result<Self> {
        Self::begin_with(places, db_name, targets, false)
    }

    /// [`Self::begin`], with the choice to overwrite the old files before they are removed. The
    /// choice is kept in the marker, so a recovery after a crash does the same.
    pub(crate) fn begin_with(places: Places<'a>, db_name: &'a str, targets: Vec<Target>, wipe: bool) -> Result<Self> {
        check_targets(&targets)?;
        let mut migration = Self { places, db_name, targets, wipe, _lock: None };
        if Self::intent_path(&places, db_name).exists()
            || Self::begin_path(&places, db_name).exists()
            || Self::commit_path(&places, db_name).exists()
            || migration.targets.iter().any(|t| migration.path(t, NEW_SUFFIX).exists() || migration.path(t, OLD_SUFFIX).exists())
        {
            return Err(bad("a migration of this database is under way or was cut short: open the database to finish it"));
        }
        let existing: Vec<bool> = migration.targets.iter().map(|t| migration.path(t, "").exists()).collect();
        for (t, existed) in migration.targets.iter_mut().zip(existing) {
            t.existed = existed;
        }
        let bytes = serde_json::to_vec(&Intent { version: 1, targets: migration.targets.clone(), wipe })?;
        // The marker is made under a temporary name, locked, written, and only then given its real
        // name: a program that finds the real name always finds a marker that is whole and locked.
        let path = Self::intent_path(&places, db_name);
        let temporary = Self::begin_path(&places, db_name);
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&temporary)?;
        let made = (|| -> Result<()> {
            lock_or_busy(&file, &temporary)?;
            std::io::Write::write_all(&mut file, &bytes)?;
            file.sync_all()?;
            match fs::hard_link(&temporary, &path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(bad("a migration of this database is under way")),
                Err(_) if !path.exists() => Ok(rename(&temporary, &path)?),
                Err(e) => Err(e.into()),
            }
        })();
        let _ = fs::remove_file(&temporary);
        made?;
        migration._lock = Some(file);
        migration.flush();
        maybe_crash("migration_after_begin");
        Ok(migration)
    }

    /// Where the new version of target `index` is written.
    pub(crate) fn new_path(&self, index: usize) -> PathBuf {
        self.path(&self.targets[index], NEW_SUFFIX)
    }

    /// Make the decision. Every new file must be there; the old ones are still the database until
    /// this returns.
    pub(crate) fn commit(&self) -> Result<()> {
        for t in self.targets.iter().filter(|t| t.replace) {
            if !self.path(t, NEW_SUFFIX).exists() {
                return Err(bad("a new file is missing: nothing was committed"));
            }
        }
        maybe_crash("migration_before_commit");
        let path = Self::commit_path(&self.places, self.db_name);
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&path)?;
        std::io::Write::write_all(&mut file, b"1").and_then(|_| file.sync_all())?;
        drop(file);
        self.flush();
        maybe_crash("migration_after_commit");
        Ok(())
    }

    /// Move the old file of target `index` aside (it is only moved, never rewritten).
    pub(crate) fn aside(&self, index: usize) -> Result<()> {
        let t = &self.targets[index];
        let (file, old) = (self.path(t, ""), self.path(t, OLD_SUFFIX));
        // A file that is to be replaced is the old one only while its new file is still waiting;
        // after that it is the new one and must stay.
        let waiting = !t.replace || self.path(t, NEW_SUFFIX).exists();
        if waiting && file.exists() && !old.exists() {
            maybe_crash(&format!("migration_before_aside_{index}"));
            rename(&file, &old)?;
            self.flush();
            maybe_crash(&format!("migration_after_aside_{index}"));
        }
        Ok(())
    }

    /// Give the new file of target `index` its real name.
    pub(crate) fn place(&self, index: usize) -> Result<()> {
        let t = &self.targets[index];
        if !t.replace {
            return Ok(());
        }
        let (file, new) = (self.path(t, ""), self.path(t, NEW_SUFFIX));
        if new.exists() && !file.exists() {
            maybe_crash(&format!("migration_before_place_{index}"));
            rename(&new, &file)?;
            self.flush();
            maybe_crash(&format!("migration_after_place_{index}"));
        }
        Ok(())
    }

    /// The state of every target must be one the sequence can produce; anything else stops here.
    fn check_state(&self, t: &Target) -> Result<()> {
        let (f, n, o) = (self.path(t, "").exists(), self.path(t, NEW_SUFFIX).exists(), self.path(t, OLD_SUFFIX).exists());
        if f && n && o {
            return Err(bad("the files of the migration are in a state this version does not know"));
        }
        if t.replace && !f && !n {
            return Err(bad("the files of the migration are in a state this version does not know"));
        }
        Ok(())
    }

    /// The whole swap: every file moved aside and replaced, in order. Can be run again.
    pub(crate) fn swap(&self) -> Result<()> {
        for t in &self.targets {
            self.check_state(t)?;
        }
        for index in 0..self.targets.len() {
            self.aside(index)?;
            self.place(index)?;
        }
        Ok(())
    }

    /// Overwrite the old file of target `index` with random bytes (the same length), if it is there.
    pub(crate) fn wipe_old(&self, index: usize) -> Result<()> {
        let old = self.path(&self.targets[index], OLD_SUFFIX);
        if old.exists() {
            maybe_crash(&format!("migration_before_wipe_{index}"));
            wipe_path(&old)?;
            maybe_crash(&format!("migration_after_wipe_{index}"));
        }
        Ok(())
    }

    pub(crate) fn remove_old(&self, index: usize) -> Result<()> {
        let old = self.path(&self.targets[index], OLD_SUFFIX);
        if old.exists() {
            if self.wipe {
                self.wipe_old(index)?;
            }
            maybe_crash(&format!("migration_before_remove_{index}"));
            remove_any(&old)?;
            self.flush();
        }
        Ok(())
    }

    pub(crate) fn remove_intent(&self) -> Result<()> {
        remove_any(&Self::intent_path(&self.places, self.db_name))?;
        self.flush();
        Ok(())
    }

    pub(crate) fn remove_commit(&self) -> Result<()> {
        remove_any(&Self::commit_path(&self.places, self.db_name))?;
        self.flush();
        Ok(())
    }

    /// After the swap: remove the old files, then the markers.
    pub(crate) fn finish(&self) -> Result<()> {
        for index in 0..self.targets.len() {
            self.remove_old(index)?;
        }
        maybe_crash("migration_before_markers_removed");
        self.remove_intent()?;
        self.remove_commit()?;
        maybe_crash("migration_after_markers_removed");
        Ok(())
    }

    /// Put the old files back and remove everything of the attempt. The decision is withdrawn
    /// first, so a crash in the middle is finished as a rollback. Only valid until `finish` starts
    /// removing the old files.
    pub(crate) fn roll_back(&self) -> Result<()> {
        self.remove_commit()?;
        for index in 0..self.targets.len() {
            self.restore(index)?;
        }
        self.remove_intent()
    }

    /// Put target `index` back as it was before the migration. Can be run again.
    pub(crate) fn restore(&self, index: usize) -> Result<()> {
        let t = &self.targets[index];
        let (file, new, old) = (self.path(t, ""), self.path(t, NEW_SUFFIX), self.path(t, OLD_SUFFIX));
        maybe_crash(&format!("migration_before_restore_{index}"));
        if !t.existed {
            // it was not there before: whatever is there now was made by the migration
            remove_any(&file)?;
        } else if old.exists() {
            remove_any(&file)?; // the new file that took its place, if it did
            rename(&old, &file)?;
        }
        remove_any(&new)?;
        // an encrypted file is made under this name and renamed when it is whole
        let mut creating = new.into_os_string();
        creating.push(".creating");
        remove_any(Path::new(&creating))?;
        self.flush();
        Ok(())
    }

    /// Whether a migration of this database is running (its marker is locked): [`ClError::DatabaseInUse`]
    /// if so. Changes nothing, so a program that opens several databases can ask this of all of
    /// them before it settles any.
    pub(crate) fn check_free(places: Places<'_>, db_name: &str) -> Result<()> {
        for path in [Self::begin_path(&places, db_name), Self::intent_path(&places, db_name)] {
            if let Ok(file) = fs::File::open(&path) {
                lock_or_busy(&file, &path)?;
            }
        }
        Ok(())
    }

    /// Settle a migration that a crash cut short. Call it before any file of the database is
    /// opened. No marker: nothing to do. A marker without the decision: the old files are the
    /// database, the attempt is removed. With the decision: the swap is finished.
    pub(crate) fn recover(places: Places<'_>, db_name: &str) -> Result<Recovery> {
        let intent_path = Self::intent_path(&places, db_name);
        let commit_path = Self::commit_path(&places, db_name);
        // A marker still being made: held by a live migration, or left by one that died before it
        // was given its name.
        let begin_path = Self::begin_path(&places, db_name);
        if let Ok(file) = fs::File::open(&begin_path) {
            lock_or_busy(&file, &begin_path)?;
            drop(file);
            let _ = fs::remove_file(&begin_path);
        }
        let (has_intent, has_commit) = (intent_path.exists(), commit_path.exists());
        if !has_intent {
            if has_commit {
                // the markers are removed one after the other; the decision was the last to go
                remove_any(&commit_path)?;
                let _ = sync_folder(places.main);
                return Ok(Recovery::RolledForward);
            }
            return Ok(Recovery::Nothing);
        }
        // A marker that is locked belongs to a migration that is running: it is neither undone nor
        // finished, and the database is not opened. The lock of a program that died is free.
        let mut file = match fs::File::open(&intent_path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Recovery::Nothing),
            Err(e) => return Err(e.into()),
        };
        lock_or_busy(&file, &intent_path)?;
        let mut text = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut text)?;
        let intent: Intent = serde_json::from_slice(&text)
            .map_err(|_| bad("the marker of an unfinished migration cannot be read"))?;
        if intent.version != 1 {
            return Err(bad("the marker of an unfinished migration is of a newer version"));
        }
        check_targets(&intent.targets)?;
        // the lock is kept until the recovery is over, so two openings do not both recover
        let migration = Migration { places, db_name, targets: intent.targets, wipe: intent.wipe, _lock: Some(file) };
        if has_commit {
            migration.swap()?;
            migration.finish()?;
            Ok(Recovery::RolledForward)
        } else {
            migration.roll_back()?;
            Ok(Recovery::RolledBack)
        }
    }
}
