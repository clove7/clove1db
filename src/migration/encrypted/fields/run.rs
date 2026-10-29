//! Making the change: new files written complete next to the old ones, checked, and put in place by
//! one decision (see the marker files). Until that decision the old files are the database and
//! nothing of them has been touched.
use super::{
    analyze::{self, Analysis, Paths},
    api::{ChangeFields, FieldChangeDone, KeyMode},
    hooks::{HistoryRewrite, MainRewrite, Rewriter},
    plan::StepKind,
};
use crate::{
    LibraryEvent,
    field_crypto::{FieldKeys, SealedField, apply_checks, keyfile, settings_checks},
    fsutil::maybe_crash,
    handle::RedbOptions,
    metadata::{store::read_meta, types::CloveMeta},
    migration::encrypted::{
        attachments::{self, Place},
        convert, history,
        marker::{Migration, NEW_SUFFIX, Places, Root},
        rows::BatchLimits,
    },
    units::{ClError, Result},
};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

fn bad(why: impl Into<String>) -> ClError {
    ClError::MigrationError(why.into())
}

fn io(e: std::io::Error) -> ClError {
    ClError::IoError(e.to_string())
}

fn suffixed(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(NEW_SUFFIX);
    PathBuf::from(s)
}

fn sync_path(path: &Path) {
    if let Ok(f) = fs::OpenOptions::new().write(true).open(path) {
        let _ = f.sync_all();
    }
}

/// A new random identity for a table with protected fields: 16 bytes as lower-case hex.
fn new_table_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    crate::crypto::random_bytes(&mut bytes).map_err(|_| bad("the system could not provide random bytes"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// The description the new main file holds: the named tables with the fields the code declares, a
/// field that stays as it is with the description it had, and the identity of each table.
fn build_meta(c: &ChangeFields, a: &Analysis, new_ids: &[Option<String>]) -> Result<Vec<u8>> {
    let mut meta: CloveMeta = a.meta.clone();
    for (i, (plan, (name, specs))) in a.plans.iter().zip(&c.tables).enumerate() {
        let table = meta.tables.iter_mut().find(|t| &t.name == name).ok_or_else(|| bad("a table of the change is not in the description"))?;
        let mut fields = Vec::with_capacity(specs.len());
        for spec in specs.iter() {
            let step = plan.steps.iter().find(|s| s.id == spec.id).ok_or_else(|| bad("a field has no step"))?;
            if step.kind == StepKind::Keep {
                fields.push(step.from.clone().ok_or_else(|| bad("a field that is kept has no description"))?);
                continue;
            }
            let mut field = SealedField::from_spec(spec);
            if let (Some(keys), Some(id)) = (&a.keys, new_ids[i].as_deref()) {
                apply_checks(std::slice::from_mut(&mut field), &settings_checks(keys, id, std::slice::from_ref(spec))?);
            }
            fields.push(field);
        }
        table.sealed = fields;
        table.table_id = new_ids[i].clone();
    }
    Ok(serde_json::to_vec(&meta)?)
}

impl ChangeFields {
    fn emit(&self, event: &'static str, files: u32, rows: u64) {
        self.events.emit(&LibraryEvent::Migration { event, files, rows });
    }

    /// Make the change. On any failure before the decision the old files are the database, exactly as
    /// they were.
    pub fn execute(&self) -> Result<FieldChangeDone> {
        let paths = self.paths();
        let places = Places { main: &paths.dir, backup: &paths.backup_dir };
        // a change that a crash cut short is settled first
        Migration::recover(places, &self.db_name)?;
        let a = analyze::analyze(self)?;
        let nothing = !a.plans.iter().any(|p| p.changes_rows() || p.new_table_id || p.drop_table_id) && a.made_keys.is_none();
        if nothing {
            return Ok(FieldChangeDone::default());
        }
        // the room it needs, checked against what the program says is free
        self.report(&a)?;
        let new_ids = a
            .plans
            .iter()
            .zip(&a.old_ids)
            .map(|(plan, old)| {
                if plan.new_table_id {
                    new_table_id().map(Some)
                } else if plan.drop_table_id {
                    Ok(None)
                } else {
                    Ok(old.clone())
                }
            })
            .collect::<Result<Vec<_>>>()?;
        let meta = build_meta(self, &a, &new_ids)?;
        let rewriter = Rewriter { plans: a.plans.clone(), old_ids: a.old_ids.clone(), new_ids, keys: a.keys.clone() };
        let expected: Vec<(String, Vec<(u32, u8)>)> =
            self.tables.iter().map(|(n, specs)| (n.clone(), specs.iter().map(|s| (s.id, s.method.code())).collect())).collect();
        let files = a.targets.len() as u32;
        let targets = a.targets.clone();
        let migration = Migration::begin_with(places, &self.db_name, targets, self.wipe_originals)?;
        self.emit("migration/started", files, 0);
        let made = self.write_new_files(&paths, a, &rewriter, &meta);
        let (mut done, attached) = match made {
            Ok(made) => made,
            Err(e) => {
                self.undo(&paths, &migration);
                self.emit("migration/rolled_back", files, 0);
                return Err(e);
            }
        };
        done.files_replaced = files;
        // the decision, then the swap, then a look at what is in place
        let placed = (|| -> Result<()> {
            migration.commit()?;
            self.emit("migration/committed", files, done.rows);
            migration.swap()?;
            maybe_crash("fields_after_swap");
            self.check_in_place(&paths, &expected, &attached)
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

    /// Put things back and remove what the attempt made.
    fn undo(&self, paths: &Paths, migration: &Migration<'_>) {
        let _ = migration.roll_back();
        for base in [&paths.main, &paths.backup] {
            let mut creating = suffixed(base).into_os_string();
            creating.push(".creating");
            let _ = fs::remove_file(PathBuf::from(creating));
        }
    }

    /// How the files are opened: for a database encrypted as a whole, with the one handle that opened
    /// the old main file, so every new file is made with the same data key and carries the same lock
    /// (the fields that are not touched stay the very bytes they were).
    fn opener(&self) -> RedbOptions {
        match &self.keys {
            KeyMode::Whole(handle) => RedbOptions {
                encryption: Some(handle.clone()),
                cache_bytes: Some(crate::migration::encrypted::rows::PAGE_CACHE_BYTES),
                ..RedbOptions::default()
            },
            _ => RedbOptions { cache_bytes: Some(crate::migration::encrypted::rows::PAGE_CACHE_BYTES), ..RedbOptions::default() },
        }
    }

    /// The attachments that changed place, as they must be found after the swap.
    fn move_attachments(&self, paths: &Paths, a: &Analysis, meta: &[u8], done: &mut FieldChangeDone) -> Result<Attached> {
        let (blobs, pblobs) = (crate::blob::blob_root(&paths.dir, &self.db_name), crate::blob::protected_blob_root(&paths.dir, &self.db_name));
        let keys = a.keys.clone().ok_or_else(|| bad("the attachments cannot be moved without the keys of the fields; nothing was changed"))?;
        let ids_of = |meta: &CloveMeta| -> HashMap<String, String> {
            meta.tables.iter().filter(|t| !t.sealed.is_empty()).filter_map(|t| t.table_id.clone().map(|id| (t.name.clone(), id))).collect()
        };
        let (old_ids, new_ids) = (ids_of(&a.meta), ids_of(&serde_json::from_slice::<CloveMeta>(meta)?));
        let plain_place = |root: PathBuf| -> Result<Place> {
            Ok(match &self.keys {
                KeyMode::Whole(handle) => {
                    Place::WholeDb { root, context: handle.context().cloned().ok_or(ClError::EncryptedOpenFailed)? }
                }
                _ => Place::Plain { root },
            })
        };
        let protected_place = |root: PathBuf, ids: &HashMap<String, String>| Place::Protected {
            root,
            keys: keys.clone() as Arc<dyn crate::encrypted_store::FileKeys>,
            ids: Arc::new(ids.clone()),
        };
        let to_protected: Vec<String> = a.moves.iter().filter(|m| m.to_protected).map(|m| m.table.clone()).collect();
        let to_plain: Vec<String> = a.moves.iter().filter(|m| !m.to_protected).map(|m| m.table.clone()).collect();
        let (new_blobs, new_pblobs) = (suffixed(&blobs), suffixed(&pblobs));
        // what stays where it is, byte for byte: its keys and names do not change
        attachments::carry_over(&plain_place(blobs.clone())?, &new_blobs, &to_protected)?;
        attachments::carry_over(&protected_place(pblobs.clone(), &old_ids), &new_pblobs, &to_plain)?;
        // what changes place is sealed again (or opened) piece by piece, and checked as it is made
        let mut moved = attachments::Copied::default();
        if !to_protected.is_empty() {
            let copied = attachments::copy_all(&a.main, Some(&to_protected), &plain_place(blobs.clone())?, &protected_place(new_pblobs, &new_ids), &mut |_| {})?;
            moved.files += copied.files;
            moved.bytes += copied.bytes;
        }
        if !to_plain.is_empty() {
            let copied = attachments::copy_all(&a.main, Some(&to_plain), &protected_place(pblobs, &old_ids), &plain_place(new_blobs)?, &mut |_| {})?;
            moved.files += copied.files;
            moved.bytes += copied.bytes;
        }
        done.attachments_moved = moved.files;
        done.attachment_bytes_moved = moved.bytes;
        maybe_crash("fields_after_attachments_written");
        Ok(Attached { keys: Some(keys), new_ids, to_protected, to_plain })
    }

    fn write_new_files(&self, paths: &Paths, a: Analysis, rewriter: &Rewriter, meta: &[u8]) -> Result<(FieldChangeDone, Attached)> {
        let opener = self.opener();
        let mut done = FieldChangeDone::default();
        let new_main = suffixed(&paths.main);
        let (to_main, _) = opener.open_timed(&new_main, true, "main")?;
        let mut hooks = MainRewrite { rewriter, meta: meta.to_vec(), made_keys: a.made_keys.clone() };
        let moved = convert::copy_main_with(&a.main, &to_main, &a.main_plan, BatchLimits::DEFAULT, &mut hooks)?;
        convert::verify_main_with(&a.main, &to_main, &a.main_plan, &mut hooks)?;
        done.rows = moved.copied.iter().map(|(_, n)| n).sum::<u64>();
        drop(to_main);
        maybe_crash("fields_after_main_written");
        let new_backup = suffixed(&paths.backup);
        let with_backup = a.targets.iter().any(|t| t.root == Root::Backup);
        if with_backup && let (Some(from), Some(plan)) = (&a.backup, &a.history_plan) {
            let (to_backup, _) = opener.open_timed(&new_backup, true, "bak")?;
            let mut hooks = HistoryRewrite { rewriter };
            history::copy_history_with(from, &to_backup, plan, BatchLimits::DEFAULT, &mut hooks)?;
            history::verify_history_with(from, &to_backup, plan, &mut hooks)?;
            done.versions = plan.items.iter().filter(|i| i.kind == history::Kind::Versions).map(|i| i.entries).sum();
            drop(to_backup);
            maybe_crash("fields_after_history_written");
        }
        // the keys file: the locked data key and the identities of the tables, beside the main file
        let keys_name = format!("{}.keys", self.db_name);
        let new_keys = suffixed(&paths.dir.join(&keys_name));
        if a.targets.iter().any(|t| t.name == keys_name && t.replace) {
            let described: CloveMeta = serde_json::from_slice(meta)?;
            let wanted: Vec<(String, String)> =
                described.tables.iter().filter_map(|t| t.table_id.clone().map(|id| (t.name.clone(), id))).collect();
            let (Some(locked), Some(keys)) = (&a.locked, &a.keys) else {
                return Err(bad("the keys file cannot be made without the keys; nothing was changed"));
            };
            fs::write(&new_keys, keyfile::encode(locked, &wanted, keys)?).map_err(io)?;
            sync_path(&new_keys);
            maybe_crash("fields_after_keyfile_written");
        }
        // the attachments of the tables that gained their first protected field or lost their last
        let attached = if a.moves.is_empty() {
            Attached::default()
        } else {
            self.move_attachments(paths, &a, meta, &mut done)?
        };
        // the old files are closed before anything is replaced, and every new file is on disk
        drop(a);
        sync_path(&new_main);
        sync_path(&new_backup);
        sync_path(&suffixed(&crate::blob::blob_root(&paths.dir, &self.db_name)));
        sync_path(&suffixed(&crate::blob::protected_blob_root(&paths.dir, &self.db_name)));
        Ok((done, attached))
    }

    /// After the swap: the files that are in place open, and describe the fields that were asked for.
    fn check_in_place(&self, paths: &Paths, expected: &[(String, Vec<(u32, u8)>)], attached: &Attached) -> Result<()> {
        let (db, _) = self.opener().open_timed(&paths.main, false, "main")?;
        let meta = read_meta(&db)?.ok_or_else(|| bad("the new main file has no description"))?;
        for (name, fields) in expected {
            let table = meta.tables.iter().find(|t| &t.name == name).ok_or_else(|| bad("the new main file lacks a table"))?;
            let mut found: Vec<(u32, u8)> = table.sealed.iter().map(|f| (f.id, f.method)).collect();
            let mut want = fields.clone();
            found.sort();
            want.sort();
            if found != want {
                return Err(bad("the new main file does not describe the fields that were asked for"));
            }
        }
        // every attachment that changed place opens where it is now, under the name it is read by
        if let Some(keys) = &attached.keys {
            let (blobs, pblobs) = (crate::blob::blob_root(&paths.dir, &self.db_name), crate::blob::protected_blob_root(&paths.dir, &self.db_name));
            if !attached.to_protected.is_empty() {
                let place = Place::Protected {
                    root: pblobs,
                    keys: keys.clone() as Arc<dyn crate::encrypted_store::FileKeys>,
                    ids: Arc::new(attached.new_ids.clone()),
                };
                attachments::check_after_swap(&db, &place, Some(&attached.to_protected))?;
            }
            if !attached.to_plain.is_empty() {
                let place = match &self.keys {
                    KeyMode::Whole(handle) => {
                        Place::WholeDb { root: blobs, context: handle.context().cloned().ok_or(ClError::EncryptedOpenFailed)? }
                    }
                    _ => Place::Plain { root: blobs },
                };
                attachments::check_after_swap(&db, &place, Some(&attached.to_plain))?;
            }
        }
        Ok(())
    }
}

/// The attachments that changed place: where they must be found after the swap.
#[derive(Default)]
struct Attached {
    keys: Option<Arc<FieldKeys>>,
    /// The identity each table with protected fields has in the new description.
    new_ids: HashMap<String, String>,
    to_protected: Vec<String>,
    to_plain: Vec<String>,
}
