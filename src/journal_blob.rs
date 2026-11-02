use crate::{
    fsutil::maybe_crash,
    journal::{CHANGES, ChangeKind},
    repository::DatabaseManager,
    units::{ClError, Result},
};
use redb::{ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use crate::blob::BlobReader;
use std::collections::HashSet;
pub(crate) const REFS: TableDefinition<&str, &[u8]> = TableDefinition::new("__blob_refs");
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BlobRef {
    pub id: String,
    pub size: u64,
}
/// True for the name of a file `fsutil::write_atomic` was writing: `{name}.tmp.{pid}.{time}.{counter}`. A name that
/// only ends in `.tmp` is a key like any other.
pub(crate) fn is_temporary_name(name: &str) -> bool {
    let mut parts = name.rsplitn(5, '.');
    let numbers = (0..3).all(|_| parts.next().is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())));
    numbers && parts.next() == Some("tmp")
}
pub(crate) fn key(table: &str, id: &str) -> String {
    serde_json::to_string(&(table, id)).expect("string pair")
}
pub(crate) fn get(tx: &redb::WriteTransaction, table: &str, id: &str) -> Result<Option<BlobRef>> {
    tx.open_table(REFS)?
        .get(key(table, id).as_str())?
        .map(|v| serde_json::from_slice(v.value()).map_err(Into::into))
        .transpose()
}
pub(crate) fn put(
    tx: &redb::WriteTransaction,
    table: &str,
    id: &str,
    reference: &BlobRef,
    changes: &mut Vec<ChangeKind>,
) -> Result<()> {
    tx.open_table(REFS)?.insert(
        key(table, id).as_str(),
        serde_json::to_vec(reference)?.as_slice(),
    )?;
    changes.push(ChangeKind::BlobPut {
        table: table.into(),
        key: id.into(),
        blob_id: reference.id.clone(),
        size: reference.size,
    });
    Ok(())
}
pub(crate) fn remove(
    tx: &redb::WriteTransaction,
    table: &str,
    id: &str,
    changes: &mut Vec<ChangeKind>,
) -> Result<bool> {
    let old = tx
        .open_table(REFS)?
        .remove(key(table, id).as_str())?
        .map(|v| serde_json::from_slice::<BlobRef>(v.value()))
        .transpose()?;
    if let Some(old) = old {
        changes.push(ChangeKind::BlobDelete {
            table: table.into(),
            key: id.into(),
            blob_id: old.id,
            size: old.size,
        });
        Ok(true)
    } else {
        Ok(false)
    }
}
impl DatabaseManager {
    /// `row` is the row the attachment belongs to; a table with protected fields binds the file to it.
    pub(crate) fn prepare_blob(&self, table: &str, row: &str, bytes: &[u8]) -> Result<BlobRef> {
        crate::journal::validate_table(table)?;
        if table.is_empty() || table.contains(['/', '\\', ':']) || table == ".." || table == "." {
            return Err(ClError::Validation("invalid blob table path".into()));
        }
        if !self.is_blob_table(table) {
            return Err(ClError::Validation("not a blob table".into()));
        }
        let id = format!("__v_{}", uuid::Uuid::new_v4());
        self.blob_store()?
            .write_atomic_with_mode(table, row, &id, bytes, self.durability())?;
        maybe_crash("journal_blob_before_descriptor");
        Ok(BlobRef {
            id,
            size: bytes.len() as u64,
        })
    }
    pub(crate) fn publish_blob(
        &self,
        table: &str,
        id: &str,
        bytes: &[u8],
        metadata: Option<Vec<u8>>,
    ) -> Result<()> {
        let blob = self.prepare_blob(table, id, bytes)?;
        self.journal_write(|tx, changes| {
            put(tx, table, id, &blob, changes)?;
            if let Some(value) = &metadata {
                tx.open_table(TableDefinition::<&str, &[u8]>::new(table))?
                    .insert(id, value.as_slice())?;
                changes.push(ChangeKind::Upsert {
                    table: table.into(),
                    key: id.into(),
                    value: value.clone(),
                });
            }
            Ok(())
        })?;
        if self.has_cache
            && let Some(value) = metadata
        {
            self.memory_cache.insert(format!("{table}:{id}"), value);
        }
        maybe_crash("journal_blob_after_descriptor");
        Ok(())
    }
    pub(crate) fn validate_blob_rows(
        &self,
        tx: &redb::WriteTransaction,
        table: &str,
        changes: &mut Vec<ChangeKind>,
    ) -> Result<()> {
        if !self.is_blob_table(table) {
            return Ok(());
        }
        let rows = tx.open_table(TableDefinition::<&str, &[u8]>::new(table))?;
        for row in rows.iter()? {
            let (k, _) = row?;
            let r = get(tx, table, k.value())?
                .ok_or_else(|| ClError::Validation("blob metadata has no immutable file".into()))?;
            if self.open_blob_version_row(table, k.value(), &r.id)?.len()? != r.size {
                return Err(ClError::Validation(
                    "blob size differs from reference".into(),
                ));
            }
        }
        let keys = tx
            .open_table(REFS)?
            .iter()?
            .map(|r| {
                let (k, _) = r?;
                Ok(serde_json::from_str::<(String, String)>(k.value())?)
            })
            .collect::<Result<Vec<_>>>()?;
        for (t, k) in keys {
            if t == table && rows.get(k.as_str())?.is_none() {
                remove(tx, table, &k, changes)?;
            }
        }
        Ok(())
    }
    /// Open immutable bytes referenced by a journal record or reset image.
    pub fn open_blob_version(&self, table: &str, blob_id: &str) -> Result<BlobReader> {
        if [table, blob_id]
            .iter()
            .any(|s| s.is_empty() || s.contains(['/', '\\', ':']) || *s == ".." || *s == ".")
        {
            return Err(ClError::Validation("invalid blob path component".into()));
        }
        self.blob_store()?.open_read(table, blob_id)
    }
    /// [`Self::open_blob_version`] for the attachment of one row. A table with protected fields
    /// binds each attachment file to its row, so only this form opens them: the file opens only if
    /// it was sealed for exactly this table, row and file.
    pub fn open_blob_version_row(&self, table: &str, row: &str, blob_id: &str) -> Result<BlobReader> {
        if [table, blob_id]
            .iter()
            .any(|s| s.is_empty() || s.contains(['/', '\\', ':']) || *s == ".." || *s == ".")
        {
            return Err(ClError::Validation("invalid blob path component".into()));
        }
        self.blob_store()?.open_read_row(table, row, blob_id)
    }
    pub(crate) fn open_current_blob(&self, table: &str, id: &str) -> Result<BlobReader> {
        let db = self.db()?;
        let tx = db.begin_read()?;
        let refs = tx.open_table(REFS)?;
        let reference: BlobRef = refs
            .get(key(table, id).as_str())?
            .map(|v| serde_json::from_slice(v.value()))
            .transpose()?
            .ok_or_else(|| ClError::NotFound("blob reference".into()))?;
        self.open_blob_version_row(table, id, &reference.id)
    }
    pub(crate) fn prepare_copy_from(
        &self,
        source: &DatabaseManager,
        source_table: &str,
        source_key: &str,
        table: &str,
        row: &str,
    ) -> Result<BlobRef> {
        crate::journal::validate_table(table)?;
        if !self.is_blob_table(table)
            || table.is_empty()
            || table.contains(['/', '\\', ':'])
            || table == ".."
            || table == "."
        {
            return Err(ClError::Validation("invalid blob table".into()));
        }
        let mut input = source.open_current_blob(source_table, source_key)?;
        let id = format!("__v_{}", uuid::Uuid::new_v4());
        self.blob_store()?.ensure_table(table)?;
        if self.blob_store()?.is_sealed() || self.blob_store()?.is_protected(table) {
            // sealed, piece by piece, with a sealed temporary file from the first byte
            let size = self.blob_store()?.write_stream(table, row, &id, &mut input, self.durability())?;
            maybe_crash("journal_blob_before_descriptor");
            return Ok(BlobRef { id, size });
        }
        let target = self.blob_store()?.path(table, &id);
        let temporary = target.with_extension("tmp");
        let result = (|| -> Result<u64> {
            let mut output = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            let size = std::io::copy(&mut input, &mut output)?;
            if self.durability().is_strict() {
                output.sync_all()?;
            }
            drop(output);
            std::fs::rename(&temporary, &target)?;
            Ok(size)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        let size = result?;
        maybe_crash("journal_blob_before_descriptor");
        Ok(BlobRef { id, size })
    }
    pub(crate) fn copy_current_blob(
        &self,
        table: &str,
        id: &str,
        dest: &DatabaseManager,
        dest_table: &str,
        dest_id: &str,
    ) -> Result<()> {
        let reference = dest.prepare_copy_from(self, table, id, dest_table, dest_id)?;
        dest.journal_write(|tx, changes| put(tx, dest_table, dest_id, &reference, changes))
    }
    /// A database that had no log when it was opened (see `journal::mark_adoption_due`) may hold
    /// attachment files an older version wrote with `write_blob`, which keeps no reference and no row. Each
    /// attachment table of this database that was not adopted yet gets a reference, `(table, file name)`
    /// with the size of the file, for every such file, and is recorded as adopted in the same transaction.
    /// Once recorded, a table is never adopted again, so an attachment its user deletes does not come back;
    /// and a table that is registered later is adopted when it first is. This version writes only
    /// `__v_*` names, so a table made by it has nothing to adopt. Temporary files are left to the clean-up.
    fn adopt_legacy_files(&self, tx: &redb::WriteTransaction) -> Result<()> {
        let seq = crate::journal::SEQ;
        if tx.open_table(seq)?.get(crate::journal::ADOPTION_DUE)?.is_none() || self.blob_store()?.is_sealed() {
            return Ok(());
        }
        for table in &self.tables_names {
            if !self.is_blob_table(table) || self.blob_store()?.is_protected(table) {
                continue;
            }
            let mark = format!("{}{table}", crate::journal::ADOPTED_PREFIX);
            if tx.open_table(seq)?.get(mark.as_str())?.is_some() {
                continue;
            }
            match std::fs::read_dir(self.blob_store()?.table_dir(table)) {
                Ok(entries) => {
                    for entry in entries {
                        let entry = entry?;
                        if !entry.file_type()?.is_file() {
                            continue;
                        }
                        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                            continue;
                        };
                        if name.starts_with("__v_") || is_temporary_name(&name) || get(tx, table, &name)?.is_some() {
                            continue;
                        }
                        let reference = BlobRef { id: name.clone(), size: entry.metadata()?.len() };
                        tx.open_table(REFS)?.insert(key(table, &name).as_str(), serde_json::to_vec(&reference)?.as_slice())?;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            tx.open_table(seq)?.insert(mark.as_str(), [1u8].as_slice())?;
        }
        Ok(())
    }
    /// At open, adopt legacy immutable files and collect only unreferenced files.
    pub(crate) fn reconcile_blobs(&self) -> Result<()> {
        if !self.blob_enabled() {
            return Ok(());
        }
        let db = self.db()?;
        let tx = db.begin_write()?;
        for table in &self.tables_names {
            // The attachments of a table with protected fields were never written in an older form.
            if !self.is_blob_table(table) || self.blob_store()?.is_protected(table) {
                continue;
            }
            let rows = tx.open_table(TableDefinition::<&str, &[u8]>::new(table))?;
            for row in rows.iter()? {
                let (k, _) = row?;
                if get(&tx, table, k.value())?.is_none() {
                    let size = self.blob_store()?.size_of(table, k.value())?;
                    tx.open_table(REFS)?.insert(
                        key(table, k.value()).as_str(),
                        serde_json::to_vec(&BlobRef {
                            id: k.value().into(),
                            size,
                        })?
                        .as_slice(),
                    )?;
                }
            }
        }
        self.adopt_legacy_files(&tx)?;
        tx.commit()?;
        let read = db.begin_read()?;
        // (table, row, file): the row matters to a table with protected fields, whose files are bound to it.
        let mut keep: HashSet<(String, String, String)> = HashSet::new();
        for row in read.open_table(REFS)?.iter()? {
            let (k, v) = row?;
            let (table, row_key): (String, String) = serde_json::from_str(k.value())?;
            let r: BlobRef = serde_json::from_slice(v.value())?;
            if !self.blob_store()?.is_unreadable(&table) {
                self.open_blob_version_row(&table, &row_key, &r.id)?;
            }
            keep.insert((table, row_key, r.id));
        }
        for row in read.open_table(CHANGES)?.iter()? {
            let (_, v) = row?;
            match ChangeKind::decode(v.value())? {
                ChangeKind::BlobPut { table, key, blob_id, .. }
                | ChangeKind::BlobDelete { table, key, blob_id, .. } => {
                    keep.insert((table, key, blob_id));
                }
                ChangeKind::TableReset { table, snapshot } => {
                    let refs = read.open_table(TableDefinition::<&str, &[u8]>::new(&format!(
                        "{snapshot}_blobs"
                    )))?;
                    for row in refs.iter()? {
                        let (k, v) = row?;
                        let (_, row_key): (String, String) = serde_json::from_str(k.value())?;
                        let r: BlobRef = serde_json::from_slice(v.value())?;
                        keep.insert((table.clone(), row_key, r.id));
                    }
                }
                _ => (),
            }
        }
        for (table, row_key, id) in &keep {
            if !self.blob_store()?.is_unreadable(table) {
                self.open_blob_version_row(table, row_key, id)?;
            }
        }
        // The attachments of tables with protected fields have their own folder and their own names.
        // A program that cannot open them is read-only and leaves them alone.
        if !self.blob_store()?.protected_unreadable() {
            self.blob_store()?.retain_only_protected(&keep)?;
        }
        let keep: HashSet<(String, String)> = keep
            .into_iter()
            .filter(|(table, _, _)| !self.blob_store().is_ok_and(|s| s.is_protected(table)))
            .map(|(table, _, id)| (table, id))
            .collect();
        if self.blob_store()?.is_sealed() {
            // the names are fingerprints: what is still wanted is named, and the rest goes
            self.blob_store()?.retain_only(&keep)?;
            return Ok(());
        }
        for entry in std::fs::read_dir(self.blob_store()?.root())? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let table = entry.file_name().to_string_lossy().into_owned();
            // Only the folders of the attachment tables this database registers are cleaned. A folder of
            // a table that is not registered now (left out of the configuration for a while) is not ours to empty.
            if !self.is_blob_table(&table) {
                continue;
            }
            for file in std::fs::read_dir(entry.path())? {
                let file = file?;
                if file.file_type()?.is_file()
                    && !keep.contains(&(
                        table.clone(),
                        file.file_name().to_string_lossy().into_owned(),
                    ))
                {
                    std::fs::remove_file(file.path())?;
                }
            }
        }
        Ok(())
    }
}
