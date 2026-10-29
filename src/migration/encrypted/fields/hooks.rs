//! The rewriting of rows and saved versions for a change of how fields are protected, and the checks
//! of what was written. A row is read as raw values and only the fields that change are replaced, so
//! every other field stays the very bytes it was.
#![allow(dead_code)] // used by `execute`
use super::plan::{FieldStep, StepKind, TablePlan};
use crate::{
    backup::codec::{decode_record, encode_record, is_v2},
    crypto::LockedDataKey,
    field_crypto::{
        FieldKeys, Row, hash_plain, keystore, open_stored, print_plain, protect_plain, read_stored, with_prints, without_prints,
    },
    metadata::types::{META_KEY, META_TABLE},
    migration::encrypted::{convert::MainHooks, history::HistoryHooks},
    units::{ClError, Result},
};
use redb::Database;
use std::sync::Arc;

fn bad(why: impl Into<String>) -> ClError {
    ClError::MigrationError(why.into())
}

/// Rewrites the rows of the named tables, and checks the result.
pub(crate) struct Rewriter {
    pub plans: Vec<TablePlan>,
    pub old_ids: Vec<Option<String>>,
    pub new_ids: Vec<Option<String>>,
    pub keys: Option<Arc<FieldKeys>>,
}

impl Rewriter {
    fn find(&self, table: &str) -> Option<usize> {
        self.plans.iter().position(|p| p.table == table && p.changes_rows())
    }

    fn keys(&self) -> Result<&FieldKeys> {
        self.keys.as_deref().ok_or_else(|| bad("this change needs the keys of the fields; nothing was changed"))
    }

    /// The identity a field's keys come from: the table's own if the field existed, the new one if not.
    fn id_of<'a>(&'a self, i: usize, step: &FieldStep) -> Result<&'a str> {
        let id = if step.from.is_some() { self.old_ids[i].as_deref() } else { self.new_ids[i].as_deref() };
        id.ok_or_else(|| bad("a table has no identity for its protected fields; nothing was changed"))
    }

    fn open(&self, i: usize, step: &FieldStep, row_key: &str, raw: &str) -> Result<crate::crypto::SecretBytes> {
        let stored = read_stored(raw)?;
        open_stored(self.keys()?, self.id_of(i, step)?, step.id, row_key, &stored)
    }

    /// The new bytes of one row (or one saved version) of `table`, whose key is `row_key`.
    pub(crate) fn rewrite(&self, table: &str, row_key: &str, old: &[u8]) -> Result<Vec<u8>> {
        let Some(i) = self.find(table) else { return Ok(old.to_vec()) };
        let mut row = Row::parse(old)?;
        for step in self.plans[i].steps.iter().filter(|s| s.kind != StepKind::Keep) {
            let raw = row
                .get(&step.key)
                .ok_or_else(|| bad("a stored row has no value for a field that changes; nothing was changed"))?
                .to_string();
            let spec = step.to;
            let need_spec = || spec.ok_or_else(|| bad("a field that is made has no declaration"));
            let out = match step.kind {
                StepKind::Seal | StepKind::Hash | StepKind::PrintOnly => {
                    protect_plain(self.keys()?, self.id_of(i, step)?, &need_spec()?, row_key, raw.as_bytes())?
                }
                StepKind::Open => String::from_utf8(self.open(i, step, row_key, &raw)?.as_bytes().to_vec())
                    .map_err(|_| bad("an opened value is not text"))?,
                StepKind::AddPrints | StepKind::RemakePrints => {
                    let stored = read_stored(&raw)?;
                    let plain = self.open(i, step, row_key, &raw)?;
                    with_prints(self.keys()?, self.id_of(i, step)?, &need_spec()?, &stored.sealed, plain.as_bytes())?
                }
                StepKind::DropPrints => without_prints(&read_stored(&raw)?),
                StepKind::OpenToHash => {
                    let plain = self.open(i, step, row_key, &raw)?;
                    hash_plain(self.keys()?, self.id_of(i, step)?, &need_spec()?, row_key, plain.as_bytes())?
                }
                StepKind::OpenToPrintOnly => {
                    let plain = self.open(i, step, row_key, &raw)?;
                    print_plain(self.keys()?, self.id_of(i, step)?, &need_spec()?, plain.as_bytes())?
                }
                StepKind::Keep => unreachable!("filtered above"),
            };
            row.set(&step.key, out)?;
        }
        Ok(row.encode())
    }

    /// Check one rewritten row against the old one: every other field is the very bytes it was, and
    /// each changed field is what it should be.
    pub(crate) fn verify(&self, table: &str, row_key: &str, old: &[u8], new: &[u8]) -> Result<()> {
        let Some(i) = self.find(table) else { return Ok(()) };
        let wrong = |what: &str| bad(format!("a rewritten row does not match: {what}"));
        let (a, b) = (Row::parse(old)?, Row::parse(new)?);
        let changed: Vec<&str> = self.plans[i].steps.iter().filter(|s| s.kind != StepKind::Keep).map(|s| s.key.as_str()).collect();
        if !a.same_but(&b, &changed) {
            return Err(wrong("a field that did not change is not the same bytes"));
        }
        for step in self.plans[i].steps.iter().filter(|s| s.kind != StepKind::Keep) {
            let old_raw = a.get(&step.key).ok_or_else(|| wrong("a field is missing in the old row"))?;
            let new_raw = b.get(&step.key).ok_or_else(|| wrong("a field is missing in the new row"))?;
            let spec = step.to;
            match step.kind {
                StepKind::Seal => {
                    let spec = spec.ok_or_else(|| wrong("no declaration"))?;
                    let stored = read_stored(new_raw)?;
                    let opened = open_stored(self.keys()?, self.id_of(i, step)?, step.id, row_key, &stored)?;
                    if opened.as_bytes() != old_raw.as_bytes() {
                        return Err(wrong("a sealed value does not open to the value it had"));
                    }
                    if stored.full.is_some() != spec.method.has_stored_print() || stored.parts.is_some() != spec.method.has_parts() {
                        return Err(wrong("the fingerprints of a sealed value are not those its method has"));
                    }
                }
                StepKind::Hash | StepKind::OpenToHash => {
                    // the hash is made by the function the row codec uses, which has its own tests; here
                    // the shape: one text that is not the value
                    let text = serde_json::from_str::<String>(new_raw).map_err(|_| wrong("a hash is not a text"))?;
                    if text.is_empty() || new_raw == old_raw {
                        return Err(wrong("a hash is empty or is the value"));
                    }
                }
                StepKind::PrintOnly | StepKind::OpenToPrintOnly => {
                    let spec = spec.ok_or_else(|| wrong("no declaration"))?;
                    let plain = if step.kind == StepKind::PrintOnly {
                        old_raw.as_bytes().to_vec()
                    } else {
                        self.open(i, step, row_key, old_raw)?.as_bytes().to_vec()
                    };
                    if print_plain(self.keys()?, self.id_of(i, step)?, &spec, &plain)? != new_raw {
                        return Err(wrong("a fingerprint is not the fingerprint of the value"));
                    }
                }
                StepKind::AddPrints | StepKind::RemakePrints => {
                    let spec = spec.ok_or_else(|| wrong("no declaration"))?;
                    let (stored_old, stored_new) = (read_stored(old_raw)?, read_stored(new_raw)?);
                    if stored_old.sealed != stored_new.sealed {
                        return Err(wrong("the sealed text changed with its fingerprints"));
                    }
                    let plain = self.open(i, step, row_key, old_raw)?;
                    let again = with_prints(self.keys()?, self.id_of(i, step)?, &spec, &stored_old.sealed, plain.as_bytes())?;
                    if again != new_raw {
                        return Err(wrong("the fingerprints are not those of the value"));
                    }
                }
                StepKind::DropPrints => {
                    let (stored_old, stored_new) = (read_stored(old_raw)?, read_stored(new_raw)?);
                    if stored_old.sealed != stored_new.sealed || stored_new.full.is_some() || stored_new.parts.is_some() {
                        return Err(wrong("fingerprints were not taken off, or the sealed text changed"));
                    }
                }
                StepKind::Open => {
                    let plain = self.open(i, step, row_key, old_raw)?;
                    if plain.as_bytes() != new_raw.as_bytes() {
                        return Err(wrong("an opened value is not the value that was sealed"));
                    }
                }
                StepKind::Keep => unreachable!("filtered above"),
            }
        }
        Ok(())
    }
}

/// The hooks of the main file: the rows of the named tables, the description, and the keys table.
pub(crate) struct MainRewrite<'a> {
    pub rewriter: &'a Rewriter,
    /// The new description, as stored.
    pub meta: Vec<u8>,
    /// The keys of the fields made now, to store in the new file.
    pub made_keys: Option<LockedDataKey>,
}

impl MainHooks for MainRewrite<'_> {
    fn changes(&self, table: &str) -> bool {
        table == META_TABLE || self.rewriter.find(table).is_some()
    }

    fn map_row(&mut self, table: &str, key: &str, old: &[u8]) -> Result<Option<Vec<u8>>> {
        if table == META_TABLE {
            return Ok((key == META_KEY).then(|| self.meta.clone()));
        }
        Ok(Some(self.rewriter.rewrite(table, key, old)?))
    }

    fn extra_tables(&mut self, to: &Database) -> Result<()> {
        if let Some(locked) = &self.made_keys {
            let write = to.begin_write().map_err(|e| bad(e.to_string()))?;
            keystore::write(&write, locked)?;
            write.commit().map_err(|e| bad(e.to_string()))?;
        }
        Ok(())
    }

    fn extra_names(&self) -> Vec<String> {
        if self.made_keys.is_some() { vec!["__field_keys".to_string()] } else { Vec::new() }
    }

    fn verify_row(&mut self, table: &str, key: &str, old: &[u8], new: &[u8]) -> Result<()> {
        if table == META_TABLE {
            // the description is the one that was made, and it describes the same tables
            let (a, b): (crate::metadata::types::CloveMeta, crate::metadata::types::CloveMeta) =
                (serde_json::from_slice(old)?, serde_json::from_slice(new)?);
            let names = |m: &crate::metadata::types::CloveMeta| m.tables.iter().map(|t| t.name.clone()).collect::<Vec<_>>();
            if key != META_KEY || names(&a) != names(&b) || new != self.meta.as_slice() {
                return Err(bad("the new description is not the one that was made"));
            }
            return Ok(());
        }
        self.rewriter.verify(table, key, old, new)
    }
}

/// The hooks of the history file: the saved versions of the named tables.
pub(crate) struct HistoryRewrite<'a> {
    pub rewriter: &'a Rewriter,
}

impl HistoryHooks for HistoryRewrite<'_> {
    fn changes(&self, table: &str) -> bool {
        self.rewriter.find(table).is_some()
    }

    fn map_row(&mut self, table: &str, key: &str, old: &[u8]) -> Result<Option<Vec<u8>>> {
        if !is_v2(old)? {
            return Err(bad("a saved version is not in the current form: open the database once to bring the history to it; nothing was changed"));
        }
        let mut record = decode_record(table, key, old)?;
        let Some(data) = record.data.take() else { return Ok(None) };
        record.data = Some(self.rewriter.rewrite(table, &record.key, &data)?);
        Ok(Some(encode_record(&record)?))
    }

    fn verify_row(&mut self, table: &str, key: &str, old: &[u8], new: &[u8]) -> Result<()> {
        let (a, b) = (decode_record(table, key, old)?, decode_record(table, key, new)?);
        if (a.version, a.timestamp, &a.date, &a.key, &a.table) != (b.version, b.timestamp, &b.date, &b.key, &b.table) {
            return Err(bad("a saved version changed more than its payload"));
        }
        match (&a.data, &b.data) {
            (None, None) => Ok(()),
            (Some(x), Some(y)) => self.rewriter.verify(table, &a.key, x, y),
            _ => Err(bad("a saved version gained or lost its payload")),
        }
    }
}
