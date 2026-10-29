//! The file of the backup history: for each table `{t}` (the saved versions), `{t}_version` (the
//! counter of each row) and `{t}_bulk` (the batches). Copied whole, all versions, none dropped.
//! As in the main file, a table that does not fit this shape stops the plan before anything is
//! written.
use super::rows::{BatchLimits, copy_bytes_table, copy_bytes_table_as, copy_number_table, io};
use crate::units::{ClError, Result};
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// The saved versions of the rows of one table.
    Versions,
    /// The counter of each row.
    Counter,
    /// The batches.
    Bulk,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Item {
    pub name: String,
    pub kind: Kind,
    pub entries: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct Plan {
    pub items: Vec<Item>,
}

fn entries(read: &redb::ReadTransaction, name: &str, kind: Kind) -> Result<u64> {
    Ok(match kind {
        Kind::Versions | Kind::Bulk => read.open_table(TableDefinition::<&str, &[u8]>::new(name)).map_err(io)?.len().map_err(io)?,
        Kind::Counter => read.open_table(TableDefinition::<&str, u64>::new(name)).map_err(io)?.len().map_err(io)?,
    })
}

/// Read the history file and decide what happens to each table. Reads only.
pub(crate) fn plan_history(from: &impl ReadableDatabase) -> Result<Plan> {
    let read = from.begin_read().map_err(io)?;
    if read.list_multimap_tables().map_err(io)?.next().is_some() {
        return Err(ClError::MigrationError(
            "the history file holds a table this version does not know how to move (a multimap); nothing was changed".into(),
        ));
    }
    let mut names: Vec<String> = read.list_tables().map_err(io)?.map(|t| t.name().to_string()).collect();
    names.sort();
    // a base is a table that has both companions
    let bases: Vec<&String> = names
        .iter()
        .filter(|n| names.contains(&format!("{n}_version")) && names.contains(&format!("{n}_bulk")))
        .collect();
    let mut items = Vec::new();
    for name in &names {
        let kind = if bases.contains(&name) {
            Kind::Versions
        } else if name.strip_suffix("_version").is_some_and(|b| bases.iter().any(|x| x.as_str() == b)) {
            Kind::Counter
        } else if name.strip_suffix("_bulk").is_some_and(|b| bases.iter().any(|x| x.as_str() == b)) {
            Kind::Bulk
        } else {
            return Err(ClError::MigrationError(format!(
                "the history file holds a table this version does not know how to move ({name}); nothing was changed"
            )));
        };
        let count = entries(&read, name, kind)?;
        items.push(Item { name: name.clone(), kind, entries: count });
    }
    Ok(Plan { items })
}

/// What a change of the rows needs to do inside the copy of the history file. Only the saved
/// versions of a table pass through it (the counters and the batches are copied as they are). The
/// key is the stored one, `{row}:{version}`, and the bytes are given and returned as stored.
pub(crate) trait HistoryHooks {
    /// Whether the saved versions of this table are rewritten.
    fn changes(&self, _table: &str) -> bool {
        false
    }
    /// The new bytes of one saved version; `None` copies it as it is.
    fn map_row(&mut self, _table: &str, _key: &str, _old: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
    /// The check of one saved version of a rewritten table, instead of comparing bytes.
    fn verify_row(&mut self, _table: &str, _key: &str, _old: &[u8], _new: &[u8]) -> Result<()> {
        Ok(())
    }
}

/// No change of any version: the copy is byte for byte.
pub(crate) struct NoHistoryHooks;

impl HistoryHooks for NoHistoryHooks {}

/// Copy every table of the history file, in batches. `to` must be a file just made.
pub(crate) fn copy_history(from: &impl ReadableDatabase, to: &Database, plan: &Plan, limits: BatchLimits) -> Result<usize> {
    copy_history_with(from, to, plan, limits, &mut NoHistoryHooks)
}

/// [`copy_history`], with the saved versions of the tables the hooks rewrite changed on the way.
pub(crate) fn copy_history_with(
    from: &impl ReadableDatabase,
    to: &Database,
    plan: &Plan,
    limits: BatchLimits,
    hooks: &mut dyn HistoryHooks,
) -> Result<usize> {
    let mut largest = 0;
    for item in &plan.items {
        let name = item.name.as_str();
        let done = match item.kind {
            Kind::Versions if hooks.changes(name) => copy_bytes_table_as(from, to, name, name, limits, &mut |k, v| {
                Ok(Some(hooks.map_row(name, k, v)?.unwrap_or_else(|| v.to_vec())))
            })?,
            Kind::Versions | Kind::Bulk => copy_bytes_table(from, to, &item.name, limits, &mut |_, v| Ok(v.to_vec()))?,
            Kind::Counter => copy_number_table(from, to, &item.name, limits)?,
        };
        largest = largest.max(done.largest_batch_bytes);
    }
    Ok(largest)
}

/// Every table of the old file has its counterpart with the same entries, one by one, and the new
/// file holds nothing else.
pub(crate) fn verify_history(from: &impl ReadableDatabase, to: &Database, plan: &Plan) -> Result<()> {
    verify_history_with(from, to, plan, &mut NoHistoryHooks)
}

/// [`verify_history`]; the saved versions of a table the hooks rewrite keep their number and their
/// keys, and each is checked by the hooks instead of being compared byte for byte.
pub(crate) fn verify_history_with(
    from: &impl ReadableDatabase,
    to: &Database,
    plan: &Plan,
    hooks: &mut dyn HistoryHooks,
) -> Result<()> {
    let bad = |why: String| ClError::MigrationError(format!("the new history file does not match the old one: {why}"));
    let (a, b) = (from.begin_read().map_err(io)?, to.begin_read().map_err(io)?);
    for item in &plan.items {
        let name = item.name.as_str();
        let n = entries(&b, name, item.kind)?;
        if n != item.entries {
            return Err(bad(format!("{name} has {n} entries, it had {}", item.entries)));
        }
        let same = match item.kind {
            Kind::Versions if hooks.changes(name) => {
                let def = TableDefinition::<&str, &[u8]>::new(name);
                let (ta, tb) = (a.open_table(def).map_err(io)?, b.open_table(def).map_err(io)?);
                let (mut ia, mut ib) = (ta.iter().map_err(io)?, tb.iter().map_err(io)?);
                loop {
                    match (ia.next(), ib.next()) {
                        (None, None) => break true,
                        (Some(x), Some(y)) => {
                            let ((ka, va), (kb, vb)) = (x.map_err(io)?, y.map_err(io)?);
                            if ka.value() != kb.value() {
                                break false;
                            }
                            hooks.verify_row(name, ka.value(), va.value(), vb.value())?;
                        }
                        _ => break false,
                    }
                }
            }
            Kind::Versions | Kind::Bulk => {
                let def = TableDefinition::<&str, &[u8]>::new(name);
                let (ta, tb) = (a.open_table(def).map_err(io)?, b.open_table(def).map_err(io)?);
                let (mut ia, mut ib) = (ta.iter().map_err(io)?, tb.iter().map_err(io)?);
                loop {
                    match (ia.next(), ib.next()) {
                        (None, None) => break true,
                        (Some(x), Some(y)) => {
                            let ((ka, va), (kb, vb)) = (x.map_err(io)?, y.map_err(io)?);
                            if ka.value() != kb.value() || va.value() != vb.value() {
                                break false;
                            }
                        }
                        _ => break false,
                    }
                }
            }
            Kind::Counter => {
                let def = TableDefinition::<&str, u64>::new(name);
                let (ta, tb) = (a.open_table(def).map_err(io)?, b.open_table(def).map_err(io)?);
                let (mut ia, mut ib) = (ta.iter().map_err(io)?, tb.iter().map_err(io)?);
                loop {
                    match (ia.next(), ib.next()) {
                        (None, None) => break true,
                        (Some(x), Some(y)) => {
                            let ((ka, va), (kb, vb)) = (x.map_err(io)?, y.map_err(io)?);
                            if ka.value() != kb.value() || va.value() != vb.value() {
                                break false;
                            }
                        }
                        _ => break false,
                    }
                }
            }
        };
        if !same {
            return Err(bad(format!("{name} holds other rows")));
        }
    }
    let found: Vec<String> = b.list_tables().map_err(io)?.map(|t| t.name().to_string()).collect();
    if let Some(extra) = found.iter().find(|n| !plan.items.iter().any(|i| &i.name == *n)) {
        return Err(bad(format!("the new file holds {extra}, which nothing accounts for")));
    }
    Ok(())
}
