//! Synchronous optional business constraints, independent of asynchronous indexes.
use crate::{
    fields::{Field, Path, codec},
    journal::ChangeKind,
    units::{ClError, Result},
};
use redb::{ReadableTable, ReadableTableMetadata, TableDefinition, WriteTransaction};
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Unique<E = ()> {
    pub(crate) paths: Vec<Path>,
    #[serde(skip)]
    marker: std::marker::PhantomData<fn(E)>,
}
pub(crate) mod private {
    /// Keeps [`UniqueField`](super::UniqueField) from being implemented outside the crate.
    pub trait Sealed {}
}
impl<E, V> private::Sealed for Field<E, V> {}
impl<E> private::Sealed for crate::field_crypto::PrintField<E> {}
/// What a unique constraint can be put on: an ordinary field, or the stored fingerprint of a field
/// that has one ([`PrintHandle::print_field`](crate::field_crypto::PrintHandle::print_field)). It
/// cannot be implemented for other types:
///
/// ```compile_fail,E0277
/// use clove1db::{fields::Path, unique::UniqueField};
/// struct Mine;
/// impl UniqueField<()> for Mine {
///     fn unique_path(self) -> Path {
///         unimplemented!()
///     }
/// }
/// ```
pub trait UniqueField<E>: private::Sealed {
    #[doc(hidden)]
    fn unique_path(self) -> Path;
}
impl<E, V> UniqueField<E> for Field<E, V> {
    fn unique_path(self) -> Path {
        self.path()
    }
}
impl<E> UniqueField<E> for crate::field_crypto::PrintField<E> {
    fn unique_path(self) -> Path {
        self.into_path()
    }
}
impl<E> Unique<E> {
    pub fn on(field: impl UniqueField<E>) -> Self {
        Self {
            paths: vec![field.unique_path()],
            marker: std::marker::PhantomData,
        }
    }
    pub(crate) fn erase(self) -> Unique<()> {
        Unique {
            paths: self.paths,
            marker: std::marker::PhantomData,
        }
    }
    pub fn and(mut self, field: impl UniqueField<E>) -> Self {
        self.paths.push(field.unique_path());
        self
    }
}
const DEFS: TableDefinition<&str, &[u8]> = TableDefinition::new("__unique_definitions");
const KEYS: TableDefinition<&[u8], &str> = TableDefinition::new("__unique_keys");
const REVERSE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("__unique_rows");
pub(crate) fn init(tx: &WriteTransaction) -> Result<()> {
    tx.open_table(DEFS)?;
    tx.open_table(KEYS)?;
    tx.open_table(REVERSE)?;
    Ok(())
}
fn rowkey(table: &str, row: &str) -> Vec<u8> {
    serde_json::to_vec(&(table, row)).unwrap()
}
fn keys(table: &str, bytes: &[u8], defs: &[Unique]) -> Result<Vec<Vec<u8>>> {
    let mut keys = vec![];
    for (i, d) in defs.iter().enumerate() {
        let mut values = vec![];
        for p in &d.paths {
            if p.steps
                .iter()
                .any(|s| matches!(s, crate::fields::Step::Any | crate::fields::Step::All))
            {
                return Err(ClError::Validation("unique requires scalar paths".into()));
            }
            let v = super::query::path_value(bytes, p)?;
            if v.is_empty() {
                values.clear();
                break;
            }
            values.push(v);
        }
        if !values.is_empty() {
            let mut key = serde_json::to_vec(&(table, i))?;
            key.extend(codec::encode_tuple(&values)?);
            keys.push(key)
        }
    }
    Ok(keys)
}
fn remove(tx: &WriteTransaction, table: &str, row: &str) -> Result<()> {
    let k = rowkey(table, row);
    let old = tx
        .open_table(REVERSE)?
        .remove(k.as_slice())?
        .map(|v| v.value().to_vec());
    if let Some(old) = old {
        let keys: Vec<Vec<u8>> = serde_json::from_slice(&old)?;
        let mut t = tx.open_table(KEYS)?;
        for key in keys {
            t.remove(key.as_slice())?;
        }
    }
    Ok(())
}
fn insert(
    tx: &WriteTransaction,
    table: &str,
    row: &str,
    bytes: &[u8],
    defs: &[Unique],
) -> Result<()> {
    let keys = keys(table, bytes, defs)?;
    {
        let mut t = tx.open_table(KEYS)?;
        for key in &keys {
            if t.get(key.as_slice())?.is_some_and(|v| v.value() != row) {
                return Err(ClError::UniqueViolation);
            }
            t.insert(key.as_slice(), row)?;
        }
    }
    if !keys.is_empty() {
        tx.open_table(REVERSE)?.insert(
            rowkey(table, row).as_slice(),
            serde_json::to_vec(&keys)?.as_slice(),
        )?;
    }
    Ok(())
}
fn clear(tx: &WriteTransaction, table: &str) -> Result<()> {
    let prefix = serde_json::to_vec(&(table,))?;
    let _ = prefix;
    // Reverse entries are walked without copying entity data; the constraint is
    // being rebuilt explicitly, never as part of a normal row write.
    let rows = tx
        .open_table(REVERSE)?
        .iter()?
        .map(|r| {
            let (k, _) = r?;
            Ok(serde_json::from_slice::<(String, String)>(k.value())?)
        })
        .collect::<Result<Vec<_>>>()?;
    for (t, k) in rows {
        if t == table {
            remove(tx, table, &k)?;
        }
    }
    Ok(())
}
pub(crate) fn configure(tx: &WriteTransaction, configured: &[(String, Vec<Unique>)]) -> Result<()> {
    init(tx)?;
    let old = tx
        .open_table(DEFS)?
        .iter()?
        .map(|r| {
            let (k, v) = r?;
            Ok((
                k.value().to_owned(),
                serde_json::from_slice::<Vec<Unique>>(v.value())?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    for (table, _) in &old {
        if !configured.iter().any(|(t, _)| t == table) {
            clear(tx, table)?;
            tx.open_table(DEFS)?.remove(table.as_str())?;
        }
    }
    for (table, defs) in configured {
        for d in defs {
            for p in &d.paths {
                if p.steps
                    .iter()
                    .any(|s| matches!(s, crate::fields::Step::Any | crate::fields::Step::All))
                {
                    return Err(ClError::Validation("unique requires scalar paths".into()));
                }
            }
        }
        if old.iter().any(|(t, d)| t == table && d == defs) {
            continue;
        }
        let rows = tx.open_table(TableDefinition::<&str, &[u8]>::new(table))?;
        // Count duplicate groups without exposing their keys or values.
        let mut counts = std::collections::BTreeMap::<Vec<u8>, u64>::new();
        for row in rows.iter()? {
            let (_, v) = row?;
            for key in keys(table, v.value(), defs)? {
                *counts.entry(key).or_default() += 1
            }
        }
        let groups = counts.values().filter(|n| **n > 1).count() as u64;
        if groups > 0 {
            return Err(ClError::DuplicateGroups { groups });
        }
        drop(counts);
        clear(tx, table)?;
        for row in rows.iter()? {
            let (k, v) = row?;
            insert(tx, table, k.value(), v.value(), defs)?;
        }
        tx.open_table(DEFS)?
            .insert(table.as_str(), serde_json::to_vec(defs)?.as_slice())?;
    }
    Ok(())
}
pub(crate) fn validate(tx: &WriteTransaction, effects: &[ChangeKind]) -> Result<()> {
    let defs = tx.open_table(DEFS)?;
    if defs.is_empty()? { return Ok(()); }
    let mut changed = std::collections::BTreeSet::new();
    let mut resets = std::collections::BTreeSet::new();
    for e in effects {
        match e {
            ChangeKind::Upsert { table, key, .. } | ChangeKind::Delete { table, key } => {
                if defs.get(table.as_str())?.is_some() {
                    changed.insert((table.clone(), key.clone()));
                }
            }
            ChangeKind::TableReset { table, .. } if defs.get(table.as_str())?.is_some() => {
                resets.insert(table.clone());
            }
            _ => (),
        }
    }
    for table in &resets {
        clear(tx, table)?;
        let rows = tx.open_table(TableDefinition::<&str, &[u8]>::new(table))?;
        for r in rows.iter()? {
            let (k, _) = r?;
            changed.insert((table.clone(), k.value().into()));
        }
    }
    for (table, key) in &changed {
        remove(tx, table, key)?;
    }
    for (table, key) in &changed {
        let definitions: Vec<Unique> =
            serde_json::from_slice(defs.get(table.as_str())?.unwrap().value())?;
        let rows = tx.open_table(TableDefinition::<&str, &[u8]>::new(table))?;
        if let Some(v) = rows.get(key.as_str())? {
            insert(tx, table, key, v.value(), &definitions)?;
        }
    }
    Ok(())
}
