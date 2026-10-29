//! Transactional validation of explicitly declared serialized row identities.
use crate::{
    fields::{Path, Step, Value, ValueKind},
    journal::ChangeKind,
    units::{ClError, Result},
};
use redb::{ReadableTable, ReadableTableMetadata, TableDefinition, WriteTransaction};
const DEFS: TableDefinition<&str, &[u8]> = TableDefinition::new("__id_contracts");
pub(crate) fn init(tx: &WriteTransaction) -> Result<()> {
    tx.open_table(DEFS)?;
    Ok(())
}
fn check(path: &Path, key: &str, bytes: &[u8]) -> Result<()> {
    if matches!(crate::query::path_value(bytes,path)?,Value::String(ref id) if id==key) {
        Ok(())
    } else {
        Err(ClError::IdFieldMismatch)
    }
}
pub(crate) fn configure(tx: &WriteTransaction, configured: &[(String, Path)]) -> Result<()> {
    init(tx)?;
    for (table, path) in configured {
        if path.kind != ValueKind::Auto
            || !path.transforms.is_empty()
            || path
                .steps
                .iter()
                .any(|s| !matches!(s, Step::Key(_) | Step::Index(_)))
        {
            return Err(ClError::Validation(
                "id_field requires an untransformed scalar path".into(),
            ));
        }
        let encoded = serde_json::to_vec(path)?;
        let same = tx
            .open_table(DEFS)?
            .get(table.as_str())?
            .is_some_and(|v| v.value() == encoded);
        if !same {
            let rows = tx.open_table(TableDefinition::<&str, &[u8]>::new(table))?;
            for row in rows.iter()? {
                let (k, v) = row?;
                check(path, k.value(), v.value())?;
            }
            tx.open_table(DEFS)?
                .insert(table.as_str(), encoded.as_slice())?;
        }
    }
    let obsolete = tx
        .open_table(DEFS)?
        .iter()?
        .map(|r| r.map(|(k, _)| k.value().to_owned()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for table in obsolete {
        if !configured.iter().any(|(t, _)| t == &table) {
            tx.open_table(DEFS)?.remove(table.as_str())?;
        }
    }
    Ok(())
}
pub(crate) fn validate(tx: &WriteTransaction, effects: &[ChangeKind]) -> Result<()> {
    let defs = tx.open_table(DEFS)?;
    if defs.is_empty()? {
        return Ok(());
    }
    for effect in effects {
        let table = match effect {
            ChangeKind::Upsert { table, .. } | ChangeKind::TableReset { table, .. } => table,
            _ => continue,
        };
        let Some(p) = defs.get(table.as_str())? else {
            continue;
        };
        let path: Path = serde_json::from_slice(p.value())?;
        match effect {
            ChangeKind::Upsert { key, value, .. } => check(&path, key, value)?,
            ChangeKind::TableReset { snapshot, .. } => {
                let rows = tx.open_table(TableDefinition::<&str, &[u8]>::new(snapshot))?;
                for row in rows.iter()? {
                    let (k, v) = row?;
                    check(&path, k.value(), v.value())?;
                }
            }
            _ => (),
        }
    }
    Ok(())
}
pub(crate) fn enforced(tx: &redb::ReadTransaction, table: &str, path: &Path) -> bool {
    let Ok(defs) = tx.open_table(DEFS) else {
        return false;
    };
    let Ok(Some(value)) = defs.get(table) else {
        return false;
    };
    serde_json::from_slice::<Path>(value.value()).is_ok_and(|p| p == *path)
}
