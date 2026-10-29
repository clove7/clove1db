use crate::{journal::ChangeKind, units::Result};
use redb::{ReadTransaction, ReadableTable, TableDefinition, WriteTransaction};
const TABLE: TableDefinition<&[u8], u64> = TableDefinition::new("__lastwrite");
fn key(table: &str, row: &str) -> Vec<u8> {
    serde_json::to_vec(&(table, row)).expect("strings serialize")
}
pub(crate) fn init(tx: &WriteTransaction) -> Result<()> {
    tx.open_table(TABLE)?;
    Ok(())
}
pub(crate) fn get(tx: &ReadTransaction, table: &str, row: &str) -> Result<u64> {
    Ok(tx
        .open_table(TABLE)?
        .get(key(table, row).as_slice())?
        .map(|v| v.value())
        .unwrap_or(0))
}
pub(crate) fn apply(tx: &WriteTransaction, change: &ChangeKind, seq: u64) -> Result<()> {
    let mut t = tx.open_table(TABLE)?;
    match change {
        ChangeKind::Upsert {
            table, key: row, ..
        } => {
            t.insert(key(table, row).as_slice(), seq)?;
        }
        ChangeKind::Delete { table, key: row } => {
            t.remove(key(table, row).as_slice())?;
        }
        ChangeKind::TableReset { table, .. } => {
            t.retain(|k, _| {
                serde_json::from_slice::<(String, String)>(k)
                    .map_or(true, |(name, _)| name != *table)
            })?;
            let rows = tx.open_table(TableDefinition::<&str, &[u8]>::new(table))?;
            for row in rows.iter()? {
                let (k, _) = row?;
                t.insert(key(table, k.value()).as_slice(), seq)?;
            }
        }
        _ => (),
    }
    Ok(())
}
