//! Raw redb database (not a `.cldb`) used as a third-party vendor catalog.

use std::path::{Path, PathBuf};

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use clove1db::units::Result;

pub const VENDOR_TABLE: &str = "vendor_catalog";
const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new(VENDOR_TABLE);

/// JSON row stored in external redb — keys are UTF-8 strings matching `id`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExternalCatalogRow {
    pub id: String,
    pub title: String,
    pub price_usd: f64,
    pub vendor_code: String,
}

pub fn vendor_inventory_path(base: &Path) -> PathBuf {
    base.join("external_import").join("vendor_inventory.redb")
}

pub fn seed_vendor_inventory(base: &Path) -> Result<Vec<ExternalCatalogRow>> {
    let path = vendor_inventory_path(base);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if path.exists() {
        std::fs::remove_file(&path)?;
    }

    let rows = vec![
        ExternalCatalogRow {
            id: "ext-headset-01".into(),
            title: "Gaming Headset X1".into(),
            price_usd: 79.99,
            vendor_code: "VND-ACME-HS".into(),
        },
        ExternalCatalogRow {
            id: "ext-desk-02".into(),
            title: "Standing Desk Pro".into(),
            price_usd: 449.00,
            vendor_code: "VND-DESKCO".into(),
        },
        ExternalCatalogRow {
            id: "ext-lamp-03".into(),
            title: "LED Desk Lamp".into(),
            price_usd: 34.50,
            vendor_code: "VND-LITE".into(),
        },
    ];

    let db = Database::create(&path).map_err(|e| clove1db::units::ClError::Database(e.into()))?;
    let write = db.begin_write().map_err(|e| clove1db::units::ClError::Database(e.into()))?;
    {
        let mut table = write
            .open_table(TABLE)
            .map_err(|e| clove1db::units::ClError::Database(e.into()))?;
        for row in &rows {
            let value = serde_json::to_vec(row)?;
            table
                .insert(row.id.as_str(), value.as_slice())
                .map_err(|e| clove1db::units::ClError::Database(e.into()))?;
        }
    }
    write
        .commit()
        .map_err(|e| clove1db::units::ClError::Database(e.into()))?;

    Ok(rows)
}

pub fn read_all_rows(path: &Path) -> Result<Vec<(String, ExternalCatalogRow)>> {
    let db = Database::open(path).map_err(|e| clove1db::units::ClError::Database(e.into()))?;
    let read = db.begin_read().map_err(|e| clove1db::units::ClError::Database(e.into()))?;
    let table = read
        .open_table(TABLE)
        .map_err(|e| clove1db::units::ClError::Database(e.into()))?;
    let mut out = Vec::new();
    for entry in table.iter().map_err(|e| clove1db::units::ClError::Database(e.into()))? {
        let (k, v) = entry.map_err(|e| clove1db::units::ClError::Database(e.into()))?;
        let row: ExternalCatalogRow = serde_json::from_slice(v.value())?;
        out.push((k.value().to_string(), row));
    }
    Ok(out)
}
