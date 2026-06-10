use std::path::Path;

use redb::{Database, TableDefinition};

use crate::paths;

const INVENTORY: TableDefinition<&str, &[u8]> = TableDefinition::new("inventory");

pub fn create() -> clove1db::units::Result<()> {
    let path = paths::foreign_cldb();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    seed_foreign_redb(&path)?;
    Ok(())
}

fn seed_foreign_redb(path: &Path) -> clove1db::units::Result<()> {
    let db = Database::create(path).map_err(|e| clove1db::units::ClError::Database(e.into()))?;
    let write = db.begin_write().map_err(|e| clove1db::units::ClError::Database(e.into()))?;
    {
        let mut table = write.open_table(INVENTORY).map_err(|e| clove1db::units::ClError::Database(e.into()))?;
        for i in 0..5 {
            let key = format!("item-{i}");
            let value = serde_json::to_vec(&serde_json::json!({"qty": i, "label": "foreign"}))?;
            table.insert(key.as_str(), value.as_slice()).map_err(|e| clove1db::units::ClError::Database(e.into()))?;
        }
    }
    write.commit().map_err(|e| clove1db::units::ClError::Database(e.into()))?;
    Ok(())
}
