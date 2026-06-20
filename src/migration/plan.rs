use crate::migration::types::{
    ExternalFrom, MigrationFrom, MigrationKind, MigrationTo, TableStorageMode,
};
use crate::repository::DatabaseManager;
use crate::units::{ClError, Result};

#[derive(Debug, Clone)]
pub enum MigrationSource {
    Clove(MigrationFrom),
    External(ExternalFrom),
}

#[derive(Debug, Clone)]
pub struct ResolvedEndpoint {
    pub db: String,
    pub table: String,
    pub storage: TableStorageMode,
}

#[derive(Debug, Clone)]
pub struct MigrationPlan {
    pub kind: MigrationKind,
    pub from: ResolvedEndpoint,
    pub to: ResolvedEndpoint,
    pub effective_delete_source: bool,
    pub external: Option<ExternalFrom>,
}

pub fn resolve_plan(source: &MigrationSource, to: Option<&MigrationTo>) -> Result<MigrationPlan> {
    match source {
        MigrationSource::External(ext) => {
            let to = to.ok_or_else(|| {
                ClError::MigrationError("external migration requires .to(...)".into())
            })?;
            let target_table = to.table.clone().ok_or_else(|| {
                ClError::MigrationError("external migration requires to.table".into())
            })?;
            Ok(MigrationPlan {
                kind: MigrationKind::ExternalImport,
                from: ResolvedEndpoint {
                    db: "external".into(),
                    table: ext.table.clone(),
                    storage: TableStorageMode::InlineJson,
                },
                to: ResolvedEndpoint {
                    db: to.db.clone(),
                    table: target_table,
                    storage: TableStorageMode::InlineJson,
                },
                effective_delete_source: false,
                external: Some(ext.clone()),
            })
        }
        MigrationSource::Clove(from) => {
            let (to_db, to_table, delete_source) = if let Some(t) = to {
                (
                    t.db.clone(),
                    t.table.clone().unwrap_or_else(|| from.table.clone()),
                    t.delete_source,
                )
            } else {
                (from.db.clone(), from.table.clone(), false)
            };

            let in_place = from.db == to_db && from.table == to_table;
            if in_place {
                return Ok(MigrationPlan {
                    kind: MigrationKind::InPlaceEvolve,
                    from: ResolvedEndpoint {
                        db: from.db.clone(),
                        table: from.table.clone(),
                        storage: TableStorageMode::InlineJson,
                    },
                    to: ResolvedEndpoint {
                        db: to_db,
                        table: to_table,
                        storage: TableStorageMode::InlineJson,
                    },
                    effective_delete_source: false,
                    external: None,
                });
            }

            Ok(MigrationPlan {
                kind: MigrationKind::DataTransfer,
                from: ResolvedEndpoint {
                    db: from.db.clone(),
                    table: from.table.clone(),
                    storage: TableStorageMode::InlineJson,
                },
                to: ResolvedEndpoint {
                    db: to_db,
                    table: to_table,
                    storage: TableStorageMode::InlineJson,
                },
                effective_delete_source: delete_source,
                external: None,
            })
        }
    }
}

pub fn resolve_table_storage(db: &DatabaseManager, table: &str) -> TableStorageMode {
    db.table_storage_mode(table)
}

pub fn apply_storage_modes(
    plan: &mut MigrationPlan,
    source_db: Option<&DatabaseManager>,
    target_db: &DatabaseManager,
) {
    if plan.external.is_none() {
        if let Some(src) = source_db {
            plan.from.storage = resolve_table_storage(src, &plan.from.table);
        }
    }
    plan.to.storage = resolve_table_storage(target_db, &plan.to.table);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use crate::migration::types::{KeyDecoder, ValueDecoder};

    #[test]
    fn no_to_is_inplace() {
        let plan = resolve_plan(
            &MigrationSource::Clove(MigrationFrom {
                db: "legacy".into(),
                table: "products".into(),
            }),
            None,
        )
        .unwrap();
        assert_eq!(plan.kind, MigrationKind::InPlaceEvolve);
        assert!(!plan.effective_delete_source);
    }

    #[test]
    fn same_from_to_ignores_delete_source() {
        let plan = resolve_plan(
            &MigrationSource::Clove(MigrationFrom {
                db: "legacy".into(),
                table: "products".into(),
            }),
            Some(&MigrationTo {
                db: "legacy".into(),
                table: Some("products".into()),
                delete_source: true,
            }),
        )
        .unwrap();
        assert_eq!(plan.kind, MigrationKind::InPlaceEvolve);
        assert!(!plan.effective_delete_source);
    }

    #[test]
    fn cross_db_same_table() {
        let plan = resolve_plan(
            &MigrationSource::Clove(MigrationFrom {
                db: "wh".into(),
                table: "products".into(),
            }),
            Some(&MigrationTo::new("shop")),
        )
        .unwrap();
        assert_eq!(plan.kind, MigrationKind::DataTransfer);
        assert_eq!(plan.to.table, "products");
    }

    #[test]
    fn external_requires_to() {
        let ext = ExternalFrom {
            path: PathBuf::from("x.redb"),
            table: "v".into(),
            key_decoder: KeyDecoder::Utf8String,
            value_decoder: ValueDecoder::JsonValidate,
        };
        assert!(resolve_plan(&MigrationSource::External(ext), None).is_err());
    }
}
