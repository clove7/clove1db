use crate::migration::layout::FieldLayout;
use crate::migration::plan::MigrationPlan;
use crate::migration::types::{MigrationKind, TargetConflictPolicy};
use crate::repository::DatabaseManager;
use crate::units::{ClError, Result};

pub fn assert_target_available(
    plan: &MigrationPlan,
    target_db: &DatabaseManager,
    policy: TargetConflictPolicy,
) -> Result<()> {
    if plan.kind == MigrationKind::InPlaceEvolve {
        return Ok(());
    }

    let count = target_db.count_keys(&plan.to.table)?;
    if count == 0 {
        return Ok(());
    }

    match policy {
        TargetConflictPolicy::Fail => Err(ClError::TargetTableOccupied {
            db: plan.to.db.clone(),
            table: plan.to.table.clone(),
            existing_keys: count,
        }),
        TargetConflictPolicy::Skip
        | TargetConflictPolicy::Overwrite
        | TargetConflictPolicy::OverwriteIfCompatible => Ok(()),
    }
}

pub fn check_compatible_overwrite(
    existing_bytes: &[u8],
    incoming_bytes: &[u8],
    target_layout: &FieldLayout,
) -> Result<bool> {
    let existing_layout = FieldLayout::capture_from_sample_json(existing_bytes)?;
    if existing_layout.layout_hash != target_layout.layout_hash {
        return Ok(false);
    }
    let incoming_layout = FieldLayout::capture_from_sample_json(incoming_bytes)?;
    if incoming_layout.diff(target_layout).kind
        != crate::migration::layout::LayoutDiffKind::Identical
        && incoming_layout.diff(target_layout).kind
            != crate::migration::layout::LayoutDiffKind::AutoSafe
    {
        return Ok(false);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compatible_when_same_shape() {
        let layout = FieldLayout::from_json_value(
            &serde_json::json!({"id":"1","name":"a"}),
        );
        let existing = br#"{"id":"1","name":"a"}"#;
        let incoming = br#"{"id":"1","name":"b"}"#;
        assert!(check_compatible_overwrite(existing, incoming, &layout).unwrap());
    }
}
