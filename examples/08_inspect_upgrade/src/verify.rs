use std::path::Path;

use clove1db::{
    backup::view::RecordData,
    metadata::{read_meta, CloveMeta, FileKind, InspectReport},
    storage::Storage,
    units::{ClError, Result},
};
use redb::Database;

use crate::entities::{BuyerV1, EmployeeV1, ProductV1, ProductV2};
use crate::entities::seed_counts;

pub fn assert_kind(report: &InspectReport, expected: FileKind, label: &str) -> Result<()> {
    if report.kind != expected {
        return Err(ClError::Validation(format!(
            "{label}: expected FileKind::{expected:?}, got {:?}",
            report.kind
        ))
        .into());
    }
    Ok(())
}

pub fn assert_meta(path: &Path, label: &str, check: impl FnOnce(&CloveMeta) -> bool) -> Result<()> {
    let db = Database::open(path).map_err(|e| ClError::Database(e.into()))?;
    let meta = read_meta(&db)?
        .ok_or_else(|| ClError::Validation(format!("{label}: missing _clove_meta")))?;
    if !check(&meta) {
        return Err(ClError::Validation(format!(
            "{label}: meta assertion failed: {:?}",
            meta
        ))
        .into());
    }
    Ok(())
}

pub fn assert_record_counts_v1(
    storage: &Storage,
    products: usize,
    buyers: usize,
    employees: usize,
) -> Result<()> {
    let p = storage.domain::<ProductV1>().list::<crate::entities::ProductV1Response>()?;
    let b = storage.domain::<BuyerV1>().list::<crate::entities::BuyerResponse>()?;
    let e = storage.domain::<EmployeeV1>().list::<crate::entities::EmployeeResponse>()?;
    if p.len() != products || b.len() != buyers || e.len() != employees {
        return Err(ClError::Validation(format!(
            "record counts: products={}/{} buyers={}/{} employees={}/{}",
            p.len(),
            products,
            b.len(),
            buyers,
            e.len(),
            employees
        ))
        .into());
    }
    Ok(())
}

pub fn assert_record_counts_v2(
    storage: &Storage,
    products: usize,
    buyers: usize,
    employees: usize,
) -> Result<()> {
    let p = storage.domain::<ProductV2>().list::<crate::entities::ProductV2Response>()?;
    let b = storage.domain::<BuyerV1>().list::<crate::entities::BuyerResponse>()?;
    let e = storage.domain::<EmployeeV1>().list::<crate::entities::EmployeeResponse>()?;
    if p.len() != products || b.len() != buyers || e.len() != employees {
        return Err(ClError::Validation(format!(
            "record counts v2: products={}/{} buyers={}/{} employees={}/{}",
            p.len(),
            products,
            b.len(),
            buyers,
            e.len(),
            employees
        ))
        .into());
    }
    Ok(())
}

pub fn assert_backup_versions(
    storage: &Storage,
    product_id: &str,
    min_versions: usize,
) -> Result<()> {
    let domain = storage.domain::<ProductV1>();
    let history = domain.history(product_id)?;
    if history.len() < min_versions {
        return Err(ClError::Validation(format!(
            "expected >= {min_versions} backup versions, got {}",
            history.len()
        ))
        .into());
    }
    Ok(())
}

pub fn assert_get_by_version_readable(storage: &Storage, product_id: &str) -> Result<()> {
    let domain = storage.domain::<ProductV1>();
    let record = domain.get_by_version(product_id, 1)?;
    match record.data {
        RecordData::Typed(_) | RecordData::Json(_) => Ok(()),
        RecordData::None => Err(ClError::Validation("version 1 data is None".into()).into()),
    }
}

pub fn default_retail_counts() -> (usize, usize, usize) {
    (seed_counts::PRODUCTS, seed_counts::BUYERS, seed_counts::EMPLOYEES)
}
