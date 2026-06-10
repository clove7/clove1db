use clove1db::units::Result;

use crate::entities::{BuyerResponse, EmployeeResponse, ProductV1Response, ProductV2Response};
use crate::entities::seed_counts;
use crate::fixtures::SeedState;
use crate::log;
use crate::paths;
use crate::storage::{retail_v1_storage, retail_v2_storage};
use crate::verify::{assert_record_counts_v1, assert_record_counts_v2, default_retail_counts};

pub fn run(seed: &SeedState) -> Result<()> {
    let (products, buyers, employees) = default_retail_counts();

    log::step("Post-upgrade 042 — record counts + field-level JSON match");
    let dir_042 = paths::upgraded_042_dir();
    let storage = retail_v1_storage(dir_042, "retail", "retail")?;
    assert_record_counts_v1(&storage, products, buyers, employees)?;
    log::ok(format!("counts: {products} products, {buyers} buyers, {employees} employees"));

    let domain = storage.domain::<crate::entities::ProductV1>();
    log::subsection("products (ProductV1 JSON)");
    for (id, expected_name) in &seed.retail_042.products {
        let got = domain.get::<ProductV1Response>(id)?;
        log::line(format!(
            "[{}] name={} (expected {})",
            log::short_id(id),
            got.name,
            expected_name
        ));
        if got.name != *expected_name {
            return Err(clove1db::units::ClError::Validation(format!(
                "product {id}: expected name {expected_name}, got {}",
                got.name
            )));
        }
    }

    let buyer_domain = storage.domain::<crate::entities::BuyerV1>();
    log::subsection("buyers");
    for (id, name, email) in &seed.retail_042.buyers {
        let got = buyer_domain.get::<BuyerResponse>(id)?;
        log::line(format!(
            "[{}] {name} <{email}>",
            log::short_id(id)
        ));
        if got.name != *name || got.email != *email {
            return Err(clove1db::units::ClError::Validation(format!(
                "buyer {id} mismatch"
            )));
        }
    }

    let employee_domain = storage.domain::<crate::entities::EmployeeV1>();
    log::subsection("employees");
    for (id, name, role) in &seed.retail_042.employees {
        let got = employee_domain.get::<EmployeeResponse>(id)?;
        log::line(format!("[{}] {name} ({role})", log::short_id(id)));
        if got.name != *name || got.role != *role {
            return Err(clove1db::units::ClError::Validation(format!(
                "employee {id} mismatch"
            )));
        }
    }
    drop(storage);

    log::step("Post-upgrade 049 — products at RetailV2 (sku + price_cents)");
    let dir_049 = paths::upgraded_049_dir();
    let storage_v2 = retail_v2_storage(dir_049, "retail", "retail")?;
    assert_record_counts_v2(&storage_v2, products, buyers, employees)?;

    let domain_v2 = storage_v2.domain::<crate::entities::ProductV2>();
    log::subsection("products (ProductV2 JSON)");
    for (id, expected_name) in &seed.retail_049.products {
        let got = domain_v2.get::<ProductV2Response>(id)?;
        log::line(format!(
            "[{}] name={} sku={} price_cents={}",
            log::short_id(id),
            got.name,
            got.sku,
            got.price_cents
        ));
        if got.name != *expected_name {
            return Err(clove1db::units::ClError::Validation(format!(
                "product v2 {id}: name mismatch"
            )));
        }
        if got.sku.is_empty() || got.price_cents != 1000 {
            return Err(clove1db::units::ClError::Validation(format!(
                "product v2 {id}: missing sku/price from migration"
            )));
        }
    }

    if seed.retail_049.products.len() != seed_counts::PRODUCTS {
        return Err(clove1db::units::ClError::Validation("049 product count".into()));
    }
    log::ok("all entity fields match seed manifests");

    Ok(())
}
