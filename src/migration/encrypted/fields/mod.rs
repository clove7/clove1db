//! Changing how the fields of a table are protected after it was made: sealing a plain
//! field, giving it or taking from it its fingerprints, opening it, or making it a hash or a
//! fingerprint that does not keep the value. What each field becomes is decided in [`plan`].
pub(crate) mod analyze;
pub(crate) mod api;
pub(crate) mod hooks;
pub(crate) mod plan;
pub(crate) mod run;
#[cfg(test)]
mod whole_tests;

#[cfg(test)]
mod dry_run_tests;
