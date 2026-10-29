//! Changing how a database is protected after it was made: the files are written again, complete,
//! next to the old ones, and replaced only when all of them are ready.
pub(crate) mod attachments;
pub(crate) mod convert;
pub(crate) mod fields;
pub(crate) mod history;
pub(crate) mod marker;
pub(crate) mod rekey;
pub(crate) mod rows;
pub(crate) mod run;
pub(crate) mod sidecars;
pub(crate) mod space;

#[cfg(test)]
mod attachments_kills;
#[cfg(test)]
mod attachments_tests;
#[cfg(test)]
mod convert_tests;
#[cfg(test)]
mod hooks_tests;
#[cfg(test)]
mod rekey_tests;
#[cfg(test)]
mod space_tests;
#[cfg(test)]
mod run_tests;
#[cfg(test)]
mod sidecars_tests;
#[cfg(test)]
mod tests;
