//! User data writes are journaled atomically. `DatabaseManager::db()` exposes
//! snapshot reads only; use set, delete, commit_batch or commit_batch_atomic.
#[cfg(test)]
mod journal_tests;
pub mod journal;
mod journal_blob;
pub mod backup;
pub mod blob;
pub mod domain;
pub mod dto;
pub mod durability;
pub mod entity;
pub mod fsutil;
pub mod handle;
#[cfg(test)]
mod handle_tests;
pub mod metadata;
pub mod migration;
pub mod repository;
#[cfg(test)]
mod repository_tests;
pub mod storage;
pub mod units;
pub mod memory;
#[cfg(feature = "crash-inject")]
pub use memory::test_fail_allocation;
#[cfg(feature = "crash-inject")]
pub use handle::test_prefetched_bytes;
pub mod upgrade;

pub use durability::{DurabilityMode, DEFAULT_MAX_COMMIT_BATCH_ENTRIES};
pub use handle::RedbOptions;
pub use metadata::{FileEra, FileKind, InspectReport, TableStorageMode, inspect_cldb};

#[cfg(test)]
mod backup_tests;

pub use journal::{Change,ChangeKind,ConsumerToken,ReadView,JournalStats,Retention,DEFAULT_JOURNAL_MAX_BYTES};

mod lastwrite;
mod id_contract;
pub mod unique;
pub use unique::Unique;
pub mod query;
pub mod events;
pub use events::LibraryEvent;
pub mod fields;
pub use fields::CloveFields;
pub use clove1db_derive::CloveFields;
extern crate self as clove1db;

pub mod indexes;
pub mod crypto;
pub mod field_crypto;
pub mod encrypted_store;
pub use encrypted_store::{EncryptionConfig, EncryptionTuning, KeySource, StoreDiagnostic};
