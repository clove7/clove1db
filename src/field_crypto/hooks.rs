//! What a repository of an entity with protected fields carries: the table identity, the keys,
//! and the two functions that encode a row and tie a row read back to its place.
//!
//! The functions are captured where the entity type is known to have protected fields
//! (`register_sealed`), so the repository itself needs no extra bound on its entity type.
use super::{
    keys::FieldKeys,
    rowcodec::{TableSeal, bind_row_named, seal_row},
    spec::{SealedFields, SealedSpec},
};
use crate::units::Result;
use serde::Serialize;
use std::sync::Arc;

pub(crate) struct SealedKit<T> {
    seal: for<'a> fn(&TableSeal<'a>, &str, &T) -> Result<Vec<u8>>,
    bind: fn(&str, &str, &str, &mut T),
}

impl<T> Clone for SealedKit<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for SealedKit<T> {}

impl<T: Serialize + SealedFields> SealedKit<T> {
    pub(crate) fn new() -> Self {
        Self { seal: seal_row::<T>, bind: bind_row_named::<T> }
    }
}

pub(crate) struct SealedHooks<T> {
    table: Arc<str>,
    table_id: Arc<str>,
    specs: &'static [SealedSpec],
    keys: Arc<FieldKeys>,
    kit: SealedKit<T>,
}

impl<T> SealedHooks<T> {
    pub(crate) fn new(
        table: &str,
        table_id: &str,
        specs: &'static [SealedSpec],
        keys: Arc<FieldKeys>,
        kit: SealedKit<T>,
    ) -> Self {
        Self { table: table.into(), table_id: table_id.into(), specs, keys, kit }
    }

    /// The stored bytes of `value` as row `key`.
    pub(crate) fn encode(&self, key: &str, value: &T) -> Result<Vec<u8>> {
        let table = TableSeal { table_id: &self.table_id, specs: self.specs, keys: &self.keys };
        (self.kit.seal)(&table, key, value)
    }

    /// The protected fields of this table.
    pub(crate) fn specs(&self) -> &'static [SealedSpec] {
        self.specs
    }

    /// A permission to search the fingerprinted fields of this table.
    pub(crate) fn search_grant(&self, sink: crate::events::EventSink) -> Result<super::search::SearchGrant<T>> {
        super::search::SearchGrant::new(self.keys.clone(), self.table.clone(), self.table_id.clone(), sink)
    }

    /// Whether the stored key is one of the protected fields of this table.
    pub(crate) fn protects(&self, key: &str) -> bool {
        self.specs.iter().any(|spec| spec.key == key)
    }

    /// Ties the protected fields of a row just read to row `key` of this table.
    pub(crate) fn bind(&self, key: &str, value: &mut T) {
        (self.kit.bind)(&self.table, &self.table_id, key, value)
    }
}
