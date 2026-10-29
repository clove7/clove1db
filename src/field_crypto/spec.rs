use super::{
    method::{HashAlgo, Method},
    slots::{Part, RowBinding},
};
use crate::units::Result;

/// One protected field as the entity declares it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedSpec {
    /// Stable number of the field. It, not the name, selects the field's keys, so renaming the
    /// field in code does not change them.
    pub id: u32,
    /// The key of the field in the stored JSON row.
    pub key: &'static str,
    pub method: Method,
    /// Set for [`Method::Hash`] only.
    pub hash: Option<HashAlgo>,
    /// For [`Method::SearchPrint`]: how a value is normalised before its fingerprint is made, in
    /// order. Empty for the other methods.
    pub normalize: &'static [crate::fields::TransformKind],
    /// For [`Method::EncryptPartPrints`]: the length, in characters, of the parts of a value that get a
    /// fingerprint. 0 for the other methods.
    pub window: u8,
    /// For [`Method::EncryptPartPrints`]: how many bits of each part's fingerprint are kept. The fewer,
    /// the more parts share a fingerprint (a stronger protection, more rows to check). 0 for the
    /// other methods.
    pub bits: u8,
}

/// Implemented by `#[derive(CloveFields)]` for an entity that has protected fields. The
/// methods are for the storage layer; they are not meant to be called directly.
pub trait SealedFields: Sized {
    /// The protected fields, in declaration order.
    const SEALED: &'static [SealedSpec];

    /// Ties every protected field to the row it was read from.
    #[doc(hidden)]
    fn bind_sealed(&mut self, row: &RowBinding);

    /// The content of every protected field, in the order of [`SealedFields::SEALED`].
    #[doc(hidden)]
    fn sealed_parts(&self) -> Result<Vec<Part<'_>>>;
}
