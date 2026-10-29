/// How one field is protected. The numeric codes are stored in the table description, so they
/// never change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// Sealed; opened only with a read grant.
    Encrypt,
    /// Sealed, with a fingerprint of the whole value for equality search.
    EncryptFullPrint,
    /// Sealed, with fingerprints of value parts for partial search.
    EncryptPartPrints,
    /// Slow salted verification hash; never readable.
    Hash,
    /// Keyed fingerprint for equality search; never readable.
    SearchPrint,
}

impl Method {
    pub const fn code(self) -> u8 {
        match self {
            Method::Encrypt => 1,
            Method::EncryptFullPrint => 2,
            Method::EncryptPartPrints => 3,
            Method::Hash => 4,
            Method::SearchPrint => 5,
        }
    }

    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Method::Encrypt),
            2 => Some(Method::EncryptFullPrint),
            3 => Some(Method::EncryptPartPrints),
            4 => Some(Method::Hash),
            5 => Some(Method::SearchPrint),
            _ => None,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Method::Encrypt => "encrypt",
            Method::EncryptFullPrint => "encrypt with full fingerprint",
            Method::EncryptPartPrints => "encrypt with part fingerprints",
            Method::Hash => "hash",
            Method::SearchPrint => "search fingerprint",
        }
    }

    /// Whether the field is stored as an object that carries a whole-value fingerprint beside the
    /// sealed text: `{"s": sealed text, "f": fingerprint}`.
    pub const fn has_stored_print(self) -> bool {
        matches!(self, Method::EncryptFullPrint | Method::EncryptPartPrints)
    }

    /// Whether the field also stores fingerprints of the parts of the value (`"p"`).
    pub const fn has_parts(self) -> bool {
        matches!(self, Method::EncryptPartPrints)
    }

    /// Whether the field can be searched by the fingerprint of a whole value.
    pub const fn has_full_print(self) -> bool {
        matches!(self, Method::EncryptFullPrint | Method::EncryptPartPrints | Method::SearchPrint)
    }

    /// Whether the stored value can be opened again.
    pub const fn is_sealing(self) -> bool {
        matches!(
            self,
            Method::Encrypt | Method::EncryptFullPrint | Method::EncryptPartPrints
        )
    }
}

/// The slow hash behind [`Method::Hash`]. Its settings come from code, never from the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgo {
    Argon2id,
    Scrypt,
}
