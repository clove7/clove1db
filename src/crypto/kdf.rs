//! Key derivation: HKDF for subkeys, a deliberately slow function for passwords.
use super::{
    error::{CryptoError, Result},
    secret::{Key32, SecretBytes, ct_eq},
};
use hkdf::Hkdf;
use sha2::{Sha256, Sha512};

/// The hash behind HKDF. A database-wide choice, never written to a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HkdfHash {
    Sha256,
    Sha512,
}

impl HkdfHash {
    /// HKDF extract then expand (RFC 5869). `out` may be up to 255 times the hash length.
    pub fn derive(
        self,
        salt: Option<&[u8]>,
        ikm: &[u8],
        info: &[u8],
        out: &mut [u8],
    ) -> Result<()> {
        let too_long = |_| CryptoError::InvalidParams("derived length too long");
        match self {
            HkdfHash::Sha256 => Hkdf::<Sha256>::new(salt, ikm)
                .expand(info, out)
                .map_err(too_long),
            HkdfHash::Sha512 => Hkdf::<Sha512>::new(salt, ikm)
                .expand(info, out)
                .map_err(too_long),
        }
    }
}

/// Password to key (or to a verification hash) by a memory-hard function. The cost settings are
/// the caller's configuration and are not stored beside the data.
///
/// The defaults and the floor below which settings are refused follow measured costs. On a
/// 12-thread x86_64 machine, running on one thread, the default Argon2id took a median of
/// 101 ms and about 68 MiB, and the default scrypt a median of 204 ms and about 132 MiB.
///
/// - [`PasswordKdf::default`] is Argon2id (the RFC 9106 choice) with 65,536 KiB, 3 iterations and
///   1 lane. One lane because the `parallel` feature of the argon2 crate is not enabled, so more
///   lanes run one after another: they change the result and do not make it faster.
/// - [`PasswordKdf::scrypt_default`] is N = 2^17, r = 8, p = 1.
/// - Every derivation, so locking and opening alike, first calls [`PasswordKdf::validate`]. A
///   setting under the floor is [`CryptoError::InvalidParams`] before any work is done, and no
///   public path skips that check. The floor: Argon2id memory at least 19,456 KiB, iterations at
///   least 2, lanes at least 1; scrypt r at least 8 and N times p at least 2^17.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordKdf {
    Argon2id {
        memory_kib: u32,
        iterations: u32,
        lanes: u32,
    },
    Scrypt {
        log_n: u8,
        r: u32,
        p: u32,
    },
}

impl Default for PasswordKdf {
    fn default() -> Self {
        Self::argon2id_default()
    }
}

impl PasswordKdf {
    pub const ARGON2ID_MIN_MEMORY_KIB: u32 = 19_456;
    pub const ARGON2ID_MIN_ITERATIONS: u32 = 2;
    pub const ARGON2ID_MIN_LANES: u32 = 1;
    pub const SCRYPT_MIN_R: u32 = 8;
    /// The floor on N times p, as a power of two: N * p >= 2^17.
    pub const SCRYPT_MIN_WORK_LOG2: u32 = 17;

    /// Argon2id, 65,536 KiB, 3 iterations, 1 lane.
    pub const fn argon2id_default() -> Self {
        PasswordKdf::Argon2id {
            memory_kib: 65_536,
            iterations: 3,
            lanes: 1,
        }
    }

    /// scrypt, N = 2^17, r = 8, p = 1.
    pub const fn scrypt_default() -> Self {
        PasswordKdf::Scrypt {
            log_n: 17,
            r: 8,
            p: 1,
        }
    }

    /// Refuse a setting under the floor. Does no hashing and reads no password.
    pub fn validate(&self) -> Result<()> {
        match *self {
            PasswordKdf::Argon2id {
                memory_kib,
                iterations,
                lanes,
            } => {
                if memory_kib < Self::ARGON2ID_MIN_MEMORY_KIB {
                    return Err(CryptoError::InvalidParams("argon2id memory under the minimum"));
                }
                if iterations < Self::ARGON2ID_MIN_ITERATIONS {
                    return Err(CryptoError::InvalidParams("argon2id iterations under the minimum"));
                }
                if lanes < Self::ARGON2ID_MIN_LANES {
                    return Err(CryptoError::InvalidParams("argon2id lanes under the minimum"));
                }
            }
            PasswordKdf::Scrypt { log_n, r, p } => {
                if r < Self::SCRYPT_MIN_R {
                    return Err(CryptoError::InvalidParams("scrypt r under the minimum"));
                }
                // N * p >= 2^17. With p at least 1 and log_n at 17 or more it holds already; below
                // that the shift is small, so the product cannot overflow.
                let enough = p >= 1
                    && (u32::from(log_n) >= Self::SCRYPT_MIN_WORK_LOG2
                        || (u64::from(p) << log_n) >= 1u64 << Self::SCRYPT_MIN_WORK_LOG2);
                if !enough {
                    return Err(CryptoError::InvalidParams("scrypt N times p under the minimum"));
                }
            }
        }
        Ok(())
    }

    /// Fill `out` from `password` and `salt` (at least 8 bytes). Refuses settings under the floor
    /// (see [`PasswordKdf::validate`]) before any work.
    pub fn derive(&self, password: &[u8], salt: &[u8], out: &mut [u8]) -> Result<()> {
        self.validate()?;
        self.compute(password, salt, out)
    }

    /// The same derivation without the floor, so the published test vectors (which use small
    /// settings) can run through this wrapper. Not compiled outside the crate's own tests.
    #[cfg(test)]
    pub(crate) fn derive_unchecked(&self, password: &[u8], salt: &[u8], out: &mut [u8]) -> Result<()> {
        self.compute(password, salt, out)
    }

    fn compute(&self, password: &[u8], salt: &[u8], out: &mut [u8]) -> Result<()> {
        const BAD: CryptoError = CryptoError::InvalidParams("password hashing settings rejected");
        match *self {
            PasswordKdf::Argon2id {
                memory_kib,
                iterations,
                lanes,
            } => {
                let params = argon2::Params::new(memory_kib, iterations, lanes, Some(out.len()))
                    .map_err(|_| BAD)?;
                argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                    .hash_password_into(password, salt, out)
                    .map_err(|_| BAD)
            }
            PasswordKdf::Scrypt { log_n, r, p } => {
                let params = scrypt::Params::new(log_n, r, p).map_err(|_| BAD)?;
                scrypt::scrypt(password, salt, &params, out).map_err(|_| BAD)
            }
        }
    }

    pub fn derive_key(&self, password: &SecretBytes, salt: &[u8]) -> Result<Key32> {
        let mut key = Key32::zeroed();
        self.derive(password.as_bytes(), salt, key.as_bytes_mut())?;
        Ok(key)
    }

    /// Recompute the hash and compare it with `expected` in constant time.
    pub fn verify(&self, password: &[u8], salt: &[u8], expected: &[u8]) -> Result<bool> {
        let mut again = SecretBytes::zeroed(expected.len());
        self.derive(password, salt, again.as_bytes_mut())?;
        Ok(ct_eq(again.as_bytes(), expected))
    }
}
