//! Verification hashes of passwords and codes.
//!
//! Stored form: URL-safe base64 of `version (1) || salt (16) || hash (32)`. Nothing else is stored:
//! the algorithm and its cost come from the code, as the cipher does, so a wrong setting verifies as
//! "no" like a wrong password.
//!
//! The hash is `Argon2id` or `scrypt` (slow on purpose) of `HMAC-SHA-256(field hash key, label ||
//! row key || secret)` with a random salt per value. The field hash key comes from the read root
//! and is not in any file, so a stolen file cannot be attacked offline without it; mixing the row
//! key in means a hash copied to another row does not verify there.
use super::{b64, envelope::Place, keys::FieldKeys, method::HashAlgo};
use crate::{
    crypto::{MacKind, PasswordKdf, ct_eq, random_bytes},
    units::{ClError, Result},
};
use zeroize::Zeroize;

const VERSION: u8 = 1;
const SALT: usize = 16;
const HASH: usize = 32;
const LABEL: &[u8] = b"cf-hash";

fn settings(algo: HashAlgo) -> PasswordKdf {
    match algo {
        HashAlgo::Argon2id => PasswordKdf::argon2id_default(),
        HashAlgo::Scrypt => PasswordKdf::scrypt_default(),
    }
}

fn fail(what: &'static str) -> ClError {
    ClError::Validation(what.into())
}

/// A keyed fingerprint of the hash settings (type, memory, passes, lanes) of one field. Stored in the
/// table description so that a later change of the settings in code is found when the database is
/// opened, instead of every old hash failing to verify. Without the field hash key it says nothing
/// about the settings.
pub(crate) fn settings_fingerprint(
    keys: &FieldKeys,
    table_id: &str,
    field_id: u32,
    algo: HashAlgo,
) -> Result<String> {
    let key = keys.hash_key(table_id, field_id)?;
    let mut data = b"cf-hash-settings".to_vec();
    match settings(algo) {
        PasswordKdf::Argon2id { memory_kib, iterations, lanes } => {
            data.push(1);
            for n in [memory_kib, iterations, lanes] {
                data.extend_from_slice(&n.to_le_bytes());
            }
        }
        PasswordKdf::Scrypt { log_n, r, p } => {
            data.push(2);
            data.push(log_n);
            for n in [r, p] {
                data.extend_from_slice(&n.to_le_bytes());
            }
        }
    }
    let tag = MacKind::HmacSha256.mac(&key, &data).map_err(|_| fail("the hash settings could not be fingerprinted"))?;
    Ok(b64::encode(tag.as_bytes()))
}

/// Whether two stored settings fingerprints are the same.
pub(crate) fn same_settings(a: &str, b: &str) -> bool {
    ct_eq(a.as_bytes(), b.as_bytes())
}

/// The slow hash of `secret` for this place with this salt.
fn compute(keys: &FieldKeys, algo: HashAlgo, place: &Place, secret: &[u8], salt: &[u8]) -> Result<[u8; HASH]> {
    let key = keys.hash_key(place.table_id, place.field_id)?;
    let mut data = Vec::with_capacity(LABEL.len() + 8 + place.row_key.len() + secret.len());
    data.extend_from_slice(LABEL);
    data.extend_from_slice(&(place.row_key.len() as u64).to_le_bytes());
    data.extend_from_slice(place.row_key.as_bytes());
    data.extend_from_slice(secret);
    let mixed = MacKind::HmacSha256.mac(&key, &data).map_err(|_| fail("the hash input could not be made"));
    data.zeroize();
    let mixed = mixed?;
    let mut out = [0u8; HASH];
    let mut input = mixed.as_bytes().to_vec();
    let derived = settings(algo).derive(&input, salt, &mut out);
    input.zeroize();
    derived.map_err(|_| fail("the hash could not be computed"))?;
    Ok(out)
}

/// The stored text for `secret` at this place, with a new random salt.
pub(crate) fn hash_value(keys: &FieldKeys, algo: HashAlgo, place: &Place, secret: &[u8]) -> Result<String> {
    let mut salt = [0u8; SALT];
    random_bytes(&mut salt).map_err(|_| fail("the system could not provide random bytes"))?;
    let mut hash = compute(keys, algo, place, secret, &salt)?;
    let mut raw = Vec::with_capacity(1 + SALT + HASH);
    raw.push(VERSION);
    raw.extend_from_slice(&salt);
    raw.extend_from_slice(&hash);
    hash.zeroize();
    Ok(b64::encode(&raw))
}

/// Whether `secret` is the one that made `stored` at this place. Any problem with `stored` (wrong
/// length, version, text) is `Ok(false)`, the same as a wrong secret. The comparison takes the same
/// time whatever the hashes are.
pub(crate) fn verify_value(
    keys: &FieldKeys,
    algo: HashAlgo,
    place: &Place,
    secret: &[u8],
    stored: &str,
) -> Result<bool> {
    let Some(raw) = b64::decode(stored) else {
        return Ok(false);
    };
    if raw.len() != 1 + SALT + HASH || raw[0] != VERSION {
        return Ok(false);
    }
    let (salt, expected) = raw[1..].split_at(SALT);
    let mut hash = compute(keys, algo, place, secret, salt)?;
    let same = ct_eq(&hash, expected);
    hash.zeroize();
    Ok(same)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CipherKind, DataKey, HkdfHash, Key32, KeySuite, ProgrammerKey};

    fn keys(seed: u8) -> FieldKeys {
        let suite = KeySuite { cipher: CipherKind::Aes256GcmSiv, hkdf: HkdfHash::Sha256 };
        let data = DataKey::generate().unwrap();
        let read = Key32::from_bytes(&[seed; 32]);
        let search = Key32::from_bytes(&[2; 32]);
        let locked = data.lock(&suite, &ProgrammerKey::Raw(&read), &ProgrammerKey::Raw(&search)).unwrap();
        let access = locked
            .unlock(&suite, Some(&ProgrammerKey::Raw(&read)), Some(&ProgrammerKey::Raw(&search)))
            .unwrap();
        FieldKeys::with_access(suite, access).unwrap()
    }

    fn place<'a>(table: &'a str, field: u32, row: &'a str) -> Place<'a> {
        Place { table_id: table, field_id: field, row_key: row }
    }

    #[test]
    fn a_secret_verifies_and_another_does_not() {
        let k = keys(1);
        let p = place("t1", 4, "user-1");
        for algo in [HashAlgo::Argon2id, HashAlgo::Scrypt] {
            let stored = hash_value(&k, algo, &p, b"hunter2").unwrap();
            assert!(!stored.contains("hunter2"));
            assert!(verify_value(&k, algo, &p, b"hunter2", &stored).unwrap());
            assert!(!verify_value(&k, algo, &p, b"hunter3", &stored).unwrap());
            assert!(!verify_value(&k, algo, &p, b"", &stored).unwrap());
        }
    }

    #[test]
    fn the_same_secret_gives_a_different_text_each_time() {
        let k = keys(1);
        let p = place("t1", 4, "user-1");
        let a = hash_value(&k, HashAlgo::Argon2id, &p, b"same").unwrap();
        let b = hash_value(&k, HashAlgo::Argon2id, &p, b"same").unwrap();
        assert_ne!(a, b);
        // 1 + 16 + 32 bytes: 66 characters, whatever the secret.
        assert_eq!(a.len(), 66);
        assert_eq!(hash_value(&k, HashAlgo::Argon2id, &p, &[7u8; 500]).unwrap().len(), 66);
    }

    #[test]
    fn a_hash_copied_to_another_row_field_or_table_does_not_verify() {
        let k = keys(1);
        let stored = hash_value(&k, HashAlgo::Argon2id, &place("t1", 4, "user-1"), b"pw").unwrap();
        for other in [place("t1", 4, "user-2"), place("t1", 5, "user-1"), place("t2", 4, "user-1")] {
            assert!(!verify_value(&k, HashAlgo::Argon2id, &other, b"pw", &stored).unwrap());
        }
    }

    #[test]
    fn a_different_database_key_or_algorithm_does_not_verify() {
        let (a, b) = (keys(1), keys(9));
        let p = place("t1", 4, "user-1");
        let stored = hash_value(&a, HashAlgo::Argon2id, &p, b"pw").unwrap();
        // Another database holds another hash key: the file alone cannot be attacked.
        assert!(!verify_value(&b, HashAlgo::Argon2id, &p, b"pw", &stored).unwrap());
        // A setting that differs from the one used to write verifies as "no".
        assert!(!verify_value(&a, HashAlgo::Scrypt, &p, b"pw", &stored).unwrap());
    }

    #[test]
    fn the_settings_fingerprint_follows_the_settings_the_field_and_the_key() {
        let k = keys(1);
        let a = settings_fingerprint(&k, "t1", 4, HashAlgo::Argon2id).unwrap();
        assert_eq!(a, settings_fingerprint(&k, "t1", 4, HashAlgo::Argon2id).unwrap());
        assert!(same_settings(&a, &a));
        for other in [
            settings_fingerprint(&k, "t1", 4, HashAlgo::Scrypt).unwrap(),
            settings_fingerprint(&k, "t1", 5, HashAlgo::Argon2id).unwrap(),
            settings_fingerprint(&k, "t2", 4, HashAlgo::Argon2id).unwrap(),
            settings_fingerprint(&keys(9), "t1", 4, HashAlgo::Argon2id).unwrap(),
        ] {
            assert!(!same_settings(&a, &other));
        }
        // 32 bytes of tag as text, and no setting in it that a reader could see.
        assert_eq!(a.len(), 43);
        assert!(!a.to_lowercase().contains("argon"));
    }

    #[test]
    fn damaged_text_is_no_not_an_error_or_a_panic() {
        let k = keys(1);
        let p = place("t1", 4, "user-1");
        let (long66, long67) = ("A".repeat(66), "A".repeat(67));
        for bad in ["", "x", "not base64 !!", "AAAA", long66.as_str(), long67.as_str()] {
            assert!(!verify_value(&k, HashAlgo::Argon2id, &p, b"pw", bad).unwrap(), "{bad}");
        }
        let stored = hash_value(&k, HashAlgo::Argon2id, &p, b"pw").unwrap();
        let mut chars: Vec<char> = stored.chars().collect();
        chars[30] = if chars[30] == 'A' { 'B' } else { 'A' };
        let changed: String = chars.into_iter().collect();
        assert!(!verify_value(&k, HashAlgo::Argon2id, &p, b"pw", &changed).unwrap());
    }

    #[test]
    fn a_program_without_the_read_key_cannot_hash_or_verify() {
        let suite = KeySuite { cipher: CipherKind::Aes256GcmSiv, hkdf: HkdfHash::Sha256 };
        let data = DataKey::generate().unwrap();
        let read = Key32::from_bytes(&[1; 32]);
        let search = Key32::from_bytes(&[2; 32]);
        let locked = data.lock(&suite, &ProgrammerKey::Raw(&read), &ProgrammerKey::Raw(&search)).unwrap();
        let full = locked
            .unlock(&suite, Some(&ProgrammerKey::Raw(&read)), Some(&ProgrammerKey::Raw(&search)))
            .unwrap();
        let writer = FieldKeys::with_access(suite, full).unwrap();
        let access = locked.unlock(&suite, None, Some(&ProgrammerKey::Raw(&search))).unwrap();
        let k = FieldKeys::with_access(suite, access).unwrap();
        let p = place("t1", 4, "user-1");
        assert!(hash_value(&k, HashAlgo::Argon2id, &p, b"pw").is_err());
        // A well-formed hash made with the read key: the search-key-only program cannot check it.
        let stored = hash_value(&writer, HashAlgo::Argon2id, &p, b"pw").unwrap();
        assert!(verify_value(&writer, HashAlgo::Argon2id, &p, b"pw", &stored).unwrap());
        assert!(verify_value(&k, HashAlgo::Argon2id, &p, b"pw", &stored).is_err());
    }
}
