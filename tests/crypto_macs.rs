//! Fingerprints and password hashes through the public API.
use clove1db::crypto::{CryptoError, Key32, MacKind, PasswordKdf, SecretBytes};

#[test]
fn a_fingerprint_is_stable_and_depends_on_key_and_value() {
    let (key, other) = (Key32::generate().unwrap(), Key32::generate().unwrap());
    let value = b"0123456789abcdef";
    for kind in MacKind::ALL {
        let tag = kind.mac(&key, value).unwrap();
        assert_eq!(tag.as_bytes().len(), kind.output_len(), "{kind:?}");
        assert_eq!(kind.mac(&key, value).unwrap(), tag, "{kind:?}: not stable");
        assert_ne!(kind.mac(&other, value).unwrap(), tag, "{kind:?}: ignores the key");
        assert_ne!(kind.mac(&key, b"0123456789abcdeg").unwrap(), tag, "{kind:?}: ignores the value");
        assert!(kind.verify(&key, value, tag.as_bytes()).unwrap());
        assert!(!kind.verify(&key, b"another value!!", tag.as_bytes()).unwrap());
        assert!(!kind.verify(&key, value, &tag.as_bytes()[1..]).unwrap());
    }
}

#[test]
fn the_kinds_give_different_tags_for_the_same_input() {
    let key = Key32::generate().unwrap();
    let tags: Vec<Vec<u8>> = MacKind::ALL
        .iter()
        .map(|k| k.mac(&key, b"value").unwrap().as_bytes().to_vec())
        .collect();
    for (i, a) in tags.iter().enumerate() {
        for b in &tags[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

#[test]
fn a_password_hash_verifies_only_the_right_password_and_salt() {
    let salt = [9u8; 16];
    for kdf in [
        PasswordKdf::Argon2id { memory_kib: 19_456, iterations: 2, lanes: 1 },
        PasswordKdf::Scrypt { log_n: 12, r: 8, p: 32 },
    ] {
        let mut hash = [0u8; 32];
        kdf.derive(b"right", &salt, &mut hash).unwrap();
        assert!(kdf.verify(b"right", &salt, &hash).unwrap(), "{kdf:?}");
        assert!(!kdf.verify(b"wrong", &salt, &hash).unwrap(), "{kdf:?}");
        assert!(!kdf.verify(b"right", &[8u8; 16], &hash).unwrap(), "{kdf:?}");
        let key = kdf.derive_key(&SecretBytes::from_slice(b"right"), &salt).unwrap();
        assert!(key == Key32::from_slice(&hash).unwrap(), "{kdf:?}");
    }
}

#[test]
fn bad_cost_settings_are_an_error_and_name_no_secret() {
    let pw = SecretBytes::from_slice(b"do-not-print-this");
    for kdf in [
        PasswordKdf::Argon2id { memory_kib: 1, iterations: 1, lanes: 1 },
        PasswordKdf::Argon2id { memory_kib: 19_456, iterations: 0, lanes: 1 },
        PasswordKdf::Argon2id { memory_kib: 64, iterations: 1, lanes: 1 },
        PasswordKdf::Scrypt { log_n: 4, r: 0, p: 1 },
        PasswordKdf::Scrypt { log_n: 4, r: 1, p: 1 },
    ] {
        let err = kdf.derive_key(&pw, &[1u8; 16]).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidParams(_)), "{kdf:?}");
        assert!(!format!("{err}").contains("do-not-print"));
    }
}
