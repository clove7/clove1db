//! Two-key system through the public API: locking, opening, changing the programmer key,
//! and keeping search apart from reading.
use clove1db::crypto::{
    Access, CipherKind, CryptoError, DataKey, HkdfHash, Key32, KeySuite, LockedDataKey, PasswordKdf,
    ProgrammerKey, ReadRoot, Scope, SearchRoot, SecretBytes,
};

const SCOPE: Scope = Scope { table: "people", field: "phone" };

fn suites() -> Vec<KeySuite> {
    let mut all = Vec::new();
    for cipher in CipherKind::ALL {
        for hkdf in [HkdfHash::Sha256, HkdfHash::Sha512] {
            all.push(KeySuite { cipher, hkdf });
        }
    }
    all
}

fn raw(key: &Key32) -> ProgrammerKey<'_> {
    ProgrammerKey::Raw(key)
}

/// The cheapest settings the library accepts (the floor), so these tests stay quick.
fn light_argon() -> PasswordKdf {
    PasswordKdf::Argon2id { memory_kib: 19_456, iterations: 2, lanes: 1 }
}

/// N times p is exactly 2^17, with a small memory use (4 MiB).
fn light_scrypt() -> PasswordKdf {
    PasswordKdf::Scrypt { log_n: 12, r: 8, p: 32 }
}

fn encryption_key(access: &Access, suite: &KeySuite) -> Key32 {
    access.read().unwrap().encryption_key(suite.hkdf, &SCOPE).unwrap()
}

#[test]
fn lock_and_unlock_round_trip_for_every_suite() {
    for suite in suites() {
        let data = DataKey::generate().unwrap();
        let (read_key, search_key) = (Key32::generate().unwrap(), Key32::generate().unwrap());
        let locked = data.lock(&suite, &raw(&read_key), &raw(&search_key)).unwrap();
        let access = locked.unlock(&suite, Some(&raw(&read_key)), Some(&raw(&search_key))).unwrap();
        assert!(
            data.read.encryption_key(suite.hkdf, &SCOPE).unwrap() == encryption_key(&access, &suite),
            "{suite:?}"
        );
        assert!(
            data.search.full_fingerprint_key(suite.hkdf, &SCOPE).unwrap()
                == access.search().unwrap().full_fingerprint_key(suite.hkdf, &SCOPE).unwrap(),
            "{suite:?}"
        );
    }
}

#[test]
fn a_password_opens_the_lock_and_a_wrong_one_does_not() {
    for kdf in [light_argon(), light_scrypt()] {
        let suite = KeySuite { cipher: CipherKind::XChaCha20Poly1305, hkdf: HkdfHash::Sha256 };
        let (good, bad) = (SecretBytes::from_slice(b"correct horse"), SecretBytes::from_slice(b"wrong horse"));
        let root = ReadRoot::generate().unwrap();
        let locked = root.lock(&suite, &ProgrammerKey::Password { password: &good, kdf: &kdf }).unwrap();
        let open = |pw: &SecretBytes| {
            ReadRoot::unlock(&locked, &suite, Some(&ProgrammerKey::Password { password: pw, kdf: &kdf }))
        };
        let back = open(&good).unwrap();
        assert!(
            root.encryption_key(suite.hkdf, &SCOPE).unwrap() == back.encryption_key(suite.hkdf, &SCOPE).unwrap()
        );
        assert_eq!(open(&bad).unwrap_err(), CryptoError::OpenFailed, "{kdf:?}");
    }
}

#[test]
fn a_password_with_other_cost_settings_does_not_open() {
    let suite = KeySuite { cipher: CipherKind::Aes256Gcm, hkdf: HkdfHash::Sha256 };
    let pw = SecretBytes::from_slice(b"pw");
    let locked = ReadRoot::generate()
        .unwrap()
        .lock(&suite, &ProgrammerKey::Password { password: &pw, kdf: &light_argon() })
        .unwrap();
    for other in [
        PasswordKdf::Argon2id { memory_kib: 19_457, iterations: 2, lanes: 1 },
        PasswordKdf::Argon2id { memory_kib: 19_456, iterations: 3, lanes: 1 },
        light_scrypt(),
    ] {
        let result = ReadRoot::unlock(&locked, &suite, Some(&ProgrammerKey::Password { password: &pw, kdf: &other }));
        assert_eq!(result.unwrap_err(), CryptoError::OpenFailed, "{other:?}");
    }
}

/// Settings under the floor are a caller mistake, refused before any hashing, when locking and
/// when opening alike. They are not the unified open failure and they carry no secret.
#[test]
fn settings_under_the_floor_are_refused_when_locking_and_opening() {
    let suite = KeySuite { cipher: CipherKind::Aes256Gcm, hkdf: HkdfHash::Sha256 };
    let pw = SecretBytes::from_slice(b"do-not-print-this");
    let good = ProgrammerKey::Password { password: &pw, kdf: &light_argon() };
    let locked = ReadRoot::generate().unwrap().lock(&suite, &good).unwrap();
    for weak in [
        PasswordKdf::Argon2id { memory_kib: 19_455, iterations: 2, lanes: 1 },
        PasswordKdf::Argon2id { memory_kib: 19_456, iterations: 1, lanes: 1 },
        PasswordKdf::Scrypt { log_n: 12, r: 8, p: 31 },
        PasswordKdf::Scrypt { log_n: 17, r: 7, p: 1 },
    ] {
        let key = ProgrammerKey::Password { password: &pw, kdf: &weak };
        let on_lock = ReadRoot::generate().unwrap().lock(&suite, &key).unwrap_err();
        let on_open = ReadRoot::unlock(&locked, &suite, Some(&key)).unwrap_err();
        for err in [on_lock, on_open] {
            assert!(matches!(err, CryptoError::InvalidParams(_)), "{weak:?}: {err:?}");
            assert!(!format!("{err} {err:?}").contains("do-not-print"));
        }
    }
}

#[test]
fn the_default_settings_lock_and_open() {
    let suite = KeySuite { cipher: CipherKind::XChaCha20Poly1305, hkdf: HkdfHash::Sha256 };
    let pw = SecretBytes::from_slice(b"correct horse");
    let kdf = PasswordKdf::default();
    let key = ProgrammerKey::Password { password: &pw, kdf: &kdf };
    let root = ReadRoot::generate().unwrap();
    let locked = root.lock(&suite, &key).unwrap();
    let back = ReadRoot::unlock(&locked, &suite, Some(&key)).unwrap();
    assert!(root.encryption_key(suite.hkdf, &SCOPE).unwrap() == back.encryption_key(suite.hkdf, &SCOPE).unwrap());
}

/// Wrong key, wrong cipher kind, wrong HKDF hash, no key, and every kind of damage: one error.
#[test]
fn every_open_failure_is_the_same_error() {
    let suite = KeySuite { cipher: CipherKind::Aes256Gcm, hkdf: HkdfHash::Sha256 };
    let key = Key32::generate().unwrap();
    let locked = ReadRoot::generate().unwrap().lock(&suite, &raw(&key)).unwrap();
    let open = |locked: &clove1db::crypto::LockedKey, suite: &KeySuite, key: Option<&ProgrammerKey>| {
        ReadRoot::unlock(locked, suite, key)
    };
    let mut failures = vec![
        open(&locked, &suite, None),
        open(&locked, &suite, Some(&raw(&Key32::generate().unwrap()))),
        open(&locked, &KeySuite { hkdf: HkdfHash::Sha512, ..suite }, Some(&raw(&key))),
    ];
    for cipher in CipherKind::ALL.into_iter().filter(|c| *c != suite.cipher) {
        failures.push(open(&locked, &KeySuite { cipher, ..suite }, Some(&raw(&key))));
    }
    // Every single-byte change, a truncation, an extension and an empty lock.
    for i in 0..locked.as_bytes().len() {
        let mut bytes = locked.as_bytes().to_vec();
        bytes[i] ^= 0x01;
        failures.push(open(&clove1db::crypto::LockedKey::from_bytes(bytes), &suite, Some(&raw(&key))));
    }
    let mut longer = locked.as_bytes().to_vec();
    longer.push(0);
    for bytes in [locked.as_bytes()[1..].to_vec(), longer, Vec::new()] {
        failures.push(open(&clove1db::crypto::LockedKey::from_bytes(bytes), &suite, Some(&raw(&key))));
    }
    assert!(failures.len() > 100);
    for (i, failure) in failures.into_iter().enumerate() {
        assert_eq!(failure.unwrap_err(), CryptoError::OpenFailed, "case {i}");
    }
}

#[test]
fn a_locked_root_cannot_be_opened_in_the_other_role() {
    let suite = KeySuite { cipher: CipherKind::ChaCha20Poly1305, hkdf: HkdfHash::Sha256 };
    let key = Key32::generate().unwrap();
    let data = DataKey::generate().unwrap();
    let locked = data.lock(&suite, &raw(&key), &raw(&key)).unwrap();
    // Same programmer key for both, so only the role binding stands in the way.
    assert_eq!(SearchRoot::unlock(&locked.read, &suite, Some(&raw(&key))).unwrap_err(), CryptoError::OpenFailed);
    assert_eq!(ReadRoot::unlock(&locked.search, &suite, Some(&raw(&key))).unwrap_err(), CryptoError::OpenFailed);
    let swapped = LockedDataKey { read: locked.search.clone(), search: locked.read.clone() };
    assert_eq!(swapped.unlock(&suite, Some(&raw(&key)), None).unwrap_err(), CryptoError::OpenFailed);
}

#[test]
fn changing_the_programmer_key_keeps_the_same_root() {
    for suite in suites() {
        let (old, new) = (Key32::generate().unwrap(), Key32::generate().unwrap());
        let root = ReadRoot::generate().unwrap();
        let locked = root.lock(&suite, &raw(&old)).unwrap();
        let relocked = ReadRoot::relock(&locked, &suite, &raw(&old), &raw(&new)).unwrap();

        let back = ReadRoot::unlock(&relocked, &suite, Some(&raw(&new))).unwrap();
        assert!(
            root.encryption_key(suite.hkdf, &SCOPE).unwrap() == back.encryption_key(suite.hkdf, &SCOPE).unwrap(),
            "{suite:?}: the root changed"
        );
        assert_ne!(relocked, locked);
        assert_eq!(
            ReadRoot::unlock(&relocked, &suite, Some(&raw(&old))).unwrap_err(),
            CryptoError::OpenFailed,
            "{suite:?}: the old key still opens the new lock"
        );
        assert_eq!(
            ReadRoot::relock(&locked, &suite, &raw(&new), &raw(&old)).unwrap_err(),
            CryptoError::OpenFailed
        );
    }
}

#[test]
fn locking_twice_gives_different_bytes_of_the_same_length() {
    let suite = KeySuite { cipher: CipherKind::Aes256Gcm, hkdf: HkdfHash::Sha256 };
    let key = Key32::generate().unwrap();
    let root = ReadRoot::generate().unwrap();
    let (a, b) = (root.lock(&suite, &raw(&key)).unwrap(), root.lock(&suite, &raw(&key)).unwrap());
    assert_ne!(a, b);
    assert_eq!(a.as_bytes().len(), b.as_bytes().len());
}

#[test]
fn a_program_with_only_the_search_key_can_search_but_not_decrypt() {
    let suite = KeySuite { cipher: CipherKind::Aes256Gcm, hkdf: HkdfHash::Sha256 };
    let (read_key, search_key) = (Key32::generate().unwrap(), Key32::generate().unwrap());
    let data = DataKey::generate().unwrap();
    let locked = data.lock(&suite, &raw(&read_key), &raw(&search_key)).unwrap();

    let search_only = locked.unlock(&suite, None, Some(&raw(&search_key))).unwrap();
    assert!(search_only.read().is_none());
    let search = search_only.search().unwrap();
    // It derives exactly the fingerprint keys the full holder derives.
    assert!(
        search.full_fingerprint_key(suite.hkdf, &SCOPE).unwrap()
            == data.search.full_fingerprint_key(suite.hkdf, &SCOPE).unwrap()
    );
    assert!(
        search.part_fingerprint_key(suite.hkdf, &SCOPE).unwrap()
            == data.search.part_fingerprint_key(suite.hkdf, &SCOPE).unwrap()
    );
    // The search key does not unlock the read root, and the read root is not in its reach.
    assert_eq!(
        ReadRoot::unlock(&locked.read, &suite, Some(&raw(&search_key))).unwrap_err(),
        CryptoError::OpenFailed
    );

    let read_only = locked.unlock(&suite, Some(&raw(&read_key)), None).unwrap();
    assert!(read_only.search().is_none() && read_only.read().is_some());
}

#[test]
fn opening_with_no_key_at_all_fails() {
    let suite = KeySuite { cipher: CipherKind::Aes256Gcm, hkdf: HkdfHash::Sha256 };
    let key = Key32::generate().unwrap();
    let locked = DataKey::generate().unwrap().lock(&suite, &raw(&key), &raw(&key)).unwrap();
    assert_eq!(locked.unlock(&suite, None, None).unwrap_err(), CryptoError::OpenFailed);
    // A wrong key for one root fails the whole open even if the other key is right.
    let wrong = Key32::generate().unwrap();
    assert_eq!(
        locked.unlock(&suite, Some(&raw(&key)), Some(&raw(&wrong))).unwrap_err(),
        CryptoError::OpenFailed
    );
}

#[test]
fn different_roots_give_different_subkeys_and_scopes_split_them() {
    let suite = KeySuite { cipher: CipherKind::Aes256Gcm, hkdf: HkdfHash::Sha256 };
    let (a, b) = (DataKey::generate().unwrap(), DataKey::generate().unwrap());
    assert!(a.read.encryption_key(suite.hkdf, &SCOPE).unwrap() != b.read.encryption_key(suite.hkdf, &SCOPE).unwrap());
    let other = Scope { table: "people", field: "email" };
    assert!(a.read.encryption_key(suite.hkdf, &SCOPE).unwrap() != a.read.encryption_key(suite.hkdf, &other).unwrap());
}

#[test]
fn nothing_secret_shows_in_debug_output() {
    let suite = KeySuite { cipher: CipherKind::Aes256Gcm, hkdf: HkdfHash::Sha256 };
    let key = Key32::from_bytes(&[0xEE; 32]);
    let pw = SecretBytes::from_slice(b"hunter2-password");
    let data = DataKey::generate().unwrap();
    let locked = data.lock(&suite, &raw(&key), &raw(&key)).unwrap();
    let access = locked.unlock(&suite, Some(&raw(&key)), Some(&raw(&key))).unwrap();
    let kdf = light_scrypt();
    let shown = [
        format!("{key:?}"),
        format!("{pw:?}"),
        format!("{pw}"),
        format!("{data:?}"),
        format!("{access:?}"),
        format!("{:?}", raw(&key)),
        format!("{:?}", ProgrammerKey::Password { password: &pw, kdf: &kdf }),
        format!("{:?}", data.read.encryption_key(suite.hkdf, &SCOPE).unwrap()),
    ];
    for text in shown {
        assert!(!text.contains("hunter2"), "{text}");
        assert!(!text.to_lowercase().contains("ee, ee"), "{text}");
        assert!(!text.contains("238"), "{text}");
    }
}
