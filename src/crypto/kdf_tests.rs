//! Defaults and the floor for password hashing settings.
use super::{error::CryptoError, kdf::PasswordKdf};
use std::time::{Duration, Instant};

fn argon(memory_kib: u32, iterations: u32, lanes: u32) -> PasswordKdf {
    PasswordKdf::Argon2id { memory_kib, iterations, lanes }
}

fn scrypt(log_n: u8, r: u32, p: u32) -> PasswordKdf {
    PasswordKdf::Scrypt { log_n, r, p }
}

#[test]
fn defaults_are_the_documented_values() {
    assert_eq!(PasswordKdf::default(), argon(65_536, 3, 1));
    assert_eq!(PasswordKdf::argon2id_default(), argon(65_536, 3, 1));
    assert_eq!(PasswordKdf::scrypt_default(), scrypt(17, 8, 1));
    assert!(PasswordKdf::default().validate().is_ok());
    assert!(PasswordKdf::scrypt_default().validate().is_ok());
}

#[test]
fn each_limit_exactly_is_accepted() {
    for kdf in [
        argon(19_456, 2, 1),
        argon(19_456, 2, 4),
        argon(u32::MAX, u32::MAX, u32::MAX),
        scrypt(17, 8, 1),
        // N times p is exactly 2^17 by other routes.
        scrypt(12, 8, 32),
        scrypt(0, 8, 1 << 17),
        scrypt(16, 8, 2),
        scrypt(17, 100, 1),
    ] {
        assert_eq!(kdf.validate(), Ok(()), "{kdf:?}");
    }
}

#[test]
fn the_minimum_settings_really_derive() {
    let mut out = [0u8; 32];
    argon(19_456, 2, 1).derive(b"password", &[1; 16], &mut out).unwrap();
    assert_ne!(out, [0u8; 32]);
    let mut out = [0u8; 32];
    scrypt(12, 8, 32).derive(b"password", &[1; 16], &mut out).unwrap();
    assert_ne!(out, [0u8; 32]);
}

#[test]
fn one_below_each_limit_is_rejected() {
    let cases = [
        (argon(19_455, 2, 1), "argon2id memory under the minimum"),
        (argon(0, 2, 1), "argon2id memory under the minimum"),
        (argon(19_456, 1, 1), "argon2id iterations under the minimum"),
        (argon(19_456, 0, 1), "argon2id iterations under the minimum"),
        (argon(19_456, 2, 0), "argon2id lanes under the minimum"),
        (scrypt(17, 7, 1), "scrypt r under the minimum"),
        (scrypt(17, 0, 1), "scrypt r under the minimum"),
        (scrypt(16, 8, 1), "scrypt N times p under the minimum"),
        (scrypt(12, 8, 31), "scrypt N times p under the minimum"),
        (scrypt(0, 8, (1 << 17) - 1), "scrypt N times p under the minimum"),
        (scrypt(17, 8, 0), "scrypt N times p under the minimum"),
        (scrypt(255, 8, 0), "scrypt N times p under the minimum"),
    ];
    for (kdf, message) in cases {
        let expected = CryptoError::InvalidParams(message);
        assert_eq!(kdf.validate(), Err(expected), "{kdf:?}");
        let mut out = [0u8; 32];
        assert_eq!(kdf.derive(b"pw", &[1; 16], &mut out), Err(expected), "{kdf:?}");
    }
}

/// A refused setting writes nothing, returns at once even when running it would take seconds, and
/// gives the same error whatever the password and salt are.
#[test]
fn a_refused_setting_does_no_work_and_reveals_nothing() {
    // Memory one under the floor, with iterations that would take seconds if it ran.
    let slow_if_run = argon(19_455, 300, 1);
    let mut first = [0xAAu8; 32];
    let started = Instant::now();
    let a = slow_if_run.derive(b"first password", &[1; 16], &mut first).unwrap_err();
    assert!(started.elapsed() < Duration::from_millis(100), "the check came after the work");
    assert_eq!(first, [0xAAu8; 32], "the output buffer was touched");

    let mut second = [0xBBu8; 32];
    let b = slow_if_run.derive(b"another one", &[2; 16], &mut second).unwrap_err();
    assert_eq!(a, b);
    assert_eq!(second, [0xBBu8; 32]);
    assert!(matches!(a, CryptoError::InvalidParams(_)));
    let shown = format!("{a} {a:?}");
    assert!(!shown.contains("password") && !shown.contains("another"), "{shown}");
}

#[test]
fn verify_and_derive_key_refuse_the_same_way() {
    let weak = argon(64, 1, 1);
    let secret = super::secret::SecretBytes::from_slice(b"pw");
    assert!(matches!(weak.derive_key(&secret, &[1; 16]), Err(CryptoError::InvalidParams(_))));
    assert!(matches!(weak.verify(b"pw", &[1; 16], &[0; 32]), Err(CryptoError::InvalidParams(_))));
}

/// The test-only path keeps the published vectors usable and is the only way under the floor.
#[test]
fn the_unchecked_path_still_runs_small_settings() {
    let mut out = [0u8; 32];
    argon(48, 3, 2).derive_unchecked(b"pw", &[1; 16], &mut out).unwrap();
    assert_ne!(out, [0u8; 32]);
    assert!(argon(48, 3, 2).derive(b"pw", &[1; 16], &mut out).is_err());
}
