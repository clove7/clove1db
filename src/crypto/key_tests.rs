//! Tests that need crate-private access: key separation by construction, and wiping.
use super::{
    cipher::{Aead, CipherKind},
    error::{CryptoError, OpenDiagnostic},
    kdf::HkdfHash,
    keys::{DataKey, KeySuite, LockedKey, ProgrammerKey, ReadRoot, Scope, SearchRoot},
    secret::{Key32, SecretBytes},
};
use zeroize::Zeroize;

const SCOPE: Scope = Scope { table: "t", field: "f" };
const SUITE: KeySuite = KeySuite { cipher: CipherKind::Aes256Gcm, hkdf: HkdfHash::Sha256 };

/// Even if both roots held the same bytes, no read-side key equals a search-side key.
#[test]
fn roles_and_purposes_never_share_a_subkey() {
    for hkdf in [HkdfHash::Sha256, HkdfHash::Sha512] {
        let read = ReadRoot::from_key(Key32::from_bytes(&[7; 32]));
        let search = SearchRoot::from_key(Key32::from_bytes(&[7; 32]));
        let keys = [
            read.encryption_key(hkdf, &SCOPE).unwrap(),
            read.hash_key(hkdf, &SCOPE).unwrap(),
            search.full_fingerprint_key(hkdf, &SCOPE).unwrap(),
            search.part_fingerprint_key(hkdf, &SCOPE).unwrap(),
        ];
        for (i, a) in keys.iter().enumerate() {
            for b in &keys[i + 1..] {
                assert!(a != b, "two purposes produced the same key");
            }
        }
    }
}

#[test]
fn the_hkdf_hash_changes_the_subkeys() {
    let read = ReadRoot::from_key(Key32::from_bytes(&[9; 32]));
    let a = read.encryption_key(HkdfHash::Sha256, &SCOPE).unwrap();
    let b = read.encryption_key(HkdfHash::Sha512, &SCOPE).unwrap();
    assert!(a != b);
}

#[test]
fn scope_names_are_length_prefixed() {
    let read = ReadRoot::from_key(Key32::from_bytes(&[5; 32]));
    let scopes = [
        Scope { table: "ab", field: "c" },
        Scope { table: "a", field: "bc" },
        Scope { table: "", field: "abc" },
        Scope { table: "abc", field: "" },
        Scope { table: "ab", field: "c\0" },
    ];
    let keys: Vec<Key32> = scopes
        .iter()
        .map(|s| read.encryption_key(HkdfHash::Sha256, s).unwrap())
        .collect();
    for (i, a) in keys.iter().enumerate() {
        for b in &keys[i + 1..] {
            assert!(a != b, "two scopes produced the same key");
        }
    }
}

#[test]
fn derivation_is_deterministic_and_scope_specific() {
    let read = ReadRoot::from_key(Key32::from_bytes(&[3; 32]));
    let first = read.encryption_key(HkdfHash::Sha256, &SCOPE).unwrap();
    let again = read.encryption_key(HkdfHash::Sha256, &SCOPE).unwrap();
    let other = read
        .encryption_key(HkdfHash::Sha256, &Scope { table: "t", field: "g" })
        .unwrap();
    assert!(first == again);
    assert!(first != other);
}

/// A key is zero in its own storage once dropped. The slot outlives the value, so reading it
/// back is sound; this is the strongest check the language allows.
#[test]
fn key_storage_is_zero_after_drop() {
    let mut slot = std::mem::MaybeUninit::new(Key32::from_bytes(&[0xAB; 32]));
    unsafe {
        std::ptr::drop_in_place(slot.as_mut_ptr());
        let bytes = std::ptr::read_volatile(slot.as_ptr().cast::<[u8; 32]>());
        assert_eq!(bytes, [0; 32]);
    }
}

#[test]
fn secret_bytes_are_zero_after_zeroize() {
    let mut secret = SecretBytes::from_slice(&[0xCD; 64]);
    let ptr = secret.as_bytes().as_ptr();
    secret.zeroize();
    // The buffer is still owned by `secret`, so the memory is valid and was written with zeros.
    let seen: Vec<u8> = (0..64).map(|i| unsafe { std::ptr::read_volatile(ptr.add(i)) }).collect();
    assert_eq!(seen, vec![0; 64]);
}

#[test]
fn a_root_unlocks_to_the_same_subkeys_it_was_locked_with() {
    let root = ReadRoot::from_key(Key32::from_bytes(&[8; 32]));
    let programmer = Key32::from_bytes(&[1; 32]);
    let locked = root.lock(&SUITE, &ProgrammerKey::Raw(&programmer)).unwrap();
    let back = ReadRoot::unlock(&locked, &SUITE, Some(&ProgrammerKey::Raw(&programmer))).unwrap();
    assert!(
        root.encryption_key(SUITE.hkdf, &SCOPE).unwrap()
            == back.encryption_key(SUITE.hkdf, &SCOPE).unwrap()
    );
}

#[test]
fn diagnostics_name_the_cause_without_changing_the_error() {
    let data = DataKey::generate().unwrap();
    let right = Key32::generate().unwrap();
    let wrong = Key32::generate().unwrap();
    let locked = data.read.lock(&SUITE, &ProgrammerKey::Raw(&right)).unwrap();

    let mut seen = Vec::new();
    let mut sink = |d| seen.push(d);
    let missing = ReadRoot::unlock_reporting(&locked, &SUITE, None, &mut sink).unwrap_err();
    let damaged = LockedKey::from_bytes(locked.as_bytes()[..10].to_vec());
    let short = ReadRoot::unlock_reporting(&damaged, &SUITE, Some(&ProgrammerKey::Raw(&right)), &mut sink)
        .unwrap_err();
    let bad = ReadRoot::unlock_reporting(&locked, &SUITE, Some(&ProgrammerKey::Raw(&wrong)), &mut sink)
        .unwrap_err();
    assert_eq!(
        seen,
        [OpenDiagnostic::KeyMissing, OpenDiagnostic::MalformedInput, OpenDiagnostic::AuthenticationFailed]
    );
    assert!(missing == CryptoError::OpenFailed && short == missing && bad == missing);
}

#[test]
fn an_aead_open_failure_reports_authentication() {
    let key = Key32::generate().unwrap();
    let aead = Aead::new(CipherKind::ChaCha20Poly1305, &key).unwrap();
    let mut sealed = aead.seal(b"aad", b"value").unwrap();
    let last = sealed.len() - 1;
    sealed[last] ^= 1;
    let mut seen = None;
    let err = aead.open_reporting(b"aad", &sealed, &mut |d| seen = Some(d)).unwrap_err();
    assert_eq!(err, CryptoError::OpenFailed);
    assert_eq!(seen, Some(OpenDiagnostic::AuthenticationFailed));
}
