//! Known-answer tests: each algorithm is checked against published vectors, so a wrong binding
//! (swapped parameter, wrong nonce size, wrong hash) cannot pass by being self-consistent.
//! The vectors in `kat_vectors.rs` are generated from the official files, never typed by hand.
use super::{
    cipher::{Aead, CipherKind, TAG_LEN},
    error::CryptoError,
    kat_vectors::*,
    kdf::{HkdfHash, PasswordKdf},
    mac::MacKind,
    secret::Key32,
};

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hkdf_cases(hash: HkdfHash, cases: &[Hkdf]) {
    assert!(!cases.is_empty());
    for v in cases {
        let (ikm, salt, info, okm) = (unhex(v.ikm), unhex(v.salt), unhex(v.info), unhex(v.okm));
        let mut out = vec![0; okm.len()];
        let salt = if salt.is_empty() { None } else { Some(&salt[..]) };
        hash.derive(salt, &ikm, &info, &mut out).unwrap();
        assert_eq!(out, okm, "{}", v.name);
    }
}

#[test]
fn hkdf_sha256_matches_rfc_5869() {
    hkdf_cases(HkdfHash::Sha256, HKDF_SHA256_RFC5869);
}

#[test]
fn hkdf_sha512_matches_published_vectors() {
    hkdf_cases(HkdfHash::Sha512, HKDF_SHA512_WYCHEPROOF);
}

fn mac_cases(kind: MacKind, cases: &[Mac]) {
    assert!(!cases.is_empty());
    for v in cases {
        let tag = kind.mac_with_key(&unhex(v.key), &unhex(v.data)).unwrap();
        assert_eq!(tag.as_bytes(), &unhex(v.tag)[..], "{}", v.name);
    }
}

#[test]
fn hmac_sha256_matches_rfc_4231() {
    mac_cases(MacKind::HmacSha256, HMAC_SHA256_RFC4231);
}

#[test]
fn hmac_sha512_matches_rfc_4231() {
    mac_cases(MacKind::HmacSha512, HMAC_SHA512_RFC4231);
}

#[test]
fn hmac_sha3_256_matches_published_vectors() {
    mac_cases(MacKind::HmacSha3_256, HMAC_SHA3_256_WYCHEPROOF);
}

#[test]
fn blake3_keyed_matches_official_vectors() {
    assert!(!BLAKE3_KEYED.is_empty());
    for v in BLAKE3_KEYED {
        // The official input is the repeating byte sequence 0, 1, ..., 250.
        let input: Vec<u8> = (0..v.input_len).map(|i| (i % 251) as u8).collect();
        let tag = MacKind::Blake3Keyed
            .mac_with_key(BLAKE3_KEY, &input)
            .unwrap();
        assert_eq!(tag.as_bytes(), &unhex(v.keyed_hash)[..], "len {}", v.input_len);
    }
}

fn aead_cases(kind: CipherKind, cases: &[AeadVec]) {
    assert!(cases.iter().any(|v| v.valid) && cases.iter().any(|v| !v.valid));
    for v in cases {
        let (nonce, aad, msg) = (unhex(v.nonce), unhex(v.aad), unhex(v.msg));
        let key = Key32::from_slice(&unhex(v.key)).unwrap();
        let aead = Aead::new(kind, &key).unwrap();
        assert_eq!(nonce.len(), kind.nonce_len());
        let mut sealed = nonce.clone();
        sealed.extend_from_slice(&unhex(v.ct));
        sealed.extend_from_slice(&unhex(v.tag));
        if v.valid {
            assert_eq!(aead.seal_with_nonce(&nonce, &aad, &msg).unwrap(), sealed, "seal {}", v.id);
            let opened = aead.open(&aad, &sealed).unwrap();
            assert_eq!(opened.as_bytes(), &msg[..], "open {}", v.id);
        } else {
            assert_eq!(aead.open(&aad, &sealed).unwrap_err(), CryptoError::OpenFailed, "reject {}", v.id);
        }
    }
}

#[test]
fn aes_256_gcm_matches_published_vectors() {
    aead_cases(CipherKind::Aes256Gcm, AES_GCM_WYCHEPROOF);
}

#[test]
fn aes_256_gcm_siv_matches_published_vectors() {
    aead_cases(CipherKind::Aes256GcmSiv, AES_GCM_SIV_WYCHEPROOF);
}

#[test]
fn chacha20_poly1305_matches_published_vectors() {
    aead_cases(CipherKind::ChaCha20Poly1305, CHACHA20_POLY1305_WYCHEPROOF);
}

#[test]
fn xchacha20_poly1305_matches_published_vectors() {
    aead_cases(CipherKind::XChaCha20Poly1305, XCHACHA20_POLY1305_WYCHEPROOF);
}

#[test]
fn scrypt_matches_rfc_7914() {
    assert_eq!(SCRYPT_RFC7914.len(), 3);
    for v in SCRYPT_RFC7914 {
        let kdf = PasswordKdf::Scrypt { log_n: v.log_n, r: v.r, p: v.p };
        let expected = unhex(v.dk);
        let mut out = vec![0; expected.len()];
        // The published vectors use settings far under the floor, so they skip the check.
        kdf.derive_unchecked(v.password.as_bytes(), v.salt.as_bytes(), &mut out).unwrap();
        assert_eq!(out, expected, "N=2^{}", v.log_n);
    }
}

#[test]
fn argon2id_primitive_matches_rfc_9106() {
    use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
    let ad = AssociatedData::new(&[4; 12]).unwrap();
    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .data(ad)
        .output_len(32)
        .build()
        .unwrap();
    let argon = Argon2::new_with_secret(&[3; 8], Algorithm::Argon2id, Version::V0x13, params).unwrap();
    let mut out = [0u8; 32];
    argon.hash_password_into(&[1; 32], &[2; 16], &mut out).unwrap();
    assert_eq!(out.to_vec(), unhex(ARGON2ID_RFC9106_TAG));
}

/// The RFC vector needs a secret and associated data, which our wrapper does not take. So the
/// wrapper is checked against the verified primitive with the same explicit parameters, which
/// catches a swapped memory, iteration or lane setting.
#[test]
fn argon2id_wrapper_matches_the_primitive() {
    use argon2::{Algorithm, Argon2, Params, Version};
    let (password, salt) = ([1u8; 32], [2u8; 16]);
    let mut expected = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(48, 3, 2, Some(32)).unwrap())
        .hash_password_into(&password, &salt, &mut expected)
        .unwrap();
    let mut out = [0u8; 32];
    PasswordKdf::Argon2id { memory_kib: 48, iterations: 3, lanes: 2 }
        .derive_unchecked(&password, &salt, &mut out)
        .unwrap();
    assert_eq!(out, expected);
    assert_eq!(TAG_LEN, 16);
}
