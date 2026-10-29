//! Authenticated encryption through the public API: round trips, rejection, nonce freshness.
use clove1db::crypto::{Aead, CipherKind, CryptoError, Key32};
use std::collections::HashSet;

const FIELD_SIZES: [usize; 3] = [16, 64, 256];
const PAGE_SIZES: [usize; 3] = [4 << 10, 16 << 10, 64 << 10];

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

fn aead(kind: CipherKind) -> Aead {
    Aead::new(kind, &Key32::generate().unwrap()).unwrap()
}

#[test]
fn every_kind_round_trips_every_size() {
    for kind in CipherKind::ALL {
        let aead = aead(kind);
        for size in FIELD_SIZES.into_iter().chain(PAGE_SIZES).chain([0, 1]) {
            let plain = pattern(size);
            let sealed = aead.seal(b"scope", &plain).unwrap();
            assert_eq!(sealed.len(), size + kind.overhead(), "{kind:?} {size}");
            assert_eq!(aead.open(b"scope", &sealed).unwrap().as_bytes(), &plain[..], "{kind:?} {size}");
        }
    }
}

#[test]
fn sealing_twice_gives_different_bytes() {
    for kind in CipherKind::ALL {
        let aead = aead(kind);
        assert_ne!(aead.seal(b"", b"same").unwrap(), aead.seal(b"", b"same").unwrap(), "{kind:?}");
    }
}

#[test]
fn every_failure_is_the_same_error() {
    for kind in CipherKind::ALL {
        let aead = aead(kind);
        let other_key = self::aead(kind);
        let sealed = aead.seal(b"aad", &pattern(64)).unwrap();

        let mut flipped_head = sealed.clone();
        flipped_head[0] ^= 1;
        let mut flipped_body = sealed.clone();
        flipped_body[kind.nonce_len()] ^= 1;
        let mut flipped_tag = sealed.clone();
        *flipped_tag.last_mut().unwrap() ^= 1;

        let failures = [
            aead.open(b"other aad", &sealed),
            other_key.open(b"aad", &sealed),
            aead.open(b"aad", &flipped_head),
            aead.open(b"aad", &flipped_body),
            aead.open(b"aad", &flipped_tag),
            aead.open(b"aad", &sealed[..sealed.len() - 1]),
            aead.open(b"aad", &sealed[..kind.overhead() - 1]),
            aead.open(b"aad", &[]),
        ];
        for (i, failure) in failures.into_iter().enumerate() {
            assert_eq!(failure.unwrap_err(), CryptoError::OpenFailed, "{kind:?} case {i}");
        }
    }
}

#[test]
fn one_key_does_not_open_another_kinds_output() {
    let key = Key32::generate().unwrap();
    for sealer in CipherKind::ALL {
        let sealed = Aead::new(sealer, &key).unwrap().seal(b"", &pattern(64)).unwrap();
        for opener in CipherKind::ALL.into_iter().filter(|k| *k != sealer) {
            let result = Aead::new(opener, &key).unwrap().open(b"", &sealed);
            assert_eq!(result.unwrap_err(), CryptoError::OpenFailed, "{sealer:?} opened as {opener:?}");
        }
    }
}

/// Random nonces must not repeat in a large sample. A repeat under one key breaks GCM.
#[test]
fn nonces_do_not_repeat_in_a_large_sample() {
    const SAMPLE: usize = 300_000;
    for kind in CipherKind::ALL {
        let aead = aead(kind);
        let mut seen = HashSet::with_capacity(SAMPLE);
        for _ in 0..SAMPLE {
            let sealed = aead.seal(b"", b"").unwrap();
            assert!(seen.insert(sealed[..kind.nonce_len()].to_vec()), "{kind:?} repeated a nonce");
        }
    }
}

#[test]
fn key_types_hide_their_bytes() {
    let key = Key32::from_bytes(&[0xAB; 32]);
    for shown in [format!("{key:?}"), format!("{key}"), format!("{:#?}", key)] {
        assert!(!shown.to_lowercase().contains("ab"), "{shown}");
        assert!(!shown.contains("171"), "{shown}");
        assert!(shown.contains("redacted"), "{shown}");
    }
}

/// The in-place functions use the same layout as `seal` and `open`, allocate nothing, and leave
/// no unauthenticated plaintext behind on failure.
#[test]
fn in_place_sealing_and_opening_match_the_allocating_ones() {
    for kind in CipherKind::ALL {
        let key = Key32::generate().unwrap();
        let aead = Aead::new(kind, &key).unwrap();
        for len in [0usize, 1, 16, 4096, 70_000] {
            let plain: Vec<u8> = (0..len).map(|i| (i * 7 + 1) as u8).collect();
            let mut sealed = vec![0u8; len + kind.overhead()];
            aead.seal_into(b"aad", &plain, &mut sealed).unwrap();
            assert_eq!(aead.open(b"aad", &sealed).unwrap().as_bytes(), plain.as_slice(), "{kind:?} {len}");
            let theirs = aead.seal(b"aad", &plain).unwrap();
            let mut buf = theirs.clone();
            let range = aead.open_in_place(b"aad", &mut buf).unwrap();
            assert_eq!(&buf[range], plain.as_slice(), "{kind:?} {len}");

            let mut bad = sealed.clone();
            let flip = bad.len() / 2;
            bad[flip] ^= 1;
            let mut copy = bad.clone();
            assert_eq!(aead.open_in_place(b"aad", &mut copy).unwrap_err(), CryptoError::OpenFailed);
            let (n, end) = (kind.nonce_len(), copy.len() - 16);
            assert!(copy[n..end].iter().all(|b| *b == 0), "{kind:?}: plaintext left after a failed open");
            let mut other_aad = sealed.clone();
            assert!(aead.open_in_place(b"other", &mut other_aad).is_err());
        }
        let mut wrong = vec![0u8; 5];
        assert!(matches!(aead.seal_into(b"a", b"abc", &mut wrong), Err(CryptoError::InvalidParams(_))));
        assert!(aead.open_in_place(b"a", &mut [0u8; 3]).is_err());
    }
}
