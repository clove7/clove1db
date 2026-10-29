//! The stored form of a sealed value: a JSON string holding URL-safe base64 of
//! `version (1) || field number (4, little endian) || nonce || ciphertext || tag`.
//!
//! The cipher is not named. What the value is bound to (table, field, row) goes into the
//! authenticated data, not into the string, so a value copied elsewhere fails to open.
use super::b64;
use crate::crypto::{Aead, CryptoError, SecretBytes};

pub(crate) const VERSION: u8 = 1;
const HEADER: usize = 1 + 4;

/// Where a value lives. Two different places never give the same authenticated data.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Place<'a> {
    pub table_id: &'a str,
    pub field_id: u32,
    pub row_key: &'a str,
}

fn push_part(out: &mut Vec<u8>, part: &[u8]) {
    out.extend_from_slice(&(part.len() as u64).to_le_bytes());
    out.extend_from_slice(part);
}

pub(crate) fn authenticated_data(place: &Place) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 1 + 8 + place.table_id.len() + 4 + 8 + place.row_key.len());
    out.extend_from_slice(b"cf");
    out.push(VERSION);
    push_part(&mut out, place.table_id.as_bytes());
    out.extend_from_slice(&place.field_id.to_le_bytes());
    push_part(&mut out, place.row_key.as_bytes());
    out
}

pub(crate) fn seal_envelope(
    aead: &Aead,
    place: &Place,
    plaintext: &[u8],
) -> Result<String, CryptoError> {
    let sealed = aead.seal(&authenticated_data(place), plaintext)?;
    let mut raw = Vec::with_capacity(HEADER + sealed.len());
    raw.push(VERSION);
    raw.extend_from_slice(&place.field_id.to_le_bytes());
    raw.extend_from_slice(&sealed);
    Ok(b64::encode(&raw))
}

/// Every failure is the same [`CryptoError::OpenFailed`]: a wrong key, a wrong place, a wrong
/// cipher, damage and text that is not an envelope at all cannot be told apart.
pub(crate) fn open_envelope(
    aead: &Aead,
    place: &Place,
    envelope: &str,
) -> Result<SecretBytes, CryptoError> {
    let raw = b64::decode(envelope).ok_or(CryptoError::OpenFailed)?;
    if raw.len() < HEADER || raw[0] != VERSION {
        return Err(CryptoError::OpenFailed);
    }
    if raw[1..HEADER] != place.field_id.to_le_bytes() {
        return Err(CryptoError::OpenFailed);
    }
    aead.open(&authenticated_data(place), &raw[HEADER..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CipherKind, Key32};

    fn place<'a>(table: &'a str, field: u32, row: &'a str) -> Place<'a> {
        Place { table_id: table, field_id: field, row_key: row }
    }

    fn aead(kind: CipherKind) -> Aead {
        Aead::new(kind, &Key32::from_bytes(&[7; 32])).unwrap()
    }

    #[test]
    fn round_trips_for_both_allowed_ciphers() {
        for kind in [CipherKind::Aes256GcmSiv, CipherKind::XChaCha20Poly1305] {
            let a = aead(kind);
            let p = place("t1", 7, "row-1");
            for len in [0usize, 1, 16, 255, 4096] {
                let data = vec![0x5a; len];
                let text = seal_envelope(&a, &p, &data).unwrap();
                assert_eq!(open_envelope(&a, &p, &text).unwrap().as_bytes(), data.as_slice());
            }
        }
    }

    #[test]
    fn a_new_envelope_for_the_same_value_differs() {
        let a = aead(CipherKind::Aes256GcmSiv);
        let p = place("t1", 7, "row-1");
        assert_ne!(
            seal_envelope(&a, &p, b"same").unwrap(),
            seal_envelope(&a, &p, b"same").unwrap()
        );
    }

    #[test]
    fn a_value_moved_to_another_place_does_not_open() {
        let a = aead(CipherKind::XChaCha20Poly1305);
        let p = place("t1", 7, "row-1");
        let text = seal_envelope(&a, &p, b"secret").unwrap();
        for other in [
            place("t2", 7, "row-1"),
            place("t1", 8, "row-1"),
            place("t1", 7, "row-2"),
            place("t1", 7, ""),
        ] {
            assert!(matches!(open_envelope(&a, &other, &text), Err(CryptoError::OpenFailed)));
        }
    }

    #[test]
    fn the_parts_of_the_place_do_not_run_together() {
        let a = aead(CipherKind::Aes256GcmSiv);
        let text = seal_envelope(&a, &place("ab", 1, "c"), b"x").unwrap();
        assert!(open_envelope(&a, &place("a", 1, "bc"), &text).is_err());
    }

    #[test]
    fn a_changed_character_or_a_wrong_key_does_not_open() {
        let a = aead(CipherKind::Aes256GcmSiv);
        let p = place("t1", 7, "row-1");
        let text = seal_envelope(&a, &p, b"secret").unwrap();
        for i in 0..text.len() {
            let mut chars: Vec<char> = text.chars().collect();
            chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
            let changed: String = chars.into_iter().collect();
            assert!(open_envelope(&a, &p, &changed).is_err(), "position {i}");
        }
        let other = Aead::new(CipherKind::Aes256GcmSiv, &Key32::from_bytes(&[8; 32])).unwrap();
        assert!(open_envelope(&other, &p, &text).is_err());
        assert!(open_envelope(&a, &p, "").is_err());
        assert!(open_envelope(&a, &p, "plain text value").is_err());
    }

    #[test]
    fn size_is_header_nonce_tag_and_four_thirds() {
        let a = aead(CipherKind::Aes256GcmSiv);
        let x = aead(CipherKind::XChaCha20Poly1305);
        let p = place("t1", 7, "row-1");
        // 18 plaintext bytes: 5 + 12 + 18 + 16 = 51 raw bytes -> 68 characters.
        assert_eq!(seal_envelope(&a, &p, &[0; 18]).unwrap().len(), 68);
        // 5 + 24 + 18 + 16 = 63 raw bytes -> 84 characters.
        assert_eq!(seal_envelope(&x, &p, &[0; 18]).unwrap().len(), 84);
    }
}
