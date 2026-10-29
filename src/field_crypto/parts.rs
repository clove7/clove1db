//! Fingerprints of the parts of a value, for searching by a piece of it.
//!
//! A value, after the normalisation its field declares, is cut into overlapping windows of `window`
//! characters. Each window gets a keyed fingerprint (HMAC-SHA-256 under the field's part key),
//! kept to `bits` bits and written in hex; the distinct ones, in order, are stored as one text
//! beside the sealed value: `"p": "0a3 1f7 5d1"`. A search cuts what is looked for the same way and
//! asks for the rows that have all of its fingerprints.
//!
//! Keeping fewer bits makes different windows share a fingerprint: a file then shows less (a
//! fingerprint stands for many windows), and a search returns more rows than match, which the
//! confirmation step has to throw out. Even with every bit kept, the rows that have all the windows
//! are a superset of the rows that have the text: the windows may be somewhere else in the value.
use super::{keys::FieldKeys, prints};
use crate::{
    crypto::MacKind,
    fields::TransformKind,
    units::{ClError, Result},
};
use std::collections::BTreeSet;

const LABEL: &[u8] = b"cf-part";

fn fail(what: &'static str) -> ClError {
    ClError::Validation(what.into())
}

/// The fingerprint of one window, as `ceil(bits / 4)` lowercase hex digits.
fn tag(key: &crate::crypto::Key32, window: u8, bits: u8, text: &str) -> Result<String> {
    let mut data = LABEL.to_vec();
    data.push(window);
    data.extend_from_slice(text.as_bytes());
    let mac = MacKind::HmacSha256.mac(key, &data).map_err(|_| fail("the fingerprint could not be made"));
    zeroize::Zeroize::zeroize(&mut data);
    let mac = mac?;
    let bytes = usize::from(bits).div_ceil(8);
    let mut kept = mac.as_bytes()[..bytes].to_vec();
    let spare = bytes * 8 - usize::from(bits);
    if spare > 0 {
        kept[0] &= 0xFF >> spare;
    }
    let hex: String = kept.iter().map(|b| format!("{b:02x}")).collect();
    let digits = usize::from(bits).div_ceil(4);
    Ok(hex[hex.len() - digits..].to_string())
}

/// The distinct fingerprints of the windows of `text`, sorted. A text shorter than `window`
/// characters has none.
pub(crate) fn part_tags(
    keys: &FieldKeys,
    table_id: &str,
    field_id: u32,
    kinds: &[TransformKind],
    window: u8,
    bits: u8,
    text: &str,
) -> Result<Vec<String>> {
    if window == 0 || !(1..=64).contains(&bits) {
        return Err(fail("the fingerprints of the parts of this field are not set up"));
    }
    let key = keys.part_key(table_id, field_id)?;
    let normalized = zeroize::Zeroizing::new(prints::normalize(text, kinds));
    let chars: Vec<char> = normalized.chars().collect();
    let mut tags = BTreeSet::new();
    for piece in chars.windows(usize::from(window)) {
        let piece: zeroize::Zeroizing<String> = zeroize::Zeroizing::new(piece.iter().collect());
        tags.insert(tag(&key, window, bits, &piece)?);
    }
    Ok(tags.into_iter().collect())
}

/// How many characters `text` has after the normalisation (what a search is measured by).
pub(crate) fn normalized_len(kinds: &[TransformKind], text: &str) -> usize {
    prints::normalize(text, kinds).chars().count()
}

/// The stored text of a set of fingerprints.
pub(crate) fn join(tags: &[String]) -> String {
    tags.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CipherKind, DataKey, HkdfHash, Key32, KeySuite, ProgrammerKey};

    fn keys(search: bool) -> FieldKeys {
        let suite = KeySuite { cipher: CipherKind::Aes256GcmSiv, hkdf: HkdfHash::Sha256 };
        let data = DataKey::generate().unwrap();
        let r = Key32::from_bytes(&[1; 32]);
        let s = Key32::from_bytes(&[2; 32]);
        let locked = data.lock(&suite, &ProgrammerKey::Raw(&r), &ProgrammerKey::Raw(&s)).unwrap();
        let access = locked.unlock(&suite, Some(&ProgrammerKey::Raw(&r)), search.then_some(&ProgrammerKey::Raw(&s))).unwrap();
        FieldKeys::with_access(suite, access).unwrap()
    }

    #[test]
    fn a_value_has_one_fingerprint_for_each_distinct_window_and_they_are_sorted_hex() {
        let k = keys(true);
        // The key is random in each run, and a fingerprint of 12 bits has 4096 values: two of the 8 windows can share
        // one (about 0.7 in a hundred runs). So the count of different windows is asserted with 64 bits, where a clash
        // cannot happen in practice, and with 12 bits the count may only fall short by a clash.
        let wide = part_tags(&k, "t", 1, &[], 3, 64, "0501234567").unwrap();
        assert_eq!(wide.len(), 8, "10 characters, windows of 3, all different");
        let tags = part_tags(&k, "t", 1, &[], 3, 12, "0501234567").unwrap();
        assert!((6..=8).contains(&tags.len()), "8 windows, fewer only if fingerprints of 12 bits clash: {}", tags.len());
        assert!(tags.iter().all(|t| t.len() == 3 && t.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())));
        let mut sorted = tags.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(tags, sorted);
        // A repeated window is one fingerprint.
        assert_eq!(part_tags(&k, "t", 1, &[], 3, 64, "aaaaaa").unwrap().len(), 1);
    }

    #[test]
    fn a_text_shorter_than_the_window_has_none() {
        let k = keys(true);
        assert!(part_tags(&k, "t", 1, &[], 4, 12, "abc").unwrap().is_empty());
        assert!(part_tags(&k, "t", 1, &[], 3, 12, "").unwrap().is_empty());
        assert_eq!(part_tags(&k, "t", 1, &[], 3, 12, "abc").unwrap().len(), 1);
    }

    #[test]
    fn the_windows_of_a_piece_are_among_the_windows_of_the_value() {
        let k = keys(true);
        // 64 bits: with a random key and 12 bits two windows can clash, which this test is not about.
        let value = part_tags(&k, "t", 1, &[], 3, 64, "0501234567").unwrap();
        let piece = part_tags(&k, "t", 1, &[], 3, 64, "12345").unwrap();
        assert_eq!(piece.len(), 3);
        assert!(piece.iter().all(|t| value.contains(t)));
        let other = part_tags(&k, "t", 1, &[], 3, 64, "99999").unwrap();
        assert!(!other.iter().all(|t| value.contains(t)));
        // With 12 bits a piece's windows are still among the value's (no false negative), whatever the key.
        let value12 = part_tags(&k, "t", 1, &[], 3, 12, "0501234567").unwrap();
        let piece12 = part_tags(&k, "t", 1, &[], 3, 12, "12345").unwrap();
        assert!(piece12.iter().all(|t| value12.contains(t)));
    }

    #[test]
    fn the_fingerprint_depends_on_the_field_the_table_the_window_and_the_database() {
        let k = keys(true);
        let a = part_tags(&k, "t", 1, &[], 3, 64, "abcdef").unwrap();
        assert_ne!(a, part_tags(&k, "t", 2, &[], 3, 64, "abcdef").unwrap());
        assert_ne!(a, part_tags(&k, "u", 1, &[], 3, 64, "abcdef").unwrap());
        assert_ne!(part_tags(&k, "t", 1, &[], 2, 64, "ab").unwrap(), part_tags(&k, "t", 1, &[], 3, 64, "ab ").unwrap());
        assert_ne!(a, part_tags(&keys(true), "t", 1, &[], 3, 64, "abcdef").unwrap());
    }

    #[test]
    fn fewer_bits_keep_the_low_bits_and_cut_the_digits() {
        let k = keys(true);
        let wide = part_tags(&k, "t", 1, &[], 3, 64, "abcdefgh").unwrap();
        let narrow = part_tags(&k, "t", 1, &[], 3, 10, "abcdefgh").unwrap();
        assert!(wide.iter().all(|t| t.len() == 16));
        assert!(narrow.iter().all(|t| t.len() == 3 && u16::from_str_radix(t, 16).unwrap() < 1024));
        let eight = part_tags(&k, "t", 1, &[], 3, 8, "abcdefgh").unwrap();
        assert!(eight.iter().all(|t| t.len() == 2));
    }

    #[test]
    fn the_declared_normalisation_comes_first() {
        let k = keys(true);
        let kinds = [TransformKind::Trim, TransformKind::NormalizeArabic];
        assert_eq!(
            part_tags(&k, "t", 1, &kinds, 4, 12, "  ٠٥٠١٢٣  ").unwrap(),
            part_tags(&k, "t", 1, &kinds, 4, 12, "050123").unwrap()
        );
        assert_eq!(normalized_len(&kinds, "  ٠٥٠١٢٣  "), 6);
    }

    /// The index of a field of fingerprints cuts the stored text with `query::eval::tokens`, and a
    /// search cuts what it asks for with the same function (indexes/worker.rs writes a text field's
    /// terms with it, indexes/planner.rs reads them with it). That function must hand back every
    /// fingerprint as it is: short ones, ones of digits only, upper and lower case alike. Fingerprints
    /// are lowercase hex, so none is changed, split or dropped.
    #[test]
    fn the_search_tokenizer_returns_every_fingerprint_unchanged() {
        let k = keys(true);
        let (mut digits_only, mut with_letters, mut two_digits) = (0, 0, 0);
        for bits in [4u8, 8, 10, 12, 16, 64] {
            for n in 0..120u32 {
                let text = format!("{:010}-{}", n * 7919 % 1_000_000_007, n);
                let tags = part_tags(&k, "t", 1, &[], 3, bits, &text).unwrap();
                let back = crate::query::eval::tokens(&join(&tags));
                assert_eq!(back, tags, "bits {bits}, text {text}");
                for tag in &tags {
                    if tag.chars().all(|c| c.is_ascii_digit()) {
                        digits_only += 1;
                    } else {
                        with_letters += 1;
                    }
                    two_digits += usize::from(tag.len() == 2);
                }
            }
        }
        assert!(digits_only > 100 && with_letters > 100 && two_digits > 100, "{digits_only} {with_letters} {two_digits}");
    }

    #[test]
    fn the_search_key_is_needed_and_the_settings_must_be_set() {
        let err = part_tags(&keys(false), "t", 1, &[], 3, 12, "abcdef").unwrap_err().to_string();
        assert!(err.contains("no search key"), "{err}");
        assert!(part_tags(&keys(true), "t", 1, &[], 0, 12, "abc").is_err());
        assert!(part_tags(&keys(true), "t", 1, &[], 3, 0, "abc").is_err());
        assert!(part_tags(&keys(true), "t", 1, &[], 3, 65, "abc").is_err());
    }
}
