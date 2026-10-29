//! URL-safe base64 without padding, with the one canonical spelling of every byte string.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() * 4).div_ceil(3));
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(char::from(ALPHABET[((n >> 18) & 63) as usize]));
        out.push(char::from(ALPHABET[((n >> 12) & 63) as usize]));
        if chunk.len() > 1 {
            out.push(char::from(ALPHABET[((n >> 6) & 63) as usize]));
        }
        if chunk.len() > 2 {
            out.push(char::from(ALPHABET[(n & 63) as usize]));
        }
    }
    out
}

/// `None` for a character outside the alphabet, an impossible length, or spare bits that are not
/// zero (a second spelling of the same bytes).
pub(crate) fn decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut table = [255u8; 256];
    for (i, c) in ALPHABET.iter().enumerate() {
        table[usize::from(*c)] = i as u8;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 2);
    for chunk in bytes.chunks(4) {
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            let v = table[usize::from(c)];
            if v == 255 {
                return None;
            }
            n |= u32::from(v) << (18 - 6 * (i as u32));
        }
        let produced = chunk.len() * 6 / 8;
        let group = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&group[..produced]);
        let total = chunk.len() * 6;
        let used = produced * 8;
        if total > used {
            let spare = (n >> (24 - total)) & ((1u32 << (total - used)) - 1);
            if spare != 0 {
                return None;
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_short_length() {
        for len in 0..40usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let text = encode(&data);
            assert!(!text.contains('=') && !text.contains('+') && !text.contains('/'));
            assert_eq!(decode(&text).as_deref(), Some(data.as_slice()), "len {len}");
        }
    }

    #[test]
    fn matches_the_standard_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg");
        assert_eq!(encode(b"fo"), "Zm8");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg");
        assert_eq!(encode(b"fooba"), "Zm9vYmE");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn rejects_bad_text() {
        assert!(decode("Z").is_none());
        assert!(decode("Zm9v=").is_none());
        assert!(decode("Zm 9v").is_none());
        assert!(decode("Zm+v").is_none());
        // "Zh" would decode to the same byte as "Zg" if spare bits were ignored.
        assert!(decode("Zh").is_none());
        assert!(decode("Zm8").is_some());
        // "Zm9" has a non-zero spare bit: it is a second spelling of "Zm8".
        assert!(decode("Zm9").is_none());
        assert!(decode("Zm-").is_none());
    }
}
