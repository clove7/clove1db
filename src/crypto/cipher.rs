//! Authenticated encryption: four cipher kinds behind one type.
//!
//! Sealed layout: `nonce || ciphertext || tag`. The nonce is random per call. For the 96-bit
//! kinds that bounds how many values one key can seal; the chunk size and per-field key
//! scope that fix this are decided by the code that uses this module, not here.
use super::{
    error::{CryptoError, OpenDiagnostic, Result},
    secret::{Key32, SecretBytes, fill_random},
};
use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInOut, KeyInit, Nonce, Tag, inout::InOutBuf},
};
use aes_gcm_siv::Aes256GcmSiv;
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};

pub const TAG_LEN: usize = 16;
const MAX_NONCE_LEN: usize = 24;

/// Which authenticated cipher seals the data. Never written to a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherKind {
    Aes256Gcm,
    Aes256GcmSiv,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

impl CipherKind {
    pub const ALL: [CipherKind; 4] = [
        CipherKind::Aes256Gcm,
        CipherKind::Aes256GcmSiv,
        CipherKind::ChaCha20Poly1305,
        CipherKind::XChaCha20Poly1305,
    ];
    pub fn nonce_len(self) -> usize {
        match self {
            CipherKind::XChaCha20Poly1305 => 24,
            _ => 12,
        }
    }
    /// Bytes added to a plaintext by sealing: the nonce and the tag.
    pub fn overhead(self) -> usize {
        self.nonce_len() + TAG_LEN
    }
}

enum Inner {
    Gcm(Aes256Gcm),
    Siv(Aes256GcmSiv),
    ChaCha(ChaCha20Poly1305),
    XChaCha(XChaCha20Poly1305),
}

macro_rules! dispatch {
    ($inner:expr, $c:ident => $body:expr) => {
        match $inner {
            Inner::Gcm($c) => $body,
            Inner::Siv($c) => $body,
            Inner::ChaCha($c) => $body,
            Inner::XChaCha($c) => $body,
        }
    };
}

/// A cipher bound to one key. The key schedule is built once, so repeated seals do not repay it.
pub struct Aead {
    kind: CipherKind,
    inner: Inner,
}

impl Aead {
    pub fn new(kind: CipherKind, key: &Key32) -> Result<Self> {
        let key = key.as_bytes().as_slice();
        let bad = |_| CryptoError::InvalidParams("key must be 32 bytes");
        let inner = match kind {
            CipherKind::Aes256Gcm => Inner::Gcm(Aes256Gcm::new_from_slice(key).map_err(bad)?),
            CipherKind::Aes256GcmSiv => {
                Inner::Siv(Aes256GcmSiv::new_from_slice(key).map_err(bad)?)
            }
            CipherKind::ChaCha20Poly1305 => {
                Inner::ChaCha(ChaCha20Poly1305::new_from_slice(key).map_err(bad)?)
            }
            CipherKind::XChaCha20Poly1305 => {
                Inner::XChaCha(XChaCha20Poly1305::new_from_slice(key).map_err(bad)?)
            }
        };
        Ok(Self { kind, inner })
    }

    pub fn kind(&self) -> CipherKind {
        self.kind
    }

    /// Seal `plaintext`, binding it to `aad`. The same `aad` must be given to open.
    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let n = self.kind.nonce_len();
        let mut nonce = [0u8; MAX_NONCE_LEN];
        fill_random(&mut nonce[..n])?;
        self.seal_with_nonce(&nonce[..n], aad, plaintext)
    }

    /// Open a value made by [`Aead::seal`]. Every failure is [`CryptoError::OpenFailed`].
    pub fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<SecretBytes> {
        self.open_reporting(aad, sealed, &mut |_| {})
    }

    /// Like [`Aead::open`], and hands the cause of a failure to `sink` first.
    pub fn open_reporting(
        &self,
        aad: &[u8],
        sealed: &[u8],
        sink: &mut dyn FnMut(OpenDiagnostic),
    ) -> Result<SecretBytes> {
        self.open_diagnosed(aad, sealed).map_err(|why| {
            sink(why);
            CryptoError::OpenFailed
        })
    }

    /// Seal `plaintext` straight into `out`, which must hold exactly the plaintext plus
    /// [`CipherKind::overhead`] bytes. The layout is the same as [`Aead::seal`]; no allocation.
    pub fn seal_into(&self, aad: &[u8], plaintext: &[u8], out: &mut [u8]) -> Result<()> {
        let n = self.kind.nonce_len();
        let mut nonce = [0u8; MAX_NONCE_LEN];
        fill_random(&mut nonce[..n])?;
        dispatch!(&self.inner, c => seal_into_with(c, &nonce[..n], aad, plaintext, out))
    }

    /// Open a sealed value where it stands. On success the plaintext is at the returned range of
    /// `buf`. On failure the ciphertext part of `buf` is wiped, so no unauthenticated plaintext is
    /// left behind. Every failure is [`CryptoError::OpenFailed`].
    pub fn open_in_place(&self, aad: &[u8], buf: &mut [u8]) -> Result<std::ops::Range<usize>> {
        let n = self.kind.nonce_len();
        dispatch!(&self.inner, c => open_in_place_with(c, n, aad, buf)).map_err(|_| CryptoError::OpenFailed)
    }

    pub(crate) fn open_diagnosed(
        &self,
        aad: &[u8],
        sealed: &[u8],
    ) -> std::result::Result<SecretBytes, OpenDiagnostic> {
        let n = self.kind.nonce_len();
        dispatch!(&self.inner, c => open_with(c, n, aad, sealed))
    }

    pub(crate) fn seal_with_nonce(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        dispatch!(&self.inner, c => seal_with(c, nonce, aad, plaintext))
    }
}

fn seal_with<C: AeadInOut>(c: &C, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let n = nonce.len();
    let nonce_array = Nonce::<C>::try_from(nonce)
        .map_err(|_| CryptoError::InvalidParams("nonce length does not match the cipher"))?;
    // One allocation of the final size: the ciphertext is made in place, nothing is copied twice.
    let mut out = Vec::with_capacity(n + plaintext.len() + TAG_LEN);
    out.extend_from_slice(nonce);
    out.extend_from_slice(plaintext);
    let tag = c
        .encrypt_inout_detached(&nonce_array, aad, InOutBuf::from(&mut out[n..]))
        .map_err(|_| CryptoError::InvalidParams("input too long"))?;
    out.extend_from_slice(&tag);
    Ok(out)
}

fn seal_into_with<C: AeadInOut>(
    c: &C,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<()> {
    let n = nonce.len();
    let nonce_array = Nonce::<C>::try_from(nonce)
        .map_err(|_| CryptoError::InvalidParams("nonce length does not match the cipher"))?;
    if out.len() != n + plaintext.len() + TAG_LEN {
        return Err(CryptoError::InvalidParams("output buffer has the wrong length"));
    }
    out[..n].copy_from_slice(nonce);
    out[n..n + plaintext.len()].copy_from_slice(plaintext);
    let tag = c
        .encrypt_inout_detached(&nonce_array, aad, InOutBuf::from(&mut out[n..n + plaintext.len()]))
        .map_err(|_| CryptoError::InvalidParams("input too long"))?;
    out[n + plaintext.len()..].copy_from_slice(&tag);
    Ok(())
}

fn open_in_place_with<C: AeadInOut>(
    c: &C,
    nonce_len: usize,
    aad: &[u8],
    buf: &mut [u8],
) -> std::result::Result<std::ops::Range<usize>, OpenDiagnostic> {
    use OpenDiagnostic::{AuthenticationFailed, MalformedInput};
    use zeroize::Zeroize;
    if buf.len() < nonce_len + TAG_LEN {
        return Err(MalformedInput);
    }
    let end = buf.len() - TAG_LEN;
    let (head, rest) = buf.split_at_mut(nonce_len);
    let (ciphertext, tag) = rest.split_at_mut(end - nonce_len);
    let nonce = Nonce::<C>::try_from(&*head).map_err(|_| MalformedInput)?;
    let tag = Tag::<C>::try_from(&*tag).map_err(|_| MalformedInput)?;
    if c
        .decrypt_inout_detached(&nonce, aad, InOutBuf::from(&mut *ciphertext), &tag)
        .is_err()
    {
        ciphertext.zeroize();
        return Err(AuthenticationFailed);
    }
    Ok(nonce_len..end)
}

fn open_with<C: AeadInOut>(
    c: &C,
    nonce_len: usize,
    aad: &[u8],
    sealed: &[u8],
) -> std::result::Result<SecretBytes, OpenDiagnostic> {
    use OpenDiagnostic::{AuthenticationFailed, MalformedInput};
    if sealed.len() < nonce_len + TAG_LEN {
        return Err(MalformedInput);
    }
    let (nonce, rest) = sealed.split_at(nonce_len);
    let (ciphertext, tag) = rest.split_at(rest.len() - TAG_LEN);
    let nonce = Nonce::<C>::try_from(nonce).map_err(|_| MalformedInput)?;
    let tag = Tag::<C>::try_from(tag).map_err(|_| MalformedInput)?;
    // The plaintext goes straight into a buffer that is wiped on drop, including on failure.
    let mut plaintext = SecretBytes::zeroed(ciphertext.len());
    let buffer = InOutBuf::new(ciphertext, plaintext.as_bytes_mut()).map_err(|_| MalformedInput)?;
    c.decrypt_inout_detached(&nonce, aad, buffer, &tag)
        .map_err(|_| AuthenticationFailed)?;
    Ok(plaintext)
}
