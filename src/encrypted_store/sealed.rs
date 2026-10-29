//! Sealed files for everything that is not a redb file: small configuration files and
//! attachments of any size, written as a stream and read back piece by piece.
//!
//! ```text
//! [salt 32 B, random][block 0][block 1] ... [last block]
//! block: nonce | up to 64 KiB of data, sealed | tag
//! ```
//! Every file has its own key (made from the database's data key and the file's salt), so no two
//! files share a nonce space. A block is bound to its number, and the last block is also bound to
//! "I am last" and to the total length of the file. The file's key also depends on its logical
//! name (`binding`: for an attachment its table and id, for a side file its role and name), so a
//! file copied to another name does not open. So a file cut at a block boundary, a file with
//! its last block removed or one added, two blocks swapped, or a block taken from another file all
//! fail to open or to read, and nothing wrong is ever returned.
use super::error::tamper_io;
use super::store::EncryptionContext;
use crate::crypto::{Aead, Scope, random_bytes};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

pub const SALT_LEN: usize = 32;
/// Plaintext bytes in a full block.
pub const BLOCK: usize = 64 * 1024;

fn aad(index: u64, last_total: Option<u64>) -> Vec<u8> {
    let mut a = Vec::with_capacity(18);
    a.push(b's');
    a.extend_from_slice(&index.to_le_bytes());
    match last_total {
        None => a.push(0),
        Some(total) => {
            a.push(1);
            a.extend_from_slice(&total.to_le_bytes());
        }
    }
    a
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Where the keys of sealed files come from: the keys of a database encrypted as a whole, or the
/// keys of the protected fields of an otherwise ordinary database.
#[doc(hidden)]
pub trait FileKeys: Send + Sync {
    /// The cipher for one sealed file: its key depends on the kind of file (`label`), the file's
    /// logical name (`binding`) and the file's own salt.
    fn sealed_aead(&self, label: &str, binding: &str, salt: &[u8]) -> io::Result<Aead>;
    /// A 128-bit name for `name` inside `domain`, as 32 hex characters.
    fn name_fingerprint(&self, domain: &str, name: &str) -> io::Result<String>;
    /// False when these keys cannot open sealed files (a program that holds only the search key).
    fn can_open(&self) -> bool {
        true
    }
}

impl FileKeys for EncryptionContext {
    fn sealed_aead(&self, label: &str, binding: &str, salt: &[u8]) -> io::Result<Aead> {
        EncryptionContext::sealed_aead(self, label, binding, salt)
    }

    fn name_fingerprint(&self, domain: &str, name: &str) -> io::Result<String> {
        EncryptionContext::name_fingerprint(self, domain, name)
    }
}

impl EncryptionContext {
    /// The cipher for one sealed file: its key comes from the data key, the kind of file (`label`)
    /// and the file's own salt.
    pub(crate) fn sealed_aead(&self, label: &str, binding: &str, salt: &[u8]) -> io::Result<Aead> {
        let read = self
            .access()
            .read()
            .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "no read key"))?;
        let field = format!("{label}:{}:{}:{binding}", binding.len(), hex(salt));
        let key = read
            .encryption_key(self.suite().hkdf, &Scope { table: "sealed", field: &field })
            .map_err(|_| io::Error::other("key derivation failed"))?;
        Aead::new(self.suite().cipher, &key).map_err(|_| io::Error::other("cipher setup failed"))
    }

    /// A 128-bit name for `name` inside `domain` (for example the folder of a table), as 32 hex
    /// characters. The same name gives the same result for the same database, nothing else can
    /// tell what it stands for, and two domains never give the same result for one name.
    pub fn name_fingerprint(&self, domain: &str, name: &str) -> io::Result<String> {
        let read = self
            .access()
            .read()
            .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "no read key"))?;
        let key = read
            .hash_key(self.suite().hkdf, &Scope { table: "names", field: domain })
            .map_err(|_| io::Error::other("key derivation failed"))?;
        let tag = crate::crypto::MacKind::HmacSha256
            .mac(&key, name.as_bytes())
            .map_err(|_| io::Error::other("mac failed"))?;
        Ok(hex(&tag.as_bytes()[..16]))
    }
}

impl EncryptionContext {
    /// `root` with each of `components` turned into its fingerprint, for side files whose folder and
    /// file names must not show what they hold (a table's folder, a migration's folder, `index.json`).
    /// The same components always give the same path for the same database.
    pub fn masked_path(&self, root: &Path, components: &[&str]) -> io::Result<std::path::PathBuf> {
        let mut path = root.to_path_buf();
        for c in components {
            path.push(self.name_fingerprint("path", c)?);
        }
        Ok(path)
    }
}

/// Writes a sealed file as a stream; the length does not have to be known first.
pub struct SealedWriter<W: Write> {
    out: W,
    aead: Aead,
    overhead: usize,
    index: u64,
    /// The block being filled. A full block is kept back until more data arrives, because it may
    /// turn out to be the last one.
    buf: Vec<u8>,
    total: u64,
    scratch: Vec<u8>,
}

impl<W: Write> SealedWriter<W> {
    pub fn new(mut out: W, context: &dyn FileKeys, label: &str, binding: &str) -> io::Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        random_bytes(&mut salt).map_err(|_| io::Error::other("no random source"))?;
        let aead = context.sealed_aead(label, binding, &salt)?;
        out.write_all(&salt)?;
        let overhead = aead.kind().overhead();
        Ok(SealedWriter {
            out,
            aead,
            overhead,
            index: 0,
            buf: Vec::with_capacity(BLOCK),
            total: 0,
            scratch: vec![0u8; BLOCK + overhead],
        })
    }

    fn emit(&mut self, last: bool) -> io::Result<()> {
        let n = self.buf.len();
        let a = aad(self.index, if last { Some(self.total) } else { None });
        self.aead
            .seal_into(&a, &self.buf, &mut self.scratch[..n + self.overhead])
            .map_err(|_| io::Error::other("sealing failed"))?;
        self.out.write_all(&self.scratch[..n + self.overhead])?;
        self.index += 1;
        self.buf.clear();
        Ok(())
    }

    /// Seal what is left as the last block and give the output back (not flushed to disk).
    pub fn finish(mut self) -> io::Result<W> {
        self.emit(true)?;
        self.out.flush()?;
        Ok(self.out)
    }
}

impl<W: Write> Write for SealedWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        if self.buf.len() == BLOCK {
            self.emit(false)?;
        }
        let n = (BLOCK - self.buf.len()).min(data.len());
        self.buf.extend_from_slice(&data[..n]);
        self.total += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Reads a sealed file, with random access. Opening checks the last block, which also proves the
/// length; every other block is checked as it is reached.
pub struct SealedReader<R: Read + Seek> {
    src: R,
    aead: Aead,
    overhead: usize,
    blocks: u64,
    total: u64,
    pos: u64,
    cached: Option<(u64, Vec<u8>)>,
}

impl<R: Read + Seek> SealedReader<R> {
    pub fn new(mut src: R, context: &dyn FileKeys, label: &str, binding: &str) -> io::Result<Self> {
        let file_len = src.seek(SeekFrom::End(0))?;
        src.seek(SeekFrom::Start(0))?;
        let mut salt = [0u8; SALT_LEN];
        if file_len < SALT_LEN as u64 {
            return Err(tamper_io(None));
        }
        src.read_exact(&mut salt)?;
        let aead = context.sealed_aead(label, binding, &salt)?;
        let overhead = aead.kind().overhead();
        let stride = (BLOCK + overhead) as u64;
        let payload = file_len - SALT_LEN as u64;
        if payload < overhead as u64 {
            return Err(tamper_io(None));
        }
        let blocks = payload.div_ceil(stride);
        let last_len = payload - (blocks - 1) * stride;
        if last_len < overhead as u64 {
            return Err(tamper_io(Some(blocks - 1)));
        }
        let total = (blocks - 1) * BLOCK as u64 + (last_len - overhead as u64);
        let mut this = SealedReader { src, aead, overhead, blocks, total, pos: 0, cached: None };
        this.load(blocks - 1)?;
        Ok(this)
    }

    /// The length of the data (authenticated when the file was opened).
    pub fn len(&self) -> u64 {
        self.total
    }

    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    fn load(&mut self, index: u64) -> io::Result<()> {
        if matches!(&self.cached, Some((i, _)) if *i == index) {
            return Ok(());
        }
        let stride = (BLOCK + self.overhead) as u64;
        let last = index + 1 == self.blocks;
        let plain_len = if last { (self.total - index * BLOCK as u64) as usize } else { BLOCK };
        let mut buf = vec![0u8; plain_len + self.overhead];
        self.src.seek(SeekFrom::Start(SALT_LEN as u64 + index * stride))?;
        self.src.read_exact(&mut buf)?;
        let a = aad(index, if last { Some(self.total) } else { None });
        let range = self.aead.open_in_place(&a, &mut buf).map_err(|_| tamper_io(Some(index)))?;
        let plain = buf[range].to_vec();
        self.cached = Some((index, plain));
        Ok(())
    }
}

impl<R: Read + Seek> Read for SealedReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.total || out.is_empty() {
            return Ok(0);
        }
        let index = self.pos / BLOCK as u64;
        self.load(index)?;
        let within = (self.pos % BLOCK as u64) as usize;
        let plain = &self.cached.as_ref().unwrap().1;
        let n = (plain.len() - within).min(out.len());
        out[..n].copy_from_slice(&plain[within..within + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for SealedReader<R> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let target = match to {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(d) => self.total as i128 + d as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if target < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek before the start"));
        }
        self.pos = target as u64;
        Ok(self.pos)
    }
}

/// Seal `bytes` into a new file at `path` through a temporary file and a rename, so a crash leaves
/// either the old file or the complete new one. `sync` also forces the data to disk first.
pub fn write_sealed_file(
    path: &Path,
    context: &dyn FileKeys,
    label: &str,
    binding: &str,
    bytes: &[u8],
    sync: bool,
) -> io::Result<()> {
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(format!(".tmp.{}", std::process::id()));
    let tmp = path.with_file_name(tmp_name);
    let result = (|| -> io::Result<()> {
        let file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(&tmp)?;
        let mut w = SealedWriter::new(io::BufWriter::new(file), context, label, binding)?;
        w.write_all(bytes)?;
        let out = w.finish()?;
        let file = out.into_inner().map_err(|e| e.into_error())?;
        if sync {
            file.sync_all()?;
        }
        drop(file);
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Read a whole sealed file. A file that was changed is an error of kind `InvalidData` that
/// [`super::is_tamper`] recognises.
pub fn read_sealed_file(path: &Path, context: &dyn FileKeys, label: &str, binding: &str) -> io::Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    let mut r = SealedReader::new(io::BufReader::new(file), context, label, binding)?;
    let mut out = Vec::with_capacity(r.len() as usize);
    r.read_to_end(&mut out)?;
    Ok(out)
}
