//! # 06 — Encryption
//!
//! Two ways to protect data, under keys you hold.
//!
//! **The whole database** (`.encryption(keys)`): every file — the `.cldb`, its history, the
//! `.inx` index, the sidecars — is sealed in 4 KiB blocks with AES-256-GCM-SIV (the default) or
//! XChaCha20-Poly1305. Nothing in the folder is readable, not even the redb signature. A wrong key
//! is `EncryptedOpenFailed`; a changed byte is `DataTampered`, never wrong data.
//!
//! **Single fields** (`.field_encryption(keys)` and `register_sealed`): the rows stay ordinary
//! rows, and only the fields you mark are protected:
//!
//! - `#[clove(encrypt)]` `Sealed<T>` — sealed; opened with a read grant;
//! - `#[clove(encrypt, print = "full")]` — sealed, plus a keyed fingerprint to **search** by equality;
//! - `#[clove(hash = "argon2id")]` `Hashed` — a slow salted hash; checked, never read back;
//! - `#[clove(search_print)]` `SearchPrint` — a fingerprint only; matched, never read back.
//!
//! The keys here are fixed bytes so the example is repeatable. A real program takes them from a
//! secret store, or uses `KeySource::Password`. Changing the keys or the kind of protection of an
//! existing database is in example 07.
//!
//! Run it with `cargo run --release` from this folder (the Argon2id hash takes about 0.1 s each).

use clove1db::{
    CloveFields, EncryptionConfig, KeySource,
    crypto::{CipherKind, HkdfHash, Key32, KeySuite},
    encrypted_store::{EncryptionHandle, verify_encrypted_files},
    entity::Entity,
    field_crypto::{Hashed, Sealed, SearchPrint},
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

const SECRET_TEXT: &str = "CONFIDENTIAL-MEDICAL-NOTE";

#[derive(Debug, Clone, Default, Serialize, Deserialize, CloveFields)]
struct Note {
    id: String,
    text: String,
}

impl Entity for Note {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Clone, Default, Serialize, Deserialize, CloveFields)]
struct Account {
    id: String,
    name: String, // an ordinary field: readable in the file, usable in any query
    #[clove(encrypt, id = 1, print = "full", normalize = "trim")]
    phone: Sealed<String>,
    #[clove(hash = "argon2id", id = 2)]
    password: Hashed,
    #[clove(search_print, id = 3, normalize = "trim,lowercase")]
    email: SearchPrint,
    #[clove(encrypt, id = 4)]
    note: Sealed<String>,
}

impl Entity for Account {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn keys(read: u8, search: u8, cipher: CipherKind) -> EncryptionConfig {
    EncryptionConfig::new(
        KeySource::Raw(Key32::from_bytes(&[read; 32])),   // decrypts everything
        KeySource::Raw(Key32::from_bytes(&[search; 32])), // makes fingerprints; decrypts nothing
    )
    .with_suite(KeySuite { cipher, hkdf: HkdfHash::Sha256 })
}

fn check(ok: bool, what: &str) -> Res<()> {
    if ok {
        println!("  ok  {what}");
        Ok(())
    } else {
        Err(format!("check failed: {what}").into())
    }
}

/// Every file under `dir`, read whole: for a check of what is on disk, on small test data only.
fn files_contain(dir: &Path, needle: &[u8]) -> Res<bool> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            if files_contain(&path, needle)? {
                return Ok(true);
            }
        } else if std::fs::read(&path)?.windows(needle.len()).any(|w| w == needle) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn whole_db(root: &Path, keys: EncryptionConfig) -> Res<Storage> {
    Ok(Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("vault", "vault")
                .dir_path(root.to_path_buf())
                .backup_enabled(true)
                .encryption(keys)
                .register::<Note>("notes"),
        )
        .build()?)
}

fn whole_database(root: &Path, cipher: CipherKind, label: &str) -> Res<()> {
    println!("\nthe whole database, {label}");
    let dir = root.join(label);
    let storage = whole_db(&dir, keys(11, 111, cipher))?;
    let notes = storage.domain::<Note>();
    for i in 0..50 {
        let id = format!("note-{i:03}");
        notes.repo().set(&id, &Note { id: id.clone(), text: format!("{SECRET_TEXT} {i}") })?;
    }
    check(
        notes.query().filter(Note::text.contains("MEDICAL")).count()? == 50,
        "queries and indexes work as on a plain database",
    )?;
    storage.close();
    drop(storage);

    let folder = dir.join("vault");
    check(!files_contain(&folder, SECRET_TEXT.as_bytes())?, "no file holds the text")?;
    check(!files_contain(&folder, b"note-0")?, "no file holds a row id")?;
    check(!files_contain(&folder, b"redb\x1A\x0A\xA9\x0D\x0A")?, "no file holds the redb signature")?;

    let handle = EncryptionHandle::new(keys(11, 111, cipher));
    verify_encrypted_files(&dir, "vault", "vault", &handle)?;
    println!("  ok  verify_encrypted_files: every block of every file is authentic");

    let wrong = whole_db(&dir, keys(99, 111, cipher));
    check(matches!(wrong, Err(ref e) if matches!(e.downcast_ref::<ClError>(), Some(ClError::EncryptedOpenFailed))), "a wrong key is EncryptedOpenFailed")?;

    let main = folder.join("vault.cldb");
    let original = std::fs::read(&main)?;
    let mut changed = original.clone();
    let middle = changed.len() / 2;
    changed[middle] ^= 0x01; // one bit
    std::fs::write(&main, &changed)?;
    let tampered = verify_encrypted_files(&dir, "vault", "vault", &handle);
    // verify_encrypted_files returns the file layer's own error; as a ClError it is DataTampered.
    check(
        matches!(tampered.map_err(ClError::from), Err(ClError::DataTampered)),
        "one changed bit is DataTampered",
    )?;
    std::fs::write(&main, &original)?;

    let storage = whole_db(&dir, keys(11, 111, cipher))?;
    let back = storage.domain::<Note>().repo().get("note-007")?;
    check(back.text == format!("{SECRET_TEXT} 7"), "with the right key and the original file, the row reads back")?;
    storage.close();
    Ok(())
}

fn fields_db(root: &Path) -> Res<Storage> {
    Ok(Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("people", "people")
                .dir_path(root.to_path_buf())
                .field_encryption(keys(22, 122, CipherKind::Aes256GcmSiv))
                .register_sealed::<Account>("accounts"),
        )
        .build()?)
}

fn protected_fields(root: &Path) -> Res<()> {
    println!("\nprotected fields");
    let dir = root.join("fields");
    let storage = fields_db(&dir)?;
    let accounts = storage.domain::<Account>();
    let people = [("u1", "Alice", "555-0100-111", "alice@example.test"), ("u2", "Bob", "555-0100-222", "BOB@example.test")];
    for (id, name, phone, email) in people {
        accounts.repo().set(
            id,
            &Account {
                id: id.into(),
                name: name.into(),
                phone: Sealed::new(phone.to_string()),
                password: Hashed::new(&format!("pass-of-{name}")),
                email: SearchPrint::new(email.to_string()),
                note: Sealed::new(format!("{SECRET_TEXT} about {name}")),
            },
        )?;
    }

    // Reading a row opens nothing: the protected fields stay sealed until a grant opens them.
    let alice = accounts.repo().get("u1")?;
    check(alice.name == "Alice", "an ordinary field reads as usual")?;
    let grant = accounts.read_grant()?;
    check(alice.phone.open(&grant)? == "555-0100-111", "a sealed field opens with a read grant")?;
    check(alice.note.open(&grant)?.contains("about Alice"), "and so does the note")?;

    let verifier = accounts.verifier()?;
    check(alice.password.verify("pass-of-Alice", &verifier)?, "the right password verifies")?;
    check(!alice.password.verify("guess", &verifier)?, "a wrong one does not")?;
    check(alice.email.matches(" ALICE@example.test ", &verifier)?, "the email fingerprint matches after trim and lowercase")?;

    let search = accounts.search_grant()?;
    let found = accounts.query().filter(Account::phone.print_eq(" 555-0100-222", &search)).collect()?;
    check(found.len() == 1 && found[0].id == "u2", "a search by the phone's fingerprint finds Bob")?;
    check(
        accounts.query().filter(Account::phone.print_eq("555-0100-999", &search)).count()? == 0,
        "an unknown phone finds nobody",
    )?;
    storage.close();
    drop(storage);

    let folder = dir.join("people");
    check(!files_contain(&folder, b"555-0100-111")?, "no file holds a phone number")?;
    check(!files_contain(&folder, b"alice@example.test")?, "no file holds an email")?;
    check(!files_contain(&folder, b"pass-of-Alice")?, "no file holds a password")?;
    check(!files_contain(&folder, SECRET_TEXT.as_bytes())?, "no file holds the note")?;
    check(files_contain(&folder, b"Alice")?, "the ordinary name field is stored as it is")?;
    check(folder.join("people.keys").is_file(), "people.keys holds a sealed copy of the data key")?;
    Ok(())
}

fn main() -> Res<()> {
    let root = std::env::temp_dir().join(format!("clove1db-example-06-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    println!("06 encryption — data in {}", root.display());

    whole_database(&root, CipherKind::Aes256GcmSiv, "aes")?;
    whole_database(&root, CipherKind::XChaCha20Poly1305, "xchacha")?;
    protected_fields(&root)?;

    std::fs::remove_dir_all(&root)?;
    println!("\n06 encryption: all checks passed");
    Ok(())
}
