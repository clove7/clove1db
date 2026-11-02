//! # 07 — Migration and recovery
//!
//! What happens to a database over its life, and after a crash.
//!
//! 1. **A schema change** (`storage.migrate::<ProductV1, ProductV2>()`): rows of one version of a
//!    struct are rewritten as the next, in place, with a `MigrateTo` you write once.
//! 2. **A file from an old release** (here a `.cldb` made by 0.0.42, in `fixtures/`): `build()`
//!    recognises it, adds the metadata it lacks and converts its history, before serving it.
//! 3. **A foreign redb file**: rows of a plain redb table are imported with `from_external`, and a
//!    large table is copied in batches with `stream_external` (`scan`, `stream`, `verify`). The
//!    source is only read; work on a copy of a file you care about.
//! 4. **Changing the protection** of a closed database: `ChangeProtection` (plain to encrypted, one
//!    key to another) and `ChangeFields` (a plain field becomes a sealed one). The new files are
//!    written next to the old ones, checked, and put in place by one decision a crash cannot split.
//! 5. **A killed process**: a writer is killed in the middle of its work. Every write it reported
//!    as done is there after the next open. `open_report()` says whether redb had to walk the
//!    file to repair it, which `quick_repair(true)` avoids; `close()` avoids it on a normal exit.
//!
//! Run it with `cargo run --release` from this folder.

use clove1db::{
    CloveFields, EncryptionConfig, FileKind, KeySource, inspect_cldb,
    crypto::Key32,
    entity::Entity,
    field_crypto::Sealed,
    migration::{
        ChangeFields, ChangeProtection, ExternalFrom, KeyDecoder, MigrateOutcome, MigrateTo, MigrationTo,
        ValueDecoder, migrate_value,
        stream_external::{self, JsonRow, Kind, Options, Target},
    },
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::ClError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

fn check(ok: bool, what: &str) -> Res<()> {
    if ok {
        println!("  ok  {what}");
        Ok(())
    } else {
        Err(format!("check failed: {what}").into())
    }
}

// ── 1. A schema change ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ProductV1 {
    id: String,
    name: String,
}

impl Entity for ProductV1 {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, CloveFields)]
struct ProductV2 {
    id: String,
    name: String,
    sku: String,
    price_cents: u64,
}

impl Entity for ProductV2 {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

impl MigrateTo<ProductV2> for ProductV1 {
    fn migrate_json(value: Value) -> clove1db::units::Result<MigrateOutcome<Value>> {
        let v1: ProductV1 = serde_json::from_value(value)?;
        let sku = format!("SKU-{}", v1.id.to_uppercase());
        migrate_value(ProductV2 { id: v1.id, name: v1.name, sku, price_cents: 0 })
    }
}

fn catalog(root: &Path, version: u32) -> Res<Storage> {
    let db = DatabaseConfig::new("catalog", "catalog").dir_path(root.to_path_buf()).has_cache(false);
    let builder = Storage::builder(StorageConfig::default());
    Ok(match version {
        1 => builder.add_database(db.register::<ProductV1>("products")).build()?,
        _ => builder.migration_step::<ProductV1, ProductV2>().add_database(db.register::<ProductV2>("products")).build()?,
    })
}

fn schema_change(root: &Path) -> Res<()> {
    println!("\n1. a schema change: ProductV1 to ProductV2");
    let dir = root.join("schema");
    let v1 = catalog(&dir, 1)?;
    for (id, name) in [("kb", "Keyboard"), ("ms", "Mouse"), ("mn", "Monitor")] {
        v1.domain::<ProductV1>().repo().set(id, &ProductV1 { id: id.into(), name: name.into() })?;
    }
    v1.migrate::<ProductV1, ProductV2>().from_db("catalog", "products").execute()?;
    v1.close();
    drop(v1);

    let v2 = catalog(&dir, 2)?;
    let kb: ProductV2 = v2.domain::<ProductV2>().repo().get("kb")?;
    check(kb.name == "Keyboard" && kb.sku == "SKU-KB", "the row was rewritten by migrate_json")?;
    check(v2.domain::<ProductV2>().query().count()? == 3, "all three rows were migrated")?;
    v2.close();
    Ok(())
}

// ── 2. A file from an old release ─────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct BuyerV1 {
    id: String,
    name: String,
    email: String,
}

impl Entity for BuyerV1 {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct EmployeeV1 {
    id: String,
    name: String,
    role: String,
}

impl Entity for EmployeeV1 {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn old_release(root: &Path) -> Res<()> {
    println!("\n2. a file made by clove1db 0.0.42");
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures").join("era_042");
    let dir = root.join("old").join("retail");
    std::fs::create_dir_all(&dir)?;
    for name in ["retail.cldb", "retail.cldb.bak"] {
        std::fs::copy(fixtures.join(name), dir.join(name))?; // never upgrade the fixture itself
    }
    let main = dir.join("retail.cldb");
    let before = inspect_cldb(&main)?;
    println!("  before: {:?}, tables {:?}", before.kind, before.tables);
    check(before.kind == FileKind::Legacy042, "inspect_cldb sees a 0.0.42 file, without opening a Storage")?;

    let storage = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("retail", "retail")
                .dir_path(root.join("old"))
                .backup_enabled(true)
                .register::<ProductV1>("products")
                .register::<BuyerV1>("buyers")
                .register::<EmployeeV1>("employees"),
        )
        .build()?;
    let products = storage.domain::<ProductV1>().repo().list()?;
    let buyers = storage.domain::<BuyerV1>().repo().list()?;
    println!("  served after the upgrade: {} products, {} buyers", products.len(), buyers.len());
    check(!products.is_empty() && !buyers.is_empty(), "the old rows read through today's API")?;
    storage.close();
    drop(storage);

    let after = inspect_cldb(&main)?;
    println!("  after: {:?}, schemas {:?}", after.kind, after.table_schemas);
    check(after.kind == FileKind::Authenticated && after.backup_upgraded, "the file now carries its metadata, and its history was converted")?;
    Ok(())
}

// ── 3. A foreign redb file ────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct VendorRow {
    id: String,
    title: String,
    price_usd: f64,
}

impl MigrateTo<ProductV2> for VendorRow {
    fn migrate_json(value: Value) -> clove1db::units::Result<MigrateOutcome<Value>> {
        let row: VendorRow = serde_json::from_value(value)?;
        if row.title.is_empty() {
            return clove1db::migration::skip_record("no title");
        }
        let price_cents = (row.price_usd * 100.0).round() as u64;
        migrate_value(ProductV2 { sku: format!("V-{}", row.id), id: row.id, name: row.title, price_cents })
    }
}

const VENDOR_TABLE: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new("vendor_catalog");

fn make_vendor_file(path: &Path, rows: usize) -> Res<()> {
    let db = redb::Database::create(path)?;
    let tx = db.begin_write()?;
    {
        let mut table = tx.open_table(VENDOR_TABLE)?;
        for i in 0..rows {
            let title = if i == 3 { String::new() } else { format!("Vendor item {i}") };
            let row = VendorRow { id: format!("v{i:05}"), title, price_usd: 1.25 + i as f64 };
            table.insert(row.id.as_str(), serde_json::to_vec(&row)?.as_slice())?;
        }
    }
    tx.commit()?;
    Ok(())
}

fn foreign_file(root: &Path) -> Res<()> {
    println!("\n3. a foreign redb file");
    let dir = root.join("foreign");
    std::fs::create_dir_all(&dir)?;
    let vendor = dir.join("vendor.redb");
    make_vendor_file(&vendor, 1_000)?;

    let shop = Storage::builder(StorageConfig::default())
        .add_database(DatabaseConfig::new("shop", "shop").dir_path(dir.clone()).has_cache(false).register::<ProductV2>("products"))
        .build()?;
    let done = shop
        .migrate::<VendorRow, ProductV2>()
        .from_external(ExternalFrom {
            path: vendor.clone(),
            table: "vendor_catalog".into(),
            key_decoder: KeyDecoder::Utf8String,
            value_decoder: ValueDecoder::JsonValidate,
        })
        .to(MigrationTo::new("shop").table("products"))
        .execute()?;
    println!("  from_external: {} migrated, {} skipped", done.records_migrated, done.report.source_skipped);
    check(done.records_migrated == 999 && done.report.source_skipped == 1, "999 rows imported, the row with no title skipped")?;
    let row: ProductV2 = shop.domain::<ProductV2>().repo().get("v00010")?;
    check(row.price_cents == 1_125, "a price of 11.25 dollars became 1,125 cents")?;
    shop.close();
    drop(shop);

    // A large table is copied as it is, in batches, and checked row by row afterwards.
    let options = Options { kind: Kind::Json, max_rows: 250, ..Options::default() };
    let scanned = stream_external::scan(&vendor, "vendor_catalog", &options)?;
    println!("  scan: {} rows, {} bytes, {} not JSON", scanned.sizes.rows, scanned.sizes.value_bytes, scanned.invalid_json);
    let copy = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("copy", "copy").dir_path(dir.clone()).has_cache(false).register::<JsonRow>("vendor_catalog"),
        )
        .build()?;
    let mut batches = 0;
    let streamed = stream_external::stream(&vendor, "vendor_catalog", Target { storage: &copy, db: "copy", table: "vendor_catalog" }, &options, Some(&mut |_| batches += 1))?;
    let verified = stream_external::verify(&vendor, "vendor_catalog", Target { storage: &copy, db: "copy", table: "vendor_catalog" }, &options)?;
    println!("  stream: {} rows in {batches} progress reports; verify equal: {}", streamed.sizes.rows, verified.is_equal());
    check(scanned.sizes.rows == 1_000 && streamed.sizes.rows == 1_000, "every row was copied")?;
    check(verified.is_equal(), "verify finds the copy equal to the source")?;
    copy.close();
    Ok(())
}

// ── 4. Changing the protection ────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize, CloveFields)]
struct Person {
    id: String,
    name: String,
    phone: String,
}

impl Entity for Person {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// The same table once its phone is sealed.
#[derive(Clone, Default, Serialize, Deserialize, CloveFields)]
struct SealedPerson {
    id: String,
    name: String,
    #[clove(encrypt, id = 1)]
    phone: Sealed<String>,
}

impl Entity for SealedPerson {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn keys(n: u8) -> EncryptionConfig {
    EncryptionConfig::new(KeySource::Raw(Key32::from_bytes(&[n; 32])), KeySource::Raw(Key32::from_bytes(&[n + 100; 32])))
}

fn people(root: &Path, protection: Option<EncryptionConfig>) -> Res<Storage> {
    let db = DatabaseConfig::new("records", "store").dir_path(root.to_path_buf()).has_cache(false);
    let db = match protection {
        Some(k) => db.encryption(k),
        None => db,
    };
    Ok(Storage::builder(StorageConfig::default()).add_database(db.register::<Person>("people")).build()?)
}

fn contains(path: &Path, needle: &[u8]) -> Res<bool> {
    Ok(std::fs::read(path)?.windows(needle.len()).any(|w| w == needle))
}

fn change_protection(root: &Path) -> Res<()> {
    println!("\n4. changing the protection of a closed database");
    let dir = root.join("protection");
    let main = dir.join("records").join("store.cldb");
    let storage = people(&dir, None)?;
    for i in 0..200 {
        let id = format!("p{i:04}");
        storage.domain::<Person>().repo().set(&id, &Person { id: id.clone(), name: format!("person {i}"), phone: format!("555-{i:06}") })?;
    }
    storage.close();
    drop(storage);
    check(contains(&main, b"555-000007")?, "the plain file holds the phone numbers")?;

    let plan = ChangeProtection::new(&dir, "records", "store").from_plain().to_whole_database(keys(1)).dry_run()?;
    println!("  dry_run: needs up to {} bytes of free disk, writes nothing", plan.required_bytes);
    ChangeProtection::new(&dir, "records", "store").from_plain().to_whole_database(keys(1)).execute()?;
    check(!contains(&main, b"555-000007")?, "after the change the file is encrypted")?;
    check(matches!(people(&dir, None), Err(ref e) if e.downcast_ref::<ClError>().is_some()), "it no longer opens as a plain database")?;

    ChangeProtection::new(&dir, "records", "store").from_whole_database(keys(1)).to_whole_database(keys(2)).execute()?;
    check(people(&dir, Some(keys(1))).is_err(), "after a key change the old key is refused")?;
    let storage = people(&dir, Some(keys(2)))?;
    check(storage.domain::<Person>().query().count()? == 200, "the new key opens every row")?;
    storage.close();
    drop(storage);

    ChangeProtection::new(&dir, "records", "store").from_whole_database(keys(2)).to_plain().execute()?;
    println!("  and back to plain files");

    ChangeFields::new(&dir, "records", "store").field_keys(keys(3)).table::<SealedPerson>("people").execute()?;
    let sealed = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("records", "store").dir_path(dir.clone()).has_cache(false).field_encryption(keys(3)).register_sealed::<SealedPerson>("people"),
        )
        .build()?;
    let domain = sealed.domain::<SealedPerson>();
    let row = domain.repo().get("p0007")?;
    check(row.name == "person 7", "the other fields are as they were")?;
    check(row.phone.open(&domain.read_grant()?)? == "555-000007", "the phone is sealed now, and opens with the keys")?;
    sealed.close();
    drop(sealed);
    check(!contains(&main, b"555-000007")?, "and is no longer in the file")?;
    Ok(())
}

// ── 5. A killed process ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Entry {
    id: String,
    n: u64,
}

impl Entity for Entry {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn journal(root: &Path, quick_repair: bool) -> Res<Storage> {
    Ok(Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("log", "log")
                .dir_path(root.to_path_buf())
                .has_cache(false)
                .quick_repair(quick_repair)
                .register::<Entry>("entries"),
        )
        .build()?)
}

/// The child: writes forever, and says "ACK n" only after the write of row n returned.
fn writer(root: &Path, quick_repair: bool) -> Res<()> {
    let storage = journal(root, quick_repair)?;
    let repo = storage.domain::<Entry>().repo();
    let mut out = std::io::stdout().lock();
    for n in 0u64.. {
        let id = format!("e{n:08}");
        repo.set(&id, &Entry { id: id.clone(), n })?;
        writeln!(out, "ACK {n}")?;
        out.flush()?;
    }
    Ok(())
}

fn kill_after(root: &Path, quick_repair: bool, acks: u64) -> Res<u64> {
    let mut child = Command::new(std::env::current_exe()?)
        .args(["--writer", &root.display().to_string(), if quick_repair { "quick" } else { "plain" }])
        .stdout(Stdio::piped())
        .spawn()?;
    let mut last = None;
    for line in BufReader::new(child.stdout.take().ok_or("no stdout")?).lines() {
        let line = line?;
        if let Some(n) = line.strip_prefix("ACK ") {
            last = Some(n.parse::<u64>()?);
            if last == Some(acks - 1) {
                break;
            }
        }
    }
    child.kill()?; // no close(), no destructors: the process just stops
    child.wait()?;
    last.ok_or_else(|| "the writer acknowledged nothing".into())
}

fn killed_process(root: &Path) -> Res<()> {
    println!("\n5. a writer killed in the middle of its work");
    for quick_repair in [false, true] {
        let dir = root.join(if quick_repair { "killed-quick" } else { "killed" });
        let last = kill_after(&dir, quick_repair, 300)?;
        let storage = journal(&dir, quick_repair)?;
        let repaired = storage.open_report().iter().any(|r| r.repaired);
        let repo = storage.domain::<Entry>().repo();
        let missing = (0..=last).filter(|n| repo.get(&format!("e{n:08}")).is_err()).count();
        println!("  quick_repair({quick_repair}): last acknowledged {last}, rows now {}, repaired on open: {repaired}", repo.list()?.len());
        check(missing == 0, "every acknowledged write is there")?;
        check(repaired != quick_repair, if quick_repair { "with quick_repair the open needed no repair" } else { "without it, redb repaired the file on open" })?;
        storage.close();
        drop(storage);
        let storage = journal(&dir, quick_repair)?;
        check(storage.open_report().iter().all(|r| !r.repaired), "after close(), the next open needs no repair")?;
        storage.close();
    }
    Ok(())
}

fn main() -> Res<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--writer") {
        return writer(&PathBuf::from(&args[2]), args.get(3).map(String::as_str) == Some("quick"));
    }

    let root = std::env::temp_dir().join(format!("clove1db-example-07-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    println!("07 migration and recovery — data in {}", root.display());

    schema_change(&root)?;
    old_release(&root)?;
    foreign_file(&root)?;
    change_protection(&root)?;
    killed_process(&root)?;

    std::fs::remove_dir_all(&root)?;
    println!("\n07 migration and recovery: all checks passed");
    Ok(())
}
