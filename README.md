# clove1db

An embedded database for Rust applications, built on [redb](https://github.com/cberner/redb).

redb is an ordered map of bytes to bytes in one file. clove1db is the layer an application builds on top of that, done once and tested hard:

- **typed entities** with input and output DTOs at the edges;
- **queries** on typed fields, with **indexes the optimizer builds by itself**;
- a **history** of every write, so any row can be read or restored as it was;
- a **change log** that other programs follow, with acknowledgements that survive restarts;
- **attachments** stored as files beside the database and read as streams;
- **encryption** of the whole database, or of single fields, under keys you hold;
- **migrations** of a table's shape, of an older file, of a foreign redb file, and of the protection itself;
- **durability** you can state: what survives a crash, and what a crash costs the next open.

Everything lives in files next to your program: `.cldb` for the data, `.cldb.bak` for the history, `.inx` for the indexes. No server, no daemon, no connection string.

```toml
[dependencies]
clove1db = "0.1.0"                                                # core only
# clove1db = { version = "0.1.0", features = ["derive"] }        # + #[derive(CloveFields)]
# clove1db = { version = "0.1.0", features = ["encryption"] }    # + encryption (includes derive)
```

- **No features:** the database, queries, indexes, history, the change log and attachments. The field constants of an entity are written by hand ([without the derive macro](#without-the-derive-macro)).
- **`derive`:** adds `#[derive(CloveFields)]`, which writes those field constants for you. The examples below use it.
- **`encryption`:** adds encryption of a whole database and of protected fields (`EncryptionConfig`, `Sealed`, `Hashed`, `SearchPrint`, `ChangeProtection`, `ChangeFields`). It turns on `derive` too.

> **Before 1.0.** The API can still change between minor versions. Every change that breaks code or files is listed in [Upgrading](#upgrading). Issues and feedback are welcome.

## Contents

- [Quick start](#quick-start)
- [Storage, databases and tables](#storage-databases-and-tables)
- [Queries](#queries)
- [Automatic indexes](#automatic-indexes)
- [History, restore and bulk changes](#history-restore-and-bulk-changes)
- [Raw batches](#raw-batches)
- [The change log](#the-change-log)
- [Attachments](#attachments)
- [Memory: the cache and large tables](#memory-the-cache-and-large-tables)
- [Durability and recovery](#durability-and-recovery)
- [Encrypting the whole database](#encrypting-the-whole-database)
- [Protected fields](#protected-fields)
- [Changing how a database is protected](#changing-how-a-database-is-protected)
- [Schema migrations and older files](#schema-migrations-and-older-files)
- [Importing from a foreign redb file](#importing-from-a-foreign-redb-file)
- [Events](#events)
- [What it costs](#what-it-costs)
- [Limits](#limits)
- [Examples](#examples)
- [Upgrading](#upgrading)
- [Contributing](#contributing)
- [License](#license)

## Quick start

```rust
use clove1db::{
    dto::{InputDto, OutputDto},
    entity::Entity,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::{ClError, Result},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct User {
    id: String,
    name: String,
}

impl Entity for User {
    fn entity_id(&self) -> &str { &self.id }
}

/// What a caller may send. Checked before anything is written.
#[derive(Deserialize)]
struct NewUser { id: String, name: String }

impl InputDto<User> for NewUser {
    fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(ClError::Validation("name is required".into()));
        }
        Ok(())
    }
    fn into_entity(self) -> Result<User> {
        Ok(User { id: self.id, name: self.name })
    }
}

/// What a caller gets back.
#[derive(Serialize)]
struct UserView { id: String, name: String }

impl OutputDto<User> for UserView {
    fn from_entity(e: User) -> Self { Self { id: e.id, name: e.name } }
}

fn main() -> Result<()> {
    let storage = Storage::builder(StorageConfig::default())
        .add_database(DatabaseConfig::new("accounts", "accounts").register::<User>("users"))
        .build()?;

    let users = storage.domain::<User>();
    users.create::<NewUser, UserView>(NewUser { id: "u1".into(), name: "Alice".into() })?;
    let alice = users.get::<UserView>("u1")?;
    users.delete(&alice.id)?;

    storage.close(); // on the way out: the next open needs no repair
    Ok(())
}
```

## Storage, databases and tables

A `Storage` holds one or more **databases**. Each database is a `.cldb` file with its own tables, cache, history and settings. A table is registered with the entity it stores:

```rust
let storage = Storage::builder(StorageConfig::default())
    .add_database(
        DatabaseConfig::new("accounts", "accounts")      // name, file name
            .dir_path("./data".into())
            .cache_bytes(8 * 1024 * 1024, 300, 60)       // 8 MiB, 5 min TTL, 1 min idle
            .backup_enabled(true)                        // keep a history of every write
            .register::<User>("users"),
    )
    .add_database(
        DatabaseConfig::new("shop", "shop")
            .register::<Order>("orders")
            .register::<Setting>("settings"),
    )
    .build()?;
```

- **`storage.domain::<E>()`** works through DTOs: `create`, `get`, `list`, `update`, `delete`, and the history calls below. `update(id, dto)` stores the whole entity the DTO builds.
- **`domain.repo()`** works on entities directly: `get`, `set`, `delete`, `list`, `list_map`, `get_uncached`, `get_uncached_as`, `commit_entities`. To change one field and keep the others, read the row, change it and `set` it.
- **`storage.db_manager(name)`** is the database itself: raw batches, the change log, snapshots, statistics.
- An entity's id is whatever `entity_id()` returns. A key can be a natural one (a setting's name): writing it twice updates one row.
- Tables whose names begin with `__` are reserved for the library.

### Adding tables to an existing database

A table that is registered but missing from an existing database file is refused (`ClError::TableMismatch`): this catches a wrong file and a misspelled name. To add tables to a database that already exists, plain or encrypted, set `DatabaseConfig::create_missing_tables(true)`. The missing tables are created empty when the database opens, and `LibraryEvent::TablesCreated { database, tables }` lists them.

### Compacting a database file

A database file never shrinks by itself: pages freed by deletes and updates are reused, not returned. `storage.compact_database(name)` compacts the main file and the history file of one database, plain or encrypted, and returns a `CompactReport { before, after, took }`. Reads and writes of that database wait while it runs; other databases are not affected. A read or write transaction kept open makes it fail with `ClError::Database(redb::Error::TransactionInProgress)` after a short wait, changing nothing. The `.inx` file is compacted by the index worker.

## Queries

`#[derive(CloveFields)]` (feature `derive`) gives every field a typed handle (`Note::score`, `Note::title`, ...). A query runs against one snapshot of the database, without the entity cache:

```rust
use clove1db::{CloveFields, query::{Asc, Desc}};

#[derive(Clone, Default, Serialize, Deserialize, CloveFields)]
struct Note { id: String, group: String, score: i64, title: String, labels: Vec<String> }

let notes = storage.domain::<Note>();
let q = notes.query()
    .filter(Note::group.eq("public").and(Note::score.ge(20)))
    .order_by(Note::score, Desc)
    .then_by(Note::id, Asc)
    .limit(25);

let page = q.page()?;                                   // rows, and a cursor
if let Some(cursor) = page.next {
    let next = q.clone().after(cursor).collect()?;
}
```

- **Conditions:** `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `between` (lower-inclusive, upper-exclusive), `is_null`, `is_missing`, `exists`, `is_empty`; on text `text` (whole words, any case), `contains`, `prefix`, `fuzzy(term, 0..=2)`; on lists `any`, `all`, `at`, `len`, `elem_match`; combined with `and`, `or`.
- **Transforms** before a comparison: `trim()`, `lowercase()`, `normalize_arabic()`.
- **Results:** `collect`, `page` with a cursor, `one()` (zero is `None`, one is the row, more is `ClError::NonUnique { count }`), `exists`, `count`.
- **Aggregates** over the whole filtered set, without building entities: `count`, `distinct`, `min`, `max`, `sum`, `group_by(field).count()`. `sum` is exact: integers as `Sum::Integer`, any fraction as `Sum::Decimal` in base ten (`0.1 + 0.2` is `Decimal("3e-1")`), never a float.
- **Order** by fields, by `LastWrite` (the sequence of each row's last write), or by `field.similarity(term)`.
- **One snapshot for several queries:** take `db.read_view_at_head()` and use `collect_in(&view)` / `page_in(&view)`.
- **Unique constraints:** `DatabaseConfig::unique::<Note>(Unique::on(Note::title.trim().lowercase()))`, with `.and(..)` for several fields. Checked in the same transaction as the write, for every write path.
- Values of different types never compare equal: there is no conversion between text and numbers. Missing and `null` are different, and neither matches an equality.

Nested fields are reached with `then` (`Note::profile.then(Profile::name)`); `serde` renames and flattening are followed. A field whose stored form `serde` cannot describe needs `#[clove(as = Type)]` or `#[clove(skip)]`.

### Without the derive macro

`#[derive(CloveFields)]` only writes what you can write by hand: the marker, and one constant per stored field. The name is the key as it is stored in the JSON (after any serde `rename`); a field of type `Option<T>` is a `Field<Self, T>`.

```rust
use clove1db::fields::{CloveFields, Field, ValueKind};

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
struct Note { id: String, score: i64, #[serde(rename = "madeAt")] made_at: i64 }

impl CloveFields for Note {}
#[allow(non_upper_case_globals)]
impl Note {
    pub const id: Field<Self, String> = Field::new("id", ValueKind::Auto);
    pub const score: Field<Self, i64> = Field::new("score", ValueKind::Auto);
    pub const made_at: Field<Self, i64> = Field::new("madeAt", ValueKind::EpochSeconds);
}
// then: notes.query().filter(Note::score.ge(5)).order_by(Note::score, Desc).collect()
```

Protected fields (`encrypt`, `hash`, `search_print`) are not written by hand: they need the `encryption` feature and the derive macro.

## Automatic indexes

There is no `create_index`. The optimizer estimates what each plan would cost — a full scan, a selective scan, a direct lookup, an index — and builds an index in the `.inx` file when a query would pay for it. Equality, range, prefix, text, `contains`, fuzzy and order indexes are all built this way.

```rust
let q = notes.query().filter(Note::title.fuzzy("alpha", 1));
let plan = q.explain()?;            // the chosen plan, the alternatives, their costs, and why
println!("{:?}", plan.selected);    // e.g. IndexFuzzy once the index is ready
```

- **Answers never depend on the index.** A missing, late or rebuilding index makes a query slower, never different: candidates are checked against the snapshot.
- **The `.inx` file is disposable.** Deleted or damaged, it is rebuilt before `build()` returns.
- `allow_stale()` lets a query use an index that is behind; the page says how far.
- `storage.index_report()` describes every index without changing any.
- Indexes not used for a while drop their contents and keep their definition. A long backlog of changes is rebuilt rather than replayed when that is cheaper. Under sustained writes faster than an index can follow, it is set aside (queries scan) and comes back when writes slow down.

## History, restore and bulk changes

With `backup_enabled(true)`, every write and delete through the domain or the repository is kept in the `.cldb.bak` file, forever:

```rust
let docs = storage.domain::<Document>();
for record in docs.history("doc-1")? {
    println!("v{} {:?} {}", record.version, record.operation, record.date);
}
let old = docs.get_by_version("doc-1", 2)?;     // the row as it was
docs.restore_by_version("doc-1", 1)?;           // itself a new version: nothing is lost

let (_rows, bulk_id) = devices.update_bulk::<SetStatus, DeviceView>(changes)?;
devices.restore_bulk(&bulk_id)?;                // undo the whole bulk
```

A history record holds its version, operation (`Set`, `Delete`, `Restore`, `RestoreBulk`), date, the row as it was, and the bulk id if any. A version and its record are written in one transaction.

## Raw batches

For imports and copies, rows can be written as bytes, outside the history:

- `db.commit_batch_atomic(writes, deletes)` — one transaction, whatever its size: all or nothing.
- `db.commit_batch(writes, deletes)` — split into chunks of `max_commit_batch_entries` (512 by default); writes before deletes. A failure in a later chunk leaves the earlier chunks committed.
- `db.replace_table(table, rows)` — the whole table at once, as one change.

Unique constraints are checked for every batch. A table with protected fields refuses raw bytes: write it through its entity, or through a prepared row as below. `repo.commit_entities(..)` follows the same limit as `commit_batch`: above `max_commit_batch_entries` it is split into several transactions, deletes after writes.

### One atomic write over several tables

`repo.prepare(id, &entity)` returns a `PreparedRow`: the row in its stored form, with any protected fields already sealed. It writes nothing. `db.commit_atomic(prepared, writes, deletes)` then writes prepared rows, raw rows of other tables and deletes in **one** transaction, however many there are: either all of it is in the file or none of it. Uniqueness, the change log, the cache and the search-key guard apply as for any write.

```rust
let phone_changed = accounts.repo().prepare("seller-1", &account)?; // sealed here
let log_line = ("activity".to_string(), "e-901".to_string(), serde_json::to_vec(&entry)?);
db.commit_atomic(
    &[phone_changed],
    &[log_line],
    &[("sessions".to_string(), "s-42".to_string())],
)?;
```

A `PreparedRow` can only be made by `prepare`, and only the database of its repository accepts it. Refused, with nothing written: raw bytes for a table with protected fields; a row prepared for another database; a row of a table that keeps attachments (write an attachment with `set_with_blob`). Like `commit_batch_atomic`, `commit_atomic` writes no backup history.

## The change log

Every committed write gets the next number of a durable sequence, and is kept for the programs that follow the database — a replica, a search service, an export:

```rust
let db = storage.db_manager("store");
let token = db.register_consumer("replica")?;

let view = db.read_view_at_head()?;               // 1. copy everything that exists
copy_rows(view.table_entries("notes")?);
let head = view.head;
drop(view);
db.ack(&token, head)?;                            // 2. "stored up to here"

let changes = db.read_changes(&token, head, 100)?; // 3. what changed after it, in order
```

- The follower's position is stored in the database and survives restarts.
- `replace_table` is one change that the follower reads whole with `read_reset`.
- `journal_retention(Retention::Default)` keeps up to 256 MiB of changes (`Unlimited` and `Limit { max_bytes }` are the other choices). A follower that falls further behind is expired: `ClError::ConsumerExpired`, and it starts again from a snapshot.
- With no follower, nothing is kept; the sequence still counts every commit.
- Registering a name again replaces the old follower; its token is refused.

## Attachments

A table registered with `register_blob` keeps one file per row in `{db}.blobs`, beside the database. The row holds the metadata, and the file is written before the row commits:

```rust
DatabaseConfig::new("files", "files")
    .blob_enabled(true)
    .register_blob::<Attachment>("attachments");

files.create_with_blob::<Upload, AttachmentView>(upload, bytes)?;
let mut reader = files.open_blob("report")?;     // Read + Seek, never loaded whole
```

The size of the file is written into the row's `size_bytes` field. Deleting the row deletes the file. A database with attachments keeps no history file.

## Memory: the cache and large tables

`cache_bytes(max_bytes, ttl_secs, idle_secs)` sizes the cache of decoded rows in **bytes**, not entries: 10,000 rows of 10 KB are 100 MiB whatever an entry count says.

- `get_uncached` reads without filling the cache. Use it for a walk over many rows read once.
- Expired entries are freed during maintenance, which runs when the cache is used. `storage.run_cache_maintenance()` frees them at once; `cache_stats()` returns `(bytes, entries)`.
- `get_uncached_as::<Summary>` reads only the fields a smaller type names; the others are skipped without being built.
- `list_map(|row| ...)` turns each row into what you keep while the table is read, so the table is never held twice.
- `redb_cache_bytes(n)` caps redb's own page cache for one file (1 GiB by default). On a large table this cache, not the index builder, decides the peak memory of an index build.
- `prefetch` reads the file in order before redb opens it, which makes the first query on a cold file much faster. It is on by itself for files of 64 MiB or more; `prefetch(true)` and `prefetch(false)` force it.

## Durability and recovery

**Strict** is the default: every commit is flushed (`redb::Durability::Immediate`) and every side file is written to a temporary name, flushed and renamed, so a crash never leaves a half-written file under its real name. **Fast** skips the flushes for speed and keeps the renames.

```rust
use clove1db::DurabilityMode;

Storage::builder(StorageConfig::default().durability(DurabilityMode::Fast));   // all databases
DatabaseConfig::new("cache", "cache").durability(DurabilityMode::Fast);        // one database
```

- **What survives:** in Strict mode, every commit that returned. A damaged or zeroed side file is set aside and rebuilt on the next open.
- **`storage.close()`**, once, on the way out: it waits for running operations and closes every file cleanly, so the next open needs no repair. Any use afterwards is `ClError::Closed`.
- **After a kill or a crash** redb walks the whole file to rebuild its allocator state, which is slow on a large file. `quick_repair(true)` saves that state with every commit, at some cost per commit, so the next open loads it instead.
- **`storage.open_report()`** says, for each file opened by `build()`: its size, how long the open took, and whether it had to be repaired.
- Inspection (`inspect_cldb`) and the migration readers open files read only, and never repair them.
- Opening a database that another program has open is the clear error `ClError::DatabaseInUse`.

## Encrypting the whole database

Every file of a database — `.cldb`, `.cldb.bak`, `.inx`, attachments and side files — is sealed in 4 KiB blocks under keys you hold. Nothing in the folder is readable, not even the redb signature or a table name. Any changed byte is an error, never wrong data. Needs the `encryption` feature; a build without it that opens an encrypted file gets an error that points to the feature.

```rust
use clove1db::{EncryptionConfig, KeySource, crypto::Key32};

let keys = EncryptionConfig::new(
    KeySource::Raw(Key32::from_bytes(&read_key)),     // decrypts everything
    KeySource::Raw(Key32::from_bytes(&search_key)),   // makes fingerprints; decrypts nothing
);
DatabaseConfig::new("vault", "vault").encryption(keys).register::<Note>("notes");
```

- **Ciphers:** AES-256-GCM-SIV (the default) and XChaCha20-Poly1305 (`.with_suite(..)`), both safe for any number of writes. The choice is not stored: open with the one you created with.
- **Keys:** raw 32-byte keys, or `KeySource::Password` stretched with Argon2id (64 MiB, 3 passes by default; settings below a safe floor are refused). A new database needs both keys; an existing one opens with the read key.
- **Errors:** a missing or not-allowed setting is `ClError::Validation` before any file is touched. A wrong key, a wrong cipher, a plain file opened with a key, or a damaged header are all the single `ClError::EncryptedOpenFailed`. A changed block in an open database is `ClError::DataTampered`.
- **Checking every block:** `verify_encrypted_files(dir, dir_name, db_name, &EncryptionHandle::new(keys))` checks the closed files; `encryption_verify_on_open(true)` does it at each open. A block put back from an older copy of the same file is only found this way.
- **Creation is all or nothing:** a new encrypted database is made under a temporary name and given its real name only when complete.
- **Speed:** the pages of a commit are sealed on up to four threads (`encryption_tuning`). Every encrypted commit is two-phase.
- **What it does not hide:** the number and sizes of files, and the folder and database names you chose. An open database is as safe as the keys in its memory.

## Protected fields

A field can be protected on its own while the rest of the row stays an ordinary row, readable and usable in any query:

```rust
use clove1db::{CloveFields, field_crypto::{Hashed, Sealed, SearchPrint}};

#[derive(Clone, Default, Serialize, Deserialize, CloveFields)]
struct Account {
    id: String,
    name: String,                                              // ordinary
    #[clove(encrypt, id = 1, print = "full", normalize = "trim")]
    phone: Sealed<String>,                                     // sealed, searchable by equality
    #[clove(hash = "argon2id", id = 2)]
    password: Hashed,                                          // checked, never read back
    #[clove(search_print, id = 3, normalize = "trim,lowercase")]
    email: SearchPrint,                                        // matched, never read back
    #[clove(encrypt, id = 4)]
    note: Sealed<String>,                                      // sealed
}

DatabaseConfig::new("people", "people")
    .field_encryption(keys)               // or .encryption(keys) for the whole database too
    .register_sealed::<Account>("accounts");
```

| Attribute | Stored | Used with |
|---|---|---|
| `encrypt` | the value sealed (AES-256-GCM-SIV or XChaCha20-Poly1305), bound to its table, field and row | `value.open(&domain.read_grant()?)` |
| `encrypt, print = "full"` | the sealed value and a keyed fingerprint of the normalised text | `Account::phone.print_eq(value, &domain.search_grant()?)`, `print_in`, a unique constraint on `print_field()` |
| `encrypt, print = "parts"` | as `full`, plus fingerprints of every run of `window` characters (3 by default) kept to `grade` bits | `part_candidates` (candidates) and `part_search(..).run(..)` (confirmed matches) |
| `hash = "argon2id"` or `"scrypt"` | a salted slow hash | `password.verify(secret, &domain.verifier()?)` |
| `search_print` | a keyed fingerprint only | `email.matches(candidate, &verifier)` |

- **Every field has a stable number** (`id = N`): renaming it in code changes nothing on disk. A value moved to another row or field is `ClError::DataTampered`.
- **Reading a row opens nothing.** A grant opens a value, and every opening sends a `FieldRead` event with names and the row key, never the value. Your application decides who gets a grant.
- **A field that cannot be searched does not compile in a query.** A sealed field without `print` has only `scan_sealed` (the slow, explicit scan); a hash field has no query methods at all.
- **What a program can do depends on its keys.** Both keys: everything. The read key alone: everything but making fingerprints. The search key alone (with `field_encryption`): read rows and match fingerprints; no writes, no opening.
- **The keys file `{db}.keys`** (under 1 KB) holds the data key sealed under your keys, so protected values can still be opened if the main file is lost. `field_keys_file(path)` keeps the data key in that file **only**: a copy of the main file alone then opens nothing — and if that file is lost, the protected values are lost for good.
- **Attachments of such a table** (`register_sealed_blob`) are sealed in 64 KiB chunks, with folder and file names that are keyed fingerprints.
- **A protected table can be added to a database that already exists.** "New" is judged for each table: one the file does not have, or has with no rows, no stored description of protected fields and no saved versions in its history. The keys are made when the file holds no protected table yet. A table that has rows, or old versions in its history, cannot be protected by opening it: that is a migration (`ChangeFields`). A program that holds only the search key cannot create a protected table.
- **Needs the `encryption` feature.** Without it, `#[clove(encrypt)]`, `hash` and `search_print` do not compile, with a message naming the feature, and a database that has a protected table is refused at open before anything is written.

## Changing how a database is protected

A database is protected when it is made. To change that later, close it and rewrite it:

- **`ChangeProtection`** changes how the whole database is protected: plain to encrypted, encrypted to plain, one key or cipher to another, or between whole-database encryption and keys for protected fields only.
- **`ChangeFields`** changes how the fields of a table are protected: seal a plain field, open a sealed one, add or remove fingerprints, turn a field into a hash.

```rust
use clove1db::migration::{ChangeFields, ChangeProtection};

let plan = ChangeProtection::new(&dir, "records", "store")
    .from_plain()
    .to_whole_database(keys.clone())
    .dry_run()?;                       // what it would do, and the disk it needs; writes nothing
ChangeProtection::new(&dir, "records", "store").from_plain().to_whole_database(keys).execute()?;

ChangeFields::new(&dir, "records", "store")
    .field_keys(field_keys)
    .table::<SealedPerson>("people")   // the entity as it should be stored now
    .execute()?;
```

- **Safe at any moment.** The new files are written beside the old ones, read back and compared row by row and file by file, and put in place by one decision a crash cannot split. Before it, the old files are the database exactly as they were; after it, the new ones. The next open settles whatever a stop left.
- **Refused before anything is written:** a wrong key, a database another program has open, a table with protected fields that is not named (`.protected_table::<E>(name)`), not enough room (`available_bytes`).
- **One-way changes** (to a hash, or to a fingerprint that does not keep the value) need `.confirm_one_way()`.
- **Keys of hashes and fingerprint-only fields are carried over** when the data key changes, since their source values are not stored: old passwords still verify and searches still find their rows.
- `wipe_originals(true)` overwrites the old files with random bytes before removing them.
- **Room:** `dry_run` gives a safe upper bound of the disk the change needs; the new files exist beside the old ones until the end.

## Schema migrations and older files

Each table has its own chain of versions. A change of a struct is a migration you write once:

```rust
use clove1db::migration::{MigrateOutcome, MigrateTo, migrate_value, skip_record};

impl MigrateTo<ProductV2> for ProductV1 {
    fn migrate_json(value: serde_json::Value) -> clove1db::units::Result<MigrateOutcome<serde_json::Value>> {
        let v1: ProductV1 = serde_json::from_value(value)?;
        if v1.name.is_empty() {
            return skip_record("no name");
        }
        migrate_value(ProductV2 { id: v1.id, name: v1.name, sku: String::new(), price_cents: 0 })
    }
}

storage.migrate::<ProductV1, ProductV2>().from_db("catalog", "products").execute()?;          // in place
storage.migrate::<ProductV1, ProductV2>()
    .from_db("warehouse", "products")
    .to(MigrationTo::new("shop").table("products").delete_source(true))                        // to another database
    .execute()?;

Storage::builder(config).migration_step::<ProductV1, ProductV2>();   // so history reads in the new shape
```

**Older files are upgraded by `build()`.** A `.cldb` made by an earlier clove1db is recognised, given the metadata it lacks, and its history converted to the current format on a checked copy, before it is served. `inspect_cldb(path)` tells what a file is (`Legacy042`, `Clove049`, `Authenticated`, `ExternalRedb`, ...) without opening a `Storage`, and never changes it.

## Importing from a foreign redb file

**Row by row, into your entity:**

```rust
use clove1db::migration::{ExternalFrom, KeyDecoder, MigrationTo, ValueDecoder};

storage.migrate::<VendorRow, ProductV2>()
    .from_external(ExternalFrom {
        path: "./vendor.redb".into(),
        table: "vendor_catalog".into(),
        key_decoder: KeyDecoder::Utf8String,       // or U64AsString
        value_decoder: ValueDecoder::JsonValidate, // or JsonString
    })
    .to(MigrationTo::new("shop").table("products"))
    .execute()?;
```

`list_external_tables(path)` and `read_external_table(path, &spec)` look at a foreign file first.

**A large table, as it is (`stream_external`).** Import JSON rows or attachments from an external redb file in bounded batches. The source is read in one transaction, one row at a time.

```rust
use clove1db::migration::stream_external::{Options, Target, inventory, scan, stream, verify};

let options = Options::json();
let tables = inventory(&copy, &options)?;
let found = scan(&copy, "orders", &options)?;
let target = Target { storage: &storage, db: "shop", table: "orders" };
stream(&copy, "orders", target, &options, Some(&mut |r| println!("{} rows", r.sizes.rows)))?;
assert!(verify(&copy, "orders", target, &options)?.is_equal());
```

- **JSON is the default:** `Options::json()` imports JSON unchanged into an ordinary table registered with `JsonRow`. Tables with protected fields, including protected attachment metadata, are refused before opening the source; use typed entity writes instead. Whole-database encryption is supported for ordinary target tables.
- **Attachments:** `Options::attachments(prefix)` imports files into `register_blob::<AttachmentMeta>`. This metadata is an intermediate shape; convert it to your entity afterwards. `FilePrefix { marker, len, group_at }` describes an optional fixed prefix; `group_at` reads four little-endian bytes into the metadata group. `FilePrefix::default()` has length 0 and matches no value: use it to complete `FilePrefix { marker, len, ..FilePrefix::default() }`.
- **Read-only source:** `inventory`, `scan`, `stream` and `verify` never repair it. Explicit `repair_copy(&copy, &options)` opens the supplied file for writing: provide a disposable copy, never the original.
- **Memory gate:** sources of 1 GiB or more require `free_memory`. The expected peak plus `reserve_memory` must fit before streaming starts.
- **Reports:** `ScanReport` contains sizes and signatures, `StreamReport` contains sizes, batches and `Duration` timings, and `VerifyReport` compares counts and content fingerprints. Shared measurements are under `sizes`. Failures are distinguishable through `ClError::StreamExternal(StreamExternalError)`; protected targets return `ClError::Validation`.
- **Limits:** numeric keys become text (`"10"` sorts before `"9"`). Matching destination keys are overwritten; other rows remain. Verification counts all target rows, so extra rows make `is_equal()` false. A limit or error leaves already committed batches. Signature recognition is limited to PNG, JPEG, GIF, WebP, PDF and ZIP; it is not file validation.

## Events

`StorageConfig::default().event_sink(|event| ...)` receives `LibraryEvent`s: slow queries (over `slow_query_threshold`, 50 ms by default), non-unique `one()` calls, expired followers, index rebuilds, encryption and migration stages, and every opening of a protected value. Events carry names, counts and row keys, never a value, a key or a searched text. Callbacks run synchronously after the operation: keep them short. `LibraryEvent` is `#[non_exhaustive]`.

## What it costs

Measured in release builds on one Windows machine with synthetic data. They describe that machine, not a guarantee.

**Encrypting the whole database**, against the same plain database (20 commits of 500 rows of about 1 KB):

| | AES-256-GCM-SIV (default) | XChaCha20-Poly1305 |
|---|---|---|
| writes, parallel sealing (default) | +5 % to +7 % | +21 % to +23 % |
| reads from the cache | +3 % to +8 % | +3 % to +8 % |
| reads cold from disk, whole table | no measurable cost | no measurable cost |
| building a text index | about +5 % | about +5 % |

XChaCha20-Poly1305 is meant for processors without AES acceleration, where it is typically the faster of the two (not measured here).

**Protected fields**, per field, compared with the same entity unprotected:

| Field | write | read and open |
|---|---|---|
| 16 bytes, AES-256-GCM-SIV | 1.7 µs | 1.2 µs |
| 16 bytes, XChaCha20-Poly1305 | 2.8 µs | 2.0 µs |
| 4 KiB, AES-256-GCM-SIV | 19.7 µs | 13.2 µs |

Searching by a whole-value fingerprint costs 1.1 to 2 times a plain indexed equality. Searching by a piece of a value costs 1.1 to 4.5 times a plain `contains`, depending on the piece's length and the grade. An Argon2id hash takes about 0.1 s and 64 MiB while it runs.

**Changing the protection** takes about 0.02 to 0.03 s per MB of rows (0.5 s for 20 MB, about 9 to 12 s for 500 MB), with memory under about 190 MiB. Turning 100,000 values into hashes takes hours: `dry_run` times one hash and says how long the whole change would take.

**History format:** 1,000 history records take about 4.2 MB, against 18.7 MB in the format used before 0.0.126.

**Under load:** 8 writers and 16 readers on one database for 30 minutes completed 286,352 checked queries (p95 0.4 ms) with no mismatch and no error. A drill of 200 forced process kills found every acknowledged write after each reopen.

## Limits

- **Power loss is not tested.** Killed processes are; whether every write a disk acknowledges survives a power cut depends on the disk and the system, and is not verified here.
- One process opens a database at a time. A second gets `ClError::DatabaseInUse`.
- Changing the protection needs the database closed, and disk room for the old and the new files at once.
- A protected field cannot be filtered, ordered, grouped, aggregated or made unique, except by its whole-value fingerprint. A search by a piece returns candidates until it is confirmed with the read key.
- A fingerprint is not tied to the sealed value beside it: someone who can change the files can swap fingerprints between rows. Equal values have equal fingerprints.
- The length of a protected value is visible to within a few bytes.
- Migration steps over an entity with protected fields are not supported yet; change its fields with `ChangeFields`.
- One attachment per row.
- The `.inx` file can be up to about twice its content, since redb grows files by doubling. A `contains` index costs about 5 ms per 20 KB row to build.
- An encrypted file whose header is not in the form of redb 4.4 cannot grow: the write fails with a clear I/O error and changes nothing.

## Examples

Seven runnable examples are in the repository under [`examples/`](https://github.com/clove7/clove1db/tree/main/examples) (they are not in the crates.io package). Each writes to a new folder under the system's temporary folder, removes it at the end, prints what it checks, and fails if a check fails.

```bash
git clone https://github.com/clove7/clove1db
cd clove1db/examples/01_getting_started && cargo run
```

| Example | What it shows |
|---|---|
| `01_getting_started` | Entities and DTOs, create, read, update, delete, two databases in one `Storage` |
| `02_queries_and_indexes` | Filters, pages, `one()`, aggregates, text and fuzzy search, a unique constraint, automatic indexes, `explain()`, a deleted `.inx` rebuilt |
| `03_backup_and_batches` | History, reading and restoring a version, bulk changes, atomic and chunked batches |
| `04_change_log` | A follower: snapshot, changes, acknowledgement, restart, table reset, expiry |
| `05_files_and_memory` | Attachments read as streams, the cache budget, reading a large table |
| `06_encryption` | The whole database with both ciphers, a wrong key, a changed byte, and protected fields |
| `07_migration_and_recovery` | A schema change, an old file upgraded, a foreign redb file imported and copied, changing the protection, a writer killed mid-work |

Run 02, 05, 06 and 07 with `cargo run --release`.

## Upgrading

### From 0.0.x to 0.1.0

The data format of existing plain databases is unchanged, and they open as before. Code may need these changes:

- **Features:** `#[derive(CloveFields)]` needs `features = ["derive"]`, and encryption needs `features = ["encryption"]`. Without features the core is the same, and field constants are written by hand.
- **`ClError`** has new variants (`EncryptedOpenFailed`, `DataTampered`, `DatabaseInUse`, `OutOfMemory`, ...). A `match` without a wildcard arm must handle them.
- **Attachments are read through `BlobReader`** (`Read + Seek`, with `len()`) instead of `std::fs::File`.
- **`RedbOptions`** is no longer `Copy` or `PartialEq`, and has new fields: build it with `..Default::default()`.
- **`BackupManager::new`** takes `&RedbOptions`.
- **`migration::DbMigrationRootIndex::tables`** is a `BTreeMap`.
- **Inspecting a file never repairs it:** a file that needs repair gives `ClError::Validation` asking to open it normally first.
- **Quarantined side files keep their whole name:** `index.json.corrupt.{time}`.
- **A failed `build()` removes the database it was creating**, and only that.
- **The examples** were rewritten: seven instead of nineteen.

New in 0.1.0: typed queries, automatic indexes, the change log, whole-database encryption, protected fields and searching them, `ChangeProtection` and `ChangeFields`, `stream_external`, events, `DatabaseInUse`, out-of-memory errors instead of aborts on large allocations, `prefetch`, the `derive` and `encryption` features, `create_missing_tables`, `compact_database`, `prepare` with `commit_atomic`. Every change is listed in [CHANGELOG.md](CHANGELOG.md).

### From 0.0.119 or earlier

The first `build()` converts each `.cldb.bak` history to the current format, on a checked copy that replaces the original only when every record compares equal. Older releases cannot read the converted history. The `.cldb` data format is unchanged. Undated records receive the conversion time, flagged `date_from_migration: true`.

## Contributing

- Bug reports and feature requests: [GitHub issues](https://github.com/clove7/clove1db/issues).
- Code: fork, branch, and open a pull request.
- Examples and documentation are especially welcome.

## License

MIT — see [LICENSE-MIT](LICENSE-MIT).
