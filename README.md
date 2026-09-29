# clove1db

An embedded database framework for Rust, built on [redb](https://github.com/cberner/redb).

redb gives you an ordered map of bytes to bytes. clove1db is the layer most applications end up writing on top of that: typed entities with DTOs at the edges, a cache with a memory budget you can state, a history of every write so any row can be restored to any earlier version, schema migrations per table, and durability settings that survive a crash mid-commit.

Everything lives in `.cldb` files next to your binary. No server, no daemon, no connection string.

```toml
[dependencies]
clove1db = "0.0.119"
```

> **Work in progress.** The API and internals are still evolving, and versions before 1.0 may break. Contributions, issue reports and real-world feedback are all welcome — see [Contributing](#contributing).

## Features

- 🗄️ **Embedded Storage**: Built on [redb](https://github.com/cberner/redb) — no external server needed
- ⚡ **Budgeted Cache**: In-memory cache via [moka](https://github.com/moka-rs/moka), sized in **bytes** with TTL and idle expiry — plus uncached reads for bulk scans
- 🔁 **Versioned Backup**: Every write/delete is recorded — restore any entity to any previous version
- 📦 **Bulk Operations**: Update and restore multiple entities at once with a single `bulk_id`
- 🧩 **Domain-Driven**: Clean separation via `Entity`, `InputDto`, `OutputDto`, `Repository`, `Domain`
- 🗂️ **Multi-Database**: Multiple isolated `.cldb` files in a single `Storage` instance
- 🔄 **Migrations**: In-place evolve, cross-DB transfer, external redb import, per-table migration chains
- 🏷️ **Metadata & Auto-Upgrade**: `_clove_meta` inside `.cldb`, automatic upgrade from legacy eras on `build()`
- 🔍 **Inspect**: Classify `.cldb` files (`Legacy042`, `Clove049`, `Authenticated`, `ExternalRedb`, …) without opening `Storage`
- 🛡️ **Durability**: Default `DurabilityMode::Strict` — atomic sidecar writes (tmp→rename), `fsync` in Strict, `redb::Durability::Immediate`, corrupt migration-index recovery, chunked commit batches
- 🔌 **Open, close & recover**: each file opened once per `build()`, an explicit `Storage::close()`, a cap on redb's page cache, quick repair after a kill or crash, and a per-file open report

## Upgrading to 0.0.119

**Nothing to change in your code.** Every signature is the same; what is new
is additive.

- **`Repository::list` reads one row at a time.** It copied every stored value
  into one `Vec<Vec<u8>>` and parsed them only once the whole table was in
  memory, so a large table was held twice while it was read, and the process
  kept much of that heap afterwards. Same signature, same result. A row that
  does not parse is now an error; it was an `unwrap()` panic.
- **`Repository::list_map(map)`** — every row, passed through `map` as it is
  read. A field `map` drops never outlives its row, and the `Vec` is sized from
  the table, not grown by doubling.
- **`Repository::get_uncached_as::<U>(id)`** — one row read as a lighter type
  `U` whose fields are a subset of the stored row's: serde skips the rest
  without building it, and the value is parsed without being copied first.
- **`DatabaseManager::count_keys`** asks redb for the count instead of copying
  the whole table to take its length.
- **`Storage::open_report()`** — how every file was opened by `build()`: per
  `.cldb` (and its `.cldb.bak`), the size, how long redb took, and whether it
  had to repair the file. Always recorded, never printed; read it if you want
  it. See [Open, close & recover](#open-close--recover).

`examples/13_large_table_open_and_read` measures all of it on a synthetic
269 MB table of 100,000 articles, 70% of them with a large `body`. Windows,
release, one process per line:

| read | kept per row | redb cache | +live | +private | retained | peak |
|---|---|---|---|---|---|---|
| copy, then parse (`list` in 0.0.112) | all but `body` | 64 MiB | 153 MiB | 365 MiB | 213 MiB | 502 MiB |
| `list_map` | all but `body` | 64 MiB | 153 MiB | 190 MiB | 39 MiB | 191 MiB |
| `list_map` | card fields only | 8 MiB | 58 MiB | 71 MiB | 14 MiB | 72 MiB |

20,000 rows by id: `get_uncached` → full row, 242 ms and 169 MiB allocated;
`get_uncached_as` → card, 151 ms and 97 MiB.

| the previous run | next open | repaired |
|---|---|---|
| `Storage::close()` | 0.8 ms | no |
| killed, `quick_repair(false)` | 358 ms | yes |
| killed, `quick_repair(true)` | 1.3 ms | no |

No data migration; the on-disk format is unchanged.

## Durability

By default clove1db runs in **Strict** mode:

- Sidecar files (`*.migration/**/index.json`, layouts, manifests, blobs) are always written via atomic tmp→rename (both Strict and Fast), so a crash never leaves a final path half-filled with NULs.
- **Strict** also `sync_all`s sidecar files and sets `redb::Durability::Immediate` on commits (independent of cache).
- **Fast** skips fsync / Immediate for throughput; still atomic.
- Corrupt / zeroed migration indexes are quarantined and rebuilt on open (not a fatal `Serialization` panic).
- Large `commit_batch` calls are split by `max_commit_batch_entries` (default 512).

```rust
use clove1db::{storage::{DatabaseConfig, Storage, StorageConfig}, DurabilityMode};

// Default: Strict for every database
Storage::builder(StorageConfig::default())
    .add_database(DatabaseConfig::new("app_db", "app").register::<User>("users"))
    .build()?;

// Whole storage on Fast
Storage::builder(StorageConfig::default().durability(DurabilityMode::Fast))
    ...

// One database Fast, others Strict
Storage::builder(StorageConfig::default())
    .add_database(DatabaseConfig::new("hot", "hot").durability(DurabilityMode::Fast).register::<User>("users"))
    .add_database(DatabaseConfig::new("cold", "cold").register::<User>("users"))
    .build()?;
```

**Guarantees:** crash-consistent sidecar files; last successfully committed redb transaction survives Strict flush; open succeeds after NUL index corruption.  
**Not guaranteed:** uncommitted in-flight work after sudden power loss; absolute immunity without UPS/hardware.

Extreme crash / pressure scenarios: `examples/10_crash_durability` (`cargo run --manifest-path examples/10_crash_durability/Cargo.toml`).

## Open, close & recover

`Durability` above is about a commit surviving. This is about the *file*: what
opening it costs, what an unclean exit costs the next open, and what redb keeps
in memory in between. `examples/12_open_close_repair` measures all of it.

- **`storage.close()`** — call it once, on the way out. It waits for operations
  already running, then closes every file cleanly, so the next open needs no
  repair. Any clone used afterwards gets `ClError::Closed`. It matters most for
  a `Storage` kept in a `static`, which is never dropped: without `close()`,
  even a clean shutdown leaves every file to be repaired.
- **`.quick_repair(true)`** — for what `close()` cannot cover: a kill, a crash,
  a power cut. Every commit saves redb's allocator state, so the next open
  loads it instead of walking the whole file. Costs each commit more; worth it
  for large files on machines that get killed.
- **`.redb_cache_bytes(n)`** — redb's own page cache, per file, underneath
  `cache_bytes` (which holds decoded rows). The default is 1 GiB per file, and
  pages a scan reads stay resident up to that.

```rust
DatabaseConfig::new("logs_db", "logs")
    .redb_cache_bytes(64 * 1024 * 1024)   // 64 MiB of redb pages per file
    .quick_repair(true)
    .register::<Event>("events");

// on shutdown, after the last request
storage.close();
```

`build()` opens each file once — inspect, upgrade and serve share one handle.

**`storage.open_report()`** says how each of those opens went — one line per
`.cldb`, then its `.cldb.bak`, sorted by database:

```rust
for r in storage.open_report() {
    println!(
        "{} {} bytes={} ms={:.1} repaired={}",
        r.database,
        r.path.display(),
        r.bytes,
        r.open_time.as_secs_f64() * 1000.0,
        r.repaired,
    );
}
```

`repaired` means redb walked the whole file to rebuild its allocator state: the
last process to write it neither closed it nor had `quick_repair` on. A brand
new file is never reported as repaired. The report is recorded on every
`build()` at the cost of a clock read and a file-size lookup per file; nothing
reads or prints it unless you do. A `.cldb.bak` that has not yet been marked
upgraded is opened once more before it is served, for a one-time format check;
that extra open is not in the report.

## Quick Start

Register tables with `.register::<YourEntity>("table_name")` — no global `schema_name` required.

```rust
use serde::{Deserialize, Serialize};
use clove1db::{
    dto::{InputDto, OutputDto},
    entity::Entity,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::Result,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct User {
    id: String,
    name: String,
}

impl Entity for User {
    fn entity_id(&self) -> &str { &self.id }
}

#[derive(Deserialize)]
struct CreateUserDto { name: String }

impl InputDto<User> for CreateUserDto {
    fn into_entity(self) -> Result<User> {
        let id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .to_string();
        Ok(User { id, name: self.name })
    }
}

#[derive(Serialize)]
struct UserResponse { id: String, name: String }

impl OutputDto<User> for UserResponse {
    fn from_entity(e: User) -> Self {
        Self { id: e.id, name: e.name }
    }
}

fn main() -> Result<()> {
    let storage = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("users_db", "users")
                .backup_enabled(true)
                .cache_bytes(32 * 1024 * 1024, 300, 60)
                .register::<User>("users"),
        )
        .build()?;

    let domain = storage.domain::<User>();
    let user = domain.create::<CreateUserDto, UserResponse>(CreateUserDto {
        name: "Alice".into(),
    })?;
    let _found = domain.get::<UserResponse>(&user.id)?;
    domain.delete(&user.id)?;
    Ok(())
}
```

### Cache budget

`cache_bytes(max_bytes, ttl_secs, idle_secs)` sizes the in-memory cache in
**bytes**, not entries.

An entry count cannot bound memory: the cached value is whatever you stored, so
`10_000` entries is ten thousand times a number the cache does not know: rows
of 10 KB each make a "10,000 entry" cache 100 MiB. `examples/11_cache_memory_budget` measures this —
the same 2,000 entries come to 2 MiB or 125 MiB depending only on the row.

Three things are worth knowing:

- **`get_uncached()`** reads a key without reading or writing the cache. Use it
  when walking many keys once — a range scan, a report, an export — so the walk
  does not spend the whole budget on rows it will never read again.
- **Expiry is not reclamation.** `ttl_secs` and `idle_secs` decide when an entry
  *expires*; `moka` frees it during maintenance, and maintenance runs when the
  cache is used. A database nobody reads keeps expired entries resident, hours
  past their TTL. Call `storage.run_cache_maintenance()` from an
  idle tick when "expired" should mean "gone".
- **`cache_stats()`** returns `(bytes, entries)`, per database or for the whole
  `Storage`, so the budget can be checked instead of assumed.

```rust
DatabaseConfig::new("logs_db", "logs")
    .cache_bytes(8 * 1024 * 1024, 300, 60)   // 8 MiB, 5 min TTL
    .register::<Event>("events");

// walking a range: do not fill the cache with rows read once
let row: Event = storage.domain::<Event>().get_uncached(&id)?;

storage.run_cache_maintenance();
let (bytes, entries) = storage.cache_stats();
```

## Schema & Migrations

Each registered table has its own version chain:

| Concept | Meaning |
|---------|---------|
| `schema_id` | Table name (e.g. `"products"`) |
| `schema_version` | `u32` per table (`1`, `2`, `3`, …) |
| Entity JSON | Fields only in primary `.cldb` — version lives in `_clove_meta` and migration files |

On-disk migration layout:

```
{db}.migration/
  index.json
  tables/
    products/
      index.json
      layouts/v1.json
      mig-*/manifest.json
      mig-*/refs/
```

### Migration kinds (resolved automatically)

| Kind | When | `delete_source` |
|------|------|-----------------|
| **InPlaceEvolve** | `.from_db(d, t)` only, or same `db` + `table` | Ignored |
| **DataTransfer** | Different `db` and/or `table` | Honoured |
| **ExternalImport** | `.from_external(...)` | Ignored |

Typed migrations use `MigrateTo` + `storage.migrate::<From, To>()`. Migration steps are keyed automatically by `layout_hash` pairs stored in each manifest (`from_layout_hash` / `to_layout_hash`).

Each `migrate_json` / `migrate_blob` call returns `Result<MigrateOutcome<T>>`:

| Outcome | Meaning |
|---------|---------|
| `MigrateOutcome::Migrate(value)` | Write the transformed row |
| `MigrateOutcome::Skip(reason)` | Omit this source row and continue (recorded in `MigrationReport::source_skipped`) |
| `Err(...)` | Hard failure — stops the migration run |

`TargetConflictPolicy::Skip` is separate: it skips rows whose **key already exists in the target table**, not rows you reject inside the transform.

> **Breaking in 0.0.84:** `migrate_json` / `migrate_blob` now return `Result<MigrateOutcome<T>>` instead of `Result<T>`. Wrap successful values with `MigrateOutcome::Migrate(...)` or use the `migrate_value` / `skip_record` helpers.

```rust
use std::path::PathBuf;
use clove1db::migration::{
    migrate_value, skip_record, ExternalFrom, KeyDecoder, MigrateOutcome, MigrateTo,
    MigrationTo, TargetConflictPolicy, ValueDecoder,
};
use serde_json::Value;

// 1) Implement the transform once
impl MigrateTo<ProductV2> for ProductV1 {
    fn migrate_json(value: Value) -> clove1db::units::Result<MigrateOutcome<Value>> {
        let v1: ProductV1 = serde_json::from_value(value)?;
        if v1.name.is_empty() {
            return skip_record("empty name");
        }
        migrate_value(ProductV2 {
            id: v1.id,
            name: v1.name,
            sku: "SKU-default".into(),
            price_cents: 0,
        })
    }
}

// 2) In-place schema evolve (same db + table)
storage.migrate::<ProductV1, ProductV2>()
    .from_db("catalog", "products")
    .execute()?;

// 3) Cross-database move
storage.migrate::<ProductV1, ProductV2>()
    .from_db("warehouse", "products")
    .to(MigrationTo::new("shop").table("products").delete_source(true))
    .on_target_conflict(TargetConflictPolicy::Fail)
    .execute()?;

// 4) External redb → clove1db (VendorRow matches vendor JSON)
storage.migrate::<VendorRow, ProductV2>()
    .from_external(ExternalFrom {
        path: PathBuf::from("./vendor.redb"),
        table: "vendor_catalog".into(),
        key_decoder: KeyDecoder::Utf8String,
        value_decoder: ValueDecoder::JsonValidate,
    })
    .to(MigrationTo::new("shop").table("products"))
    .execute()?;

// Optional: warm registry at build for backup history replay without running migrate
Storage::builder(config)
    .migration_step::<ProductV1, ProductV2>()
    .add_database(/* ... */)
    .build()?;
```

### External redb key/value layouts

| `KeyDecoder` | `ValueDecoder` | Typical source |
|--------------|----------------|----------------|
| `Utf8String` | `JsonValidate` | UTF-8 keys, JSON bytes (`&[u8]`) |
| `U64AsString` | `JsonValidate` | `u64` keys, JSON bytes |
| `U64AsString` | `JsonString` | `u64` keys, JSON stored as redb `String` |

Use `list_external_tables(path)` and `read_external_table(path, &spec)` to probe a foreign `.redb` before importing.

## Backup & Versioning

```rust
use redb::TableDefinition;
use clove1db::{backup::view::HistoryDisplayMode, units::Result};

fn demo(storage: &clove1db::storage::Storage, id: &str) -> Result<()> {
    let domain = storage.domain::<User>();
    let bm = storage.db_manager("users_db").backup_manager.as_ref().unwrap();

    let history = bm.history(TableDefinition::new("users"), id)?;
    let _at_v2 = bm.view_by_version(TableDefinition::new("users"), id, 2)?;
    domain.restore_by_version(id, 1)?;

    // Domain API with normalized history (applies migration chain)
    let _record = domain.get_by_version_with_mode(id, 1, HistoryDisplayMode::Normalized)?;
    Ok(())
}
```

## Bulk Operations

```rust
let domain = storage.domain::<User>();
let payload = vec![
    ("id-1".into(), CreateUserDto { name: "Alice".into() }),
    ("id-2".into(), CreateUserDto { name: "Bob".into() }),
];
let (_updated, bulk_id) = domain.update_bulk::<CreateUserDto, UserResponse>(payload)?;
domain.restore_bulk(&bulk_id)?;
```

## Multi-Database

```rust
use std::path::PathBuf;
use clove1db::storage::{DatabaseConfig, Storage, StorageConfig};

let storage = Storage::builder(StorageConfig::default())
    .add_database(
        DatabaseConfig::new("users_db", "users")
            .register::<User>("users"),
    )
    .add_database(
        DatabaseConfig::new("inventory_db", "catalog")
            .dir_path(PathBuf::from("./data"))
            .backup_enabled(true)
            .register::<Product>("products"),
    )
    .build()?;
```

## Metadata, Inspect & Auto-Upgrade

On `Storage::build()`, clove1db automatically:

1. Classifies the `.cldb` era (`Legacy042`, `Clove049`, or current)
2. Writes or updates `_clove_meta` (per-table `schema_id` / `schema_version`)
3. Ensures `{db}.migration/tables/{table}/` matches registered layouts
4. Upgrades legacy v0.0.49 single-root migration indexes to per-table chains
5. Normalizes `.cldb.bak` to canonical `BackupRecord` JSON (`.pre-upgrade` copy removed on success)

Inspect without opening `Storage`:

```rust
use clove1db::{inspect_cldb, FileKind};

let report = inspect_cldb("./data/shop/shop.cldb")?;
match report.kind {
    FileKind::New => { /* empty / missing */ }
    FileKind::Legacy042 => { /* pre-metadata clove */ }
    FileKind::Clove049 => { /* old migration index */ }
    FileKind::Authenticated => { /* _clove_meta present */ }
    FileKind::ExternalRedb => { /* raw redb, not clove */ }
    FileKind::Invalid => { /* directory or unreadable */ }
    _ => {}
}
```

## Examples & local demos

Runnable examples live in the **Git repository** under `examples/` (not included in the crates.io package). Clone the repo and run from each folder:

```bash
git clone https://github.com/clove7/clove1db
cd clove1db/examples/01_basic_crud && cargo run
```

| Example | Topic |
|---------|-------|
| `01_basic_crud` | Entity, DTO, CRUD |
| `02_multi_database` | Multiple `.cldb` files in one `Storage` |
| `03_backup_history` | Versioned backup, restore, history |
| `04_bulk_operations` | Bulk update / restore |
| `05_domain_dto_patterns` | Input/Output DTO patterns |
| `06_large_files_no_cache` | Large blobs, cache off |
| `07_migration` | In-place evolve, cross-DB move, external import, restore guards |
| `08_inspect_upgrade` | Era fixtures (0.0.42 / 0.0.49 / 0.0.70), upgrade pipeline |
| `09_blob_attachments` | Blob sidecar CRUD, migration scan, external→blob, inline→blob |
| `10_crash_durability` | Strict durability: crash inject, NUL index recovery, RAM pressure |
| `11_cache_memory_budget` | What the cache costs: byte budgets, uncached reads, expiry vs reclamation |
| `12_open_close_repair` | Between runs: redb cache cap, quick repair after a kill, `close()`, one open per build |
| `13_large_table_open_and_read` | A large table: `list_map` vs copy-then-parse, `get_uncached_as`, and `open_report` after a clean close and after a kill |

## Contributing

This project is under active development:

- **Bug reports & feature requests** — [GitHub issues](https://github.com/clove7/clove1db/issues)
- **Code contributions** — fork, branch, open a pull request
- **Examples & docs** — scenarios in `examples/` are especially welcome
- **Feedback** — tell us how you use (or want to use) clove1db

Before large changes, open an issue to discuss the approach.

## License

Licensed under the MIT license — see [LICENSE-MIT](LICENSE-MIT).
