# clove1db

An embedded database framework for Rust — built on [redb](https://github.com/cberner/redb) with layered cache, versioned backup, per-table schema migrations, and domain-driven storage.

> **Work in progress.** The API and internals are still evolving. We welcome contributions, issue reports, and real-world feedback — see [Contributing](#contributing) below.

## Features

- 🗄️ **Embedded Storage**: Built on [redb](https://github.com/cberner/redb) — no external server needed
- ⚡ **Layered Cache**: In-memory cache via [moka](https://github.com/moka-rs/moka) with TTL and idle expiry
- 🔁 **Versioned Backup**: Every write/delete is recorded — restore any entity to any previous version
- 📦 **Bulk Operations**: Update and restore multiple entities at once with a single `bulk_id`
- 🧩 **Domain-Driven**: Clean separation via `Entity`, `InputDto`, `OutputDto`, `Repository`, `Domain`
- 🗂️ **Multi-Database**: Multiple isolated `.cldb` files in a single `Storage` instance
- 🔄 **Migrations**: In-place evolve, cross-DB transfer, external redb import, per-table migration chains
- 🏷️ **Metadata & Auto-Upgrade**: `_clove_meta` inside `.cldb`, automatic upgrade from legacy eras on `build()`
- 🔍 **Inspect**: Classify `.cldb` files (`Legacy042`, `Clove049`, `Authenticated`, `ExternalRedb`, …) without opening `Storage`

## Install

```toml
[dependencies]
clove1db = "0.0.70"
```

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
                .cache(10_000, 300, 60)
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

> **Breaking in 0.0.63:** `migration_runner()`, `.with_decoder()`, `field_map`, and string-keyed `decoder` manifests are removed. Re-seed or re-run migrations so manifests include `from_layout_hash` / `to_layout_hash`. Register steps at build via `.migration_step::<From, To>()` when you need backup history replay without calling `migrate()` in the same session.

```rust
use std::path::PathBuf;
use clove1db::migration::{
    ExternalFrom, KeyDecoder, MigrateTo, MigrationTo, TargetConflictPolicy, ValueDecoder,
};
use serde_json::Value;

// 1) Implement the transform once
impl MigrateTo<ProductV2> for ProductV1 {
    fn migrate_json(value: Value) -> clove1db::units::Result<Value> {
        let v1: ProductV1 = serde_json::from_value(value)?;
        Ok(serde_json::to_value(ProductV2 {
            id: v1.id,
            name: v1.name,
            sku: "SKU-default".into(),
            price_cents: 0,
        })?)
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
        DatabaseConfig::new("catalog_db", "catalog")
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

## Contributing

This project is under active development:

- **Bug reports & feature requests** — [GitHub issues](https://github.com/clove7/clove1db/issues)
- **Code contributions** — fork, branch, open a pull request
- **Examples & docs** — scenarios in `examples/` are especially welcome
- **Feedback** — tell us how you use (or want to use) clove1db

Before large changes, open an issue to discuss the approach.

## License

Licensed under the MIT license — see [LICENSE-MIT](LICENSE-MIT).
