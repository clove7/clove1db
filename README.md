# clove1db

An embedded database framework for Rust — built on [redb](https://github.com/cberner/redb) with layered cache, versioned backup, schema migrations, and domain-driven storage.

> **Work in progress.** The API and internals are still evolving. We welcome contributions, issue reports, and real-world feedback — see [Contributing](#contributing) below.

## Features

- 🗄️ **Embedded Storage**: Built on [redb](https://github.com/cberner/redb) — no external server needed
- ⚡ **Layered Cache**: In-memory cache via [moka](https://github.com/moka-rs/moka) with TTL and idle expiry
- 🔁 **Versioned Backup**: Every write/delete is recorded — restore any entity to any previous version
- 📦 **Bulk Operations**: Update and restore multiple entities at once with a single `bulk_id`
- 🧩 **Domain-Driven**: Clean separation via `Entity`, `InputDto`, `OutputDto`, `Repository`, `Domain`
- 🗂️ **Multi-Database**: Multiple isolated DB files in a single `Storage` instance
- 🔄 **Migrations**: Schema upgrades, cross-database moves, migration chains, and safe history display

## Install

```toml
[dependencies]
clove1db = "0.0.49"

```

## Quick Start

```rust
use serde::{Deserialize, Serialize};
use clove1db::{
    storage::{DatabaseConfig, Storage, StorageConfig},
    entity::Entity,
    dto::{InputDto, OutputDto},
    units::Result,
};

// 1. Define your entity
#[derive(Debug, Clone, Serialize, Deserialize)]
struct User {
    id: String,
    name: String,
}

impl Entity for User {
    fn entity_id(&self) -> &str { &self.id }
}

// (Assuming CreateUserDto implements InputDto and UserResponse implements OutputDto)
#[derive(Deserialize)] struct CreateUserDto { name: String }
#[derive(Serialize)] struct UserResponse { id: String, name: String }

fn main() -> Result<()> {
    // 2. Build storage (Synchronous)
    let storage = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("users_db", "users")
                .cache(10_000, 300, 60)
                .register::<User>("users")
        )
        .build()?;

    // 3. Use domain
    let domain = storage.domain::<User>();
    
    let input = CreateUserDto { name: "Alice".into() };

    // CRUD Operations
    let user  = domain.create::<CreateUserDto, UserResponse>(input)?;
    let found = domain.get::<UserResponse>(&user.id)?;
    let list  = domain.list::<UserResponse>()?;
    
    domain.update::<CreateUserDto, UserResponse>(
        &user.id, 
        CreateUserDto { name: "Alice Updated".into() }
    )?;
    
    domain.delete(&user.id)?;

    Ok(())
}

```

## Backup & Versioning

```rust
use redb::TableDefinition;
use clove1db::units::Result;

fn main() -> Result<()> {
    // ... (Storage setup with backup_enabled(true) assumed) ...
    
    let domain = storage.domain::<User>();
    let id = "some-user-id";

    // View full history
    let bm = storage.db_manager("users_db").backup_manager.as_ref().unwrap();
    let history = bm.history(TableDefinition::new("users"), id)?;

    // View data at a specific version (read-only)
    let data_v2 = bm.view_by_version(TableDefinition::new("users"), id, 2)?;

    // View data at a point in time (read-only)
    let timestamp_ms = chrono::Utc::now().timestamp_millis();
    let data_time = bm.view_at(TableDefinition::new("users"), id, timestamp_ms)?;

    // Restore to a specific version (writes to DB + cache + backup)
    domain.restore_by_version(id, 1)?;

    // Restore to a point in time
    domain.restore_at(id, timestamp_ms)?;

    Ok(())
}

```

## Bulk Operations

```rust
use clove1db::units::Result;

fn main() -> Result<()> {
    // ... (Storage setup assumed) ...
    let domain = storage.domain::<User>();

    // Update multiple entities at once — returns (results, bulk_id)
    let bulk_payload = vec![
        ("id-1".to_string(), CreateUserDto { name: "Alice".into() }),
        ("id-2".to_string(), CreateUserDto { name: "Bob".into()   }),
    ];

    let (updated, bulk_id) = domain.update_bulk::<CreateUserDto, UserResponse>(bulk_payload)?;

    // Restore all entities to their state before the bulk update
    domain.restore_bulk(&bulk_id)?;

    // List all saved bulk snapshots
    let bm = storage.db_manager("users_db").backup_manager.as_ref().unwrap();
    let snapshots = bm.list_bulk("users")?;
    
    for snap in snapshots {
        println!("bulk_id: {} | {} entries | {}", snap.bulk_id, snap.entries.len(), snap.date);
    }

    Ok(())
}

```

## Multi-Database

```rust
use std::path::PathBuf;
use clove1db::{storage::{DatabaseConfig, Storage, StorageConfig}, units::Result};

fn main() -> Result<()> {
    let storage = Storage::builder(StorageConfig::default())
        // DB 1 — default path
        .add_database(
            DatabaseConfig::new("users_db", "users")
                .register::<User>("users")
        )
        // DB 2 — custom path + backup enabled
        .add_database(
            DatabaseConfig::new("catalog_db", "catalog")
                .dir_path(PathBuf::from("./data"))
                .backup_enabled(true)
                .register::<Product>("products") // Assumes Product Entity
                .register::<Order>("orders")     // Assumes Order Entity
        )
        .build()?;

    Ok(())
}

```

## Contributing

This project is under active development and needs help to grow:

- **Bug reports & feature requests** — open a [GitHub issue](https://github.com/clove7/clove1db/issues)
- **Code contributions** — fork, branch, and open a pull request
- **Examples & docs** — see `examples/` for patterns; new scenarios are especially welcome
- **Feedback** — tell us how you use (or want to use) clove1db in your apps

Before large changes, open an issue to discuss the approach. Smaller fixes and example improvements can go straight to a PR.

## License

Licensed under the MIT license — see [LICENSE-MIT](LICENSE-MIT).
