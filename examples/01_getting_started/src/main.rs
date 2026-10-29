//! # 01 — Getting started
//!
//! The pieces every clove1db program has:
//!
//! - an **entity** (`Entity`): the row as it is stored;
//! - **input DTOs** (`InputDto`): what a caller may send, checked before anything is written;
//! - **output DTOs** (`OutputDto`): what a caller gets back, so a field like a password hash
//!   never leaves the program by accident;
//! - a **`Storage`** with one or more databases, each a `.cldb` file with its own tables;
//! - the **domain** (`storage.domain::<E>()`) for create, read, update, delete and list.
//!
//! Run it with `cargo run` from this folder. It writes to a fresh folder under the system's
//! temporary folder, removes it at the end, and exits with an error if any check fails.

use clove1db::{
    dto::{InputDto, OutputDto},
    entity::Entity,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::{ClError, Result},
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

// ── Entities ──────────────────────────────────────────────────────────────────

/// A user account. `password_hash` is stored but never returned by `UserView`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct User {
    id: String,
    name: String,
    email: String,
    password_hash: String,
}

impl Entity for User {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// An order. Its total is computed when it is created, not sent by the caller.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Order {
    id: String,
    user_id: String,
    item: String,
    price_cents: u64,
    tax_cents: u64,
    total_cents: u64,
}

impl Entity for Order {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

/// A setting whose key is its id, so writing it twice updates the same row.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Setting {
    key: String,
    value: String,
}

impl Entity for Setting {
    fn entity_id(&self) -> &str {
        &self.key
    }
}

// ── Input DTOs ────────────────────────────────────────────────────────────────

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn new_id(prefix: &str) -> String {
    format!("{prefix}-{:06}", NEXT_ID.fetch_add(1, Ordering::Relaxed))
}

#[derive(Debug, Deserialize)]
struct RegisterUser {
    name: String,
    email: String,
    password: String,
}

impl InputDto<User> for RegisterUser {
    fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(ClError::Validation("name is required".into()));
        }
        if !self.email.contains('@') {
            return Err(ClError::Validation("email must contain @".into()));
        }
        if self.password.len() < 8 {
            return Err(ClError::Validation("password must have at least 8 characters".into()));
        }
        Ok(())
    }

    fn into_entity(self) -> Result<User> {
        // A real program hashes the password here (see example 06 for a hashed field).
        let password_hash = format!("not-a-real-hash:{}", self.password.len());
        Ok(User { id: new_id("user"), name: self.name, email: self.email, password_hash })
    }
}

#[derive(Debug, Deserialize)]
struct PlaceOrder {
    user_id: String,
    item: String,
    price_cents: u64,
}

impl InputDto<Order> for PlaceOrder {
    fn validate(&self) -> Result<()> {
        if self.price_cents == 0 {
            return Err(ClError::Validation("price must be above zero".into()));
        }
        Ok(())
    }

    fn into_entity(self) -> Result<Order> {
        let tax_cents = self.price_cents * 15 / 100;
        Ok(Order {
            id: new_id("order"),
            user_id: self.user_id,
            item: self.item,
            price_cents: self.price_cents,
            tax_cents,
            total_cents: self.price_cents + tax_cents,
        })
    }
}

#[derive(Debug, Deserialize)]
struct PutSetting {
    key: String,
    value: String,
}

impl InputDto<Setting> for PutSetting {
    fn into_entity(self) -> Result<Setting> {
        Ok(Setting { key: self.key, value: self.value })
    }
}

// ── Output DTOs ───────────────────────────────────────────────────────────────

/// What the outside world sees of a user: no password hash.
#[derive(Debug, Serialize)]
struct UserView {
    id: String,
    name: String,
    email: String,
}

impl OutputDto<User> for UserView {
    fn from_entity(e: User) -> Self {
        Self { id: e.id, name: e.name, email: e.email }
    }
}

#[derive(Debug, Serialize)]
struct Receipt {
    id: String,
    line: String,
    total_cents: u64,
}

impl OutputDto<Order> for Receipt {
    fn from_entity(e: Order) -> Self {
        Self { id: e.id, line: format!("{} (+15% tax)", e.item), total_cents: e.total_cents }
    }
}

#[derive(Debug, Serialize)]
struct SettingView {
    key: String,
    value: String,
}

impl OutputDto<Setting> for SettingView {
    fn from_entity(e: Setting) -> Self {
        Self { key: e.key, value: e.value }
    }
}

// ── The program ───────────────────────────────────────────────────────────────

fn check(ok: bool, what: &str) -> Result<()> {
    if ok {
        println!("  ok  {what}");
        Ok(())
    } else {
        Err(ClError::Validation(format!("check failed: {what}")))
    }
}

/// Two databases in one `Storage`: `accounts` (users) and `shop` (orders and settings).
fn open(root: &PathBuf) -> Result<Storage> {
    Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("accounts", "accounts")
                .dir_path(root.clone())
                .cache_bytes(8 * 1024 * 1024, 300, 60) // 8 MiB of decoded rows, 5 min TTL, 1 min idle
                .register::<User>("users"),
        )
        .add_database(
            DatabaseConfig::new("shop", "shop")
                .dir_path(root.clone())
                .register::<Order>("orders")
                .register::<Setting>("settings"),
        )
        .build()
}

fn main() -> Result<()> {
    let root = std::env::temp_dir().join(format!("clove1db-example-01-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);

    println!("01 getting started — data in {}", root.display());
    let storage = open(&root)?;
    println!("databases: {:?}", storage.db_list_names());

    let users = storage.domain::<User>();
    let orders = storage.domain::<Order>();
    let settings = storage.domain::<Setting>();

    println!("\ncreate");
    let alice = users.create::<RegisterUser, UserView>(RegisterUser {
        name: "Alice".into(),
        email: "alice@example.test".into(),
        password: "correct horse".into(),
    })?;
    let bob = users.create::<RegisterUser, UserView>(RegisterUser {
        name: "Bob".into(),
        email: "bob@example.test".into(),
        password: "battery staple".into(),
    })?;
    check(alice.id != bob.id, "each user has its own id")?;

    println!("\nvalidation runs before anything is written");
    let bad = users.create::<RegisterUser, UserView>(RegisterUser {
        name: "".into(),
        email: "no-at-sign".into(),
        password: "short".into(),
    });
    check(matches!(bad, Err(ClError::Validation(_))), "an invalid user is refused with Validation")?;
    check(users.list::<UserView>()?.len() == 2, "the refused user was not stored")?;

    println!("\nread");
    let found = users.get::<UserView>(&alice.id)?;
    check(found.name == "Alice" && found.email == "alice@example.test", "get returns what was created")?;
    let stored: User = users.repo().get_uncached(&alice.id)?;
    check(stored.password_hash.starts_with("not-a-real-hash"), "the hash is stored, but UserView never shows it")?;

    println!("\nupdate");
    // `domain.update(id, dto)` stores the whole entity the DTO builds. To change one field
    // and keep the others (here the hash), read the row, change it and write it back.
    let mut row: User = users.repo().get(&alice.id)?;
    row.name = "Alice Smith".into();
    users.repo().set(&alice.id, &row)?;
    let renamed = users.get::<UserView>(&alice.id)?;
    let kept: User = users.repo().get_uncached(&alice.id)?;
    check(renamed.name == "Alice Smith", "the name changed")?;
    check(kept.password_hash == stored.password_hash, "the fields that were not changed are kept")?;

    println!("\ncomputed fields and a second database");
    let receipt = orders.create::<PlaceOrder, Receipt>(PlaceOrder {
        user_id: alice.id.clone(),
        item: "Keyboard".into(),
        price_cents: 10_000,
    })?;
    check(receipt.total_cents == 11_500, "the total is computed by the DTO: 100.00 + 15%")?;

    println!("\na key as the id: writing twice updates one row");
    settings.create::<PutSetting, SettingView>(PutSetting { key: "theme".into(), value: "dark".into() })?;
    settings.update::<PutSetting, SettingView>("theme", PutSetting { key: "theme".into(), value: "light".into() })?;
    let theme = settings.get::<SettingView>("theme")?;
    check(theme.value == "light", "the setting holds the last value")?;
    check(settings.list::<SettingView>()?.len() == 1, "there is one setting row")?;

    println!("\ndelete");
    users.delete(&bob.id)?;
    check(users.get::<UserView>(&bob.id).is_err(), "a deleted user is not found")?;
    check(users.list::<UserView>()?.len() == 1, "one user is left")?;

    println!("\nclose, open again, and the data is there");
    storage.close();
    drop(storage);
    let storage = open(&root)?;
    let again = storage.domain::<User>().get::<UserView>(&alice.id)?;
    check(again.name == "Alice Smith", "the update survived closing the files")?;
    check(storage.domain::<Order>().list::<Receipt>()?.len() == 1, "the order is in the second database")?;
    storage.close();

    std::fs::remove_dir_all(&root)?;
    println!("\n01 getting started: all checks passed");
    Ok(())
}
