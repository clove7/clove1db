use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use clove1db::{
    dto::{InputDto, OutputDto},
    entity::Entity,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::{ClError, Result},
};

// ═══════════════════════════════════════════════════════════
// 1. ENTITIES (spread across different databases)
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
struct User {
    id: String,
    username: String,
}

impl Entity for User {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Product {
    id: String,
    title: String,
    price: f64,
}

impl Entity for Product {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

// ═══════════════════════════════════════════════════════════
// 2. INPUT DTOs
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
struct CreateUserDto {
    username: String,
}

impl InputDto<User> for CreateUserDto {
    fn validate(&self) -> Result<()> {
        if self.username.trim().is_empty() {
            return Err(ClError::Validation("Username is required".into()).into());
        }
        Ok(())
    }

    fn into_entity(self) -> Result<User> {
        Ok(User {
            id: uuid::Uuid::new_v4().to_string(),
            username: self.username,
        })
    }
}

#[derive(Debug, Deserialize)]
struct CreateProductDto {
    title: String,
    price: f64,
}

impl InputDto<Product> for CreateProductDto {
    fn validate(&self) -> Result<()> {
        if self.price <= 0.0 {
            return Err(ClError::Validation("Price must be > 0".into()).into());
        }
        Ok(())
    }

    fn into_entity(self) -> Result<Product> {
        Ok(Product {
            id: uuid::Uuid::new_v4().to_string(),
            title: self.title,
            price: self.price,
        })
    }
}

// ═══════════════════════════════════════════════════════════
// 3. OUTPUT DTOs
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Serialize)]
struct UserResponse {
    id: String,
    username: String,
}

impl OutputDto<User> for UserResponse {
    fn from_entity(e: User) -> Self {
        Self {
            id: e.id,
            username: e.username,
        }
    }
}

#[derive(Debug, Serialize)]
struct ProductResponse {
    id: String,
    title: String,
    price: f64,
}

impl OutputDto<Product> for ProductResponse {
    fn from_entity(e: Product) -> Self {
        Self {
            id: e.id,
            title: e.title,
            price: e.price,
        }
    }
}

// ═══════════════════════════════════════════════════════════
// 4. MAIN
// ═══════════════════════════════════════════════════════════

fn main() -> Result<()> {
    let base_dir = PathBuf::from("./examples_data/02_multi_database");

    // ── 1. Build Multi-Database Storage ────────────────────
    println!("━━━ Building Multi-Database Storage ━━━");

    let storage = Storage::builder(StorageConfig::default())
        // Database 1: users
        .add_database(
            DatabaseConfig::new("users_db", "users")
                .dir_path(base_dir.clone())
                .register::<User>("users"),
        )
        // Database 2: catalog (products, orders, etc.)
        .add_database(
            DatabaseConfig::new("catalog_db", "catalog")
                .dir_path(base_dir.clone())
                .cache(5_000, 600, 120) // custom cache settings
                .register::<Product>("products"),
        )
        // Database 3: no cache (e.g. large files)
        .add_database(
            DatabaseConfig::new("attachments_db", "attachments")
                .dir_path(base_dir.clone())
                .has_cache(false),
        )
        .build()?;

    // List registered databases
    println!("\n  ✅ Active Databases: {:?}", storage.db_list_names());

    // ── 2. Interact with Database 1 (Users) ────────────────
    println!("\n━━━ Operations on users_db ━━━");
    let user_domain = storage.domain::<User>();

    let user = user_domain.create::<CreateUserDto, UserResponse>(CreateUserDto {
        username: "system_admin".into(),
    })?;
    println!("  ✅ Saved to users_db: {:?}", user);

    // ── 3. Interact with Database 2 (Catalog) ──────────────
    println!("\n━━━ Operations on catalog_db ━━━");
    let product_domain = storage.domain::<Product>();

    let product = product_domain.create::<CreateProductDto, ProductResponse>(CreateProductDto {
        title: "Mechanical Keyboard".into(),
        price: 149.99,
    })?;
    println!("  ✅ Saved to catalog_db: {:?}", product);

    // ── 4. Verify Isolation ────────────────────────────────
    println!("\n━━━ Data Isolation Check ━━━");
    let users_count = user_domain.list::<UserResponse>()?.len();
    let products_count = product_domain.list::<ProductResponse>()?.len();

    println!("  Total Users in DB 1: {}", users_count);
    println!("  Total Products in DB 2: {}", products_count);

    println!("\n✅ Multi-Database Example completed successfully!");
    Ok(())
}
