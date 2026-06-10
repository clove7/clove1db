use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use clove1db::{
    dto::{InputDto, OutputDto},
    entity::Entity,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::{ClError, Result},
};

// ═══════════════════════════════════════════════════════════
// 1. ENTITY
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct User {
    id: String,
    name: String,
    email: String,
    created_at: i64,
}

impl Entity for User {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

// ═══════════════════════════════════════════════════════════
// 2. INPUT DTO
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
struct CreateUserDto {
    name: String,
    email: String,
}

impl InputDto<User> for CreateUserDto {
    fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(ClError::Validation("Name cannot be empty".into()).into());
        }
        if !self.email.contains('@') {
            return Err(ClError::Validation("Invalid email format".into()).into());
        }
        Ok(())
    }

    fn into_entity(self) -> Result<User> {
        Ok(User {
            id: uuid::Uuid::new_v4().to_string(),
            name: self.name,
            email: self.email,
            created_at: chrono::Utc::now().timestamp(),
        })
    }
}

// ═══════════════════════════════════════════════════════════
// 3. OUTPUT DTO
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Serialize)]
struct UserResponse {
    id: String,
    name: String,
    email: String,
}

impl OutputDto<User> for UserResponse {
    fn from_entity(e: User) -> Self {
        Self {
            id: e.id,
            name: e.name,
            email: e.email,
        }
    }
}

// ═══════════════════════════════════════════════════════════
// 4. MAIN
// ═══════════════════════════════════════════════════════════

fn main() -> Result<()> {
    let base_dir = PathBuf::from("./examples_data/01_basic_crud");
    let _ = std::fs::remove_dir_all(&base_dir);

    // ── 1. Build Storage ───────────────────────────────────
    println!("━━━ Building Storage ━━━");
    let storage = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("users_db", "users")
                .dir_path(base_dir)
                .cache(10_000, 300, 60)
                .register::<User>("users"),
        )
        .build()?;

    let user_domain = storage.domain::<User>();

    // ── 2. Create ✅ ───────────────────────────────────────
    println!("\n━━━ 1. Create User ━━━");
    let new_user = user_domain.create::<CreateUserDto, UserResponse>(CreateUserDto {
        name: "Alice Doe".into(),
        email: "alice@example.com".into(),
    })?;
    println!("  ✅ Created: {:?}", new_user);

    // ── 3. Validate Failure ❌ ─────────────────────────────
    println!("\n━━━ 2. Validation Test ━━━");
    let bad_user = user_domain.create::<CreateUserDto, UserResponse>(CreateUserDto {
        name: "".into(),
        email: "invalid-email".into(),
    });
    println!("  ❌ Expected Error: {}", bad_user.unwrap_err());

    // ── 4. Read (Get) ✅ ───────────────────────────────────
    println!("\n━━━ 3. Read User ━━━");
    let found_user = user_domain.get::<UserResponse>(&new_user.id)?;
    println!("  ✅ Found: {:?}", found_user);

    // ── 5. List ✅ ─────────────────────────────────────────
    println!("\n━━━ 4. List Users ━━━");
    let list = user_domain.list::<UserResponse>()?;
    println!("  ✅ Total users in DB: {}", list.len());

    // ── 6. Update ✅ ───────────────────────────────────────
    println!("\n━━━ 5. Update User ━━━");
    let updated_user = user_domain.update::<CreateUserDto, UserResponse>(
        &new_user.id,
        CreateUserDto {
            name: "Alice Smith".into(),
            email: "alice.smith@example.com".into(),
        },
    )?;
    println!("  ✅ Updated: {:?}", updated_user);

    // ── 7. Delete ✅ ───────────────────────────────────────
    println!("\n━━━ 6. Delete User ━━━");
    user_domain.delete(&new_user.id)?;
    println!("  ✅ Deleted user ID: {}", new_user.id);

    // Verify Deletion
    let after_delete = user_domain.get::<UserResponse>(&new_user.id);
    println!("  ❌ Get after delete: {}", after_delete.unwrap_err());

    println!("\n✅ Basic CRUD Example completed successfully!");
    Ok(())
}
