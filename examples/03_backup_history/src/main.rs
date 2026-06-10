use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use clove1db::{
    backup::view::RecordData,
    dto::{InputDto, OutputDto},
    entity::Entity,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::{ClError, Result},
};

// ═══════════════════════════════════════════════════════════
// 1. ENTITY
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Document {
    id: String,
    title: String,
    content: String,
}

impl Entity for Document {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

// ═══════════════════════════════════════════════════════════
// 2. INPUT DTO
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
struct DocumentDto {
    title: String,
    content: String,
}

impl InputDto<Document> for DocumentDto {
    fn validate(&self) -> Result<()> {
        if self.title.trim().is_empty() {
            return Err(ClError::Validation("Title is required".into()).into());
        }
        Ok(())
    }

    fn into_entity(self) -> Result<Document> {
        Ok(Document {
            id: uuid::Uuid::new_v4().to_string(),
            title: self.title,
            content: self.content,
        })
    }
}

// ═══════════════════════════════════════════════════════════
// 3. OUTPUT DTO
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Serialize)]
struct DocumentResponse {
    id: String,
    title: String,
    content: String,
}

impl OutputDto<Document> for DocumentResponse {
    fn from_entity(e: Document) -> Self {
        Self {
            id: e.id,
            title: e.title,
            content: e.content,
        }
    }
}

// ═══════════════════════════════════════════════════════════
// 4. MAIN
// ═══════════════════════════════════════════════════════════

fn main() -> Result<()> {
    let base_dir = PathBuf::from("./examples_data/03_backup_history");
    let _ = std::fs::remove_dir_all(&base_dir);

    // ── 1. Build Storage with Backup Enabled ───────────────
    println!("━━━ Building Storage ━━━");
    let storage = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("docs_db", "documents")
                .dir_path(base_dir)
                .backup_enabled(true) // enable versioned backup
                .register::<Document>("documents"),
        )
        .build()?;

    let doc_domain = storage.domain::<Document>();

    // ── 2. Create (Version 1) ──────────────────────────────
    println!("\n━━━ 1. Create Document (v1) ━━━");
    let doc = doc_domain.create::<DocumentDto, DocumentResponse>(DocumentDto {
        title: "Draft 1".into(),
        content: "Initial ideas...".into(),
    })?;
    println!("  ✅ v1 Created: {} | {}", doc.title, doc.content);

    // ── 3. Update (Version 2) ──────────────────────────────
    println!("\n━━━ 2. Update Document (v2) ━━━");
    doc_domain.update::<DocumentDto, DocumentResponse>(
        &doc.id,
        DocumentDto {
            title: "Draft 2".into(),
            content: "Expanding the ideas with more details...".into(),
        },
    )?;
    println!("  ✅ v2 Updated");

    // ── 4. Update (Version 3) ──────────────────────────────
    println!("\n━━━ 3. Update Document (v3) ━━━");
    doc_domain.update::<DocumentDto, DocumentResponse>(
        &doc.id,
        DocumentDto {
            title: "Final Version".into(),
            content: "This is the final polished content.".into(),
        },
    )?;
    println!("  ✅ v3 Updated");

    // ── 5. Delete (Version 4) ──────────────────────────────
    println!("\n━━━ 4. Delete Document (v4) ━━━");
    doc_domain.delete(&doc.id)?;
    println!("  ✅ v4 Deleted (Record removed from main DB, but kept in Backup)");

    // ── 6. View Full History ───────────────────────────────
    println!("\n━━━ 5. Audit History ━━━");
    let history = doc_domain.history(&doc.id)?;
    println!("  Total versions found: {}", history.len());

    for record in &history {
        match &record.data {
            RecordData::Typed(json) | RecordData::Json(json) => {
                let title = json.get("title").and_then(|v| v.as_str()).unwrap_or("?");
                println!(
                    "  v{} | Op: {:?} | Date: {} | Title: {} | restorable: {}",
                    record.version, record.operation, record.date, title, record.restorable
                );
            }
            RecordData::None => {
                println!(
                    "  v{} | Op: {:?} | Date: {} | ❌ Data Deleted",
                    record.version, record.operation, record.date
                );
            }
        }
    }

    // ── 7. View Past Version (Read-Only) ───────────────────
    println!("\n━━━ 6. Inspect Past Version (v2) ━━━");
    let v2_record = doc_domain.get_by_version(&doc.id, 2)?;
    if let Some(json) = v2_record.data.as_json() {
        let title = json.get("title").and_then(|v| v.as_str()).unwrap_or("?");
        let content = json.get("content").and_then(|v| v.as_str()).unwrap_or("?");
        println!(
            "  🔍 Found v2 Data -> Title: {} | Content: {}",
            title, content
        );
    }

    // ── 8. Restore to Past Version ─────────────────────────
    println!("\n━━━ 7. Restore Document to v1 ━━━");
    // Restores v1 data and records a new version in the database
    doc_domain.restore_by_version(&doc.id, 1)?;

    let restored_doc = doc_domain.get::<DocumentResponse>(&doc.id)?;
    println!(
        "  ✅ Restored Successfully -> Current Title: {}",
        restored_doc.title
    );

    // ── 9. Final History Check ─────────────────────────────
    println!("\n━━━ Final History After Restore ━━━");
    let final_history = doc_domain.history(&doc.id)?;
    if let Some(latest) = final_history.last() {
        println!(
            "  Latest Version: v{} | Restored From: v{:?} | Op: {:?}",
            latest.version, latest.restored_version, latest.operation
        );
    }

    println!("\n✅ Backup & History Example completed successfully!");
    Ok(())
}
