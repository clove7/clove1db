use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use clove1db::{
    dto::{InputDto, OutputDto},
    entity::Entity,
    storage::{DatabaseConfig, Storage, StorageConfig},
    units::{ClError, Result},
};

// ═══════════════════════════════════════════════════════════
// 1. ENTITY (Binary Storage)
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileRecord {
    id: String,
    filename: String,
    mime_type: String,
    size_bytes: usize,
    data: Vec<u8>, // file binary payload
    uploaded_at: i64,
}

impl Entity for FileRecord {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

// ═══════════════════════════════════════════════════════════
// 2. INPUT DTO
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
struct UploadFileDto {
    filename: String,
    mime_type: String,
    data: Vec<u8>,
}

impl InputDto<FileRecord> for UploadFileDto {
    fn validate(&self) -> Result<()> {
        if self.data.is_empty() {
            return Err(ClError::Validation("File data cannot be empty".into()).into());
        }
        // optional max file size (e.g. 50MB)
        if self.data.len() > 50 * 1024 * 1024 {
            return Err(ClError::Validation("File size exceeds 50MB limit".into()).into());
        }
        Ok(())
    }

    fn into_entity(self) -> Result<FileRecord> {
        let size_bytes = self.data.len();
        Ok(FileRecord {
            id: uuid::Uuid::new_v4().to_string(),
            filename: self.filename,
            mime_type: self.mime_type,
            size_bytes,
            data: self.data,
            uploaded_at: chrono::Utc::now().timestamp(),
        })
    }
}

// ═══════════════════════════════════════════════════════════
// 3. OUTPUT DTOs (Metadata vs Full Download)
// ═══════════════════════════════════════════════════════════

// DTO 1: metadata only — no binary loaded
#[derive(Debug, Serialize)]
struct FileMetadataResponse {
    id: String,
    filename: String,
    mime_type: String,
    size_bytes: usize,
}

impl OutputDto<FileRecord> for FileMetadataResponse {
    fn from_entity(e: FileRecord) -> Self {
        Self {
            id: e.id,
            filename: e.filename,
            mime_type: e.mime_type,
            size_bytes: e.size_bytes,
        }
    }
}

// DTO 2: full download — loads binary into memory
#[derive(Debug, Serialize)]
struct FileDownloadResponse {
    filename: String,
    mime_type: String,
    data: Vec<u8>,
}

impl OutputDto<FileRecord> for FileDownloadResponse {
    fn from_entity(e: FileRecord) -> Self {
        Self {
            filename: e.filename,
            mime_type: e.mime_type,
            data: e.data,
        }
    }
}

// ═══════════════════════════════════════════════════════════
// 4. MAIN
// ═══════════════════════════════════════════════════════════

fn main() -> Result<()> {
    let base_dir = PathBuf::from("./examples_data/06_large_files");

    // ── 1. Build Storage (Optimized for Large Files) ───────
    println!("━━━ Building Storage for Attachments ━━━");

    let storage = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("attachments_db", "attachments")
                .dir_path(base_dir)
                .backup_enabled(false) // disable backup to save disk space
                .has_cache(false) // disable cache to protect RAM
                .register::<FileRecord>("files"),
        )
        .build()?;

    let file_domain = storage.domain::<FileRecord>();

    // ── 2. Simulate File Upload ────────────────────────────
    println!("\n━━━ 1. Uploading Large File ━━━");

    // simulate ~2MB file payload
    let mock_binary_data = vec![0u8; 2 * 1024 * 1024];

    let upload_input = UploadFileDto {
        filename: "high_res_image.png".into(),
        mime_type: "image/png".into(),
        data: mock_binary_data,
    };

    // return metadata only after upload
    let metadata = file_domain.create::<UploadFileDto, FileMetadataResponse>(upload_input)?;
    println!("  ✅ File Uploaded Successfully!");
    println!("     ID: {}", metadata.id);
    println!("     Name: {}", metadata.filename);
    println!("     Size: {} bytes", metadata.size_bytes);

    // ── 3. List Files (Metadata Only) ──────────────────────
    println!("\n━━━ 2. Listing Files (Without fetching Data) ━━━");
    let files_list = file_domain.list::<FileMetadataResponse>()?;
    for file in files_list {
        println!("  📄 {} ({} bytes)", file.filename, file.size_bytes);
    }

    // ── 4. Download File (Fetch Full Binary) ───────────────
    println!("\n━━━ 3. Downloading File ━━━");
    // load full Vec<u8> from the database
    let download = file_domain.get::<FileDownloadResponse>(&metadata.id)?;
    println!(
        "  ✅ Downloaded '{}' | Loaded {} bytes into memory.",
        download.filename,
        download.data.len()
    );

    // ── 5. Delete File ─────────────────────────────────────
    println!("\n━━━ 4. Deleting File ━━━");
    file_domain.delete(&metadata.id)?;
    println!("  ✅ File permanently deleted (No backup exists).");

    println!("\n✅ Large Files Example completed successfully!");
    Ok(())
}
