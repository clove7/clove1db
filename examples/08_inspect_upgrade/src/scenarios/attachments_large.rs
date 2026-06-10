use clove1db::{units::Result, FileKind};

use crate::entities::{
    seed_counts, AttachmentMetaResponse, AttachmentV1, UploadAttachmentDto,
};
use crate::fixtures::SeedState;
use crate::log;
use crate::paths::{self, copy_dir_all};
use crate::storage::attachments_storage;
use crate::verify::assert_meta;

pub fn run(seed: &SeedState) -> Result<()> {
    log::step("Upgrade era_042 attachments (backup OFF) → AttachmentV1");

    let parent = paths::upgraded_attachments_dir();
    if parent.exists() {
        std::fs::remove_dir_all(&parent)?;
    }
    copy_dir_all(
        &paths::era_042_attachments_dir(),
        &parent.join("attachments"),
    )?;
    log::path_entry("source (legacy 042)", &paths::era_042_attachments_cldb());

    log::line("Storage::build() — register AttachmentV1@files, backup_enabled=false");
    let storage = attachments_storage(parent.clone())?;
    drop(storage);

    let cldb = parent.join("attachments").join("attachments.cldb");
    log::print_meta(&cldb, "attachments after upgrade")?;
    assert_meta(&cldb, "attachments upgrade", |m| {
        m.upgrade_complete
            && !m.backup_enabled
            && m.backup_upgraded
            && m.table_meta("files")
                .map(|t| t.schema_version)
                == Some(1)
    })?;

    let bak = parent.join("attachments").join("attachments.cldb.bak");
    log::path_entry("backup file", &bak);
    if bak.exists() {
        return Err(clove1db::units::ClError::Validation(
            "attachments should not have .bak when backup disabled".into(),
        ));
    }
    log::ok("no .bak file (backup disabled)");

    let report = log::print_inspect("attachments upgraded", &cldb)?;
    if report.kind != FileKind::Authenticated {
        return Err(clove1db::units::ClError::Validation(format!(
            "attachments inspect {:?}",
            report.kind
        )));
    }

    let storage = attachments_storage(parent)?;
    let files = storage.domain::<AttachmentV1>();

    let meta = files.get::<AttachmentMetaResponse>(&seed.attachment_id)?;
    log::subsection("seeded ~2 MiB attachment (metadata DTO)");
    log::kv("id", log::short_id(&meta.id));
    log::kv("filename", &meta.filename);
    log::kv("size_bytes", meta.size_bytes);
    if meta.size_bytes != seed_counts::ATTACHMENT_BYTES {
        return Err(clove1db::units::ClError::Validation(format!(
            "post-upgrade size {}",
            meta.size_bytes
        )));
    }

    log::step("Post-upgrade upload via UploadAttachmentDto");
    let uploaded = files.create::<UploadAttachmentDto, AttachmentMetaResponse>(UploadAttachmentDto {
        filename: "post_upgrade_marker.txt".into(),
        data: b"upgraded-ok".to_vec(),
    })?;
    log::line(format!(
        "created [{}] {} ({} bytes)",
        log::short_id(&uploaded.id),
        uploaded.filename,
        uploaded.size_bytes
    ));
    log::ok(format!(
        "legacy {} byte blob preserved + new upload OK",
        seed_counts::ATTACHMENT_BYTES
    ));

    Ok(())
}
