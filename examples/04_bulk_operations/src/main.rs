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
struct Device {
    id: String,
    name: String,
    status: String,
}

impl Entity for Device {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

// ═══════════════════════════════════════════════════════════
// 2. INPUT DTO
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
struct DeviceConfigDto {
    name: String,
    status: String,
}

impl InputDto<Device> for DeviceConfigDto {
    fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(ClError::Validation("Device name required".into()).into());
        }
        Ok(())
    }

    fn into_entity(self) -> Result<Device> {
        Ok(Device {
            id: uuid::Uuid::new_v4().to_string(),
            name: self.name,
            status: self.status,
        })
    }
}

// ═══════════════════════════════════════════════════════════
// 3. OUTPUT DTO
// ═══════════════════════════════════════════════════════════

#[derive(Debug, Serialize)]
struct DeviceResponse {
    id: String,
    name: String,
    status: String,
}

impl OutputDto<Device> for DeviceResponse {
    fn from_entity(e: Device) -> Self {
        Self {
            id: e.id,
            name: e.name,
            status: e.status,
        }
    }
}

// ═══════════════════════════════════════════════════════════
// 4. MAIN
// ═══════════════════════════════════════════════════════════

fn main() -> Result<()> {
    let base_dir = PathBuf::from("./examples_data/04_bulk_operations");
    let _ = std::fs::remove_dir_all(&base_dir);

    // ── 1. Build Storage with Backup (Required for restore_bulk) ──
    println!("━━━ Building Storage ━━━");
    let storage = Storage::builder(StorageConfig::default())
        .add_database(
            DatabaseConfig::new("devices_db", "devices")
                .dir_path(base_dir)
                .backup_enabled(true) // backup required for restore_bulk
                .register::<Device>("devices"),
        )
        .build()?;

    let device_domain = storage.domain::<Device>();

    // ── 2. Create Initial Devices ──────────────────────────
    println!("\n━━━ 1. Creating Initial Devices ━━━");
    let dev1 = device_domain.create::<DeviceConfigDto, DeviceResponse>(DeviceConfigDto {
        name: "Server-Alpha".into(),
        status: "Online".into(),
    })?;
    let dev2 = device_domain.create::<DeviceConfigDto, DeviceResponse>(DeviceConfigDto {
        name: "Server-Beta".into(),
        status: "Online".into(),
    })?;

    println!("  ✅ dev1: {} - {}", dev1.name, dev1.status);
    println!("  ✅ dev2: {} - {}", dev2.name, dev2.status);

    // ── 3. Update Bulk (Simulating a network-wide update) ──
    println!("\n━━━ 2. Performing Bulk Update ━━━");

    let bulk_payload = vec![
        (
            dev1.id.clone(),
            DeviceConfigDto {
                name: "Server-Alpha".into(),
                status: "Maintenance".into(),
            },
        ),
        (
            dev2.id.clone(),
            DeviceConfigDto {
                name: "Server-Beta".into(),
                status: "Maintenance".into(),
            },
        ),
    ];

    let (updated_devices, bulk_id) =
        device_domain.update_bulk::<DeviceConfigDto, DeviceResponse>(bulk_payload)?;

    println!("  ✅ Bulk Update Complete! Received bulk_id: {}", bulk_id);
    for d in &updated_devices {
        println!("     Updated -> {}: {}", d.name, d.status);
    }

    // ── 4. Modify Individual Devices Afterward ─────────────
    println!("\n━━━ 3. Individual Updates After Bulk ━━━");
    // Change one device to Offline after the bulk update
    device_domain.update::<DeviceConfigDto, DeviceResponse>(
        &dev1.id,
        DeviceConfigDto {
            name: "Server-Alpha".into(),
            status: "Offline".into(),
        },
    )?;
    println!("  ✅ dev1 changed to Offline manually.");

    // ── 5. Restore Bulk ────────────────────────────────────
    println!("\n━━━ 4. Restoring Entire Bulk Snapshot ━━━");
    // Roll back all devices to the bulk snapshot
    device_domain.restore_bulk(&bulk_id)?;

    let restored1 = device_domain.get::<DeviceResponse>(&dev1.id)?;
    let restored2 = device_domain.get::<DeviceResponse>(&dev2.id)?;

    println!("  ✅ Successfully restored to bulk snapshot:");
    println!(
        "     dev1 Restored State: {} - {}",
        restored1.name, restored1.status
    ); // back to "Maintenance"
    println!(
        "     dev2 Restored State: {} - {}",
        restored2.name, restored2.status
    );

    // ── 6. Verify Audit Logs with bulk_id ──────────────────
    println!("\n━━━ 5. Audit History for dev1 ━━━");
    let history = device_domain.history(&dev1.id)?;
    for r in &history {
        let status = r
            .data
            .as_json()
            .and_then(|j| j.get("status").and_then(|s| s.as_str()))
            .unwrap_or("❌ Deleted");
        println!(
            "  v{} | Op: {:?} | Status: {:<12} | bulk_id: {:?}",
            r.version, r.operation, status, r.bulk_id
        );
    }

    println!("\n✅ Bulk Operations Example completed successfully!");
    Ok(())
}
