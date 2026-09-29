use serde::{Deserialize, Serialize};

use clove1db::dto::{InputDto, OutputDto};
use clove1db::entity::Entity;
use clove1db::migration::MigrateTo;
use clove1db::units::Result;
use serde_json::Value;

/// Heavy store-order V1 record (sensitive-looking operational data).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrderV1 {
    pub id: String,
    pub store_id: String,
    pub clerk_id: String,
    pub customer_name: String,
    pub items_json: String,
    pub notes: String,
    pub total_cents: i64,
    pub created_at_ms: i64,
}

impl Entity for OrderV1 {
    fn entity_id(&self) -> &str {
        &self.id
    }
}
impl InputDto<OrderV1> for OrderV1 {
    fn into_entity(self) -> Result<OrderV1> {
        Ok(self)
    }
}
impl OutputDto<OrderV1> for OrderV1 {
    fn from_entity(e: OrderV1) -> Self {
        e
    }
}

/// V2 adds payment breakdown + status (breaking-ish additive migrate).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrderV2 {
    pub id: String,
    pub store_id: String,
    pub clerk_id: String,
    pub customer_name: String,
    pub items_json: String,
    pub notes: String,
    pub total_cents: i64,
    pub created_at_ms: i64,
    pub status: String,
    pub cash_cents: i64,
    pub card_cents: i64,
}

impl Entity for OrderV2 {
    fn entity_id(&self) -> &str {
        &self.id
    }
}
impl InputDto<OrderV2> for OrderV2 {
    fn into_entity(self) -> Result<OrderV2> {
        Ok(self)
    }
}
impl OutputDto<OrderV2> for OrderV2 {
    fn from_entity(e: OrderV2) -> Self {
        e
    }
}

impl MigrateTo<OrderV2> for OrderV1 {
    fn migrate_json(value: Value) -> Result<clove1db::migration::MigrateOutcome<Value>> {
        let mut v = value;
        if let Some(obj) = v.as_object_mut() {
            let total = obj
                .get("total_cents")
                .and_then(|x| x.as_i64())
                .unwrap_or(0);
            obj.insert("status".into(), Value::String("completed".into()));
            obj.insert("cash_cents".into(), Value::from(total / 2));
            obj.insert("card_cents".into(), Value::from(total - total / 2));
        }
        Ok(clove1db::migration::MigrateOutcome::Migrate(v))
    }
}

/// V3 adds tax, loyalty points, and a large audit trail blob-as-string.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrderV3 {
    pub id: String,
    pub store_id: String,
    pub clerk_id: String,
    pub customer_name: String,
    pub items_json: String,
    pub notes: String,
    pub total_cents: i64,
    pub created_at_ms: i64,
    pub status: String,
    pub cash_cents: i64,
    pub card_cents: i64,
    pub tax_cents: i64,
    pub loyalty_points: i64,
    pub audit_trail: String,
}

impl Entity for OrderV3 {
    fn entity_id(&self) -> &str {
        &self.id
    }
}
impl InputDto<OrderV3> for OrderV3 {
    fn into_entity(self) -> Result<OrderV3> {
        Ok(self)
    }
}
impl OutputDto<OrderV3> for OrderV3 {
    fn from_entity(e: OrderV3) -> Self {
        e
    }
}

impl MigrateTo<OrderV3> for OrderV2 {
    fn migrate_json(value: Value) -> Result<clove1db::migration::MigrateOutcome<Value>> {
        let mut v = value;
        if let Some(obj) = v.as_object_mut() {
            let total = obj
                .get("total_cents")
                .and_then(|x| x.as_i64())
                .unwrap_or(0);
            let tax = total * 10 / 100;
            obj.insert("tax_cents".into(), Value::from(tax));
            obj.insert("loyalty_points".into(), Value::from(total / 100));
            let id = obj
                .get("id")
                .and_then(|x| x.as_str())
                .unwrap_or("unknown")
                .to_string();
            // Heavy audit trail string to stress migrate payload size.
            let audit = format!(
                "migrated_v2_to_v3|id={id}|checksum={}|pad={}",
                total ^ 0x5a5a_5a5a,
                "AUDIT".repeat(64)
            );
            obj.insert("audit_trail".into(), Value::String(audit));
        }
        Ok(clove1db::migration::MigrateOutcome::Migrate(v))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub label: String,
    pub store_id: String,
    pub firmware: String,
    pub meta_json: String,
}

impl Entity for Device {
    fn entity_id(&self) -> &str {
        &self.id
    }
}
impl InputDto<Device> for Device {
    fn into_entity(self) -> Result<Device> {
        Ok(self)
    }
}
impl OutputDto<Device> for Device {
    fn from_entity(e: Device) -> Self {
        e
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeedEvent {
    pub id: String,
    pub kind: String,
    pub text: String,
    pub payload: String,
}

impl Entity for FeedEvent {
    fn entity_id(&self) -> &str {
        &self.id
    }
}
impl InputDto<FeedEvent> for FeedEvent {
    fn into_entity(self) -> Result<FeedEvent> {
        Ok(self)
    }
}
impl OutputDto<FeedEvent> for FeedEvent {
    fn from_entity(e: FeedEvent) -> Self {
        e
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InvoiceBlob {
    pub id: String,
    pub order_id: String,
    pub title: String,
    pub size_bytes: usize,
    pub content_type: String,
}

impl Entity for InvoiceBlob {
    fn entity_id(&self) -> &str {
        &self.id
    }
}
impl InputDto<InvoiceBlob> for InvoiceBlob {
    fn into_entity(self) -> Result<InvoiceBlob> {
        Ok(self)
    }
}
impl OutputDto<InvoiceBlob> for InvoiceBlob {
    fn from_entity(e: InvoiceBlob) -> Self {
        e
    }
}

/// Names in several scripts, so rows exercise multi-byte UTF-8.
pub const CUSTOMER_NAMES: &[&str] = &[
    "Alice Moore",
    "José Álvarez",
    "Zoë Müller",
    "Ana Petrova",
    "Αλέξης Παππάς",
    "Иван Смирнов",
    "李明",
    "佐藤 花子",
    "김민준",
    "Priya Sharma",
    "Tomás Ó Briain",
    "Nguyễn Văn An",
];

pub const STORES: &[&str] = &["store-01", "store-02", "store-03", "store-04", "store-05"];
pub const CLERKS: &[&str] = &["clerk-01", "clerk-02", "clerk-03", "clerk-04", "clerk-05", "clerk-06"];

pub const MENU_ITEMS: &[&str] = &[
    "notebook",
    "pencil set",
    "desk lamp",
    "stapler",
    "paper ream",
    "marker pack",
    "sticky notes",
    "folder",
    "ruler",
    "tape",
];

pub fn make_order_v1(i: usize, now_ms: i64) -> OrderV1 {
    let store = STORES[i % STORES.len()];
    let clerk = CLERKS[i % CLERKS.len()];
    let customer = CUSTOMER_NAMES[i % CUSTOMER_NAMES.len()];
    let n_lines = 2 + (i % 5);
    let mut lines = Vec::new();
    let mut total = 0i64;
    for k in 0..n_lines {
        let name = MENU_ITEMS[(i + k) % MENU_ITEMS.len()];
        let qty = 1 + ((i + k) % 3) as i64;
        let price = 500 + ((i * 17 + k * 31) % 4500) as i64;
        total += qty * price;
        lines.push(format!(r#"{{"name":"{name}","qty":{qty},"unit_cents":{price}}}"#));
    }
    // Sensitive-looking notes + padding to grow row size.
    let notes = format!(
        "order#{i}|priority={}|gift_wrap=yes|pad={}",
        i % 7 == 0,
        "N".repeat(128 + (i % 256))
    );
    OrderV1 {
        id: format!("ord-{i:06}"),
        store_id: store.into(),
        clerk_id: clerk.into(),
        customer_name: customer.into(),
        items_json: format!("[{}]", lines.join(",")),
        notes,
        total_cents: total,
        created_at_ms: now_ms + i as i64,
    }
}

pub fn make_device(i: usize) -> Device {
    Device {
        id: format!("dev-{i:04}"),
        label: format!("POS-{}", i),
        store_id: STORES[i % STORES.len()].into(),
        firmware: format!("1.{}.{}", i % 10, i % 100),
        meta_json: format!(
            r#"{{"mac":"AA:BB:CC:DD:{:02X}:{:02X}","serial":"SN{i:08}","pad":"{}"}}"#,
            (i % 255) as u8,
            ((i * 3) % 255) as u8,
            "M".repeat(200)
        ),
    }
}

pub fn make_feed(i: usize) -> FeedEvent {
    let kinds = ["sale", "refund", "login", "alert", "shift_open", "shift_close"];
    FeedEvent {
        id: format!("evt-{i:06}"),
        kind: kinds[i % kinds.len()].into(),
        text: format!("event {i} — {}", CUSTOMER_NAMES[i % CUSTOMER_NAMES.len()]),
        payload: "P".repeat(512 + (i % 1024)),
    }
}

pub fn make_blob_bytes(seed: usize, size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    for (idx, b) in buf.iter_mut().enumerate() {
        *b = ((idx * 31 + seed * 17) % 251) as u8;
    }
    // Embed a recognizable header for verification.
    let header = format!("CLOVE-BLOB-SEED={seed};SIZE={size};").into_bytes();
    let n = header.len().min(size);
    buf[..n].copy_from_slice(&header[..n]);
    buf
}
