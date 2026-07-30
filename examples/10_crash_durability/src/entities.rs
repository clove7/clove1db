use serde::{Deserialize, Serialize};

use clove1db::dto::{InputDto, OutputDto};
use clove1db::entity::Entity;
use clove1db::migration::MigrateTo;
use clove1db::units::Result;
use serde_json::Value;

/// Heavy cafe-order-like V1 record (sensitive operational data).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrderV1 {
    pub id: String,
    pub branch_id: String,
    pub cashier_id: String,
    pub customer_name: String,
    pub items_json: String,
    pub notes: String,
    pub total_halalas: i64,
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
    pub branch_id: String,
    pub cashier_id: String,
    pub customer_name: String,
    pub items_json: String,
    pub notes: String,
    pub total_halalas: i64,
    pub created_at_ms: i64,
    pub status: String,
    pub cash_halalas: i64,
    pub card_halalas: i64,
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
                .get("total_halalas")
                .and_then(|x| x.as_i64())
                .unwrap_or(0);
            obj.insert("status".into(), Value::String("completed".into()));
            obj.insert("cash_halalas".into(), Value::from(total / 2));
            obj.insert("card_halalas".into(), Value::from(total - total / 2));
        }
        Ok(clove1db::migration::MigrateOutcome::Migrate(v))
    }
}

/// V3 adds tax, loyalty points, and a large audit trail blob-as-string.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrderV3 {
    pub id: String,
    pub branch_id: String,
    pub cashier_id: String,
    pub customer_name: String,
    pub items_json: String,
    pub notes: String,
    pub total_halalas: i64,
    pub created_at_ms: i64,
    pub status: String,
    pub cash_halalas: i64,
    pub card_halalas: i64,
    pub tax_halalas: i64,
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
                .get("total_halalas")
                .and_then(|x| x.as_i64())
                .unwrap_or(0);
            let tax = total * 15 / 100;
            obj.insert("tax_halalas".into(), Value::from(tax));
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
    pub branch_id: String,
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

/// Arabic + English customer names for diversity.
pub const CUSTOMER_NAMES: &[&str] = &[
    "أحمد العتيبي",
    "فاطمة الزهراني",
    "محمد القحطاني",
    "نورة الشمري",
    "خالد الدوسري",
    "Sara Al-Harbi",
    "Omar Al-Ghamdi",
    "Layla Hassan",
    "Yousef Faris",
    "Maha Alotaibi",
    "عبدالله السبيعي",
    "ريم الحربي",
];

pub const BRANCHES: &[&str] = &["RYD-01", "JED-02", "DMM-03", "MED-04", "ABH-05"];
pub const CASHIERS: &[&str] = &["csh-01", "csh-02", "csh-03", "csh-04", "csh-05", "csh-06"];

pub const MENU_ITEMS: &[&str] = &[
    "قهوة عربية",
    "كابتشينو",
    "لاتيه",
    "شاي كرك",
    "كرواسون",
    "تشيز كيك",
    "ماء",
    "عصير برتقال",
    "آيس كوفي",
    "ساندويش تونة",
];

pub fn make_order_v1(i: usize, now_ms: i64) -> OrderV1 {
    let branch = BRANCHES[i % BRANCHES.len()];
    let cashier = CASHIERS[i % CASHIERS.len()];
    let customer = CUSTOMER_NAMES[i % CUSTOMER_NAMES.len()];
    let n_lines = 2 + (i % 5);
    let mut lines = Vec::new();
    let mut total = 0i64;
    for k in 0..n_lines {
        let name = MENU_ITEMS[(i + k) % MENU_ITEMS.len()];
        let qty = 1 + ((i + k) % 3) as i64;
        let price = 500 + ((i * 17 + k * 31) % 4500) as i64;
        total += qty * price;
        lines.push(format!(r#"{{"name":"{name}","qty":{qty},"unit_halalas":{price}}}"#));
    }
    // Sensitive-looking notes + padding to grow row size.
    let notes = format!(
        "order#{i}|vip={}|allergy=nuts|pad={}",
        i % 7 == 0,
        "N".repeat(128 + (i % 256))
    );
    OrderV1 {
        id: format!("ord-{i:06}"),
        branch_id: branch.into(),
        cashier_id: cashier.into(),
        customer_name: customer.into(),
        items_json: format!("[{}]", lines.join(",")),
        notes,
        total_halalas: total,
        created_at_ms: now_ms + i as i64,
    }
}

pub fn make_device(i: usize) -> Device {
    Device {
        id: format!("dev-{i:04}"),
        label: format!("POS-{}", i),
        branch_id: BRANCHES[i % BRANCHES.len()].into(),
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
