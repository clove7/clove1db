//! One codec for raw, legacy, v1 and v2 history. Payload JSON is never reserialized.
use super::{BackupOperation, BackupRecord};
use crate::units::{ClError, Result};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{MapAccess, Visitor},
};
use serde_json::value::RawValue;
use std::collections::HashMap;

struct Fields<'a> {
    values: HashMap<String, &'a RawValue>,
    duplicates: Vec<String>,
}
impl<'de> Deserialize<'de> for Fields<'de> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct FieldsVisitor;
        impl<'de> Visitor<'de> for FieldsVisitor {
            type Value = Fields<'de>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a backup JSON object")
            }
            fn visit_map<M: MapAccess<'de>>(
                self,
                mut map: M,
            ) -> std::result::Result<Self::Value, M::Error> {
                let mut fields = Fields {
                    values: HashMap::new(),
                    duplicates: Vec::new(),
                };
                while let Some((name, value)) = map.next_entry::<String, &'de RawValue>()? {
                    if fields.values.insert(name.clone(), value).is_some() {
                        fields.duplicates.push(name);
                    }
                }
                Ok(fields)
            }
        }
        deserializer.deserialize_map(FieldsVisitor)
    }
}
fn envelope(fields: &HashMap<String, &RawValue>) -> bool {
    // Ordinary entity rows commonly have id; historical wrappers do not. Before explicit
    // wire tags existed, the remaining signature was the metadata field group.
    !fields.contains_key("id")
        && ["version", "timestamp", "date", "operation", "table", "key"]
            .iter()
            .filter(|name| fields.contains_key(**name))
            .count()
            >= 4
}

#[derive(Serialize, Deserialize)]
struct Metadata {
    version: u64,
    timestamp: i64,
    date: String,
    operation: BackupOperation,
    table: String,
    key: String,
    #[serde(default)]
    bulk_id: Option<String>,
    #[serde(default)]
    restored_version: Option<u64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    date_from_migration: bool,
}
impl Metadata {
    fn from_record(r: &BackupRecord) -> Self {
        Self {
            version: r.version,
            timestamp: r.timestamp,
            date: r.date.clone(),
            operation: r.operation.clone(),
            table: r.table.clone(),
            key: r.key.clone(),
            bulk_id: r.bulk_id.clone(),
            restored_version: r.restored_version,
            date_from_migration: r.date_from_migration,
        }
    }
    fn record(self, data: Option<Vec<u8>>) -> BackupRecord {
        BackupRecord {
            version: self.version,
            timestamp: self.timestamp,
            date: self.date,
            operation: self.operation,
            table: self.table,
            key: self.key,
            bulk_id: self.bulk_id,
            restored_version: self.restored_version,
            date_from_migration: self.date_from_migration,
            data,
        }
    }
}
pub(crate) fn encode_record(record: &BackupRecord) -> Result<Vec<u8>> {
    if matches!(record.operation, BackupOperation::Set) && record.data.is_none() {
        return Err(invalid("set record has no payload"));
    }
    let mut metadata = Metadata::from_record(record);
    if metadata.date_from_migration && metadata.date.is_empty() {
        let now = chrono::Local::now();
        metadata.timestamp = now.timestamp_millis();
        metadata.date = now.format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    }
    let mut encoded = serde_json::to_vec(&metadata)?;
    if let Some(data) = &record.data {
        if matches!(record.operation, BackupOperation::Delete) {
            return Err(invalid("delete record contains a payload"));
        }
        encoded.pop();
        if serde_json::from_slice::<&RawValue>(data).is_ok() {
            // RawValue validates the JSON. Append the original slice as the LAST field,
            // including outer whitespace that RawValue itself normally trims.
            encoded.extend_from_slice(b",\"doc\":");
            encoded.extend_from_slice(data);
        } else {
            encoded.extend_from_slice(b",\"data_b64\":");
            encoded.extend_from_slice(&serde_json::to_vec(&encode_base64(data))?);
        }
        encoded.push(b'}');
    }
    Ok(encoded)
}
pub(crate) fn is_v2(bytes: &[u8]) -> Result<bool> {
    let Ok(fields) = serde_json::from_slice::<Fields>(bytes) else {
        return Ok(false);
    };
    if !envelope(&fields.values) {
        return Ok(false);
    }
    let record = decode_record("", "", bytes)?;
    Ok(!(fields.values.contains_key("data")
        || (record.date_from_migration && record.date.is_empty())))
}
pub(crate) fn decode_record(table: &str, key: &str, bytes: &[u8]) -> Result<BackupRecord> {
    if let Ok(fields) = serde_json::from_slice::<Fields>(bytes)
        && envelope(&fields.values)
    {
        if !fields.duplicates.is_empty() {
            return Err(invalid("duplicate backup envelope field"));
        }
        let fields = fields.values;
        let meta: Metadata = serde_json::from_slice(bytes)?;
        let modes = ["data", "doc", "data_b64"]
            .iter()
            .filter(|name| fields.contains_key(**name))
            .count();
        if modes > 1 {
            return Err(invalid("ambiguous backup payload fields"));
        }
        let data = if let Some(raw) = fields.get("data") {
            serde_json::from_str::<Option<Vec<u8>>>(raw.get())?
        } else if let Some(doc) = fields.get("doc") {
            let raw = doc.get();
            let mut start = raw.as_ptr() as usize - bytes.as_ptr() as usize;
            let mut end = start + raw.len();
            // The encoder puts no formatting space around doc; all adjacent
            // JSON whitespace belongs to the original payload.
            while start > 0 && json_space(bytes[start - 1]) {
                start -= 1;
            }
            while end < bytes.len() && json_space(bytes[end]) {
                end += 1;
            }
            Some(bytes[start..end].to_vec())
        } else if let Some(raw) = fields.get("data_b64") {
            Some(decode_base64(&serde_json::from_str::<String>(raw.get())?)?)
        } else {
            None
        };
        if matches!(meta.operation, BackupOperation::Set) && data.is_none() {
            return Err(invalid("set record has no payload"));
        }
        if matches!(meta.operation, BackupOperation::Delete) && data.is_some() {
            return Err(invalid("delete record contains a payload"));
        }
        return Ok(meta.record(data));
    }
    raw_record(table, key, bytes)
}
fn json_space(b: u8) -> bool {
    matches!(b, b' ' | b'\n' | b'\r' | b'\t')
}
fn invalid(reason: &str) -> ClError {
    ClError::BackupNormalizeFailed {
        reason: reason.into(),
    }
}
pub(crate) fn raw_record(table: &str, key: &str, bytes: &[u8]) -> Result<BackupRecord> {
    let (key, version) = key
        .rsplit_once(':')
        .ok_or_else(|| invalid("backup key is not versioned"))?;
    let version = version
        .parse()
        .map_err(|_| invalid("invalid backup version suffix"))?;
    Ok(BackupRecord {
        version,
        timestamp: 0,
        date: String::new(),
        operation: if bytes.is_empty() {
            BackupOperation::Delete
        } else {
            BackupOperation::Set
        },
        table: table.into(),
        key: key.into(),
        data: if bytes.is_empty() {
            None
        } else {
            Some(bytes.to_vec())
        },
        bulk_id: None,
        restored_version: None,
        date_from_migration: true,
    })
}
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
fn encode_base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = *chunk.get(1).unwrap_or(&0);
        let c = *chunk.get(2).unwrap_or(&0);
        out.push(ALPHABET[(a >> 2) as usize] as char);
        out.push(ALPHABET[(((a & 3) << 4) | (b >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(((b & 15) << 2) | (c >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(c & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}
fn decode_base64(text: &str) -> Result<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err(invalid("invalid base64 length"));
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let digit = |b| {
        ALPHABET
            .iter()
            .position(|v| *v == b)
            .map(|i| i as u8)
            .ok_or_else(|| invalid("invalid base64 digit"))
    };
    for (i, c) in bytes.chunks_exact(4).enumerate() {
        let a = digit(c[0])?;
        let b = digit(c[1])?;
        let last = (i + 1) * 4 == bytes.len();
        if c[2] == b'=' {
            if !last || c[3] != b'=' || b & 15 != 0 {
                return Err(invalid("invalid base64 padding"));
            }
            out.push((a << 2) | (b >> 4));
            continue;
        }
        let d = digit(c[2])?;
        out.push((a << 2) | (b >> 4));
        out.push((b << 4) | (d >> 2));
        if c[3] == b'=' {
            if !last || d & 3 != 0 {
                return Err(invalid("invalid base64 padding"));
            }
        } else {
            out.push((d << 6) | digit(c[3])?);
        }
    }
    Ok(out)
}
