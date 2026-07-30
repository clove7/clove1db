use std::fs;
use std::path::Path;

use crate::durability::DurabilityMode;
use crate::fsutil::write_atomic;
use crate::units::{ClError, Result};

/// Ensures `.migration/*/refs/*.json` snapshot files are valid JSON arrays of (key, hex-bytes).
pub fn upgrade_migration_refs(migration_dir: &Path) -> Result<usize> {
    upgrade_migration_refs_with_durability(migration_dir, DurabilityMode::Strict)
}

pub fn upgrade_migration_refs_with_durability(
    migration_dir: &Path,
    durability: DurabilityMode,
) -> Result<usize> {
    if !migration_dir.exists() {
        return Ok(0);
    }

    let mut upgraded = 0usize;
    for entry in fs::read_dir(migration_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let refs_dir = entry.path().join("refs");
        if !refs_dir.exists() {
            continue;
        }
        for ref_entry in fs::read_dir(&refs_dir)? {
            let ref_entry = ref_entry?;
            let path = ref_entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let data = fs::read_to_string(&path)?;
            let parsed: serde_json::Value = serde_json::from_str(&data).map_err(|e| {
                ClError::MigrationError(format!("invalid ref file {:?}: {}", path, e))
            })?;

            let normalized = normalize_ref_json(&parsed)?;
            let out = serde_json::to_string_pretty(&normalized)?;
            if out != data {
                write_atomic(&path, out.as_bytes(), durability)?;
                upgraded += 1;
            }
        }
    }
    Ok(upgraded)
}

fn normalize_ref_json(value: &serde_json::Value) -> Result<Vec<(String, String)>> {
    let arr = value.as_array().ok_or_else(|| {
        ClError::MigrationError("migration ref must be a JSON array".into())
    })?;

    let mut out = Vec::new();
    for item in arr {
        let pair = item.as_array().ok_or_else(|| {
            ClError::MigrationError("migration ref entry must be [key, bytes]".into())
        })?;
        if pair.len() != 2 {
            return Err(ClError::MigrationError(
                "migration ref entry must have exactly 2 elements".into(),
            ));
        }
        let key = pair[0]
            .as_str()
            .ok_or_else(|| ClError::MigrationError("ref key must be string".into()))?
            .to_string();
        let bytes_str = if let Some(s) = pair[1].as_str() {
            s.to_string()
        } else if let Some(arr) = pair[1].as_array() {
            let bytes: Vec<u8> = arr
                .iter()
                .filter_map(|v| v.as_u64().map(|n| n as u8))
                .collect();
            hex_encode(&bytes)
        } else {
            return Err(ClError::MigrationError(
                "ref bytes must be hex string or byte array".into(),
            ));
        };
        out.push((key, bytes_str));
    }
    Ok(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_byte_array_ref() {
        let input = serde_json::json!([["k1", [1u8, 2, 3]]]);
        let out = normalize_ref_json(&input).unwrap();
        assert_eq!(out[0].0, "k1");
        assert_eq!(out[0].1, "010203");
    }
}
