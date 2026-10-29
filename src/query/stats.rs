//! RAM-only byte-bounded sampling. Values never enter diagnostics.
use super::eval::path_value;
use crate::{
    fields::{Path, Value, codec},
    units::Result,
};
use redb::{ReadableTable, ReadableTableMetadata, TableDefinition};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};
pub const SAMPLE_BYTES: usize = 256 * 1024;
pub const BANK_BYTES: usize = 1024 * 1024;
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Statistics {
    pub rows: u64,
    pub missing: u64,
    pub nulls: u64,
    pub ndistinct: u64,
    pub mcv_frequencies: Vec<u64>,
    pub histogram_bounds: usize,
    pub average_json_bytes: f64,
    pub average_key_bytes: f64,
    pub list_fanout: f64,
    pub sample_bytes: usize,
    pub sample_rows: u64,
    pub generation: u64,
    pub correlation:f64,
    pub orderable:bool,
}
#[derive(Clone)]
pub(crate) struct FieldStats {
    pub summary: Statistics,
    pub(crate) mcv: Vec<(Vec<u8>, u64)>,
    pub(crate) histogram: Vec<Vec<u8>>,
}
impl FieldStats {
    pub fn equality(&self, value: &Value) -> Result<f64> {
        let key = codec::encode_equality(value)?;
        let s = &self.summary;
        Ok(self
            .mcv
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, n)| *n as f64 / s.sample_rows.max(1) as f64)
            .unwrap_or(1.0 / s.ndistinct.max(1) as f64))
    }
    pub fn range(&self, value: &Value) -> Result<f64> {
        let key = codec::encode_equality(value)?;
        let denominator = self.summary.sample_rows.max(1) as f64;
        let common = self
            .mcv
            .iter()
            .map(|(_, n)| *n as f64 / denominator)
            .sum::<f64>();
        let below = self
            .mcv
            .iter()
            .filter(|(k, _)| *k < key)
            .map(|(_, n)| *n as f64 / denominator)
            .sum::<f64>();
        Ok(below
            + (1. - common) * self.histogram.iter().filter(|v| **v < key).count() as f64
                / self.histogram.len().max(1) as f64)
    }
    fn weight(&self) -> usize {
        self.summary.sample_bytes
            + self.mcv.iter().map(|(k, _)| k.len() + 32).sum::<usize>()
            + self.histogram.iter().map(|k| k.len() + 24).sum::<usize>()
            + 256
    }
}
#[derive(Default)]
pub(crate) struct Bank {
    entries: VecDeque<(Vec<u8>, Arc<FieldStats>)>,
    bytes: usize,
    pub generation: u64,
}
impl Bank {
    pub(crate) fn invalidate(&mut self) {
        self.entries.clear();
        self.bytes = 0;
        self.generation += 1;
    }
    pub fn lookup(
        &mut self,
        table: &str,
        path: &Path,
        rows: u64,
    ) -> Result<Option<Arc<FieldStats>>> {
        let key = serde_json::to_vec(&(table, path))?;
        let Some(i) = self.entries.iter().position(|(k, _)| *k == key) else {
            return Ok(None);
        };
        let item = self.entries.remove(i).unwrap();
        if item.1.summary.rows.abs_diff(rows) > (item.1.summary.rows / 5).max(1) {
            self.bytes -= item.0.len() + item.1.weight();
            self.generation += 1;
            return Ok(None);
        }
        let result = item.1.clone();
        self.entries.push_back(item);
        Ok(Some(result))
    }

    pub(crate) fn insert_shared(&mut self,table:&str,path:&Path,value:Arc<FieldStats>)->Result<()> {
        let key=serde_json::to_vec(&(table,path))?;
        if let Some(i)=self.entries.iter().position(|(k,_)|k==&key) {
            if Arc::ptr_eq(&self.entries[i].1,&value){return Ok(())}
            let old=self.entries.remove(i).unwrap();self.bytes-=old.0.len()+old.1.weight();
        }
        let weight=key.len()+value.weight();
        while self.bytes+weight>BANK_BYTES {if let Some((k,v))=self.entries.pop_front(){self.bytes-=k.len()+v.weight()}else{break}}
        if weight<=BANK_BYTES {self.generation+=1;self.bytes+=weight;self.entries.push_back((key,value));}Ok(())
    }
    pub fn insert(
        &mut self,
        table: &str,
        path: &Path,
        mut value: FieldStats,
    ) -> Result<Arc<FieldStats>> {
        let key = serde_json::to_vec(&(table, path))?;
        if let Some(i) = self.entries.iter().position(|(k, _)| *k == key) {
            let old = self.entries.remove(i).unwrap();
            self.bytes -= old.0.len() + old.1.weight();
        }
        self.generation += 1;
        value.summary.generation = self.generation;
        let value = Arc::new(value);
        let weight = key.len() + value.weight();
        while self.bytes + weight > BANK_BYTES {
            if let Some((k, v)) = self.entries.pop_front() {
                self.bytes -= k.len() + v.weight()
            } else {
                break;
            }
        }
        if weight <= BANK_BYTES {
            self.bytes += weight;
            self.entries.push_back((key, value.clone()));
        }
        Ok(value)
    }
}
pub const SAMPLE_ROWS: usize = 64;
pub const SAMPLE_INPUT_BYTES: usize = 64 * 1024;

pub(crate) fn sample(tx: &redb::ReadTransaction, table: &str, path: &Path) -> Result<FieldStats> {
    let table = tx.open_table(TableDefinition::<&str, &[u8]>::new(table))?;
    let actual_rows = table.len()?;
    let mut input_bytes = 0usize;
    let mut values = Vec::<Vec<u8>>::new();
    let (mut used, mut seen, mut missing, mut nulls, mut json, mut keys, mut fanout) =
        (0usize, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    for row in table.iter()?.take(SAMPLE_ROWS) {
        let (k, v) = row?;
        let bytes = k.value().len() + v.value().len();
        if bytes > SAMPLE_INPUT_BYTES.saturating_sub(input_bytes) {
            break;
        }
        input_bytes += bytes;
        seen += 1;
        json += v.value().len() as u64;
        keys += k.value().len() as u64;
        let value = path_value(v.value(), path)?;
        if value.is_missing() {
            missing += 1
        }
        if value.is_null() {
            nulls += 1
        }
        fanout += match &value {
            Value::Array(a) => a.len() as u64,
            _ => 1,
        };
        let encoded = codec::encode_equality(&value)?;
        let weight = encoded.len() + 32;
        // Fixed byte budget includes vector slots. Oversized values are excluded.
        if weight > SAMPLE_BYTES / 64 {
            continue;
        }
        if used + weight <= SAMPLE_BYTES {
            used += weight;
            values.push(encoded)
        }
    }
    let sample_rows = values.len() as u64;
    let mut counts = BTreeMap::<Vec<u8>, u64>::new();
    for value in values {
        *counts.entry(value).or_default() += 1
    }
    let ndistinct = (counts.len() as u64
        + ((counts.values().filter(|n| **n == 1).count() as f64
            * (actual_rows.saturating_sub(sample_rows)) as f64
            / sample_rows.max(1) as f64)
            .round() as u64))
        .min(actual_rows);
    let mut common = counts
        .iter()
        .map(|(v, n)| (v.clone(), *n))
        .collect::<Vec<_>>();
    common.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    common.truncate(32);
    let remaining = counts
        .keys()
        .filter(|k| !common.iter().any(|(v, _)| v == *k))
        .collect::<Vec<_>>();
    let mut histogram = vec![];
    for i in 0..remaining.len().min(64) {
        histogram.push(remaining[i * remaining.len() / remaining.len().min(64)].clone());
    }
    Ok(FieldStats {
        summary: Statistics {
            rows: actual_rows,
            missing: (missing as f64 * actual_rows as f64 / seen.max(1) as f64).round() as u64,
            nulls: (nulls as f64 * actual_rows as f64 / seen.max(1) as f64).round() as u64,
            ndistinct,
            mcv_frequencies: common.iter().map(|(_, n)| *n).collect(),
            histogram_bounds: histogram.len(),
            average_json_bytes: json as f64 / seen.max(1) as f64,
            average_key_bytes: keys as f64 / seen.max(1) as f64,
            list_fanout: fanout as f64 / seen.max(1) as f64,
            sample_bytes: used,
            sample_rows,
            generation: 0,correlation:0.,orderable:false,
        },
        mcv: common,
        histogram,
    })
}
