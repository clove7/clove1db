//! Persisted exact counters and a deterministic, key-distributed bounded reservoir.
use crate::{fields::{Value,codec},query::stats::{Statistics,FieldStats},units::Result};
use serde::{Serialize,Deserialize};use std::collections::BTreeMap;
pub(super) const RESERVOIR_ROWS:usize=512;
pub(super) const RESERVOIR_BYTES:usize=256*1024;
#[derive(Clone,Serialize,Deserialize)]
pub(super) struct RowStats {pub key:String,pub missing:u64,pub nulls:u64,pub fanout:u64,pub json_bytes:u64,pub key_bytes:u64,pub values:Vec<Vec<u8>>,pub unorderable:u64}
impl RowStats {
 pub fn new(key:&str,json:usize,values:&[Value])->Result<Self> {
  let mut encoded=vec![];let mut used=0;for v in values {let b=codec::encode_equality(v)?;if b.len()>4096||used+b.len()>4096 {encoded.clear();break}used+=b.len();encoded.push(b);}
  Ok(Self{key:key.into(),missing:u64::from(values.iter().any(Value::is_missing)),nulls:u64::from(values.iter().any(Value::is_null)),fanout:values.len() as u64,json_bytes:json as u64,key_bytes:key.len() as u64,values:encoded,unorderable:u64::from(values.iter().any(|v|codec::encode(v).is_err()))})
 }
 fn priority(&self)->(u64,String) {let mut z=crate::query::optimizer::fingerprint(self.key.as_bytes());z=(z^(z>>30)).wrapping_mul(0xbf58476d1ce4e5b9);z=(z^(z>>27)).wrapping_mul(0x94d049bb133111eb);((z^(z>>31)),self.key.clone())}
 fn weight(&self)->usize {self.key.len()+self.values.iter().map(|v|v.len()+24).sum::<usize>()+96}
}
#[derive(Clone,Default,Serialize,Deserialize)]
pub(super) struct Reservoir {
 pub rows:u64,pub missing:u64,pub nulls:u64,pub fanout:u64,pub json:u64,pub keys:u64,pub revision:u64,pub unorderable:u64,
 samples:BTreeMap<(u64,String),RowStats>,bytes:usize,
}
// JSON maps require string keys; the durable representation is a vector.
#[derive(Serialize,Deserialize)] struct Stored {format:u8,revision:u64,unorderable:u64,rows:u64,missing:u64,nulls:u64,fanout:u64,json:u64,keys:u64,samples:Vec<RowStats>}
impl Reservoir {
 pub fn encode(&self)->Result<Vec<u8>> {Ok(serde_json::to_vec(&Stored{format:2,revision:self.revision,unorderable:self.unorderable,rows:self.rows,missing:self.missing,nulls:self.nulls,fanout:self.fanout,json:self.json,keys:self.keys,samples:self.samples.values().cloned().collect()})?)}
 pub fn decode(bytes:&[u8])->Result<Self> {let s:Stored=serde_json::from_slice(bytes)?;if s.format!=2{return Err(crate::units::ClError::Validation("unsupported index statistics format".into()))}let mut out=Self{revision:s.revision,unorderable:s.unorderable,rows:s.rows,missing:s.missing,nulls:s.nulls,fanout:s.fanout,json:s.json,keys:s.keys,..Self::default()};for row in s.samples {out.bytes+=row.weight();out.samples.insert(row.priority(),row);}Ok(out)}
 pub fn apply(&mut self,old:Option<&RowStats>,new:Option<RowStats>) {
  if old.is_some()||new.is_some(){self.revision=self.revision.saturating_add(1);}
  if let Some(old)=old {self.unorderable=self.unorderable.saturating_sub(old.unorderable);self.rows=self.rows.saturating_sub(1);self.missing=self.missing.saturating_sub(old.missing);self.nulls=self.nulls.saturating_sub(old.nulls);self.fanout=self.fanout.saturating_sub(old.fanout);self.json=self.json.saturating_sub(old.json_bytes);self.keys=self.keys.saturating_sub(old.key_bytes);if let Some(row)=self.samples.remove(&old.priority()){self.bytes-=row.weight();}}
  if let Some(row)=new {self.unorderable+=row.unorderable;self.rows+=1;self.missing+=row.missing;self.nulls+=row.nulls;self.fanout+=row.fanout;self.json+=row.json_bytes;self.keys+=row.key_bytes;
   if !row.values.is_empty()&&row.weight()<=RESERVOIR_BYTES/4 {self.bytes+=row.weight();if let Some(old)=self.samples.insert(row.priority(),row){self.bytes-=old.weight();}while self.samples.len()>RESERVOIR_ROWS||self.bytes>RESERVOIR_BYTES {let(_,row)=self.samples.pop_last().unwrap();self.bytes-=row.weight();}}
  }
 }
 pub fn field_stats(&self,generation:u64)->FieldStats {
  let mut counts=BTreeMap::<Vec<u8>,u64>::new();for row in self.samples.values(){for value in &row.values{*counts.entry(value.clone()).or_default()+=1;}}
  let leaves=counts.values().sum::<u64>();let ndistinct=(counts.len() as u64+(counts.values().filter(|n|**n==1).count() as u64*self.fanout.saturating_sub(leaves)/leaves.max(1))).min(self.fanout);
  let mut mcv=counts.iter().map(|(k,n)|(k.clone(),*n)).collect::<Vec<_>>();mcv.sort_by(|a,b|b.1.cmp(&a.1).then(a.0.cmp(&b.0)));mcv.truncate(32);
  let rest=counts.keys().filter(|k|!mcv.iter().any(|(v,_)|v==*k)).collect::<Vec<_>>();let n=rest.len().min(64);let histogram=(0..n).map(|i|rest[i*rest.len()/n].clone()).collect::<Vec<_>>();
  FieldStats{summary:Statistics{rows:self.rows,missing:self.missing,nulls:self.nulls,ndistinct,mcv_frequencies:mcv.iter().map(|(_,n)|*n).collect(),histogram_bounds:histogram.len(),average_json_bytes:self.json as f64/self.rows.max(1) as f64,average_key_bytes:self.keys as f64/self.rows.max(1) as f64,list_fanout:self.fanout as f64/self.rows.max(1) as f64,sample_bytes:self.bytes,sample_rows:self.samples.len() as u64,generation,correlation:self.correlation(),orderable:self.unorderable==0},mcv,histogram}
 }
 pub fn clear_samples(&mut self){self.samples.clear();self.bytes=0;}
 pub fn correlation(&self)->f64 {
  let mut pairs=self.samples.values().filter_map(|r|r.values.first().map(|v|(r.key.clone(),v.clone()))).collect::<Vec<_>>();pairs.sort_by(|a,b|a.0.cmp(&b.0));let mut ranks=pairs.iter().enumerate().map(|(i,(_,v))|(v,i)).collect::<Vec<_>>();ranks.sort_by(|a,b|a.0.cmp(b.0));let n=ranks.len() as f64;if n<2.{return 0.}
  let center=(n-1.)/2.;let mut xy=0.;let mut xx=0.;let mut yy=0.;let mut start=0;while start<ranks.len(){let mut end=start+1;while end<ranks.len()&&ranks[end].0==ranks[start].0{end+=1}let value_rank=(start+end-1) as f64/2.-center;for(_,key_rank)in &ranks[start..end]{let x=*key_rank as f64-center;xy+=x*value_rank;xx+=x*x;yy+=value_rank*value_rank;}start=end;}if xx==0.||yy==0.{0.}else{xy/(xx*yy).sqrt()}
 }
}
#[cfg(test)] mod tests {use super::*;
 #[test] fn time_ordered_keys_use_distributed_sample() {let mut sample=Reservoir::default();for n in 0..10000 {let row=RowStats::new(&format!("{n:06}"),40,&[Value::Number(n.to_string())]).unwrap();sample.apply(None,Some(row));}let field=sample.field_stats(1);assert_eq!(field.summary.rows,10000);assert_eq!(field.summary.sample_rows,512);let estimate=1.-field.range(&Value::Number("9000".into())).unwrap();assert!((estimate-0.1).abs()<=0.03,"last-decile estimate exceeds 3 percentage points");assert!(sample.correlation()>0.99);let bytes=sample.encode().unwrap();assert_eq!(Reservoir::decode(&bytes).unwrap().field_stats(1).summary.rows,10000);}
}
