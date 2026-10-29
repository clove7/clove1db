use crate::{fields::{Path,Value,codec}, units::{Result,ClError}};
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Serialize,Deserialize};
pub(super) const FORMAT:u32=4;
pub(super) const META:TableDefinition<&str,&[u8]>=TableDefinition::new("__inx_meta");
pub(super) const DEFS:TableDefinition<u64,&[u8]>=TableDefinition::new("__inx_definitions");
pub(super) const STATS:TableDefinition<u64,&[u8]>=TableDefinition::new("__inx_statistics");
pub(super) const FST:TableDefinition<u64,&[u8]>=TableDefinition::new("__inx_dictionary");
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
pub(super) struct Identity {pub format:u32,pub codec:u8,pub uuid:Vec<u8>,pub schema:Vec<u8>}
#[derive(Clone,Debug,Serialize,Deserialize)]
pub(super) struct Metadata {pub identity:Identity,pub reset:u64,pub applied:u64,pub generation:u64,pub uptime_ms:u64}
#[derive(Clone,Copy,Debug,Serialize,Deserialize,PartialEq,Eq)]
pub(crate) enum Kind {Value,Token,Trigram,LastWrite,
 /// The fingerprints of the parts of a protected value (`Compare::Parts`): stored like the trigrams of a text, as posting blocks, but the terms are the
 /// space-separated fingerprints of the stored field, cut with `query::eval::tokens`.
 Parts}
impl Kind {
 /// Whether the index is kept as posting blocks of row numbers (`trigram.rs`).
 pub(crate) fn postings(self)->bool {matches!(self,Kind::Trigram|Kind::Parts)}
}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
pub(crate) struct Definition {pub table:String,pub paths:Vec<Path>,pub kind:Kind,#[serde(default)]pub directions:Vec<crate::query::Direction>}
impl Definition {pub fn canonical(&self)->Result<Vec<u8>> {Ok(serde_json::to_vec(&(FORMAT,crate::fields::codec::VERSION,crate::query::TOKENIZER_VERSION,self))?)} }
#[derive(Clone,Copy,Debug,Serialize,Deserialize,PartialEq,Eq)]
pub enum IndexState {Active,Idle,Abandoned,Merged}
#[derive(Clone,Debug,Serialize,Deserialize)]
pub(super) struct Manifest {
 pub id:u64,pub definition:Definition,pub canonical:Vec<u8>,pub generation:u64,pub ready:bool,pub state:IndexState,
 pub reason:String,pub last_use_ms:u64,pub interval_ms:u64,pub build_ms:f64,pub reads:u64,pub matched:u64,pub bytes:u64,pub waste:u64,pub replacement:Option<u64>,#[serde(default)] pub estimated_ms:f64,#[serde(default)] pub actual_ms:f64,#[serde(default)]pub summary:Option<crate::query::stats::Statistics>,#[serde(default)]pub orderable:bool,#[serde(default)]pub prefix_only_reads:u64,#[serde(default)]pub verified_prefixes:Vec<u64>,
}
impl Manifest {
 pub fn validate(&self)->Result<()> {if self.definition.canonical()?!=self.canonical {return Err(ClError::Validation("index definition fingerprint mismatch".into()))} Ok(())}
 pub fn entries(&self)->String {format!("__inx_keys_{}_{}",self.id,self.generation)}
 pub fn reverse(&self)->String {format!("__inx_rows_{}_{}",self.id,self.generation)}
}
pub(super) fn metadata(tx:&redb::ReadTransaction)->Result<Metadata> {let t=tx.open_table(META)?;let v=t.get("manifest")?.ok_or_else(||ClError::Validation("missing index manifest".into()))?;Ok(serde_json::from_slice(v.value())?)}
pub(super) fn put_metadata(tx:&redb::WriteTransaction,m:&Metadata)->Result<()> {tx.open_table(META)?.insert("manifest",serde_json::to_vec(m)?.as_slice())?;Ok(())}
pub(super) fn definitions(tx:&redb::ReadTransaction)->Result<Vec<Manifest>> {tx.open_table(DEFS)?.iter()?.map(|r| {let(_,v)=r?;let m:Manifest=serde_json::from_slice(v.value())?;m.validate()?;Ok(m)}).collect()}
pub(super) fn put_definition(tx:&redb::WriteTransaction,m:&Manifest)->Result<()> {m.validate()?;tx.open_table(DEFS)?.insert(m.id,serde_json::to_vec(m)?.as_slice())?;Ok(())}
pub(super) fn initialize(db:&Database,identity:Identity,reset:u64,seq:u64)->Result<()> {
 let tx=db.begin_write()?;tx.open_table(DEFS)?;tx.open_table(STATS)?;tx.open_table(FST)?;
 put_metadata(&tx,&Metadata{identity,reset,applied:seq,generation:0,uptime_ms:0})?;tx.commit()?;Ok(())
}
pub(super) fn entry_key(value:&Value,row:&str)->Result<Vec<u8>> {let mut key=codec::encode_equality(value)?;key.extend(codec::encode(&Value::String(row.into()))?);Ok(key)}
#[cfg(test)] mod tests {
 use super::*; use redb::ReadableDatabase;
 fn identity()->Identity {Identity{format:FORMAT,codec:codec::VERSION,uuid:vec![1;16],schema:vec![2]}}
 #[test] fn identity_and_canonical_content_survive_reopen() {
  let path=std::env::temp_dir().join(format!("{}.inx",uuid::Uuid::new_v4()));
  let db=Database::create(&path).unwrap();initialize(&db,identity(),3,8).unwrap();let tx=db.begin_read().unwrap();let m=metadata(&tx).unwrap();assert_eq!(m.identity,identity());assert_eq!((m.reset,m.applied),(3,8));drop(tx);drop(db);
  let db=Database::open(path).unwrap();assert_eq!(metadata(&db.begin_read().unwrap()).unwrap().identity,identity());
  let def=Definition{table:"notes".into(),paths:vec![],kind:Kind::Value,directions:vec![]};let mut manifest=Manifest{id:1,canonical:def.canonical().unwrap(),definition:def,generation:1,ready:false,state:IndexState::Active,reason:"build".into(),last_use_ms:0,interval_ms:0,build_ms:0.,reads:0,matched:0,bytes:0,waste:0,replacement:None,estimated_ms:0.,actual_ms:0.,summary:None,orderable:false,prefix_only_reads:0,verified_prefixes:vec![]};
  manifest.validate().unwrap();manifest.canonical.push(0);assert!(manifest.validate().is_err());
 }
 #[test] fn row_suffix_preserves_value_order_without_collision() {assert!(entry_key(&Value::Number("2".into()),"z").unwrap()<entry_key(&Value::Number("10".into()),"a").unwrap());assert_ne!(entry_key(&Value::String("ab".into()),"c").unwrap(),entry_key(&Value::String("a".into()),"bc").unwrap());}
}
