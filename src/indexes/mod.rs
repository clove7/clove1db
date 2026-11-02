//! Automatically maintained, disposable indexes adjacent to the primary file.
mod format;
mod worker;
mod access;
mod statistics;
mod report;
mod planner;
mod ordered;
mod execution;
mod trigram;
pub use report::{IndexReport,DefinitionReport};
pub use format::IndexState;
use crate::{journal::ReadView, units::Result};
use std::{sync::{Arc,Mutex},time::Instant};
pub(crate) use worker::Worker;
/// `keep` is the `.inx` database `index` was read from. The worker drops its own handle when it swaps in a compacted file; a query that took this pair before the swap
/// still reads from `index`, and a read transaction does not keep a closed database readable, so the pair holds the database open until the last query is done with it.
/// It comes after `index`: fields drop in order, so the read transaction is released before the database.
pub(crate) struct Pair {pub primary:Arc<ReadView>,pub index:redb::ReadTransaction,pub published:Instant,pub ready:usize,pub statistics:Vec<(String,crate::fields::Path,Arc<crate::query::stats::FieldStats>)>,#[allow(dead_code)] pub keep:Arc<redb::Database>,
 /// What the index file of this pair says about itself (its identity and its definitions): the snapshot cannot change, so they are read once per pair, not once per query.
 memo:std::sync::OnceLock<(format::Identity,Vec<format::Manifest>)>}
impl Pair {
 pub(in crate::indexes) fn memo(&self)->Result<&(format::Identity,Vec<format::Manifest>)> {
  if let Some(m)=self.memo.get(){return Ok(m)}
  let m=(format::metadata(&self.index)?.identity,format::definitions(&self.index)?);
  Ok(self.memo.get_or_init(||m))
 }
}
#[derive(Default)]
pub(crate) struct Shared {pub pair:Mutex<Option<Arc<Pair>>>,wanted:Mutex<Vec<format::Definition>>,observations:Mutex<std::collections::BTreeMap<Vec<u8>,Observation>>,clock:report::Clock,usages:Mutex<std::collections::BTreeMap<u64,report::Usage>>,reports:Mutex<Vec<IndexReport>>,compact_requested:std::sync::atomic::AtomicBool}
impl std::fmt::Debug for Shared {fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.write_str("IndexRuntime")}}
impl Shared {
 pub(super) fn request(&self,def:format::Definition) {let mut wanted=self.wanted.lock().unwrap_or_else(|e|e.into_inner());if wanted.len()<128&&!wanted.contains(&def){wanted.push(def);}}
 pub fn view(&self,db:&crate::repository::DatabaseManager,allow_stale:bool)->Result<Arc<ReadView>> {
  let current=Arc::new(db.read_view_at_head()?);
  let Some(pair)=self.pair() else{return Ok(current)};
  if pair.ready==0||allow_stale{return Ok(current)}
  if pair.primary.head==current.head{return Ok(current)}
  if pair.primary.head>current.head{return Ok(pair.primary.clone())}
  let rows=current.tx.open_table(redb::TableDefinition::<&str,&[u8]>::new(&db.tables_names.first().map(String::as_str).unwrap_or("")));
  use redb::ReadableTableMetadata;
  let estimated_scan_ms=rows.ok().and_then(|t|t.len().ok()).unwrap_or(0) as f64*0.0003;
  let budget=std::time::Duration::from_secs_f64((estimated_scan_ms*0.25).min(2.).max(0.)/1000.);
  let started=Instant::now();
  while started.elapsed()<budget {if let Some(pair)=self.pair(){if pair.primary.head>=current.head{return Ok(pair.primary.clone())}}std::thread::sleep(std::time::Duration::from_micros(100));}
  // Timeout uses the already retained primary snapshot, never implicit stale.
  Ok(current)
 }
 pub fn pair(&self)->Option<Arc<Pair>> {self.pair.lock().unwrap_or_else(|e|e.into_inner()).clone()}
 pub fn publish(&self,pair:Arc<Pair>) {let old=self.pair.lock().unwrap_or_else(|e|e.into_inner()).replace(pair);drop(old);}
 pub fn clear(&self) {let old=self.pair.lock().unwrap_or_else(|e|e.into_inner()).take();drop(old);}
}
pub(crate) fn boot(databases:&mut std::collections::HashMap<String,crate::repository::DatabaseManager>)->Result<Worker> {worker::boot(databases)}

#[derive(Default)] struct Observation {saved_ms:f64,queued:bool,reads:u64}
impl Shared {
 pub(crate) fn observe(&self,table:&str,expr:Option<&crate::fields::Expr>,order:&[(crate::query::OrderSource,crate::query::Direction)],work:crate::query::optimizer::Work) {
  let definitions=access::wanted(table,expr,order);let n=definitions.len().max(1) as f64;
  let savings=work.micros as f64/1000.-work.matches as f64*0.0003-0.03;
  if savings<=0. {return}
  let estimated_build=2.+work.rows as f64*0.001+work.bytes as f64/1_000_000.;
  let mut requests=vec![];
  {let mut observations=self.observations.lock().unwrap_or_else(|e|e.into_inner());for def in definitions {let Ok(key)=def.canonical() else{continue};if observations.len()>=128&&!observations.contains_key(&key){continue}let observation=observations.entry(key).or_default();observation.saved_ms+=savings/n;observation.reads+=1;if !observation.queued&&observation.reads>=2&&observation.saved_ms>estimated_build*2. {observation.queued=true;requests.push(def);}}}
  for definition in requests{self.request(definition)}
 }
}

impl Shared {
 pub(crate) fn field_statistics(&self,table:&str,view:&ReadView)->Vec<(crate::fields::Path,Arc<crate::query::stats::FieldStats>)> {
  let Some(pair)=self.pair() else{return vec![]};if pair.primary.head!=view.head||pair.primary.database_uuid!=view.database_uuid{return vec![]}
  if worker::identity(view).ok().as_ref()!=pair.memo().ok().map(|m|&m.0){return vec![]}
  pair.statistics.iter().filter(|(t,_,_)|t==table).map(|(_,p,s)|(p.clone(),s.clone())).collect()
 }
}

impl Shared {#[cfg(any(test,feature="crash-inject"))]pub(crate) fn advance_clock(&self,ms:u64){self.clock.advance(ms);}}

impl Shared {#[cfg(any(test,feature="crash-inject"))]pub(crate) fn request_compact(&self){self.compact_requested.store(true,std::sync::atomic::Ordering::Release);}}

#[cfg(any(test,feature="crash-inject"))]
impl Shared {
 pub(crate) fn request_verification_indexes(&self,table:&str,expr:Option<&crate::fields::Expr>,order:&[(crate::query::OrderSource,crate::query::Direction)])->Result<Vec<Vec<u8>>> {
  let definitions=access::wanted(table,expr,order);if definitions.len()>128{return Err(crate::units::ClError::Validation("verification index request exceeds runtime limit".into()))}
  let canonical=definitions.iter().map(format::Definition::canonical).collect::<Result<Vec<_>>>()?;for definition in definitions{self.request(definition);}Ok(canonical)
 }
 pub(crate) fn definitions_ready(&self,definitions:&[Vec<u8>])->Result<bool>{let Some(pair)=self.pair()else{return Ok(false)};let ready=format::definitions(&pair.index)?;Ok(definitions.iter().all(|d|ready.iter().any(|r|r.ready&&r.state==IndexState::Active&&r.canonical==*d)))}
}
