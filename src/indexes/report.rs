use super::{format::*,Shared};
use std::{sync::atomic::{AtomicU64,Ordering},time::Instant};
/// Diagnostic definition shape. Dynamic path keys and query literals are omitted.
#[derive(Clone,Debug)] pub struct DefinitionReport {pub table:String,pub kind:String,pub root_fields:Vec<Option<String>>,pub path_steps:Vec<usize>,pub transforms:Vec<usize>}
#[derive(Clone,Debug)] pub struct IndexReport {
 pub database:String,pub id:u64,pub definition:DefinitionReport,pub fingerprint:u64,pub canonical_bytes:usize,pub generation:u64,pub ready:bool,pub state:IndexState,pub reason:String,
 pub bytes:u64,pub file_bytes:u64,pub last_use_ms:u64,pub build_ms:f64,pub reads:u64,pub matched_rows:u64,pub estimated_ms:f64,pub actual_ms:f64,pub lag:u64,pub wait_ms:f64,pub replacement:Option<u64>,pub repair_errors:u64,pub rows:u64,pub correlation:f64,pub idle_after_ms:u64,pub abandon_after_ms:u64,
}
pub(super) struct Clock {origin:Instant,base:AtomicU64,offset:AtomicU64}
impl Default for Clock {fn default()->Self{Self{origin:Instant::now(),base:AtomicU64::new(0),offset:AtomicU64::new(0)}}}
impl Clock {pub fn now(&self)->u64 {self.base.load(Ordering::Relaxed).saturating_add(self.offset.load(Ordering::Relaxed)).saturating_add(self.origin.elapsed().as_millis() as u64)}pub fn initialize(&self,base:u64){self.base.store(base,Ordering::Relaxed);}#[cfg(any(test,feature="crash-inject"))]pub fn advance(&self,ms:u64){self.offset.fetch_add(ms,Ordering::Relaxed);}}
pub(super) fn deadlines(d:&Manifest)->(u64,u64) {let factor=1.+(1.+d.build_ms/1000.).log2();(((30.*60.*1000.*factor).ceil() as u64).max(d.interval_ms.saturating_mul(2)),((72.*60.*60.*1000.*factor).ceil() as u64).max(d.interval_ms.saturating_mul(3)))}
#[derive(Clone)] pub(super) struct Usage {pub id:u64,pub at:u64,pub count:u64,pub matched:u64,pub estimated_ms:f64,pub actual_ms:f64}
impl Shared {
 pub(crate) fn used(&self,ids:&[u64],matched:u64,estimated_ms:f64,actual_ms:f64) {let now=self.clock.now();let mut usages=self.usages.lock().unwrap_or_else(|e|e.into_inner());for id in ids {if usages.len()>=128&&!usages.contains_key(id){continue}let value=usages.entry(*id).or_insert(Usage{id:*id,at:now,count:0,matched:0,estimated_ms:0.,actual_ms:0.});value.at=now;value.count+=1;value.matched+=matched;value.estimated_ms+=estimated_ms;value.actual_ms+=actual_ms;}}
 pub(crate) fn reports(&self)->Vec<IndexReport> {self.reports.lock().unwrap_or_else(|e|e.into_inner()).clone()}
}
pub(super) fn definition(d:&Definition)->DefinitionReport {DefinitionReport{table:d.table.clone(),kind:format!("{:?}",d.kind),root_fields:d.paths.iter().map(|p|match p.steps.first(){Some(crate::fields::Step::Key(s))=>Some(s.clone()),_=>None}).collect(),path_steps:d.paths.iter().map(|p|p.steps.len()).collect(),transforms:d.paths.iter().map(|p|p.transforms.len()).collect()}}
#[cfg(test)] mod tests {use super::*;
 #[test]fn cost_and_periodic_deadlines_ignore_wall_clock(){let def=Definition{table:"notes".into(),paths:vec![],kind:Kind::Value,directions:vec![]};let mut d=Manifest{id:1,canonical:def.canonical().unwrap(),definition:def,generation:1,ready:true,state:IndexState::Active,reason:"test".into(),last_use_ms:0,interval_ms:0,build_ms:1000.,reads:0,matched:0,bytes:0,waste:0,replacement:None,estimated_ms:0.,actual_ms:0.,summary:None,orderable:false,prefix_only_reads:0,verified_prefixes:vec![]};assert_eq!(deadlines(&d),(3600000,518400000));d.interval_ms=400000000;assert_eq!(deadlines(&d),(800000000,1200000000));let clock=Clock::default();clock.initialize(100);clock.advance(300);assert!(clock.now()>=400);}
}
