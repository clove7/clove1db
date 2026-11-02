use super::statistics::{Reservoir,RowStats};
use std::collections::BTreeMap;
use super::{format::*,Pair,Shared};
use crate::{journal::{ChangeKind,ConsumerToken,ReadView},repository::DatabaseManager,units::{Result,ClError}};
use redb::{Database, ReadableDatabase,ReadableTable,TableDefinition};
use std::{sync::{Arc,Mutex,atomic::{AtomicBool,Ordering}},thread::{self,JoinHandle},time::{Duration,Instant}};
#[cfg(all(test, feature = "derive"))] use redb::ReadableTableMetadata;
const CATALOG_META:TableDefinition<&str,&[u8]>=TableDefinition::new("__inx_catalog_meta");
const CATALOG:TableDefinition<u64,&[u8]>=TableDefinition::new("__inx_catalog");
/// Fair turn budgets. A single indivisible row/commit can exceed the time limit.
pub const BATCH_BYTES:usize=256*1024;
pub const BATCH_TIME:Duration=Duration::from_millis(4);
/// A turn of building an index reads rows for up to this long (or `BUILD_BATCH_BYTES`): a turn ends in a durable commit, and 4 ms turns spent most of a build in fsync.
const BUILD_BATCH_TIME:Duration=Duration::from_millis(100);
const BUILD_BATCH_BYTES:usize=2*1024*1024;
/// The most entries (keys and row ids) a build holds in memory before writing them, sorted. An index smaller than this is written once, in key order.
const HELD_BYTES:usize=32*1024*1024;
/// How long one turn may spend applying the changes it collected (see `Driver::tick`).
pub const APPLY_TIME:Duration=Duration::from_millis(50);
/// Lets a caller ask the worker to let go of a database's files for a while (compaction needs the file with no read open on it).
#[derive(Default)]
pub(crate) struct Gate {wanted:Mutex<std::collections::HashMap<String,usize>>,parked:Mutex<std::collections::HashSet<String>>}
impl Gate {
 fn held(&self,db:&str)->bool {self.wanted.lock().unwrap_or_else(|e|e.into_inner()).get(db).is_some_and(|n|*n>0)}
 fn park(&self,db:&str,on:bool) {let mut p=self.parked.lock().unwrap_or_else(|e|e.into_inner());if on {p.insert(db.to_string());}else{p.remove(db);}}
 fn is_parked(&self,db:&str)->bool {self.parked.lock().unwrap_or_else(|e|e.into_inner()).contains(db)}
}
/// While it lives the worker keeps no read open on the database; dropping it lets the worker go on.
pub(crate) struct Pause {gate:Arc<Gate>,db:String}
impl Drop for Pause {fn drop(&mut self){let mut w=self.gate.wanted.lock().unwrap_or_else(|e|e.into_inner());if let Some(n)=w.get_mut(&self.db){*n=n.saturating_sub(1);}}}
pub(crate) struct Worker {stop:Arc<AtomicBool>,thread:Mutex<Option<JoinHandle<()>>>,gate:Arc<Gate>}
impl Worker {
 /// Waits until the worker has let go of `db` (it finishes a running build first). Gives up with an error after `wait`.
 pub fn pause(&self,db:&str,wait:Duration)->Result<Pause> {
  *self.gate.wanted.lock().unwrap_or_else(|e|e.into_inner()).entry(db.to_string()).or_insert(0)+=1;
  let pause=Pause{gate:self.gate.clone(),db:db.to_string()};
  let start=Instant::now();
  loop {
   // a stopped worker holds nothing
   if self.thread.lock().unwrap_or_else(|e|e.into_inner()).is_none()||self.gate.is_parked(db) {return Ok(pause)}
   if start.elapsed()>wait {return Err(ClError::Validation("the index worker is busy with this database and did not let go of it in time; try again".into()))}
   thread::sleep(Duration::from_millis(2));
  }
 }
 pub fn stop(&self) {self.stop.store(true,Ordering::Release);let t=self.thread.lock().unwrap_or_else(|e|e.into_inner()).take();if let Some(t)=t {let _=t.join();}}
}
impl Drop for Worker {fn drop(&mut self){self.stop();}}
struct Driver {db:DatabaseManager,file:Arc<Database>,state:Arc<Shared>,token:Option<ConsumerToken>,meta:Metadata,defs:Vec<Manifest>,target:Option<Arc<ReadView>>,pending:Vec<Definition>,build:Option<Build>,samplers:BTreeMap<u64,Reservoir>,last_flush:Instant,repair_errors:u64,retired:Vec<Manifest>,reset_job:Option<ResetJob>,compact_job:Option<CompactJob>,last_compact_check:Instant,compact_checked_seq:Option<u64>,last_compact_bytes:u64,prepared:BTreeMap<u64,(u64,u64,Arc<crate::query::stats::FieldStats>)>,dictionary_job:Option<DictionaryJob>,budget_override:Option<Duration>,replay_since:Option<Instant>,budget_rebuilds:Vec<Instant>,hold:Option<(u64,Instant)>,
 /// The journal sequence acknowledged so far. Only a durable `.inx` checkpoint moves it (see `maintain`).
 acked:u64}
enum DictionaryFinish {Batch(u64),Build(Build),Reset(ResetJob)}
struct DictionaryJob {source:redb::ReadTransaction,targets:Vec<Manifest>,target:usize,last:Option<String>,builder:Option<fst::SetBuilder<Vec<u8>>>,finish:DictionaryFinish}
struct CompactJob {file:Arc<Database>,path:std::path::PathBuf,source:Arc<Pair>,metadata:Metadata,defs:Vec<Manifest>,tasks:Vec<CopyTask>,task:usize,last:Option<Vec<u8>>}
struct CopyTask {kind:u8,source:String,target:String,id:Option<u64>}
struct ResetJob {seq:u64,source:String,view:Arc<ReadView>,defs:Vec<Manifest>,samplers:BTreeMap<u64,Reservoir>,last:Option<String>,
 /// Trigram indexes of the reset are built in memory like a first build (`trigram::Builder`), one per index.
 builders:BTreeMap<u64,super::trigram::Builder>}
struct Build {view:Arc<ReadView>,manifest:Manifest,last:Option<String>,started:Instant,sampler:Reservoir,
 /// A trigram index is built in memory and written in key order (`trigram::Builder`): `flushing` while it is being written, `read_done` once every row has been read.
 tri:Option<super::trigram::Builder>,flushing:bool,read_done:bool,
 /// Entries of a value or token index built so far and not yet written: they are written sorted, in one pass, when the table is read or `HELD_BYTES` is reached (see `build_turn`).
 held:Vec<(Vec<u8>,String)>,held_bytes:usize,fresh:bool}
pub(super) fn identity(view:&ReadView)->Result<Identity> {
 let schema=match view.tx.open_table(TableDefinition::<&str,&[u8]>::new(crate::metadata::types::META_TABLE)) {
  Ok(t)=>match t.get(crate::metadata::types::META_KEY)? {Some(v)=>{let m:crate::metadata::types::CloveMeta=serde_json::from_slice(v.value())?;serde_json::to_vec(&m.tables)?},None=>vec![]},Err(_)=>vec![]};
 Ok(Identity{format:FORMAT,codec:crate::fields::codec::VERSION,uuid:view.database_uuid.clone(),schema})
}
fn reset(view:&ReadView)->Result<u64> {let t=view.tx.open_table(crate::journal::SEQ)?;let v=t.get("reset_generation")?.ok_or_else(||ClError::Validation("missing reset generation".into()))?;Ok(u64::from_be_bytes(v.value().try_into().map_err(|_|ClError::Validation("invalid reset generation".into()))?))}
impl Driver {
 fn open(db:DatabaseManager)->Result<Self> {Self::open_with(db,false)}
 /// `force_rebuild` is set by the open that replaces one which found the journal backlog too long to replay (see `replay_budget`): it takes the rebuild branch below.
 fn open_with(db:DatabaseManager,force_rebuild:bool)->Result<Self> {
  let state=db.indexes.clone();
  let initial=db.read_view_at_head()?;let expected_catalog=identity(&initial)?;drop(initial);
  db.journal_write(|tx,_| {let old=tx.open_table(CATALOG_META)?.get("identity")?.map(|v|serde_json::from_slice::<Identity>(v.value())).transpose()?;if old.as_ref()!=Some(&expected_catalog){tx.delete_table(CATALOG)?;tx.open_table(CATALOG)?;tx.open_table(CATALOG_META)?.insert("identity",serde_json::to_vec(&expected_catalog)?.as_slice())?;}Ok(())})?;
  let catalog=db.journal_write(|tx,_| {tx.open_table(CATALOG)?.iter()?.map(|r|{let(_,v)=r?;Ok(serde_json::from_slice::<Manifest>(v.value())?)}).collect::<Result<Vec<_>>>()})?;
  let (token,needs_rebuild)=if catalog.iter().any(|d|d.state==IndexState::Active) {let(t,r)=db.resume_index_consumer()?;(Some(t),r)} else {db.disable_index_consumer()?;(None,false)};
  let view=Arc::new(db.read_view_at_head()?);let expected=identity(&view)?;let generation=reset(&view)?;
  let path=db.dir.dir.join(format!("{}.inx",db.db_name));
  // A `.inx` that cannot be opened is rebuilt, except one another program has locked: that is "in use", and it must not be renamed away.
  let existing=if path.exists(){crate::handle::guard_open(&path,true)?;match db.redb.open_index_file(&path,false,&db.event_sink){Ok(f)=>Some(f),Err(e@crate::units::ClError::DatabaseInUse{..})=>return Err(e),Err(_)=>None}}else{None};
  let valid=existing.as_ref().and_then(|f|f.begin_read().ok()).and_then(|tx|metadata(&tx).ok()).is_some_and(|m|m.identity==expected&&m.applied<=view.head&&((m.applied<view.head&&m.reset<=generation)||(m.applied==view.head&&m.reset==generation)));
  let (file,mut meta,mut defs)=if valid {
   let f=existing.unwrap();let tx=f.begin_read()?;let m=metadata(&tx)?;let d=definitions(&tx);drop(tx);
   if let Ok(d)=d {(f,m,d)} else {drop(f);let old=path.with_extension(format!("inx.invalid-{}",uuid::Uuid::new_v4()));std::fs::rename(&path,old)?;let f=db.redb.open_index_file(&path,true,&db.event_sink)?;initialize(&f,expected.clone(),generation,view.head)?;let m=metadata(&f.begin_read()?)?;(f,m,vec![])}
  } else {
   drop(existing);if path.exists(){#[cfg(feature = "encryption")]{if db.redb.encryption.is_some(){db.event_sink.emit(&crate::LibraryEvent::Encryption{event:"encryption/index_rebuilt",file:"index"})}}std::fs::rename(&path,path.with_extension(format!("inx.invalid-{}",uuid::Uuid::new_v4())))?;}
   let f=db.redb.open_index_file(&path,true,&db.event_sink)?;initialize(&f,expected,generation,view.head)?;let m=metadata(&f.begin_read()?)?;(f,m,vec![])
  };
  let file=Arc::new(file);
  let replayable=!needs_rebuild&&token.as_ref().is_none_or(|t|db.read_changes(t,meta.applied,1).is_ok());
  let mut samplers=BTreeMap::new();{let read=file.begin_read()?;let table=read.open_table(STATS)?;for d in &defs {if let Some(bytes)=table.get(d.id)? {if let Ok(stats)=Reservoir::decode(bytes.value()){samplers.insert(d.id,stats);}}}}
  let rebuild=force_rebuild||defs.iter().any(|d|d.ready&&!samplers.contains_key(&d.id))||!valid||!replayable||defs.iter().any(|m|m.state==IndexState::Active&&!m.ready)||catalog.iter().any(|c|!defs.iter().any(|d|d.canonical==c.canonical));
  if rebuild {
   defs=catalog.into_iter().filter(|d|matches!(d.state,IndexState::Active|IndexState::Idle)&&d.validate().is_ok()).collect();
   meta.identity=identity(&view)?;meta.reset=generation;meta.applied=view.head;meta.generation+=1;
   let tx=file.begin_write()?;
   for d in defs.iter_mut().filter(|d|d.state==IndexState::Active) {d.generation=meta.generation;d.ready=false;put_definition(&tx,d)?;create_tables(&tx,d)?;}
   put_metadata(&tx,&meta)?;tx.commit()?;
   // Opening must complete repair before returning. Rows stream from one view.
   for d in defs.iter_mut().filter(|d|d.state==IndexState::Active) {
    let started=Instant::now();let mut sampler=Reservoir::default();let rows=view.tx.open_table(TableDefinition::<&str,&[u8]>::new(&d.definition.table))?;
    if d.definition.kind.postings() {
     // Held in memory and written in key order (see `trigram::Builder`).
     let mut builder=super::trigram::Builder::default();
     for row in rows.iter()? {let(k,v)=row?;let(grams,stats)=trigram_inputs(d,k.value(),v.value())?;builder.add(k.value(),&grams,&stats)?;sampler.apply(None,Some(stats));if let Some(flush)=builder.due(){flush_all(&file,d,&mut builder,flush)?;}}
     flush_all(&file,d,&mut builder,super::trigram::Flush::All)?;
    } else {
     let mut tx=file.begin_write()?;let(mut bytes,mut turn)=(0usize,Instant::now());let mut pending=vec![];
     for row in rows.iter()? {let(k,v)=row?;let seq=crate::lastwrite::get(&view.tx,&d.definition.table,k.value())?;let delta=write_row_buffered(&tx,d,k.value(),v.value(),seq,Some(&mut pending))?;sampler.apply(delta.old.as_ref(),Some(delta.new));bytes+=k.value().len()+v.value().len();if bytes>=BATCH_BYTES||turn.elapsed()>=BATCH_TIME {insert_run(&tx,d,&mut pending)?;tx.commit()?;tx=file.begin_write()?;bytes=0;turn=Instant::now();}}
     insert_run(&tx,d,&mut pending)?;tx.commit()?;
    }
    let tx=file.begin_write()?;refresh_dictionary(&tx,d)?;tx.open_table(STATS)?.insert(d.id,sampler.encode()?.as_slice())?;tx.commit()?;samplers.insert(d.id,sampler);d.ready=true;d.orderable=samplers.get(&d.id).is_some_and(|s|s.unorderable==0);d.build_ms=started.elapsed().as_secs_f64()*1000.;d.reason="recovered".into();
   }
   let tx=file.begin_write()?;for d in &defs {put_definition(&tx,d)?;}put_metadata(&tx,&meta)?;crate::fsutil::maybe_crash("index_before_manifest");tx.commit()?;crate::fsutil::maybe_crash("index_after_manifest");
   if let Some(t)=&token {db.ack(t,meta.applied)?;}
  }
  prune_invalid_indexes(&path);
  state.clock.initialize(meta.uptime_ms);
  let acked_at_open=meta.applied;
  let mut driver=Self{db,file,state,token,meta,defs,target:Some(view),pending:vec![],build:None,samplers,last_flush:Instant::now(),repair_errors:0,retired:vec![],reset_job:None,compact_job:None,last_compact_check:Instant::now(),compact_checked_seq:None,last_compact_bytes:0,prepared:BTreeMap::new(),dictionary_job:None,budget_override:budget_override(),replay_since:None,budget_rebuilds:vec![],hold:None,acked:acked_at_open};
  let (started,budget)=(Instant::now(),driver.replay_budget());
  while driver.target.as_ref().is_some_and(|v|driver.meta.applied<v.head) {
   driver.tick()?;
   // Replaying the journal change by change is slower than building the index once more when many rows changed; past the budget it stops and the existing rebuild branch builds from the current rows.
   if !force_rebuild&&started.elapsed()>=budget&&driver.target.as_ref().is_some_and(|v|driver.meta.applied<v.head) {
    driver.db.event_sink.emit(&crate::LibraryEvent::Index{event:"index/rebuild/replay_budget",generation:driver.meta.generation,fingerprint:0,rows:0,bytes:0,elapsed:started.elapsed()});
    crate::fsutil::maybe_crash("index_replay_budget_rebuild");
    let again=driver.db.clone();driver.state.clear();drop(driver);return Self::open_with(again,true);
   }
  }
  driver.publish()?;Ok(driver)
 }
 fn publish(&mut self)->Result<()> {
  let Some(view)=self.target.take() else{return Ok(())};
  if view.head!=self.meta.applied {self.target=Some(view);return Ok(())}
  let index=self.file.begin_read()?;
  if metadata(&index)?.applied!=view.head {return Err(ClError::Validation("index snapshot mismatch".into()))}
  let mut statistics=vec![];
  for d in self.defs.iter().filter(|d|d.ready&&d.state==IndexState::Active&&d.definition.kind==Kind::Value&&d.definition.paths.len()==1){if let Some(stats)=self.samplers.get(&d.id){let cached=self.prepared.entry(d.id).or_insert_with(||(d.generation,stats.revision,Arc::new(stats.field_stats(stats.revision))));if cached.0!=d.generation||cached.1!=stats.revision{*cached=(d.generation,stats.revision,Arc::new(stats.field_stats(stats.revision)));}statistics.push((d.definition.table.clone(),d.definition.paths[0].clone(),cached.2.clone()));}}

  self.update_report()?;
  self.state.publish(Arc::new(Pair{primary:view,index,published:Instant::now(),ready:self.defs.iter().filter(|d|d.ready&&d.state==IndexState::Active).count(),statistics,keep:self.file.clone(),memo:Default::default()}));Ok(())
 }
 fn start_build(&mut self,definition:Definition)->Result<()> {
  let view=if self.token.is_none() {let(t,_)=self.db.resume_index_consumer()?;self.token=Some(t);let view=Arc::new(self.db.read_view_at_head()?);self.meta.applied=view.head;self.meta.reset=reset(&view)?;view} else {self.state.pair().ok_or_else(||ClError::Validation("missing paired snapshot".into()))?.primary.clone()};
  let previous=self.defs.iter().find(|d|d.definition==definition&&!d.ready).cloned();
  let replacement=previous.as_ref().filter(|d|d.state==IndexState::Idle).map(|d|d.id);let id=if replacement.is_some(){self.defs.iter().chain(self.retired.iter()).map(|d|d.id).max().unwrap_or(0)+1}else{previous.as_ref().map(|d|d.id).unwrap_or_else(||self.defs.iter().chain(self.retired.iter()).map(|d|d.id).max().unwrap_or(0)+1)};self.meta.generation+=1;
  let mut d=Manifest{id,canonical:definition.canonical()?,definition,generation:self.meta.generation,ready:false,state:IndexState::Active,reason:"observed read benefit exceeds build cost".into(),last_use_ms:self.state.clock.now(),interval_ms:0,build_ms:0.,reads:0,matched:0,bytes:0,waste:0,replacement,estimated_ms:0.,actual_ms:0.,summary:None,orderable:false,prefix_only_reads:0,verified_prefixes:vec![]};
  if let Some(old)=previous{d.interval_ms=old.interval_ms;d.reads=old.reads;d.matched=old.matched;d.estimated_ms=old.estimated_ms;d.actual_ms=old.actual_ms;}
  // The durable definition catalog lets a deleted/corrupt derived file recover.
  self.db.journal_write(|tx,_| {tx.open_table(CATALOG)?.insert(id,serde_json::to_vec(&d)?.as_slice())?;Ok(())})?;
  let tx=self.file.begin_write()?;put_definition(&tx,&d)?;create_tables(&tx,&d)?;put_metadata(&tx,&self.meta)?;let fresh={let reverse=tx.open_table(TableDefinition::<&str,&[u8]>::new(&d.reverse()))?;redb::ReadableTableMetadata::len(&reverse)?==0};tx.commit()?;
  let tri=(d.definition.kind.postings()).then(super::trigram::Builder::default);
  self.build=Some(Build{view,manifest:d,last:None,started:Instant::now(),sampler:Reservoir::default(),tri,flushing:false,read_done:false,held:Vec::new(),held_bytes:0,fresh});Ok(())
 }
 /// One turn of a trigram build: read rows into the in-memory builder (no commit), or write part of it out in key order.
 fn trigram_build_turn(&mut self)->Result<bool> {
  let b=self.build.as_mut().unwrap();
  if b.flushing {
   let tx=self.file.begin_write()?;
   let finished=b.tri.as_mut().unwrap().flush_some(&tx,&b.manifest,super::trigram::FLUSH_CHUNK_BYTES,super::trigram::FLUSH_CHUNK_TIME)?;
   crate::fsutil::maybe_crash("index_during_build");tx.commit()?;
   if finished {b.flushing=false;}
   if finished&&b.read_done {
    let b=self.build.take().unwrap();let tx=self.file.begin_write()?;tx.open_table(STATS)?.insert(b.manifest.id,b.sampler.encode()?.as_slice())?;put_definition(&tx,&b.manifest)?;tx.commit()?;self.finish_build(b)?;
   }
   self.refresh_pair()?;return Ok(true)
  }
  let rows=b.view.tx.open_table(TableDefinition::<&str,&[u8]>::new(&b.manifest.definition.table))?;
  let lower=b.last.as_deref().map(std::ops::Bound::Excluded).unwrap_or(std::ops::Bound::Unbounded);let(mut bytes,mut done)=(0usize,true);let start=Instant::now();
  let builder=b.tri.as_mut().unwrap();
  for row in rows.range::<&str>((lower,std::ops::Bound::Unbounded))? {
   let(k,v)=row?;
   let(grams,stats)=trigram_inputs(&b.manifest,k.value(),v.value())?;builder.add(k.value(),&grams,&stats)?;b.sampler.apply(None,Some(stats));
   b.last=Some(k.value().into());bytes+=k.value().len()+v.value().len();if bytes>=BATCH_BYTES||start.elapsed()>=BATCH_TIME||builder.due().is_some(){done=false;break}
  }
  b.manifest.bytes+=bytes as u64;crate::fsutil::maybe_crash("index_during_build");
  if done {b.read_done=true;}
  // Rows are done: write everything held. Otherwise write what the held data calls for (the rows, or everything for a table too large for one pass).
  if done {builder.begin(super::trigram::Flush::All);b.flushing=true;} else if let Some(flush)=builder.due() {builder.begin(flush);b.flushing=true;}
  Ok(true)
 }
 fn build_turn(&mut self)->Result<bool> {
  if self.build.as_ref().is_some_and(|b|b.tri.is_some()) {return self.trigram_build_turn()}
  let b=self.build.as_mut().unwrap();let rows=b.view.tx.open_table(TableDefinition::<&str,&[u8]>::new(&b.manifest.definition.table))?;
  let tx=self.file.begin_write()?;let(mut bytes,mut done)=(0usize,true);let start=Instant::now();
  let lower=b.last.as_deref().map(std::ops::Bound::Excluded).unwrap_or(std::ops::Bound::Unbounded);
  for row in rows.range::<&str>((lower,std::ops::Bound::Unbounded))? {let(k,v)=row?;let seq=crate::lastwrite::get(&b.view.tx,&b.manifest.definition.table,k.value())?;crate::memory::reserve("index.build_held",&mut b.held,8)?;let before=b.held.len();let delta=write_row_core(&tx,&b.manifest,k.value(),v.value(),seq,Some(&mut b.held),b.fresh)?;for e in &b.held[before..] {b.held_bytes+=e.0.len()+e.1.len()}b.sampler.apply(delta.old.as_ref(),Some(delta.new));b.last=Some(k.value().into());bytes+=k.value().len()+v.value().len();if bytes>=BUILD_BATCH_BYTES||start.elapsed()>=BUILD_BATCH_TIME{done=false;break}}
  if done||b.held_bytes>=HELD_BYTES{insert_run(&tx,&b.manifest,&mut b.held)?;b.held_bytes=0;}
  b.manifest.bytes+=bytes as u64;crate::fsutil::maybe_crash("index_during_build");tx.commit()?;self.refresh_pair()?;
  if done {
   let b=self.build.take().unwrap();let tx=self.file.begin_write()?;tx.open_table(STATS)?.insert(b.manifest.id,b.sampler.encode()?.as_slice())?;put_definition(&tx,&b.manifest)?;tx.commit()?;
   if b.manifest.definition.kind==Kind::Token{self.start_dictionary(vec![b.manifest.clone()],DictionaryFinish::Build(b))?;}else{self.finish_build(b)?;}
  } Ok(true)
 }

 /// Lets go of every read this driver keeps on the primary, unless a job is using one (then it goes on with the job and asks again next turn).
 fn try_park(&mut self)->bool {
  if self.build.is_some()||self.dictionary_job.is_some()||self.compact_job.is_some()||self.reset_job.is_some() {return false}
  self.target=None;self.state.clear();true
 }

 fn tick(&mut self)->Result<bool> {
  self.maintain(false)?;
  if self.dictionary_job.is_some(){return self.dictionary_turn()}
  if self.compact_job.is_some(){return self.compact_turn()}
  if self.reset_job.is_some(){return self.reset_turn()}
  // While writes outpace the replay (see `idle_for_overload`) no index is rebuilt: a request for one is dropped and the optimizer asks again later. The hold ends when the journal has not grown for `quiet_period`.
  if let Some((head,since))=self.hold {let now_head=self.db.journal_head()?;if now_head!=head {self.hold=Some((now_head,Instant::now()))}else if since.elapsed()>=self.quiet_period() {self.hold=None}}
  let wanted=std::mem::take(&mut *self.state.wanted.lock().unwrap_or_else(|e|e.into_inner()));
  if self.hold.is_some() {let mut observations=self.state.observations.lock().unwrap_or_else(|e|e.into_inner());for def in &wanted {if let Ok(key)=def.canonical() {if let Some(o)=observations.get_mut(&key){o.queued=false;}}}}
  else {for def in wanted {if !self.defs.iter().any(|d|d.definition==def&&d.state==IndexState::Active)&&!self.pending.contains(&def)&&self.build.as_ref().is_none_or(|b|b.manifest.definition!=def){self.pending.push(def)}}}
  if self.build.is_some(){return self.build_turn()}
  if self.target.is_none()&&!self.pending.is_empty(){let definition=self.pending.remove(0);self.start_build(definition)?;return self.build_turn()}

  if self.target.is_none() {let view=Arc::new(self.db.read_view_at_head()?);if identity(&view)?!=self.meta.identity {self.invalidate_schema(view)?;return Ok(true)}if view.head==self.meta.applied {return self.maybe_compact()}self.target=Some(view);}
  let target=self.target.as_ref().unwrap().head;
  if self.token.is_none() {self.meta.applied=target;self.meta.reset=reset(self.target.as_ref().unwrap())?;let mut tx=self.file.begin_write()?;tx.set_durability(redb::Durability::None)?;put_metadata(&tx,&self.meta)?;tx.commit()?;self.publish()?;return Ok(true)}
  if target==self.meta.applied {self.replay_since=None;self.publish()?;return Ok(false)}
  // A backlog that has been replayed for longer than the index would take to build again is rebuilt instead (see `replay_budget`): the index is not ready until that ends and queries scan.
  let since=*self.replay_since.get_or_insert_with(Instant::now);
  if since.elapsed()>=self.replay_budget() {self.replay_since=None;return self.rebuild_for_replay_budget()}
  let start=Instant::now();let mut bytes=0;let mut effects=vec![];let mut last=self.meta.applied;
  while last<target&&bytes<BATCH_BYTES&&start.elapsed()<BATCH_TIME {
   let next=self.db.read_changes(self.token.as_ref().unwrap(),last,1)?;let Some(change)=next.into_iter().next() else {return Err(ClError::ConsumerNeedsRebuild)};
   if change.seq!=last+1 {return Err(ClError::ConsumerNeedsRebuild)}
   if let ChangeKind::TableReset{table,snapshot}=&change.kind {if self.defs.iter().any(|d|d.ready&&d.state==IndexState::Active&&d.definition.table==*table){if effects.is_empty(){self.start_reset(change.seq,table,snapshot)?;return Ok(true)}else{break}}}
   bytes+=change.kind.encode()?.len();last=change.seq;effects.push(change);
  }
  if effects.is_empty(){return Ok(false)}
  let mut tx=self.file.begin_write()?;let mut dirty=std::collections::BTreeSet::new();
  // The changes collected are applied in one transaction, but not past `APPLY_TIME`: a row that rewrites most of its trigrams costs milliseconds, and one turn of thousands of them
  // would run for seconds, past a replay budget or a stop signal. What is left is read again next turn from `meta.applied`.
  let apply_start=Instant::now();let mut done_to=self.meta.applied;
  for change in effects {if done_to!=self.meta.applied&&apply_start.elapsed()>=APPLY_TIME {break}let seq=change.seq;match change.kind {
   ChangeKind::Upsert{table,key,value}=>for d in self.defs.iter().filter(|d|d.ready&&d.state==IndexState::Active&&d.definition.table==table) {dirty.insert(d.id);let delta=write_row(&tx,d,&key,&value,change.seq)?;self.samplers.entry(d.id).or_default().apply(delta.old.as_ref(),Some(delta.new));},
   ChangeKind::Delete{table,key}=>for d in self.defs.iter().filter(|d|d.ready&&d.state==IndexState::Active&&d.definition.table==table){dirty.insert(d.id);let old=remove_row(&tx,d,&key)?;self.samplers.entry(d.id).or_default().apply(old.as_ref(),None);},
   ChangeKind::TableReset{..}=>(),_=>()
  }done_to=seq;}
  let last=done_to;
  for d in self.defs.iter_mut().filter(|d|dirty.contains(&d.id)){if let Some(stats)=self.samplers.get(&d.id){d.orderable=stats.unorderable==0;tx.open_table(STATS)?.insert(d.id,stats.encode()?.as_slice())?;put_definition(&tx,d)?;}}
  let dictionaries=self.defs.iter().filter(|d|dirty.contains(&d.id)&&d.definition.kind==Kind::Token).cloned().collect::<Vec<_>>();
  if dictionaries.is_empty(){self.meta.applied=last;if last==target{self.meta.reset=reset(self.target.as_ref().unwrap())?;}}
  // `.inx` is derived and replayable, so an applied batch is not fsynced on its own: the next durable `.inx` commit (the checkpoint in `maintain`,
  // at least once a second and at close) persists every batch before it. The journal is acknowledged only up to what a checkpoint has persisted,
  // so after any crash `.inx` falls back to its last checkpoint and the worker continues from the journal. The text path (dictionaries) keeps its own durable commits.
  if dictionaries.is_empty(){tx.set_durability(redb::Durability::None)?;}
  put_metadata(&tx,&self.meta)?;crate::fsutil::maybe_crash("index_before_commit");tx.commit()?;crate::fsutil::maybe_crash("index_after_commit");
  // Caught up with the target: there is no backlog any more, so the time a backlog has been replayed starts again with the next write (`replay_since` is the age of a backlog, not of the first write).
  if dictionaries.is_empty(){if last==target{self.replay_since=None;self.publish()?;}}
  else{self.start_dictionary(dictionaries,DictionaryFinish::Batch(last))?;}
  Ok(true)
 }
}
/// The least a journal backlog may be replayed for before a rebuild is considered (see `Driver::replay_budget`).
const MIN_REPLAY_BUDGET:Duration=Duration::from_millis(500);
/// How many times in a row (within `Driver::overload_window`) a backlog may be given up on and the index rebuilt before the writes are taken to outpace the replay: the next
/// time the index is set aside (`Idle`, queries scan) instead of being rebuilt again, and it is not rebuilt until the journal has stopped growing for `Driver::quiet_period`.
const MAX_BUDGET_REBUILDS:usize=3;
#[cfg(test)] thread_local!{static TEST_REPLAY_BUDGET:std::cell::Cell<Option<Duration>>=const{std::cell::Cell::new(None)};}
/// A replay budget fixed from outside, so that tests decide by an event and not by a clock: the thread that opens the storage can set one in a unit test,
/// and a child process of a crash test sets `CLOVE_REPLAY_BUDGET_MS`. Nothing in a normal build reads either.
fn budget_override()->Option<Duration> {
 #[cfg(test)] if let Some(d)=TEST_REPLAY_BUDGET.with(|b|b.get()) {return Some(d)}
 #[cfg(feature="crash-inject")] if let Some(ms)=std::env::var("CLOVE_REPLAY_BUDGET_MS").ok().and_then(|v|v.parse::<u64>().ok()) {return Some(Duration::from_millis(ms))}
 None
}
/// A `.inx` that could not be used is set aside as `<name>.inx.invalid-<uuid>` (see `Driver::open`). Once the new index file is in place the
/// older ones are of no use and nothing else removes them, so only the newest stays (for a person to look at). A failure to remove one is ignored.
fn prune_invalid_indexes(path:&std::path::Path) {
 let (Some(dir),Some(stem))=(path.parent(),path.file_stem().and_then(|s|s.to_str())) else{return};
 let prefix=format!("{stem}.inx.invalid-");
 let Ok(read)=std::fs::read_dir(dir) else{return};
 let mut found:Vec<(std::time::SystemTime,std::path::PathBuf)>=read.filter_map(|e|e.ok()).filter(|e|e.file_name().to_string_lossy().starts_with(&prefix)).filter_map(|e|Some((e.metadata().ok()?.modified().ok()?,e.path()))).collect();
 found.sort();found.pop();
 for (_,old) in found {let _=std::fs::remove_file(old);}
}
#[derive(serde::Serialize,serde::Deserialize)]
struct Reverse {keys:Vec<Vec<u8>>,#[serde(default)] terms:Vec<String>,#[serde(default)] stats:Option<RowStats>}
struct RowDelta {old:Option<RowStats>,new:RowStats}
/// The tables of one index generation, by kind. Trigram indexes have their own layout (`trigram.rs`).
fn create_tables(tx:&redb::WriteTransaction,d:&Manifest)->Result<()> {
 if d.definition.kind.postings() {return super::trigram::create(tx,d)}
 tx.open_table(TableDefinition::<&[u8],&str>::new(&d.entries()))?;tx.open_table(TableDefinition::<&str,&[u8]>::new(&d.reverse()))?;Ok(())
}
fn drop_tables(tx:&redb::WriteTransaction,d:&Manifest)->Result<()> {
 if d.definition.kind.postings() {return super::trigram::delete(tx,d)}
 tx.delete_table(TableDefinition::<&[u8],&str>::new(&d.entries()))?;tx.delete_table(TableDefinition::<&str,&[u8]>::new(&d.reverse()))?;
 if d.definition.kind==Kind::Token {tx.delete_table(TableDefinition::<&str,u64>::new(&terms_name(d)))?;tx.open_table(FST)?.remove(d.id)?;}Ok(())
}
fn remove_row(tx:&redb::WriteTransaction,d:&Manifest,row:&str)->Result<Option<RowStats>> {
 if d.definition.kind.postings() {return super::trigram::remove(tx,d,row)}
 let name=d.reverse();let old=tx.open_table(TableDefinition::<&str,&[u8]>::new(&name))?.remove(row)?.map(|v|v.value().to_vec());
 let Some(old)=old else{return Ok(None)};let old:Reverse=decode_reverse(row,&old)?;
 let name=d.entries();let mut entries=tx.open_table(TableDefinition::<&[u8],&str>::new(&name))?;for key in old.keys {entries.remove(key.as_slice())?;}
 if d.definition.kind==Kind::Token {let name=terms_name(d);let mut terms=tx.open_table(TableDefinition::<&str,u64>::new(&name))?;for term in old.terms {let count=terms.get(term.as_str())?.map(|n|n.value()).unwrap_or(0);if count<=1{terms.remove(term.as_str())?;}else{terms.insert(term.as_str(),count-1)?;}}}
 Ok(old.stats)
}
fn write_row(tx:&redb::WriteTransaction,d:&Manifest,row:&str,bytes:&[u8],seq:u64)->Result<RowDelta> {write_row_buffered(tx,d,row,bytes,seq,None)}
fn write_row_buffered(tx:&redb::WriteTransaction,d:&Manifest,row:&str,bytes:&[u8],seq:u64,pending:Option<&mut Vec<(Vec<u8>,String)>>)->Result<RowDelta> {write_row_core(tx,d,row,bytes,seq,pending,false)}
/// `fresh`: the row cannot have an entry already (the first build of an index whose tables were empty when it began), so there is none to remove.
fn write_row_core(tx:&redb::WriteTransaction,d:&Manifest,row:&str,bytes:&[u8],seq:u64,pending:Option<&mut Vec<(Vec<u8>,String)>>,fresh:bool)->Result<RowDelta> {
 if d.definition.kind.postings() {let(grams,stats)=trigram_inputs(d,row,bytes)?;let old=super::trigram::write(tx,d,row,&grams,&stats)?;return Ok(RowDelta{old,new:stats})}
 let old=if fresh {None} else {remove_row(tx,d,row)?};
 let sampled=if d.definition.kind==Kind::LastWrite {vec![crate::fields::Value::Number(seq.to_string())]}else if let Some(path)=d.definition.paths.first(){path_values(bytes,path)?}else{vec![]};
 let mut stats=RowStats::new(row,bytes.len(),&sampled)?;
 let values=if d.definition.kind==Kind::LastWrite {vec![crate::fields::Value::Number(seq.to_string())]}else if d.definition.paths.len()==1 {let values=sampled.clone();match d.definition.kind {Kind::Token|Kind::Trigram=>{let mut out=vec![];for value in values {if let crate::fields::Value::String(s)=value {crate::memory::probe("index.row_terms",s.len().saturating_mul(48))?;let terms=if d.definition.kind==Kind::Token {crate::query::eval::tokens(&s)}else{super::access::trigrams(&s)};out.extend(terms.into_iter().map(crate::fields::Value::String));}}out},_=>values}}else{let mut tuple=vec![];for path in &d.definition.paths {if path.steps.iter().any(|s|matches!(s,crate::fields::Step::Any|crate::fields::Step::All)){return Err(ClError::Validation("compound multikey requires a single expansion path".into()))}tuple.push(crate::query::path_value(bytes,path)?);}vec![crate::fields::Value::Array(tuple)]};
 if d.definition.paths.len()>1{stats.unorderable=u64::from(values.iter().any(|v|crate::fields::codec::encode(v).is_err()));}
 let terms=if d.definition.kind==Kind::Token {values.iter().filter_map(|v|if let crate::fields::Value::String(s)=v {Some(s.clone())}else{None}).collect::<std::collections::BTreeSet<_>>().into_iter().collect::<Vec<_>>()}else{vec![]};
 if d.definition.kind==Kind::Token {let name=terms_name(d);let mut table=tx.open_table(TableDefinition::<&str,u64>::new(&name))?;for term in &terms {let count=table.get(term.as_str())?.map(|v|v.value()).unwrap_or(0);table.insert(term.as_str(),count+1)?;}}
 let mut keys=std::collections::BTreeSet::new();for value in values {keys.insert(definition_key(d,&value,row)?);}
 if let Some(pending)=pending {pending.extend(keys.iter().map(|key|(key.clone(),row.to_owned())));}else{let name=d.entries();let mut t=tx.open_table(TableDefinition::<&[u8],&str>::new(&name))?;for key in &keys {t.insert(key.as_slice(),row)?;}}
 let mut counters=stats.clone();counters.values.clear();
 let reverse=encode_reverse(row,&Reverse{keys:keys.into_iter().collect(),terms,stats:Some(counters)})?;tx.open_table(TableDefinition::<&str,&[u8]>::new(&d.reverse()))?.insert(row,reverse.as_slice())?;Ok(RowDelta{old,new:stats})
}
/// How long the worker waits when it found nothing to do: 1 ms while changes were arriving a moment ago (`busy_until`), else 10 ms.
fn idle_pause(now:Instant,busy_until:Instant)->Duration {if now<busy_until {Duration::from_millis(1)} else {Duration::from_millis(10)}}
pub(super) fn boot(databases:&mut std::collections::HashMap<String,DatabaseManager>)->Result<Worker> {
 let mut drivers=vec![];for db in databases.values() {drivers.push(Driver::open(db.clone())?);}
 let stop=Arc::new(AtomicBool::new(false));let signal=stop.clone();let gate=Arc::new(Gate::default());let hold=gate.clone();
 let t=thread::Builder::new().name("clove-indexer".into()).spawn(move|| {
  // While changes keep arriving the worker looks again after 1 ms, so that the index is at most a moment behind the last write (a query is answered by the index only when it is at the head); once quiet for 250 ms it looks every 10 ms.
  let mut busy_until=Instant::now();
  while !signal.load(Ordering::Acquire) {
   let mut work=false;
   for d in &mut drivers {if signal.load(Ordering::Acquire){break}
    // Asked to let go of this database (compaction): once no job holds a read, drop the views and wait.
    let name=d.db.db_name.clone();
    if hold.held(&name) {if d.try_park() {hold.park(&name,true);continue}hold.park(&name,false);} else {hold.park(&name,false);}
    match d.tick() {Ok(w)=>work|=w,Err(e)=>{
    // A retained journal gap requests a fresh snapshot, never stale query output.
    d.repair_errors+=1;d.state.clear();
    // The system refused memory: the same work would be refused again at once, so repair, tell the programmer, and wait before the next attempt.
    if let ClError::OutOfMemory{bytes,..}=e {d.db.event_sink.emit(&crate::LibraryEvent::Index{event:"index/out_of_memory",generation:d.meta.generation,fingerprint:0,rows:0,bytes,elapsed:Duration::ZERO});let _=d.repair();thread::sleep(Duration::from_millis(250));continue}
    if d.repair().is_ok(){work=true;}
   }}}
   if work {busy_until=Instant::now()+Duration::from_millis(250);}
   if !work {thread::sleep(idle_pause(Instant::now(),busy_until));}
  }
  for d in &mut drivers {let _=d.maintain(true);d.state.clear();}
 }).map_err(|e|ClError::IoError(e.to_string()))?;
 Ok(Worker{stop,thread:Mutex::new(Some(t)),gate})
}

#[cfg(all(test, feature = "derive"))] mod tests {
 use super::*;use crate::{CloveFields,entity::Entity,storage::{Storage,StorageConfig,DatabaseConfig}};
 #[derive(Clone,Default,serde::Serialize,serde::Deserialize,CloveFields)] struct Note{id:String,n:i64}
 impl Entity for Note {fn entity_id(&self)->&str {&self.id}}
 fn storage(root:&std::path::Path)->Storage {Storage::builder(StorageConfig::default()).add_database(DatabaseConfig::new("records","store").dir_path(root.to_path_buf()).has_cache(false).register::<Note>("notes")).build().unwrap()}
 /// Plain database for the one test that rewrites the `.inx` with raw redb (7-5-plain-only.md).
 fn storage_plain(root:&std::path::Path)->Storage {let db=DatabaseConfig::new("records","store");#[cfg(clove_test_encrypt_all)]let db=db.plain();Storage::builder(StorageConfig::default()).add_database(db.dir_path(root.to_path_buf()).has_cache(false).register::<Note>("notes")).build().unwrap()}
 /// How long a test waits for an index. Under `--cfg clove_test_encrypt_all` every database is encrypted and the unit tests
 /// run in a debug build, where the cipher is not optimised (a build that takes 1 s plain takes 3.5-5 s encrypted); in release the
 /// contains-index build is only +2 % to +6 % (measured), so the larger limit is for the debug test build only.
 fn wait_limit()->Duration {if cfg!(clove_test_encrypt_all) {Duration::from_secs(25)} else {Duration::from_secs(5)}}
 fn wait(db:&DatabaseManager,head:u64)->Arc<Pair> {let start=Instant::now();loop {if let Some(pair)=db.indexes.pair(){if pair.primary.head==head&&definitions(&pair.index).unwrap().iter().any(|d|d.ready){return pair}}assert!(start.elapsed()<wait_limit());thread::sleep(Duration::from_millis(5));}}
 #[test] fn streamed_build_replay_and_missing_file_recovery() {
  let root=std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());let s=storage(&root);let db=s.db_manager("store");
  let entries=(0..300).map(|i|("notes".into(),format!("{i:04}"),serde_json::to_vec(&Note{id:format!("{i:04}"),n:i%7}).unwrap())).collect::<Vec<_>>();db.commit_batch_atomic(&entries,&[]).unwrap();
  db.indexes.request(Definition{table:"notes".into(),paths:vec![Note::n.path()],kind:Kind::Value,directions:vec![]});
  let pair=wait(db,db.journal_head().unwrap());let defs=definitions(&pair.index).unwrap();assert_eq!(pair.index.open_table(TableDefinition::<&[u8],&str>::new(&defs[0].entries())).unwrap().len().unwrap(),300);drop(pair);
  db.commit_batch_atomic(&[("notes".into(),"0000".into(),serde_json::to_vec(&Note{id:"0000".into(),n:99}).unwrap())],&[("notes".into(),"0001".into())]).unwrap();
  let pair=wait(db,db.journal_head().unwrap());let defs=definitions(&pair.index).unwrap();let keys=pair.index.open_table(TableDefinition::<&[u8],&str>::new(&defs[0].entries())).unwrap();assert_eq!(keys.len().unwrap(),299);assert!(keys.get(entry_key(&crate::fields::Value::Number("99".into()),"0000").unwrap().as_slice()).unwrap().is_some());drop(keys);drop(pair);
  let reset_rows=(0..200).map(|i|(format!("{i:04}"),serde_json::to_vec(&Note{id:format!("{i:04}"),n:2}).unwrap())).collect::<Vec<_>>();db.replace_table("notes",&reset_rows).unwrap();db.commit_batch_atomic(&[("notes".into(),"0000".into(),serde_json::to_vec(&Note{id:"0000".into(),n:99}).unwrap())],&[]).unwrap();let pair=wait(db,db.journal_head().unwrap());assert_eq!(s.domain::<Note>().query().filter(Note::n.eq(99)).count().unwrap(),1);let current=definitions(&pair.index).unwrap();assert_eq!(pair.index.open_table(TableDefinition::<&[u8],&str>::new(&current[0].entries())).unwrap().len().unwrap(),200);drop(pair);
  let path=db.dir.dir.join("store.inx");s.close();drop(s);std::fs::remove_file(&path).unwrap();
  let s=storage(&root);let db=s.db_manager("store");let pair=wait(db,db.journal_head().unwrap());let defs=definitions(&pair.index).unwrap();assert_eq!(pair.index.open_table(TableDefinition::<&[u8],&str>::new(&defs[0].entries())).unwrap().len().unwrap(),200);drop(pair);s.close();
 }
 #[test]fn ordered_limit_descending_ties_and_compound_esr(){
  let root=std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());let s=storage(&root);let db=s.db_manager("store");let entries=(0..3000).map(|i|("notes".into(),format!("{i:04}"),serde_json::to_vec(&Note{id:format!("{i:04}"),n:i%7}).unwrap())).collect::<Vec<_>>();db.commit_batch_atomic(&entries,&[]).unwrap();
  db.indexes.request(Definition{table:"notes".into(),paths:vec![Note::n.path()],kind:Kind::Value,directions:vec![]});drop(wait(db,db.journal_head().unwrap()));
  let rows=s.domain::<Note>().query().order_by(Note::n,crate::query::Desc).limit(5).collect().unwrap();assert_eq!(rows.iter().map(|r|r.id.as_str()).collect::<Vec<_>>(),["0006","0013","0020","0027","0034"]);
  db.indexes.request(Definition{table:"notes".into(),paths:vec![Note::n.path(),Note::id.path()],kind:Kind::Value,directions:vec![crate::query::Asc,crate::query::Desc]});let start=Instant::now();loop{if db.indexes.pair().is_some_and(|p|definitions(&p.index).unwrap().iter().any(|d|d.ready&&d.definition.paths.len()==2)){break}assert!(start.elapsed()<wait_limit());thread::sleep(Duration::from_millis(5));}
  let q=s.domain::<Note>().query().filter(Note::n.eq(3)).order_by(Note::id,crate::query::Desc).limit(5);assert_eq!(q.explain().unwrap().selected,crate::query::optimizer::Plan::IndexEsr);let rows=q.collect().unwrap();assert_eq!(rows.iter().map(|r|r.id.as_str()).collect::<Vec<_>>(),["2999","2992","2985","2978","2971"]);assert_eq!(q.count().unwrap(),429);
  let count_hint=q.test_plans(true).unwrap().into_iter().find(|h|h.plan==crate::query::optimizer::Plan::IndexCount).expect("covered IndexCount hint");assert_eq!(q.clone().test_force_plan(count_hint).count().unwrap(),429);
  let ers=s.domain::<Note>().query().filter(Note::n.ge(3)).order_by(Note::id,crate::query::Desc).limit(5);let ers_hint=ers.test_plans(false).unwrap().into_iter().find(|h|h.plan==crate::query::optimizer::Plan::IndexErs).expect("range-sort compound hint");let rows=ers.test_force_plan(ers_hint).collect().unwrap();assert_eq!(rows.iter().map(|r|r.id.as_str()).collect::<Vec<_>>(),["2999","2995","2994","2993","2992"]);s.close();
 }
 #[test]fn conflicting_equalities_cannot_use_a_covering_compound_prefix(){
  let root=std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());let s=storage(&root);let db=s.db_manager("store");let entries=(0..137).map(|i|("notes".into(),format!("{i:04}"),serde_json::to_vec(&Note{id:format!("{i:04}"),n:i%37}).unwrap())).collect::<Vec<_>>();db.commit_batch_atomic(&entries,&[]).unwrap();let definition=Definition{table:"notes".into(),paths:vec![Note::n.path(),Note::id.path()],kind:Kind::Value,directions:vec![crate::query::Asc,crate::query::Asc]};db.indexes.request(definition.clone());let started=Instant::now();let id=loop{if let Some(pair)=db.indexes.pair(){if let Some(found)=definitions(&pair.index).unwrap().into_iter().find(|d|d.definition==definition&&d.ready){break found.id;}}assert!(started.elapsed()<wait_limit());thread::sleep(Duration::from_millis(5));};
  let q=s.domain::<Note>().query().filter(Note::n.eq(1).and(Note::n.eq(24)));let hints=q.test_plans(true).unwrap().into_iter().filter(|h|h.plan==crate::query::optimizer::Plan::IndexCount&&h.index_ids==vec![id]).collect::<Vec<_>>();assert!(!hints.is_empty(),"compound count candidate");for hint in hints{assert_eq!(q.clone().test_force_plan(hint).count().unwrap(),0);}assert_eq!(q.count().unwrap(),0);s.close();
 }
 #[test]fn compact_swap_keeps_old_index_reader_alive(){
  use std::sync::atomic::AtomicU64;let compacts=Arc::new(AtomicU64::new(0));let count=compacts.clone();let config=StorageConfig::default().event_sink(move|event|{if matches!(event,crate::LibraryEvent::Index{event:"index/compact",..}){count.fetch_add(1,Ordering::Relaxed);}});
  let root=std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());let s=Storage::builder(config).add_database(DatabaseConfig::new("records","store").dir_path(root).has_cache(false).register::<Note>("notes")).build().unwrap();let db=s.db_manager("store");let entries=(0..1000).map(|i|("notes".into(),format!("{i:04}"),serde_json::to_vec(&Note{id:format!("{i:04}"),n:i%7}).unwrap())).collect::<Vec<_>>();db.commit_batch_atomic(&entries,&[]).unwrap();db.indexes.request(Definition{table:"notes".into(),paths:vec![Note::n.path()],kind:Kind::Value,directions:vec![]});let old=wait(db,db.journal_head().unwrap());let old_def=definitions(&old.index).unwrap()[0].clone();let old_generation=metadata(&old.index).unwrap().generation;
  db.indexes.compact_requested.store(true,Ordering::Release);let start=Instant::now();while compacts.load(Ordering::Acquire)==0{assert!(start.elapsed()<Duration::from_secs(10),"compact did not publish");thread::sleep(Duration::from_millis(5));}
  let new=db.indexes.pair().unwrap();assert!(metadata(&new.index).unwrap().generation>old_generation);assert_eq!(old.index.open_table(TableDefinition::<&[u8],&str>::new(&old_def.entries())).unwrap().len().unwrap(),1000);assert_eq!(s.domain::<Note>().query().filter(Note::n.eq(3)).count().unwrap(),143);drop(new);drop(old);s.close();
 }
 /// An `.inx` made when the terms of a stored field were kept in a text (Token) index: a condition on the terms (`Compare::Parts`) is answered right by a scan while there is no index of its own kind,
 /// the index of that kind (posting blocks) is built when it is asked for, and the old text index is left alone and unused.
 #[test] fn an_index_file_with_a_text_index_on_the_same_path_answers_parts_conditions_and_gets_its_own_index(){
  use crate::fields::{Compare,Expr,Predicate,Value};
  let root=std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());let s=storage_plain(&root);let db=s.db_manager("store");
  let id=|i:usize|format!("{i:04x} {:03x} {:03x}",i%512,(i*7)%512);
  let entries=(0..1500).map(|i|("notes".into(),id(i),serde_json::to_vec(&Note{id:id(i),n:0}).unwrap())).collect::<Vec<_>>();db.commit_batch_atomic(&entries,&[]).unwrap();
  db.indexes.request(Definition{table:"notes".into(),paths:vec![Note::id.path()],kind:Kind::Token,directions:vec![]});drop(wait(db,db.journal_head().unwrap()));
  s.close();drop(s);
  let s=storage_plain(&root);
  let pred=|terms:&str|Predicate::<Note>::with_printed(Expr::Compare{path:Note::id.path(),op:Compare::Parts,values:vec![Value::String(terms.into())]},vec![]);
  let expected=|terms:&str|{let want=crate::query::eval::tokens(terms);(0..1500).filter(|i|{let have=crate::query::eval::tokens(&id(*i));want.iter().all(|t|have.contains(t))}).count() as u64};
  let queries=["007 00e","1f0","000 001","0001 001"];
  for t in queries {assert_eq!(s.domain::<Note>().query().filter(pred(t)).count().unwrap(),expected(t),"by scan: {t}");}
  let start=Instant::now();loop{let q=s.domain::<Note>().query().filter(pred("007 00e"));let _=q.test_build_indexes();if s.index_report().iter().any(|r|r.ready&&r.definition.kind=="Parts"){break}assert!(start.elapsed()<wait_limit(),"no parts index: {:?}",s.index_report());thread::sleep(Duration::from_millis(5));}
  for t in queries {let q=s.domain::<Note>().query().filter(pred(t));assert_eq!(q.count().unwrap(),expected(t),"with the index: {t}");assert_eq!(q.collect().unwrap().len() as u64,expected(t));}
  assert_eq!(s.domain::<Note>().query().filter(pred("007 00e")).explain().unwrap().selected,crate::query::optimizer::Plan::IndexContains);
  s.close();
 }
 /// The pair that was published before a swap keeps its own `.inx` database open (`Pair::keep`), and the database closes when the last such pair is gone, leaving one file with the index's name.
 #[test]fn the_old_index_database_stays_open_for_its_last_pair_and_closes_after_it(){
  use std::sync::atomic::AtomicU64;let compacts=Arc::new(AtomicU64::new(0));let count=compacts.clone();let config=StorageConfig::default().event_sink(move|event|{if matches!(event,crate::LibraryEvent::Index{event:"index/compact",..}){count.fetch_add(1,Ordering::Relaxed);}});
  let root=std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());let s=Storage::builder(config).add_database(DatabaseConfig::new("records","store").dir_path(root.clone()).has_cache(false).register::<Note>("notes")).build().unwrap();let db=s.db_manager("store");
  let entries=(0..1000).map(|i|("notes".into(),format!("{i:04}"),serde_json::to_vec(&Note{id:format!("{i:04}"),n:i%7}).unwrap())).collect::<Vec<_>>();db.commit_batch_atomic(&entries,&[]).unwrap();db.indexes.request(Definition{table:"notes".into(),paths:vec![Note::n.path()],kind:Kind::Value,directions:vec![]});
  let old=wait(db,db.journal_head().unwrap());let old_def=definitions(&old.index).unwrap()[0].clone();let gone=Arc::downgrade(&old.keep);
  db.indexes.compact_requested.store(true,Ordering::Release);let start=Instant::now();while compacts.load(Ordering::Acquire)==0{assert!(start.elapsed()<Duration::from_secs(10),"compact did not publish");thread::sleep(Duration::from_millis(5));}
  let new=db.indexes.pair().unwrap();assert!(!Arc::ptr_eq(&new.keep,&old.keep),"the swap published a pair on the new file");
  // The old pair still reads, and it alone holds its database.
  assert_eq!(old.index.open_table(TableDefinition::<&[u8],&str>::new(&old_def.entries())).unwrap().len().unwrap(),1000);
  assert_eq!(gone.strong_count(),1,"only the old pair holds the old database");
  drop(old);let start=Instant::now();while gone.upgrade().is_some(){assert!(start.elapsed()<Duration::from_secs(5),"the old database is still open after its last pair");thread::sleep(Duration::from_millis(5));}
  // One file carries the index's name; the compacted copy that was built beside it is not left behind.
  let names=std::fs::read_dir(&db.dir.dir).unwrap().filter_map(|e|e.ok()).map(|e|e.file_name().to_string_lossy().to_string()).filter(|n|n.starts_with("store.inx")).collect::<Vec<_>>();assert_eq!(names,["store.inx"],"{names:?}");
  assert_eq!(s.domain::<Note>().query().filter(Note::n.eq(3)).count().unwrap(),143);drop(new);s.close();
 }
 #[test] fn trigram_index_survives_compaction_incremental_writes_and_a_lost_inx_file() {
  use std::sync::atomic::AtomicU64;use crate::query::optimizer::Plan;
  let compacts=Arc::new(AtomicU64::new(0));
  let root=std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());let open=||Storage::builder(config_clone(&compacts)).add_database(DatabaseConfig::new("records","store").dir_path(root.clone()).has_cache(false).register::<Note>("notes")).build().unwrap();
  fn config_clone(c:&Arc<AtomicU64>)->StorageConfig {let count=c.clone();StorageConfig::default().event_sink(move|event|{if matches!(event,crate::LibraryEvent::Index{event:"index/compact",..}){count.fetch_add(1,Ordering::Relaxed);}})}
  let word=|i:usize|["alpha","beta","gamma","delta"][i%4];let id=|i:usize|format!("k{i:04}-{}",word(i));
  let mut model=std::collections::BTreeMap::<String,()>::new();
  let s=open();let db=s.db_manager("store");
  let entries=(0..2000).map(|i|{model.insert(id(i),());("notes".into(),id(i),serde_json::to_vec(&Note{id:id(i),n:0}).unwrap())}).collect::<Vec<_>>();db.commit_batch_atomic(&entries,&[]).unwrap();
  db.indexes.request(Definition{table:"notes".into(),paths:vec![Note::id.path()],kind:Kind::Trigram,directions:vec![]});drop(wait(db,db.journal_head().unwrap()));
  let check=|s:&Storage,model:&std::collections::BTreeMap<String,()>,label:&str|{for needle in ["alph","eta-","k00","amm","delta","k0012-g","zzz"] {
   let q=s.domain::<Note>().query().filter(Note::id.contains(needle));let hint=q.test_plans(true).unwrap().into_iter().find(|h|h.plan==Plan::IndexContains).unwrap_or_else(||panic!("{label}: no contains plan for {needle}"));
   let expected=model.keys().filter(|k|k.contains(needle)).cloned().collect::<Vec<_>>();let got=q.clone().test_force_plan(hint).collect().unwrap().into_iter().map(|n|n.id).collect::<Vec<_>>();assert_eq!(got,expected,"{label}: {needle}");}};
  check(&s,&model,"built");
  db.indexes.compact_requested.store(true,Ordering::Release);let start=Instant::now();while compacts.load(Ordering::Acquire)==0{assert!(start.elapsed()<Duration::from_secs(20),"compact did not publish");thread::sleep(Duration::from_millis(5));}
  drop(wait(db,db.journal_head().unwrap()));check(&s,&model,"compacted");
  // Writes after the compaction go through the copied tables: new rows get fresh numbers, deleted ones leave no trace.
  let more=(2000..2300).map(|i|{model.insert(id(i),());("notes".into(),id(i),serde_json::to_vec(&Note{id:id(i),n:0}).unwrap())}).collect::<Vec<_>>();let gone=(0..2000).step_by(7).map(|i|{model.remove(&id(i));("notes".to_string(),id(i))}).collect::<Vec<_>>();db.commit_batch_atomic(&more,&gone).unwrap();drop(wait(db,db.journal_head().unwrap()));check(&s,&model,"written after compaction");
  // The derived file is lost: the catalog in the primary file rebuilds it.
  let path=db.dir.dir.join("store.inx");s.close();drop(s);std::fs::remove_file(&path).unwrap();
  let s=open();let db=s.db_manager("store");drop(wait(db,db.journal_head().unwrap()));check(&s,&model,"rebuilt from the catalog");s.close();
 }
 // ── the replay budget: a journal backlog that takes longer to replay than the index takes to build is rebuilt instead ──
 #[derive(Clone,Default,serde::Serialize,serde::Deserialize,CloveFields)] struct Doc{id:String,text:String}
 impl Entity for Doc {fn entity_id(&self)->&str {&self.id}}
 fn doc_text(i:u64,variant:u64)->String {format!("row {i} variant {variant} alpha beta gamma delta {} {}",i*7%13,"filler text to make the row longer ".repeat(5))}
 fn doc_rows(variant:u64,count:u64)->Vec<(String,String,Vec<u8>)> {(0..count).map(|i|("docs".to_string(),format!("{i:05}"),serde_json::to_vec(&Doc{id:format!("{i:05}"),text:doc_text(i,variant)}).unwrap())).collect()}
 fn events_storage(root:&std::path::Path,seen:&Arc<Mutex<Vec<&'static str>>>)->Storage {
  let sink=seen.clone();let config=StorageConfig::default().event_sink(move|e|{if let crate::LibraryEvent::Index{event,..}=e{sink.lock().unwrap().push(*event)}});
  let db=DatabaseConfig::new("records","store");#[cfg(clove_test_encrypt_all)]let db=db.plain();
  Storage::builder(config).add_database(db.dir_path(root.to_path_buf()).has_cache(false).register::<Doc>("docs")).build().unwrap()
 }
 fn count_of(seen:&Arc<Mutex<Vec<&'static str>>>,name:&str)->usize {seen.lock().unwrap().iter().filter(|e|**e==name).count()}
 /// (answer by the contains index if it is ready, answer by a full scan) for one needle.
 fn answers(s:&Storage,needle:&str)->(Option<u64>,u64) {use crate::query::optimizer::Plan;
  let q=s.domain::<Doc>().query().filter(Doc::text.contains(needle));let hints=q.test_plans(true).unwrap();
  let indexed=hints.iter().find(|h|h.plan==Plan::IndexContains).map(|h|q.clone().test_force_plan(h.clone()).count().unwrap());
  let scan=hints.iter().find(|h|h.plan==Plan::FullScan).map(|h|q.clone().test_force_plan(h.clone()).count().unwrap()).unwrap();(indexed,scan)
 }
 fn until_indexed(s:&Storage,needle:&str)->(u64,u64) {let start=Instant::now();loop{let (i,scan)=answers(s,needle);if let Some(i)=i{return (i,scan)}assert!(start.elapsed()<Duration::from_secs(60),"the contains index never became ready");thread::sleep(Duration::from_millis(10));}}
 fn copy_dir(from:&std::path::Path,to:&std::path::Path) {std::fs::create_dir_all(to).unwrap();for e in std::fs::read_dir(from).unwrap().flatten(){let p=e.path();let t=to.join(e.file_name());if p.is_dir(){copy_dir(&p,&t)}else{std::fs::copy(&p,&t).unwrap();}}}
 /// A database whose index is current for variant 0, then 6000 rewrites written and the storage closed at once, so that most of them are still in the journal.
 fn with_backlog()->std::path::PathBuf {
  let root=std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());let seen=Arc::new(Mutex::new(vec![]));let s=events_storage(&root,&seen);let db=s.db_manager("store");
  db.commit_batch_atomic(&doc_rows(0,6000),&[]).unwrap();
  db.indexes.request(Definition{table:"docs".into(),paths:vec![Doc::text.path()],kind:Kind::Trigram,directions:vec![]});drop(wait(db,db.journal_head().unwrap()));
  db.commit_batch_atomic(&doc_rows(1,6000),&[]).unwrap();s.close();drop(s);root
 }
 /// At open: a backlog over the budget is rebuilt (with the event), one under it is replayed; both give the answers a full scan gives, and the same ones.
 #[test] fn a_journal_backlog_over_the_replay_budget_is_rebuilt_at_open_and_the_answers_match() {
  let rebuilt_root=with_backlog();let replayed_root=std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());copy_dir(&rebuilt_root,&replayed_root);
  TEST_REPLAY_BUDGET.with(|b|b.set(Some(Duration::ZERO)));let seen=Arc::new(Mutex::new(vec![]));let a=events_storage(&rebuilt_root,&seen);
  assert_eq!(count_of(&seen,"index/rebuild/replay_budget"),1,"the backlog was over the budget, so the open rebuilt: {:?}",seen.lock().unwrap());
  TEST_REPLAY_BUDGET.with(|b|b.set(Some(Duration::from_secs(3600))));let seen2=Arc::new(Mutex::new(vec![]));let b=events_storage(&replayed_root,&seen2);
  TEST_REPLAY_BUDGET.with(|b|b.set(None));
  assert_eq!(count_of(&seen2,"index/rebuild/replay_budget"),0,"under the budget the backlog is replayed: {:?}",seen2.lock().unwrap());
  for needle in ["alpha","variant 1 ","variant 0 ","row 77 ","delta 5 ","zzzzz"] {
   let (ia,sa)=until_indexed(&a,needle);let (ib,sb)=until_indexed(&b,needle);
   assert_eq!(ia,sa,"rebuilt: index equals scan for {needle:?}");assert_eq!(ib,sb,"replayed: index equals scan for {needle:?}");assert_eq!((ia,sa),(ib,sb),"rebuilding and replaying give the same answers for {needle:?}");
  }
  assert_eq!(answers(&a,"variant 1 ").1,6000);assert_eq!(answers(&a,"variant 0 ").1,0,"every row was rewritten");
  a.close();b.close();let _=std::fs::remove_dir_all(&rebuilt_root);let _=std::fs::remove_dir_all(&replayed_root);
 }
 /// While running: a backlog over the budget is given up on and the index is built again; it is not ready meanwhile and the answers stay right.
 #[test] fn a_running_worker_rebuilds_a_backlog_over_the_budget() {
  let root=std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());let seen=Arc::new(Mutex::new(vec![]));
  TEST_REPLAY_BUDGET.with(|b|b.set(Some(Duration::ZERO)));let s=events_storage(&root,&seen);TEST_REPLAY_BUDGET.with(|b|b.set(None));
  let db=s.db_manager("store");db.commit_batch_atomic(&doc_rows(0,3000),&[]).unwrap();
  db.indexes.request(Definition{table:"docs".into(),paths:vec![Doc::text.path()],kind:Kind::Trigram,directions:vec![]});
  drop(wait(db,db.journal_head().unwrap()));
  db.commit_batch_atomic(&doc_rows(1,3000),&[]).unwrap();
  let start=Instant::now();while count_of(&seen,"index/rebuild/replay_budget")==0{assert!(start.elapsed()<Duration::from_secs(30),"no rebuild for the replay budget: {:?}",seen.lock().unwrap());thread::sleep(Duration::from_millis(5));}
  let (i,scan)=until_indexed(&s,"variant 1 ");assert_eq!((i,scan),(3000,3000));assert_eq!(answers(&s,"variant 0 ").1,0);
  assert!(count_of(&seen,"index/rebuild")>=1,"the existing rebuild path ran too");
  s.close();let _=std::fs::remove_dir_all(&root);
 }
 /// Writes that the worker keeps up with, for longer than the replay budget: the backlog is never more than a moment old, so nothing is rebuilt and the index keeps answering.
 /// (The budget is the time a backlog may be replayed, not the time since the first write.)
 #[test] fn writes_the_worker_keeps_up_with_never_rebuild_the_index_however_long_they_last() {
  let root=std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());let seen=Arc::new(Mutex::new(vec![]));
  TEST_REPLAY_BUDGET.with(|b|b.set(Some(Duration::from_millis(400))));let s=events_storage(&root,&seen);TEST_REPLAY_BUDGET.with(|b|b.set(None));
  let db=s.db_manager("store");db.commit_batch_atomic(&doc_rows(0,2000),&[]).unwrap();
  let def=||Definition{table:"docs".into(),paths:vec![Doc::text.path()],kind:Kind::Trigram,directions:vec![]};
  db.indexes.request(def());drop(wait(db,db.journal_head().unwrap()));
  until_indexed(&s,"variant 0 ");
  // one small write every 20 ms for five budgets: the worker applies each at once
  let start=Instant::now();let mut written=0u64;
  while start.elapsed()<Duration::from_secs(2) {written+=1;db.commit_batch_atomic(&doc_rows(written,1),&[]).unwrap();thread::sleep(Duration::from_millis(20));}
  assert_eq!(count_of(&seen,"index/rebuild/replay_budget"),0,"a rebuild although the worker kept up with {written} writes: {:?}",seen.lock().unwrap());
  assert_eq!(count_of(&seen,"index/state"),0,"the index was set aside: {:?}",seen.lock().unwrap());
  let (indexed,scan)=until_indexed(&s,"variant 0 ");assert_eq!(indexed,scan,"the index answers like a scan");
 }
 /// What a published pair says about its index file (identity, definitions) is read once for the pair: an index built after queries were answered is in the next pair, and the next query uses it.
 #[test] fn an_index_built_after_queries_were_answered_is_used_by_the_next_query() {
  use crate::query::optimizer::Plan;
  let root=std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());let seen=Arc::new(Mutex::new(vec![]));let s=events_storage(&root,&seen);
  let db=s.db_manager("store");db.commit_batch_atomic(&doc_rows(0,2000),&[]).unwrap();
  db.indexes.request(Definition{table:"docs".into(),paths:vec![Doc::text.path()],kind:Kind::Trigram,directions:vec![]});drop(wait(db,db.journal_head().unwrap()));
  until_indexed(&s,"variant 0 ");
  for _ in 0..50 {assert_eq!(answers(&s,"variant 0 ").0.is_some(),true);}
  // a second index, of another kind, after the first was answering
  db.indexes.request(Definition{table:"docs".into(),paths:vec![Doc::id.path()],kind:Kind::Value,directions:vec![]});
  let start=Instant::now();
  loop {
   let plan=s.domain::<Doc>().query().filter(Doc::id.eq("00007".to_string())).explain().map(|e|e.selected).ok();
   if plan==Some(Plan::IndexEquality) {break}
   assert!(start.elapsed()<Duration::from_secs(30),"the index built later was never used: {plan:?} {:?}",s.index_report());thread::sleep(Duration::from_millis(10));
  }
  assert_eq!(s.domain::<Doc>().query().filter(Doc::id.eq("00007".to_string())).count().unwrap(),1);
  assert!(answers(&s,"variant 0 ").0.is_some(),"the first index still answers");
 }
 /// While changes keep arriving the worker looks again after 1 ms (so the index is at most a moment behind the last write, and a query is answered by the index and not by a scan); once quiet it looks every 10 ms.
 #[test] fn the_worker_looks_again_at_once_while_changes_arrive_and_slowly_when_quiet() {
  let now=Instant::now();
  assert_eq!(idle_pause(now,now+Duration::from_millis(250)),Duration::from_millis(1));
  assert_eq!(idle_pause(now,now),Duration::from_millis(10));
  assert_eq!(idle_pause(now+Duration::from_secs(1),now+Duration::from_millis(250)),Duration::from_millis(10));
 }
 /// Writes that keep outpacing the replay: three rebuilds, then the index is set aside (`Idle`, queries scan), nothing is rebuilt while the journal keeps growing, and once the
 /// writes stop the index comes back and answers like a scan. Decided by events, with the replay budget fixed at zero so that every backlog is over it.
 #[test] fn writes_that_outpace_the_replay_stop_the_rebuilding_until_the_journal_is_quiet() {
  let root=std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());let seen=Arc::new(Mutex::new(vec![]));
  TEST_REPLAY_BUDGET.with(|b|b.set(Some(Duration::ZERO)));let s=events_storage(&root,&seen);TEST_REPLAY_BUDGET.with(|b|b.set(None));
  let db=s.db_manager("store");db.commit_batch_atomic(&doc_rows(0,2000),&[]).unwrap();
  let def=||Definition{table:"docs".into(),paths:vec![Doc::text.path()],kind:Kind::Trigram,directions:vec![]};
  db.indexes.request(def());drop(wait(db,db.journal_head().unwrap()));
  for round in 0..3usize {
   db.commit_batch_atomic(&doc_rows(round as u64+1,2000),&[]).unwrap();
   let start=Instant::now();while count_of(&seen,"index/rebuild/replay_budget")<round+1{assert!(start.elapsed()<Duration::from_secs(30),"rebuild {round} never came: {:?}",seen.lock().unwrap());thread::sleep(Duration::from_millis(5));}
   until_indexed(&s,&format!("variant {} ",round+1));
  }
  assert_eq!(count_of(&seen,"index/rebuild/replay_budget"),3);assert_eq!(count_of(&seen,"index/state"),0);
  // the fourth backlog is not rebuilt: the index is set aside
  db.commit_batch_atomic(&doc_rows(4,2000),&[]).unwrap();
  let start=Instant::now();while count_of(&seen,"index/state")==0{assert!(start.elapsed()<Duration::from_secs(30),"the index was never set aside: {:?}",seen.lock().unwrap());thread::sleep(Duration::from_millis(5));}
  assert_eq!(count_of(&seen,"index/rebuild/replay_budget"),3,"no fourth rebuild: {:?}",seen.lock().unwrap());
  // the report is published right after the event
  let start=Instant::now();while !s.index_report().iter().all(|r|!r.ready&&format!("{:?}",r.state)=="Idle"){assert!(start.elapsed()<Duration::from_secs(10),"set aside: {:?}",s.index_report());thread::sleep(Duration::from_millis(5));}
  let (indexed,scan)=answers(&s,"variant 4 ");assert_eq!((indexed,scan),(None,2000),"queries scan and are right");
  // while the journal keeps growing nothing is rebuilt, however often the index is asked for
  let (builds,state_events)=(count_of(&seen,"index/build"),count_of(&seen,"index/state"));
  for i in 0..60u64 {db.commit_batch_atomic(&doc_rows(4,1)[..1],&[]).unwrap_or(());let _=i;db.indexes.request(def());thread::sleep(Duration::from_millis(20));}
  assert_eq!(count_of(&seen,"index/build"),builds,"no index was built during the overload: {:?}",seen.lock().unwrap());
  assert_eq!(count_of(&seen,"index/rebuild/replay_budget"),3);assert_eq!(count_of(&seen,"index/state"),state_events);
  // the writes stop: after the quiet period the next request builds the index again
  let start=Instant::now();let (i,scan)=loop{db.indexes.request(def());let (i,scan)=answers(&s,"variant 4 ");if let Some(i)=i{break (i,scan)}assert!(start.elapsed()<Duration::from_secs(60),"the index never came back: {:?}",seen.lock().unwrap());thread::sleep(Duration::from_millis(50));};
  assert_eq!((i,scan),(2000,2000));assert_eq!(count_of(&seen,"index/rebuild/replay_budget"),3,"still three");
  s.close();let _=std::fs::remove_dir_all(&root);
 }
 /// Three index files in a row are set aside (here: overwritten with garbage); once each new one is in place only the newest set-aside file is left.
 #[test] fn only_the_newest_set_aside_index_file_stays() {
  let root=std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());let mut s=storage_plain(&root);let db=s.db_manager("store");
  let entries=(0..200).map(|i|("notes".into(),format!("{i:04}"),serde_json::to_vec(&Note{id:format!("{i:04}"),n:i%7}).unwrap())).collect::<Vec<_>>();db.commit_batch_atomic(&entries,&[]).unwrap();
  db.indexes.request(Definition{table:"notes".into(),paths:vec![Note::n.path()],kind:Kind::Value,directions:vec![]});drop(wait(db,db.journal_head().unwrap()));
  let invalid=|dir:&std::path::Path|{let mut v=std::fs::read_dir(dir).unwrap().filter_map(|e|e.ok()).map(|e|e.file_name().to_string_lossy().to_string()).filter(|n|n.starts_with("store.inx.invalid-")).collect::<Vec<_>>();v.sort();v};
  let mut previous=vec![];
  for round in 0..3 {
   let inx=s.db_manager("store").dir.dir.join("store.inx");s.close();drop(s);std::fs::write(&inx,b"not a redb file").unwrap();
   s=storage_plain(&root);let db=s.db_manager("store");drop(wait(db,db.journal_head().unwrap()));
   let now=invalid(&db.dir.dir);assert_eq!(now.len(),1,"round {round}: only the newest set-aside file stays, got {now:?}");
   assert_ne!(now,previous,"round {round}: the file kept is the newest, not the first");previous=now;
  }
  s.close();let _=std::fs::remove_dir_all(&root);
 }
 /// An index file written before the layout changed (format 3) is not read: it is replaced, and the index is built again; a catalog written before
 /// the change is dropped, and the index is built again when a query asks for it. Answers are right throughout.
 #[test] fn an_index_file_of_the_previous_format_is_rebuilt() {
  use crate::query::optimizer::Plan;
  let root=std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
  let id=|i:usize|format!("k{i:04}-{}",["alpha","beta","gamma","delta"][i%4]);
  let expected=|needle:&str|(0..1500).filter(|i|id(*i).contains(needle)).count() as u64;
  let forced=|s:&Storage,needle:&str|->Option<u64>{let q=s.domain::<Note>().query().filter(Note::id.contains(needle));let hint=q.test_plans(true).unwrap().into_iter().find(|h|h.plan==Plan::IndexContains)?;Some(q.test_force_plan(hint).count().unwrap())};
  let ready=|s:&Storage|{let start=Instant::now();loop{if forced(s,"alph").is_some(){return}assert!(start.elapsed()<Duration::from_secs(20),"the contains index never became current");thread::sleep(Duration::from_millis(5));}};
  let s=storage_plain(&root);let db=s.db_manager("store");
  let entries=(0..1500).map(|i|("notes".into(),id(i),serde_json::to_vec(&Note{id:id(i),n:0}).unwrap())).collect::<Vec<_>>();db.commit_batch_atomic(&entries,&[]).unwrap();
  db.indexes.request(Definition{table:"notes".into(),paths:vec![Note::id.path()],kind:Kind::Trigram,directions:vec![]});drop(wait(db,db.journal_head().unwrap()));
  assert_eq!(forced(&s,"alph"),Some(expected("alph")));
  let inx=db.dir.dir.join("store.inx");
  let old_format=|path:&std::path::Path|{let f=Database::open(path).unwrap();let rt=f.begin_read().unwrap();let mut m=metadata(&rt).unwrap();drop(rt);m.identity.format=3;let tx=f.begin_write().unwrap();put_metadata(&tx,&m).unwrap();tx.commit().unwrap();};
  // (a) only the index file is of the old format: the catalog still knows the index, so it is rebuilt before the database opens.
  s.close();drop(s);old_format(&inx);
  let s=storage_plain(&root);ready(&s);assert_eq!(forced(&s,"alph"),Some(expected("alph")));assert_eq!(forced(&s,"eta-"),Some(expected("eta-")));
  let invalid=|dir:&std::path::Path|std::fs::read_dir(dir).unwrap().filter_map(|e|e.ok()).filter(|e|e.file_name().to_string_lossy().starts_with("store.inx.invalid-")).count();
  assert_eq!(invalid(&s.db_manager("store").dir.dir),1,"the old file was set aside, not read");
  // (b) the catalog is old too: it is dropped. Queries stay right (by scan), and the index is built again when asked for.
  let db=s.db_manager("store");db.journal_write(|tx,_|{let mut old=Identity{format:3,codec:0,uuid:vec![],schema:vec![]};if let Some(v)=tx.open_table(CATALOG_META)?.get("identity")?{old=serde_json::from_slice(v.value())?;}old.format=3;tx.open_table(CATALOG_META)?.insert("identity",serde_json::to_vec(&old)?.as_slice())?;Ok(())}).unwrap();
  let inx=db.dir.dir.join("store.inx");s.close();drop(s);old_format(&inx);
  let s=storage_plain(&root);let q=s.domain::<Note>().query().filter(Note::id.contains("alph"));assert_eq!(q.count().unwrap(),expected("alph"),"right before any index exists again");
  assert!(forced(&s,"alph").is_none()&&!s.index_report().iter().any(|r|r.ready),"the old catalog and index file were dropped");
  q.test_build_indexes().unwrap();ready(&s);assert_eq!(forced(&s,"alph"),Some(expected("alph")));assert_eq!(q.count().unwrap(),expected("alph"));
  s.close();let _=std::fs::remove_dir_all(&root);
 }
 #[test] fn fst_dictionary_replays_updates_and_deletes() {
  let root=std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());let s=storage(&root);let db=s.db_manager("store");
  let entries=(0..1000).map(|i|("notes".into(),format!("{i:04}"),serde_json::to_vec(&Note{id:if i==0{"alpha".into()}else if i==1{"alphi".into()}else{"ordinary".into()},n:i}).unwrap())).collect::<Vec<_>>();db.commit_batch_atomic(&entries,&[]).unwrap();db.indexes.request(Definition{table:"notes".into(),paths:vec![Note::id.path()],kind:Kind::Token,directions:vec![]});drop(wait(db,db.journal_head().unwrap()));
  let q=s.domain::<Note>().query().filter(Note::id.fuzzy("alpha",1));assert_eq!(q.count().unwrap(),2);assert_eq!(q.explain().unwrap().selected,crate::query::optimizer::Plan::IndexFuzzy);
  db.commit_batch_atomic(&[("notes".into(),"0000".into(),serde_json::to_vec(&Note{id:"ordinary".into(),n:0}).unwrap())],&[("notes".into(),"0001".into())]).unwrap();drop(wait(db,db.journal_head().unwrap()));assert_eq!(q.count().unwrap(),0);s.close();
 }
 #[test] fn matching_pairs_during_continuous_commits() {
  use std::sync::atomic::AtomicU64;
  let active=Arc::new(AtomicBool::new(false));let indexed=Arc::new(AtomicU64::new(0));let a=active.clone();let n=indexed.clone();
  let config=StorageConfig::default().event_sink(move|event|{if a.load(Ordering::Relaxed)&&matches!(event,crate::LibraryEvent::Query{plan:crate::query::optimizer::Plan::IndexEquality,..}){n.fetch_add(1,Ordering::Relaxed);}});
  let root=std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());let s=Storage::builder(config).add_database(DatabaseConfig::new("records","store").dir_path(root).has_cache(false).register::<Note>("notes")).build().unwrap();let db=s.db_manager("store");
  let entries=(0..1000).map(|i|("notes".into(),format!("{i:04}"),serde_json::to_vec(&Note{id:format!("{i:04}"),n:i%7}).unwrap())).collect::<Vec<_>>();db.commit_batch_atomic(&entries,&[]).unwrap();db.indexes.request(Definition{table:"notes".into(),paths:vec![Note::n.path()],kind:Kind::Value,directions:vec![]});drop(wait(db,db.journal_head().unwrap()));
  let writer=db.clone();let running=active.clone();let thread=thread::spawn(move||{running.store(true,Ordering::Release);for i in 0..1000 {let key=format!("{:04}",i%50);writer.commit_batch_atomic(&[("notes".into(),key.clone(),serde_json::to_vec(&Note{id:key,n:i%11}).unwrap())],&[]).unwrap();thread::sleep(Duration::from_millis(2));}running.store(false,Ordering::Release);});
  let query=s.domain::<Note>().query().filter(Note::n.eq(3));
  for _ in 0..1000 {let view=db.indexes.view(db,false).unwrap();let expected=view.table_entries("notes").unwrap().into_iter().filter_map(|(key,bytes)|{let note:Note=serde_json::from_slice(&bytes).unwrap();(note.n==3).then_some(key)}).collect::<Vec<_>>();let found=query.collect_in(&view).unwrap().into_iter().map(|n|n.id).collect::<Vec<_>>();assert_eq!(found,expected);}
  thread.join().unwrap();assert!(indexed.load(Ordering::Relaxed)>0,"must exercise an index while the writer is active");s.close();
 }
}

fn path_values(bytes:&[u8],path:&crate::fields::Path)->Result<Vec<crate::fields::Value>> {
 if let Some(i)=path.steps.iter().position(|s|matches!(s,crate::fields::Step::Any)) {
  let crate::fields::Value::Array(items)=crate::fields::extract(bytes,&path.steps[..i])? else{return Ok(vec![])};
  let mut result=vec![];for n in 0..items.len(){let mut next=path.clone();next.steps[i]=crate::fields::Step::Index(n);result.extend(path_values(bytes,&next)?);}Ok(result)
 }else {Ok(vec![crate::query::path_value(bytes,path)?])}
}

fn terms_name(d:&Manifest)->String {format!("__inx_terms_{}_{}",d.id,d.generation)}
fn refresh_dictionary(tx:&redb::WriteTransaction,d:&Manifest)->Result<()> {
 if d.definition.kind!=Kind::Token {return Ok(())}
 let mut builder=fst::SetBuilder::memory();let table=tx.open_table(TableDefinition::<&str,u64>::new(&terms_name(d)))?;
 for row in table.iter()? {let(term,_)=row?;builder.insert(term.value()).map_err(|_|ClError::Validation("token dictionary encoding failed".into()))?;}
 let bytes=builder.into_inner().map_err(|_|ClError::Validation("token dictionary encoding failed".into()))?;
 tx.open_table(FST)?.insert(d.id,bytes.as_slice())?;Ok(())
}

fn insert_run(tx:&redb::WriteTransaction,d:&Manifest,pending:&mut Vec<(Vec<u8>,String)>)->Result<()> {
 if pending.is_empty(){return Ok(())}pending.sort_unstable_by(|a,b|a.0.cmp(&b.0));
 let name=d.entries();let mut table=tx.open_table(TableDefinition::<&[u8],&str>::new(&name))?;
 let append=table.last()?.is_none_or(|(key,_)|key.value()<pending[0].0.as_slice());
 if append {let mut cursor=table.lower_bound_mut(std::ops::Bound::Included(pending[0].0.as_slice()))?;for(key,row)in pending.iter(){cursor.insert_before(key.as_slice(),row.as_str()).map_err(redb::Error::from)?;}cursor.close()?;}else {for(key,row)in pending.iter(){table.insert(key.as_slice(),row.as_str())?;}}
 pending.clear();Ok(())
}

impl Driver {
 fn emit(&self,event:&'static str,d:&Manifest){self.db.event_sink.emit(&crate::LibraryEvent::Index{event,generation:d.generation,fingerprint:crate::query::optimizer::fingerprint(&d.canonical),rows:self.samplers.get(&d.id).map(|s|s.rows).unwrap_or(0),bytes:d.bytes,elapsed:Duration::from_secs_f64(d.build_ms/1000.)});}
 /// How long the journal may be replayed change by change before rebuilding is cheaper: the time the ready indexes took to build (stored in their manifests),
 /// so the worst case is about twice a build. The floor is for tables so small that the stored time is near zero: starting a rebuild (a snapshot, tables,
 /// a transaction) has a fixed cost, and below half a second replaying always wins.
 fn replay_budget(&self)->Duration {
  if let Some(d)=self.budget_override {return d}
  let built:f64=self.defs.iter().filter(|d|d.ready&&d.state==IndexState::Active).map(|d|d.build_ms).sum();
  Duration::from_secs_f64(built/1000.).max(MIN_REPLAY_BUDGET)
 }
  fn rebuild_for_replay_budget(&mut self)->Result<bool> {
  let now=Instant::now();let window=self.overload_window();self.budget_rebuilds.retain(|t|now.duration_since(*t)<window);
  if self.budget_rebuilds.len()>=MAX_BUDGET_REBUILDS {return self.idle_for_overload()}
  self.budget_rebuilds.push(now);
  self.db.event_sink.emit(&crate::LibraryEvent::Index{event:"index/rebuild/replay_budget",generation:self.meta.generation,fingerprint:0,rows:0,bytes:0,elapsed:Duration::ZERO});
  crate::fsutil::maybe_crash("index_replay_budget_rebuild");
  self.repair_with("the journal backlog took longer to replay than the index takes to build")?;Ok(true)
 }
 /// The window in which `MAX_BUDGET_REBUILDS` rebuilds count as one overload: ten builds of the index (a rebuild that keeps being undone by the writes that arrive while it runs).
 fn overload_window(&self)->Duration {
  if self.budget_override.is_some() {return Duration::from_secs(60)}
  let built:f64=self.defs.iter().map(|d|d.build_ms).sum();Duration::from_secs_f64(10.*built/1000.).max(Duration::from_secs(5))
 }
 /// How long the journal must stay the same before an index set aside for overload may be rebuilt: the same window.
 fn quiet_period(&self)->Duration {if self.budget_override.is_some() {return Duration::from_millis(300)}self.overload_window()}
 /// Writes keep arriving faster than they can be replayed, so rebuilding only starts the next round of the same thing: set the active indexes aside (`Idle`: their tables dropped,
 /// no journal consumer held, queries scan) and rebuild none until the journal is quiet. The state transition is the one the idle deadline makes, and sends the same event.
 fn idle_for_overload(&mut self)->Result<bool> {
  let ids:Vec<u64>=self.defs.iter().filter(|d|d.state==IndexState::Active).map(|d|d.id).collect();
  self.budget_rebuilds.clear();if ids.is_empty() {return Ok(false)}
  self.build=None;self.reset_job=None;self.compact_job=None;self.dictionary_job=None;self.pending.clear();
  let view=Arc::new(self.db.read_view_at_head()?);self.meta.identity=identity(&view)?;self.meta.reset=reset(&view)?;self.meta.applied=view.head;
  let tx=self.file.begin_write()?;
  for id in &ids {let d=self.defs.iter_mut().find(|d|d.id==*id).unwrap();if d.ready {drop_tables(&tx,d)?;}d.summary=self.samplers.get(&d.id).map(|s|s.field_stats(self.meta.applied).summary);if let Some(stats)=self.samplers.get_mut(&d.id){stats.clear_samples();tx.open_table(STATS)?.insert(d.id,stats.encode()?.as_slice())?;}d.bytes=0;d.ready=false;d.state=IndexState::Idle;d.reason="writes outpace replay".into();put_definition(&tx,d)?;
   let mut observations=self.state.observations.lock().unwrap_or_else(|e|e.into_inner());if let Some(o)=observations.get_mut(&d.canonical){o.queued=false;}}
  put_metadata(&tx,&self.meta)?;tx.commit()?;
  for id in &ids {let d=self.defs.iter().find(|d|d.id==*id).unwrap();self.emit("index/state",d);}
  if self.defs.iter().all(|d|d.state!=IndexState::Active) {self.db.disable_index_consumer()?;self.token=None;}
  self.hold=Some((self.db.journal_head()?,Instant::now()));self.target=Some(view);self.publish()?;Ok(true)
 }
 fn update_report(&self)->Result<()> {
  let file_bytes=std::fs::metadata(self.db.dir.dir.join(format!("{}.inx",self.db.db_name)))?.len();let head=self.db.journal_head()?;
  let reports=self.defs.iter().chain(self.retired.iter()).map(|d|{let(idle,abandon)=super::report::deadlines(d);super::report::IndexReport{database:self.db.db_name.clone(),id:d.id,definition:super::report::definition(&d.definition),fingerprint:crate::query::optimizer::fingerprint(&d.canonical),canonical_bytes:d.canonical.len(),generation:d.generation,ready:d.ready,state:d.state,reason:d.reason.clone(),bytes:d.bytes,file_bytes,last_use_ms:d.last_use_ms,build_ms:d.build_ms,reads:d.reads,matched_rows:d.matched,estimated_ms:d.estimated_ms,actual_ms:d.actual_ms,lag:head.saturating_sub(self.meta.applied),wait_ms:0.,replacement:d.replacement,repair_errors:self.repair_errors,rows:self.samplers.get(&d.id).map(|s|s.rows).unwrap_or(0),correlation:self.samplers.get(&d.id).map(|s|s.correlation()).unwrap_or(0.),idle_after_ms:idle,abandon_after_ms:abandon}}).collect();
  *self.state.reports.lock().unwrap_or_else(|e|e.into_inner())=reports;Ok(())
 }
 fn maintain(&mut self,force:bool)->Result<()> {
  let now=self.state.clock.now();let usages=std::mem::take(&mut *self.state.usages.lock().unwrap_or_else(|e|e.into_inner()));let mut dirty=!usages.is_empty();
  for usage in usages.values(){if let Some(d)=self.defs.iter_mut().find(|d|d.id==usage.id&&d.state==IndexState::Active){let gap=usage.at.saturating_sub(d.last_use_ms);if d.reads>0&&gap>0 {d.interval_ms=if d.interval_ms==0{gap}else{(d.interval_ms.saturating_mul(3)+gap)/4};}d.last_use_ms=usage.at;d.reads+=usage.count;d.matched+=usage.matched;d.estimated_ms+=usage.estimated_ms;d.actual_ms+=usage.actual_ms;}}
  let transitions=self.defs.iter().filter(|_|self.build.is_none()&&self.reset_job.is_none()&&self.compact_job.is_none()&&self.dictionary_job.is_none()).filter(|d|d.ready||d.state==IndexState::Idle).filter_map(|d|{let(idle,abandon)=super::report::deadlines(d);let age=now.saturating_sub(d.last_use_ms);if age>=abandon{Some((d.id,IndexState::Abandoned))}else if age>=idle&&d.state==IndexState::Active{Some((d.id,IndexState::Idle))}else{None}}).collect::<Vec<_>>();
  if !transitions.is_empty(){let tx=self.file.begin_write()?;for(id,state)in &transitions{let d=self.defs.iter_mut().find(|d|d.id==*id).unwrap();if d.ready {drop_tables(&tx,d)?;}d.summary=self.samplers.get(&d.id).map(|s|s.field_stats(self.meta.applied).summary);if let Some(stats)=self.samplers.get_mut(&d.id){stats.clear_samples();tx.open_table(STATS)?.insert(d.id,stats.encode()?.as_slice())?;}d.bytes=0;d.ready=false;d.state=*state;d.reason=if *state==IndexState::Idle{"active uptime exceeded cost-adjusted idle deadline"}else{"active uptime exceeded periodic abandonment deadline"}.into();if *state==IndexState::Abandoned {tx.open_table(DEFS)?.remove(d.id)?;tx.open_table(STATS)?.remove(d.id)?;}else{put_definition(&tx,d)?;}
    let mut observations=self.state.observations.lock().unwrap_or_else(|e|e.into_inner());if *state==IndexState::Abandoned{observations.remove(&d.canonical);}else if let Some(o)=observations.get_mut(&d.canonical){o.queued=false;}
   }tx.commit()?;dirty=true;
   for(id,state)in transitions {let d=self.defs.iter().find(|d|d.id==id).unwrap();self.emit("index/state",d);if state==IndexState::Abandoned {let i=self.defs.iter().position(|d|d.id==id).unwrap();let d=self.defs.remove(i);self.retired.push(d);if self.retired.len()>128{self.retired.remove(0);}self.samplers.remove(&id);}}
   if self.defs.iter().all(|d|d.state!=IndexState::Active) {self.db.disable_index_consumer()?;self.token=None;}
   if let Some(pair)=self.state.pair(){self.target=Some(pair.primary.clone());self.publish()?;}
  }
  if dirty||force||self.last_flush.elapsed()>=Duration::from_secs(1) {
   self.meta.uptime_ms=now;let tx=self.file.begin_write()?;for d in &self.defs{put_definition(&tx,d)?;}put_metadata(&tx,&self.meta)?;
   // The checkpoint: this durable commit persists every earlier non-durable `.inx` batch, and only then may the journal be acknowledged that far.
   crate::fsutil::maybe_crash("index_checkpoint_before_commit");tx.commit()?;crate::fsutil::maybe_crash("index_checkpoint_after_commit");
   if let Some(token)=&self.token {if self.meta.applied>self.acked{self.db.ack(token,self.meta.applied)?;self.acked=self.meta.applied;crate::fsutil::maybe_crash("index_checkpoint_after_ack");}}
   self.db.journal_write(|tx,_| {let mut catalog=tx.open_table(CATALOG)?;let ids=catalog.iter()?.map(|r|r.map(|(k,_)|k.value())).collect::<std::result::Result<Vec<_>,_>>()?;for id in ids {if !self.defs.iter().any(|d|d.id==id)&&self.build.as_ref().is_none_or(|b|b.manifest.id!=id){catalog.remove(id)?;}}for d in &self.defs{catalog.insert(d.id,serde_json::to_vec(d)?.as_slice())?;}Ok(())})?;
   self.last_flush=Instant::now();
   let view=Arc::new(self.db.read_view_at_head()?);if view.head==self.meta.applied&&self.reset_job.is_none(){self.target=Some(view);self.publish()?;}else{self.update_report()?;}
  }Ok(())
 }
}

impl Driver {
 fn repair(&mut self)->Result<()> {self.repair_with("journal gap requested a new snapshot generation")}
 fn repair_with(&mut self,reason:&str)->Result<()> {
  self.build=None;self.reset_job=None;self.compact_job=None;self.dictionary_job=None;self.pending=self.defs.iter().filter(|d|d.state==IndexState::Active).map(|d|d.definition.clone()).collect();
  if self.pending.is_empty(){self.db.disable_index_consumer()?;self.token=None;}else {self.token=Some(self.db.register_journal_consumer("__indexer",true)?);}
  let view=Arc::new(self.db.read_view_at_head()?);self.meta.identity=identity(&view)?;self.meta.reset=reset(&view)?;self.meta.applied=view.head;
  let tx=self.file.begin_write()?;for d in self.defs.iter_mut().filter(|d|d.state==IndexState::Active){d.ready=false;d.reason=reason.into();put_definition(&tx,d)?;}put_metadata(&tx,&self.meta)?;tx.commit()?;
  if let Some(token)=&self.token{self.db.ack(token,self.meta.applied)?;}self.target=Some(view);self.publish()?;
  self.db.event_sink.emit(&crate::LibraryEvent::Index{event:"index/rebuild",generation:self.meta.generation,fingerprint:0,rows:0,bytes:0,elapsed:Duration::ZERO});Ok(())
 }
}

impl Driver {
 fn start_reset(&mut self,seq:u64,table:&str,snapshot:&str)->Result<()> {
  let view=Arc::new(self.db.read_view_at_head()?);view.tx.open_table(TableDefinition::<&str,&[u8]>::new(snapshot))?;
  self.meta.generation+=1;let mut defs=self.defs.iter().filter(|d|d.ready&&d.state==IndexState::Active&&d.definition.table==table).cloned().collect::<Vec<_>>();let tx=self.file.begin_write()?;
  for d in &mut defs {d.generation=self.meta.generation;d.ready=false;d.bytes=0;d.waste=0;create_tables(&tx,d)?;}
  put_metadata(&tx,&self.meta)?;tx.commit()?;self.reset_job=Some(ResetJob{seq,source:snapshot.into(),view,defs,samplers:BTreeMap::new(),last:None,builders:BTreeMap::new()});Ok(())
 }
 fn reset_turn(&mut self)->Result<bool> {
  let job=self.reset_job.as_mut().unwrap();let rows=job.view.tx.open_table(TableDefinition::<&str,&[u8]>::new(&job.source))?;
  let lower=job.last.as_deref().map(std::ops::Bound::Excluded).unwrap_or(std::ops::Bound::Unbounded);let tx=self.file.begin_write()?;let start=Instant::now();let(mut bytes,mut done)=(0usize,true);let mut pending=BTreeMap::<u64,Vec<(Vec<u8>,String)>>::new();
  for row in rows.range::<&str>((lower,std::ops::Bound::Unbounded))? {let(k,v)=row?;for d in &job.defs {if d.definition.kind.postings() {let(grams,stats)=trigram_inputs(d,k.value(),v.value())?;job.builders.entry(d.id).or_default().add(k.value(),&grams,&stats)?;job.samplers.entry(d.id).or_default().apply(None,Some(stats));continue}let delta=write_row_buffered(&tx,d,k.value(),v.value(),job.seq,Some(pending.entry(d.id).or_default()))?;job.samplers.entry(d.id).or_default().apply(delta.old.as_ref(),Some(delta.new));}job.last=Some(k.value().into());bytes+=k.value().len()+v.value().len();if bytes>=BATCH_BYTES||start.elapsed()>=BATCH_TIME{done=false;break}}
  for d in &mut job.defs {if let Some(pending)=pending.get_mut(&d.id){insert_run(&tx,d,pending)?;}d.bytes+=bytes as u64;}
  crate::fsutil::maybe_crash("index_during_reset");
  // The turn's one writer ends before the in-memory trigram builders write (they take their own): when the reset is read to its end, or a builder is due.
  if job.defs.iter().all(|d|d.definition.kind.postings()) {drop(tx);} else {tx.commit()?;}
  for d in &job.defs {if let Some(builder)=job.builders.get_mut(&d.id) {let flush=if done {Some(super::trigram::Flush::All)} else {builder.due()};if let Some(flush)=flush {flush_all(&self.file,d,builder,flush)?;}}}
  self.refresh_pair()?;
  if done {let job=self.reset_job.take().unwrap();let tx=self.file.begin_write()?;for d in &job.defs {tx.open_table(STATS)?.insert(d.id,job.samplers.get(&d.id).unwrap_or(&Reservoir::default()).encode()?.as_slice())?;put_definition(&tx,d)?;}tx.commit()?;
   let dictionaries=job.defs.iter().filter(|d|d.definition.kind==Kind::Token).cloned().collect::<Vec<_>>();if dictionaries.is_empty(){self.finish_reset(job)?;}else{self.start_dictionary(dictionaries,DictionaryFinish::Reset(job))?;}
  }Ok(true)
 }
}

impl Driver {
 fn maybe_compact(&mut self)->Result<bool> {
  let forced=self.state.compact_requested.swap(false,Ordering::AcqRel);
  if !forced&&(self.defs.is_empty()||self.compact_checked_seq==Some(self.meta.applied)||self.last_compact_check.elapsed()<Duration::from_secs(1)){return Ok(false)}
  self.last_compact_check=Instant::now();self.compact_checked_seq=Some(self.meta.applied);
  if !forced&&self.last_compact_bytes>0&&std::fs::metadata(self.db.dir.dir.join(format!("{}.inx",self.db.db_name)))?.len()<self.last_compact_bytes.saturating_add(BATCH_BYTES as u64){return Ok(false)}
  if !forced {let tx=self.file.begin_write()?;let stats=tx.stats()?;let total=stats.stored_bytes()+stats.metadata_bytes()+stats.fragmented_bytes();if stats.fragmented_bytes()<BATCH_BYTES as u64||stats.fragmented_bytes().saturating_mul(2)<total{return Ok(false)}}
  let Some(source)=self.state.pair()else{return Ok(false)};
  let path=self.db.dir.dir.join(format!("{}.inx.build-{}",self.db.db_name,uuid::Uuid::new_v4()));
  let file=Arc::new(self.db.redb.open_index_file(&path,true,&self.db.event_sink)?);let mut metadata=self.meta.clone();metadata.generation+=1;metadata.uptime_ms=self.state.clock.now();initialize(&file,metadata.identity.clone(),metadata.reset,metadata.applied)?;
  let mut defs=self.defs.clone();let mut tasks=vec![];for d in &mut defs {let old=d.clone();d.generation=metadata.generation;d.bytes=0;d.waste=0;if d.ready&&d.definition.kind.postings() {
    // Posting blocks (4), reverse rows (1), trigram dictionary (5), row numbers (6) and counters (2): see `trigram.rs`.
    tasks.push(CopyTask{kind:4,source:old.entries(),target:d.entries(),id:Some(d.id)});tasks.push(CopyTask{kind:1,source:old.reverse(),target:d.reverse(),id:Some(d.id)});
    tasks.push(CopyTask{kind:5,source:super::trigram::dict_name(&old),target:super::trigram::dict_name(d),id:Some(d.id)});tasks.push(CopyTask{kind:6,source:super::trigram::ids_name(&old),target:super::trigram::ids_name(d),id:Some(d.id)});
    tasks.push(CopyTask{kind:2,source:super::trigram::counters_name(&old),target:super::trigram::counters_name(d),id:Some(d.id)});d.ready=false;
   } else if d.ready {tasks.push(CopyTask{kind:0,source:old.entries(),target:d.entries(),id:Some(d.id)});tasks.push(CopyTask{kind:1,source:old.reverse(),target:d.reverse(),id:Some(d.id)});if d.definition.kind==Kind::Token {tasks.push(CopyTask{kind:2,source:terms_name(&old),target:terms_name(d),id:Some(d.id)});}d.ready=false;}}
  tasks.push(CopyTask{kind:3,source:"__inx_statistics".into(),target:"__inx_statistics".into(),id:None});tasks.push(CopyTask{kind:3,source:"__inx_dictionary".into(),target:"__inx_dictionary".into(),id:None});
  let tx=file.begin_write()?;for d in &defs{put_definition(&tx,d)?;}put_metadata(&tx,&metadata)?;tx.commit()?;
  self.compact_job=Some(CompactJob{file,path,source,metadata,defs,tasks,task:0,last:None});Ok(true)
 }
 fn compact_turn(&mut self)->Result<bool> {
  let job=self.compact_job.as_mut().unwrap();
  if job.task<job.tasks.len(){let task=&job.tasks[job.task];let tx=job.file.begin_write()?;let start=Instant::now();let(mut bytes,mut done)=(0usize,true);
   match task.kind {
    4=>{let source=job.source.index.open_table(TableDefinition::<&[u8],&[u8]>::new(&task.source))?;let mut target=tx.open_table(TableDefinition::<&[u8],&[u8]>::new(&task.target))?;let lower=job.last.as_deref().map(std::ops::Bound::Excluded).unwrap_or(std::ops::Bound::Unbounded);let mut cursor=target.upper_bound_mut(std::ops::Bound::<&[u8]>::Unbounded)?;for row in source.range::<&[u8]>((lower,std::ops::Bound::Unbounded))? {let(k,v)=row?;cursor.insert_before(k.value(),v.value()).map_err(redb::Error::from)?;job.last=Some(k.value().to_vec());bytes+=k.value().len()+v.value().len();if bytes>=BATCH_BYTES||start.elapsed()>=BATCH_TIME {done=false;break}}cursor.close()?;},
    5=>{let source=job.source.index.open_table(TableDefinition::<&str,u32>::new(&task.source))?;let mut target=tx.open_table(TableDefinition::<&str,u32>::new(&task.target))?;let lower=job.last.as_deref().map(std::str::from_utf8).transpose()?.map(std::ops::Bound::Excluded).unwrap_or(std::ops::Bound::Unbounded);let mut cursor=target.upper_bound_mut(std::ops::Bound::<&str>::Unbounded)?;for row in source.range::<&str>((lower,std::ops::Bound::Unbounded))?{let(k,v)=row?;cursor.insert_before(k.value(),v.value()).map_err(redb::Error::from)?;job.last=Some(k.value().as_bytes().to_vec());bytes+=k.value().len()+4;if bytes>=BATCH_BYTES||start.elapsed()>=BATCH_TIME{done=false;break}}cursor.close()?;},
    6=>{let source=job.source.index.open_table(TableDefinition::<u64,&str>::new(&task.source))?;let mut target=tx.open_table(TableDefinition::<u64,&str>::new(&task.target))?;let last=job.last.as_ref().map(|v|u64::from_be_bytes(v.as_slice().try_into().unwrap()));let lower=last.map(std::ops::Bound::Excluded).unwrap_or(std::ops::Bound::Unbounded);let mut cursor=target.upper_bound_mut(std::ops::Bound::<u64>::Unbounded)?;for row in source.range((lower,std::ops::Bound::Unbounded))?{let(k,v)=row?;cursor.insert_before(k.value(),v.value()).map_err(redb::Error::from)?;job.last=Some(k.value().to_be_bytes().to_vec());bytes+=8+v.value().len();if bytes>=BATCH_BYTES||start.elapsed()>=BATCH_TIME{done=false;break}}cursor.close()?;},
    0=>{let source=job.source.index.open_table(TableDefinition::<&[u8],&str>::new(&task.source))?;let mut target=tx.open_table(TableDefinition::<&[u8],&str>::new(&task.target))?;let lower=job.last.as_deref().map(std::ops::Bound::Excluded).unwrap_or(std::ops::Bound::Unbounded);let mut cursor=target.upper_bound_mut(std::ops::Bound::<&[u8]>::Unbounded)?;for row in source.range::<&[u8]>((lower,std::ops::Bound::Unbounded))? {let(k,v)=row?;cursor.insert_before(k.value(),v.value()).map_err(redb::Error::from)?;job.last=Some(k.value().to_vec());bytes+=k.value().len()+v.value().len();if bytes>=BATCH_BYTES||start.elapsed()>=BATCH_TIME {done=false;break}}cursor.close()?;},
    1=>{let source=job.source.index.open_table(TableDefinition::<&str,&[u8]>::new(&task.source))?;let mut target=tx.open_table(TableDefinition::<&str,&[u8]>::new(&task.target))?;let lower=job.last.as_deref().map(std::str::from_utf8).transpose()?.map(std::ops::Bound::Excluded).unwrap_or(std::ops::Bound::Unbounded);let mut cursor=target.upper_bound_mut(std::ops::Bound::<&str>::Unbounded)?;for row in source.range::<&str>((lower,std::ops::Bound::Unbounded))?{let(k,v)=row?;cursor.insert_before(k.value(),v.value()).map_err(redb::Error::from)?;job.last=Some(k.value().as_bytes().to_vec());bytes+=k.value().len()+v.value().len();if bytes>=BATCH_BYTES||start.elapsed()>=BATCH_TIME{done=false;break}}cursor.close()?;},
    2=>{let source=job.source.index.open_table(TableDefinition::<&str,u64>::new(&task.source))?;let mut target=tx.open_table(TableDefinition::<&str,u64>::new(&task.target))?;let lower=job.last.as_deref().map(std::str::from_utf8).transpose()?.map(std::ops::Bound::Excluded).unwrap_or(std::ops::Bound::Unbounded);let mut cursor=target.upper_bound_mut(std::ops::Bound::<&str>::Unbounded)?;for row in source.range::<&str>((lower,std::ops::Bound::Unbounded))?{let(k,v)=row?;cursor.insert_before(k.value(),v.value()).map_err(redb::Error::from)?;job.last=Some(k.value().as_bytes().to_vec());bytes+=k.value().len()+8;if bytes>=BATCH_BYTES||start.elapsed()>=BATCH_TIME{done=false;break}}cursor.close()?;},
    _=>{let source=job.source.index.open_table(TableDefinition::<u64,&[u8]>::new(&task.source))?;let mut target=tx.open_table(TableDefinition::<u64,&[u8]>::new(&task.target))?;let last=job.last.as_ref().map(|v|u64::from_be_bytes(v.as_slice().try_into().unwrap()));let lower=last.map(std::ops::Bound::Excluded).unwrap_or(std::ops::Bound::Unbounded);for row in source.range((lower,std::ops::Bound::Unbounded))? {let(k,v)=row?;if job.defs.iter().any(|d|d.id==k.value()){target.insert(k.value(),v.value())?;if let Some(d)=job.defs.iter_mut().find(|d|d.id==k.value()){d.bytes+=8+v.value().len() as u64;}}job.last=Some(k.value().to_be_bytes().to_vec());bytes+=8+v.value().len();if bytes>=BATCH_BYTES||start.elapsed()>=BATCH_TIME{done=false;break}}}
   }
   if let Some(id)=task.id {if let Some(d)=job.defs.iter_mut().find(|d|d.id==id){d.bytes+=bytes as u64;}}
   crate::fsutil::maybe_crash("index_during_compact");tx.commit()?;if done{job.task+=1;job.last=None;}return Ok(true)
  }
  let mut job=self.compact_job.take().unwrap();let tx=job.file.begin_write()?;
  for d in &mut job.defs {if let Some(current)=self.defs.iter().find(|old|old.id==d.id){d.ready=current.ready;d.last_use_ms=current.last_use_ms;d.reads=current.reads;d.matched=current.matched;d.interval_ms=current.interval_ms;d.estimated_ms=current.estimated_ms;d.actual_ms=current.actual_ms;}d.reason="compacted generation published".into();put_definition(&tx,d)?;}
  job.metadata.uptime_ms=self.state.clock.now();put_metadata(&tx,&job.metadata)?;crate::fsutil::maybe_crash("index_compact_before_manifest");tx.commit()?;crate::fsutil::maybe_crash("index_compact_after_manifest");
  crate::fsutil::maybe_crash("index_compact_before_swap");std::fs::rename(&job.path,self.db.dir.dir.join(format!("{}.inx",self.db.db_name)))?;crate::fsutil::maybe_crash("index_compact_after_swap");
  self.last_compact_bytes=std::fs::metadata(self.db.dir.dir.join(format!("{}.inx",self.db.db_name)))?.len();
  self.file=job.file;self.meta=job.metadata;self.defs=job.defs;self.target=Some(job.source.primary.clone());self.publish()?;
  self.db.event_sink.emit(&crate::LibraryEvent::Index{event:"index/compact",generation:self.meta.generation,fingerprint:0,rows:self.samplers.values().map(|s|s.rows).sum(),bytes:std::fs::metadata(self.db.dir.dir.join(format!("{}.inx",self.db.db_name)))?.len(),elapsed:Duration::ZERO});Ok(true)
 }
}

impl Driver {
 fn invalidate_schema(&mut self,view:Arc<ReadView>)->Result<()> {
  self.state.clear();self.build=None;self.reset_job=None;self.compact_job=None;self.dictionary_job=None;self.pending.clear();
  let tx=self.file.begin_write()?;for d in &mut self.defs {d.ready=false;d.state=IndexState::Abandoned;d.reason="schema or codec identity changed".into();}tx.delete_table(DEFS)?;tx.open_table(DEFS)?;tx.delete_table(STATS)?;tx.open_table(STATS)?;tx.delete_table(FST)?;tx.open_table(FST)?;
  self.meta.identity=identity(&view)?;self.meta.applied=view.head;self.meta.reset=reset(&view)?;put_metadata(&tx,&self.meta)?;tx.commit()?;
  self.db.journal_write(|tx,_|{tx.delete_table(CATALOG)?;tx.open_table(CATALOG)?;tx.open_table(CATALOG_META)?.insert("identity",serde_json::to_vec(&self.meta.identity)?.as_slice())?;Ok(())})?;
  self.db.disable_index_consumer()?;self.token=None;self.retired.append(&mut self.defs);self.retired.truncate(128);self.samplers.clear();self.prepared.clear();self.state.observations.lock().unwrap_or_else(|e|e.into_inner()).clear();self.target=Some(view);self.publish()?;Ok(())
 }
}

impl Driver {
 fn start_dictionary(&mut self,targets:Vec<Manifest>,finish:DictionaryFinish)->Result<()> {self.dictionary_job=Some(DictionaryJob{source:self.file.begin_read()?,targets,target:0,last:None,builder:Some(fst::SetBuilder::memory()),finish});Ok(())}
 fn dictionary_turn(&mut self)->Result<bool> {
  let job=self.dictionary_job.as_mut().unwrap();let d=&job.targets[job.target];let table=job.source.open_table(TableDefinition::<&str,u64>::new(&terms_name(d)))?;let lower=job.last.as_deref().map(std::ops::Bound::Excluded).unwrap_or(std::ops::Bound::Unbounded);let start=Instant::now();let(mut bytes,mut done)=(0usize,true);
  for row in table.range::<&str>((lower,std::ops::Bound::Unbounded))?{let(term,_)=row?;job.builder.as_mut().unwrap().insert(term.value()).map_err(|_|ClError::Validation("token dictionary encoding failed".into()))?;job.last=Some(term.value().into());bytes+=term.value().len()+8;if bytes>=BATCH_BYTES||start.elapsed()>=BATCH_TIME{done=false;break}}
  crate::fsutil::maybe_crash("index_during_dictionary");
  if done {let bytes=job.builder.take().unwrap().into_inner().map_err(|_|ClError::Validation("token dictionary encoding failed".into()))?;let tx=self.file.begin_write()?;tx.open_table(FST)?.insert(d.id,bytes.as_slice())?;tx.commit()?;job.target+=1;job.last=None;
   if job.target<job.targets.len(){job.builder=Some(fst::SetBuilder::memory());}
   else{let job=self.dictionary_job.take().unwrap();match job.finish {
    DictionaryFinish::Batch(seq)=>{self.meta.applied=seq;if self.target.as_ref().is_some_and(|v|v.head==seq){self.meta.reset=reset(self.target.as_ref().unwrap())?;}let tx=self.file.begin_write()?;put_metadata(&tx,&self.meta)?;tx.commit()?;self.db.ack(self.token.as_ref().unwrap(),seq)?;if self.target.as_ref().is_some_and(|v|v.head==seq){self.replay_since=None;self.publish()?;}},
    DictionaryFinish::Build(build)=>self.finish_build(build)?,DictionaryFinish::Reset(reset)=>self.finish_reset(reset)?,
   }}
  }Ok(true)
 }
 fn finish_build(&mut self,mut b:Build)->Result<()> {
  b.manifest.ready=true;b.manifest.orderable=b.sampler.unorderable==0;b.manifest.build_ms=b.started.elapsed().as_secs_f64()*1000.;let tx=self.file.begin_write()?;put_definition(&tx,&b.manifest)?;put_metadata(&tx,&self.meta)?;crate::fsutil::maybe_crash("index_before_manifest");tx.commit()?;crate::fsutil::maybe_crash("index_after_manifest");
  if let Some(old_id)=b.manifest.replacement { if let Some(old)=self.defs.iter_mut().find(|d|d.id==old_id&&d.state==IndexState::Idle) { old.state=IndexState::Merged;old.ready=false;old.replacement=Some(b.manifest.id);old.reason="idle definition merged into its rebuilt generation".into();let snapshot=old.clone();let tx=self.file.begin_write()?;put_definition(&tx,&snapshot)?;tx.commit()?;self.db.journal_write(|tx,_|{tx.open_table(CATALOG)?.insert(snapshot.id,serde_json::to_vec(&snapshot)?.as_slice())?;Ok(())})?; }}
  self.db.journal_write(|tx,_|{tx.open_table(CATALOG)?.insert(b.manifest.id,serde_json::to_vec(&b.manifest)?.as_slice())?;Ok(())})?;
  self.samplers.insert(b.manifest.id,b.sampler);self.defs.retain(|d|d.id!=b.manifest.id);self.emit("index/build",&b.manifest);self.defs.push(b.manifest);self.target=Some(b.view);self.publish()?;Ok(())
 }
 fn finish_reset(&mut self,mut job:ResetJob)->Result<()> {
  let tx=self.file.begin_write()?;for d in &mut job.defs {d.ready=true;d.orderable=job.samplers.get(&d.id).is_some_and(|s|s.unorderable==0);d.reason="immutable reset image applied".into();put_definition(&tx,d)?;}
  self.meta.applied=job.seq;if self.target.as_ref().is_some_and(|v|v.head==job.seq){self.meta.reset=reset(self.target.as_ref().unwrap())?;}put_metadata(&tx,&self.meta)?;crate::fsutil::maybe_crash("index_before_manifest");tx.commit()?;crate::fsutil::maybe_crash("index_after_manifest");
  for d in job.defs {self.defs.retain(|old|old.id!=d.id);self.samplers.insert(d.id,job.samplers.remove(&d.id).unwrap_or_default());self.defs.push(d);}self.db.ack(self.token.as_ref().unwrap(),job.seq)?;if self.target.as_ref().is_some_and(|v|v.head==job.seq){self.publish()?;}Ok(())
 }
}

fn definition_key(d:&Manifest,value:&crate::fields::Value,row:&str)->Result<Vec<u8>> {
 if d.definition.paths.len()<=1{return entry_key(value,row)}
 let crate::fields::Value::Array(values)=value else{return Err(ClError::Validation("invalid compound index value".into()))};let mut key=vec![8];
 for(i,value)in values.iter().enumerate(){let mut part=crate::fields::codec::encode_equality(value)?;if d.definition.directions.get(i)==Some(&crate::query::Desc){for b in &mut part{*b=!*b;}}key.extend(part);}key.push(0);key.extend(crate::fields::codec::encode(&crate::fields::Value::String(row.into()))?);Ok(key)
}

// Reverse-map row value, format 3: binary instead of JSON. A JSON array of byte arrays costs about 3.4 text bytes per key byte and repeats
// the row key in every entry key and in the statistics; this keeps each entry key's own bytes only and rebuilds the row suffix on read.
// Format-2 rows (JSON, first byte `{`) still decode, so a file is read either way.
pub(super) fn put_varint(out:&mut Vec<u8>,mut v:u64){while v>=0x80{out.push((v as u8)|0x80);v>>=7;}out.push(v as u8);}
pub(super) fn get_varint(bytes:&mut &[u8])->Result<u64>{let mut v=0u64;let mut shift=0;loop{let Some((&b,rest))=bytes.split_first()else{return Err(ClError::Validation("truncated reverse row".into()))};*bytes=rest;v|=((b&0x7f) as u64)<<shift;if b&0x80==0{return Ok(v)}shift+=7;if shift>63{return Err(ClError::Validation("corrupt reverse row".into()))}}}
fn get_bytes<'a>(bytes:&mut &'a [u8])->Result<&'a [u8]>{let n=usize::try_from(get_varint(bytes)?).map_err(|_|ClError::Validation("corrupt reverse row".into()))?;if bytes.len()<n{return Err(ClError::Validation("truncated reverse row".into()))}let(a,b)=bytes.split_at(n);*bytes=b;Ok(a)}
fn encode_reverse(row:&str,r:&Reverse)->Result<Vec<u8>> {
 let suffix=crate::fields::codec::encode(&crate::fields::Value::String(row.into()))?;
 let mut out=vec![2u8];put_varint(&mut out,r.keys.len() as u64);
 for k in &r.keys{let own=k.ends_with(&suffix);out.push(u8::from(own));let body=if own{&k[..k.len()-suffix.len()]}else{k.as_slice()};put_varint(&mut out,body.len() as u64);out.extend_from_slice(body);}
 put_varint(&mut out,r.terms.len() as u64);for t in &r.terms{put_varint(&mut out,t.len() as u64);out.extend_from_slice(t.as_bytes());}
 match &r.stats{Some(s)=>{out.push(1);for v in [s.missing,s.nulls,s.fanout,s.json_bytes,s.key_bytes,s.unorderable]{put_varint(&mut out,v);}},None=>out.push(0)}
 Ok(out)
}
fn decode_reverse(row:&str,bytes:&[u8])->Result<Reverse> {
 if bytes.first()!=Some(&2){return Ok(serde_json::from_slice(bytes)?)}
 let suffix=crate::fields::codec::encode(&crate::fields::Value::String(row.into()))?;
 let mut b=&bytes[1..];let n=get_varint(&mut b)?;let mut keys=vec![];
 for _ in 0..n{let Some((&own,rest))=b.split_first()else{return Err(ClError::Validation("truncated reverse row".into()))};b=rest;let mut k=get_bytes(&mut b)?.to_vec();if own==1{k.extend_from_slice(&suffix);}keys.push(k);}
 let t=get_varint(&mut b)?;let mut terms=vec![];for _ in 0..t{terms.push(String::from_utf8(get_bytes(&mut b)?.to_vec()).map_err(|_|ClError::Validation("corrupt reverse row".into()))?);}
 let stats=if b.first()==Some(&1){b=&b[1..];let mut v=[0u64;6];for x in v.iter_mut(){*x=get_varint(&mut b)?;}Some(RowStats{key:row.into(),missing:v[0],nulls:v[1],fanout:v[2],json_bytes:v[3],key_bytes:v[4],values:vec![],unorderable:v[5]})}else{None};
 Ok(Reverse{keys,terms,stats})
}
impl Driver {
 /// Publish the pair again with a fresh `.inx` read snapshot. A read transaction taken before a long run of commits (a build, a reset) keeps every
 /// page freed since from being reused, so the file grows with the number of commits; this lets the old one go after each commit.
 fn refresh_pair(&mut self)->Result<()> {
  if let Some(old)=self.state.pair(){let index=self.file.begin_read()?;self.state.publish(Arc::new(Pair{primary:old.primary.clone(),index,published:old.published,ready:old.ready,statistics:old.statistics.clone(),keep:self.file.clone(),memo:Default::default()}));}
  Ok(())
 }
}
#[cfg(test)] mod reverse_row_tests {
 use super::*;
 fn sample(row:&str)->Reverse {
  let suffix=crate::fields::codec::encode(&crate::fields::Value::String(row.into())).unwrap();
  let mut own=b"abc".to_vec();own.extend(&suffix);
  Reverse{keys:vec![own,b"foreign".to_vec()],terms:vec!["x".into(),"yz".into()],stats:Some(RowStats{key:row.into(),missing:0,nulls:1,fanout:3,json_bytes:99,key_bytes:row.len() as u64,values:vec![],unorderable:0})}
 }
 fn same(a:&Reverse,b:&Reverse) {
  assert_eq!(a.keys,b.keys);assert_eq!(a.terms,b.terms);
  let(x,y)=(a.stats.as_ref().unwrap(),b.stats.as_ref().unwrap());
  assert_eq!((&x.key,x.missing,x.nulls,x.fanout,x.json_bytes,x.key_bytes,x.unorderable),(&y.key,y.missing,y.nulls,y.fanout,y.json_bytes,y.key_bytes,y.unorderable));
 }
 #[test] fn binary_row_round_trips_and_is_smaller_than_json() {
  let row="row-0042";let r=sample(row);let binary=encode_reverse(row,&r).unwrap();
  same(&decode_reverse(row,&binary).unwrap(),&r);
  assert!(binary.len()*3<serde_json::to_vec(&r).unwrap().len(),"binary {} json {}",binary.len(),serde_json::to_vec(&r).unwrap().len());
 }
 #[test] fn format_2_json_rows_still_decode() {
  let row="row-0042";let r=sample(row);
  same(&decode_reverse(row,&serde_json::to_vec(&r).unwrap()).unwrap(),&r);
 }
 #[test] fn truncated_binary_row_is_an_error_not_a_panic() {
  let row="row-0042";let binary=encode_reverse(row,&sample(row)).unwrap();
  for cut in 1..binary.len()-1 {let _=decode_reverse(row,&binary[..cut]);}
  assert!(decode_reverse(row,&binary[..3]).is_err());
 }
}

/// What a trigram index keeps of one row: the distinct trigrams of its text values, and the counters for the sampler.
fn trigram_inputs(d:&Manifest,row:&str,bytes:&[u8])->Result<(std::collections::BTreeSet<String>,RowStats)> {
 let values=match d.definition.paths.first(){Some(path)=>path_values(bytes,path)?,None=>vec![]};
 let stats=RowStats::new(row,bytes.len(),&values)?;let mut grams=std::collections::BTreeSet::new();
 for value in values {if let crate::fields::Value::String(s)=value {crate::memory::probe("index.row_terms",s.len().saturating_mul(48))?;if d.definition.kind==Kind::Parts {grams.extend(crate::query::eval::tokens(&s));}else{grams.extend(super::access::trigrams(&s));}}}
 Ok((grams,stats))
}

/// Writes everything a trigram `Builder` holds, in as few commits as its chunk size allows.
fn flush_all(file:&Database,d:&Manifest,builder:&mut super::trigram::Builder,flush:super::trigram::Flush)->Result<()> {
 builder.begin(flush);
 loop {let tx=file.begin_write()?;let done=builder.flush_some(&tx,d,super::trigram::FLUSH_CHUNK_BYTES,super::trigram::FLUSH_CHUNK_TIME)?;tx.commit()?;if done {return Ok(())}}
}
