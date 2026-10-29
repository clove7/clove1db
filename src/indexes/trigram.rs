//! Storage of the contains (trigram) index, format 4.
//!
//! The earlier layout stored one `.inx` entry per (trigram, row): the trigram text, the row key (twice: in the entry key and as its value) and a JSON-sized
//! reverse map. This layout stores, per index generation:
//!  - `entries()`  `<&[u8],&[u8]>`  posting blocks. Key: trigram number (u32, big endian) + first row number (u64, big endian); value: the following
//!    row numbers of the block as varint deltas (the first row is in the key). A block holds at most `BLOCK_MAX` value bytes.
//!  - `reverse()`  `<&str,&[u8]>`   row key -> its row number, its trigram numbers (sorted, varint deltas) and the few counters the sampler needs.
//!  - `dict`       `<&str,u32>`     trigram text -> trigram number (numbers are handed out in first-seen order and never reused).
//!  - `ids`        `<u64,&str>`     row number -> row key (row numbers are handed out in increasing order and never reused).
//!  - `counters`   `<&str,u64>`     the next row number and the next trigram number.
//! A query reads the posting blocks of the trigrams of its needle, intersects row numbers, and turns the survivors into row keys.
use super::{format::*,statistics::RowStats,worker::{put_varint,get_varint}};
use crate::units::{Result,ClError};
use redb::{ReadableTable,TableDefinition};
use std::collections::{BTreeSet,HashMap};

/// Largest value size of one posting block; a block that would grow past it is split.
pub(super) const BLOCK_MAX:usize=384;
pub(super) const ROWS_FLUSH_BYTES:usize=16*1024*1024;
/// Postings and dictionary held in memory (as built blocks, about 2 bytes a posting) before a table that large is written in more than one pass.
pub(super) const POSTS_FLUSH_BYTES:usize=256*1024*1024;
/// Asked of the system at the start of each segment (see `memory::probe`).
const PROBE_BYTES:usize=64*1024*1024;
/// One commit of the write-out holds up to this many bytes (and runs up to the time limit). Every commit leaves copy-on-write garbage in the file (the
/// pages of the paths it rewrote), so a build is written in a few large commits instead of one per 256 KiB.
pub(super) const FLUSH_CHUNK_BYTES:usize=4*1024*1024;
pub(super) const FLUSH_CHUNK_TIME:std::time::Duration=std::time::Duration::from_millis(100);

pub(super) fn dict_name(d:&Manifest)->String {format!("__inx_tgd_{}_{}",d.id,d.generation)}
pub(super) fn ids_name(d:&Manifest)->String {format!("__inx_tgi_{}_{}",d.id,d.generation)}
pub(super) fn counters_name(d:&Manifest)->String {format!("__inx_tgc_{}_{}",d.id,d.generation)}
fn corrupt()->ClError {ClError::Validation("corrupt trigram index".into())}

pub(super) fn create(tx:&redb::WriteTransaction,d:&Manifest)->Result<()> {
 tx.open_table(TableDefinition::<&[u8],&[u8]>::new(&d.entries()))?;tx.open_table(TableDefinition::<&str,&[u8]>::new(&d.reverse()))?;
 tx.open_table(TableDefinition::<&str,u32>::new(&dict_name(d)))?;tx.open_table(TableDefinition::<u64,&str>::new(&ids_name(d)))?;tx.open_table(TableDefinition::<&str,u64>::new(&counters_name(d)))?;Ok(())
}
pub(super) fn delete(tx:&redb::WriteTransaction,d:&Manifest)->Result<()> {
 for name in [d.entries(),d.reverse(),dict_name(d),ids_name(d),counters_name(d)] {tx.delete_table(TableDefinition::<&str,&[u8]>::new(&name))?;}Ok(())
}

pub(super) fn post_key(tri:u32,first:u64)->[u8;12] {let mut k=[0u8;12];k[..4].copy_from_slice(&tri.to_be_bytes());k[4..].copy_from_slice(&first.to_be_bytes());k}
/// Appends the row numbers of one posting block to `out`.
pub(super) fn decode_block(key:&[u8],value:&[u8],out:&mut Vec<u64>)->Result<()> {
 if key.len()!=12 {return Err(corrupt())}
 let mut last=u64::from_be_bytes(key[4..12].try_into().unwrap());out.push(last);let mut b=value;
 while !b.is_empty() {last=last.checked_add(get_varint(&mut b)?).ok_or_else(corrupt)?;out.push(last);}Ok(())
}
fn varint_len(mut v:u64)->usize {let mut n=1;while v>=0x80 {v>>=7;n+=1;}n}
/// Splits ascending row numbers into blocks of at most `BLOCK_MAX` value bytes and calls `put(first, value)` for each.
fn blocks(ids:&[u64],mut put:impl FnMut(u64,&[u8])->Result<()>)->Result<()> {
 let mut start=0;
 while start<ids.len() {
  let mut value=Vec::new();let mut end=start+1;
  while end<ids.len() {let delta=ids[end]-ids[end-1];if value.len()+varint_len(delta)>BLOCK_MAX {break}put_varint(&mut value,delta);end+=1;}
  put(ids[start],&value)?;start=end;
 }Ok(())
}
type Posts<'a>=redb::Table<'a,&'static [u8],&'static [u8]>;
/// The block of `tri` whose first row is the greatest one not above `row`, as owned bytes.
fn block_at_or_before(t:&Posts,tri:u32,row:u64)->Result<Option<(Vec<u8>,Vec<u8>)>> {
 let (lo,key)=(post_key(tri,0),post_key(tri,row));
 Ok(t.range::<&[u8]>(lo.as_slice()..=key.as_slice())?.next_back().transpose()?.map(|(k,v)|(k.value().to_vec(),v.value().to_vec())))
}
pub(super) fn add_posting(t:&mut Posts,tri:u32,row:u64)->Result<()> {
 let mut ids=Vec::new();
 match block_at_or_before(t,tri,row)? {
  Some((k,v))=>{decode_block(&k,&v,&mut ids)?;match ids.binary_search(&row) {Ok(_)=>return Ok(()),Err(i)=>ids.insert(i,row)}}
  None=>{
   // `row` is below every block of this trigram: it becomes the first row of the lowest block, whose key changes.
   let (key,hi)=(post_key(tri,row),post_key(tri,u64::MAX));
   let next=t.range::<&[u8]>(key.as_slice()..=hi.as_slice())?.next().transpose()?.map(|(k,v)|(k.value().to_vec(),v.value().to_vec()));
   ids.push(row);if let Some((k,v))=next {decode_block(&k,&v,&mut ids)?;t.remove(k.as_slice())?;}
  }
 }
 blocks(&ids,|first,value|{t.insert(post_key(tri,first).as_slice(),value)?;Ok(())})
}
pub(super) fn remove_posting(t:&mut Posts,tri:u32,row:u64)->Result<()> {
 let Some((k,v))=block_at_or_before(t,tri,row)? else{return Ok(())};
 let mut ids=Vec::new();decode_block(&k,&v,&mut ids)?;
 let Ok(i)=ids.binary_search(&row) else{return Ok(())};ids.remove(i);
 if i==0 {t.remove(k.as_slice())?;}
 blocks(&ids,|first,value|{t.insert(post_key(tri,first).as_slice(),value)?;Ok(())})
}

/// What the reverse map keeps about one row.
pub(super) struct Record {pub id:u64,pub tris:Vec<u32>,pub flags:u8,pub fanout:u64,pub json:u64}
impl Record {
 pub fn new(id:u64,tris:Vec<u32>,s:&RowStats)->Self {Record{id,tris,flags:u8::from(s.missing>0)|(u8::from(s.nulls>0)<<1)|(u8::from(s.unorderable>0)<<2),fanout:s.fanout,json:s.json_bytes}}
 pub fn encode(&self)->Vec<u8> {
  let mut out=vec![3u8];put_varint(&mut out,self.id);out.push(self.flags);put_varint(&mut out,self.fanout);put_varint(&mut out,self.json);put_varint(&mut out,self.tris.len() as u64);
  let mut last=0u32;for (i,t) in self.tris.iter().enumerate() {put_varint(&mut out,u64::from(if i==0{*t}else{*t-last}));last=*t;}out
 }
 pub fn decode(bytes:&[u8])->Result<Self> {
  if bytes.first()!=Some(&3) {return Err(corrupt())}
  let mut b=&bytes[1..];let id=get_varint(&mut b)?;let Some((&flags,rest))=b.split_first() else{return Err(corrupt())};b=rest;
  let (fanout,json,n)=(get_varint(&mut b)?,get_varint(&mut b)?,get_varint(&mut b)?);
  let mut tris=Vec::with_capacity(usize::try_from(n).unwrap_or(0).min(bytes.len()));let mut last=0u32;
  for i in 0..n {let d=u32::try_from(get_varint(&mut b)?).map_err(|_|corrupt())?;last=if i==0{d}else{last.checked_add(d).ok_or_else(corrupt)?};tris.push(last);}
  Ok(Record{id,tris,flags,fanout,json})
 }
 pub fn stats(&self,row:&str)->RowStats {RowStats{key:row.into(),missing:u64::from(self.flags&1),nulls:u64::from((self.flags>>1)&1),fanout:self.fanout,json_bytes:self.json,key_bytes:row.len() as u64,values:vec![],unorderable:u64::from((self.flags>>2)&1)}}
}

/// Replaces one row's trigrams. A row that is already indexed keeps its row number and only its changed trigrams are touched.
pub(super) fn write(tx:&redb::WriteTransaction,d:&Manifest,row:&str,grams:&BTreeSet<String>,new:&RowStats)->Result<Option<RowStats>> {
 let mut rev=tx.open_table(TableDefinition::<&str,&[u8]>::new(&d.reverse()))?;let mut posts=tx.open_table(TableDefinition::<&[u8],&[u8]>::new(&d.entries()))?;
 let mut dict=tx.open_table(TableDefinition::<&str,u32>::new(&dict_name(d)))?;let mut ids=tx.open_table(TableDefinition::<u64,&str>::new(&ids_name(d)))?;let mut counters=tx.open_table(TableDefinition::<&str,u64>::new(&counters_name(d)))?;
 let old=rev.get(row)?.map(|v|Record::decode(v.value())).transpose()?;
 let next_row=counters.get("row")?.map(|v|v.value()).unwrap_or(0);let next_tri=counters.get("tri")?.map(|v|v.value()).unwrap_or(0);let (mut row_n,mut tri_n)=(next_row,next_tri);
 let id=match &old {Some(o)=>o.id,None=>{let id=row_n;row_n+=1;ids.insert(id,row)?;id}};
 let mut tris=Vec::with_capacity(grams.len());
 for g in grams {let found=dict.get(g.as_str())?.map(|v|v.value());let t=match found {Some(t)=>t,None=>{let t=u32::try_from(tri_n).map_err(|_|corrupt())?;tri_n+=1;dict.insert(g.as_str(),t)?;t}};tris.push(t);}
 tris.sort_unstable();
 let before:&[u32]=old.as_ref().map(|o|o.tris.as_slice()).unwrap_or(&[]);
 for t in before {if tris.binary_search(t).is_err() {remove_posting(&mut posts,*t,id)?;}}
 for t in &tris {if before.binary_search(t).is_err() {add_posting(&mut posts,*t,id)?;}}
 if row_n!=next_row {counters.insert("row",row_n)?;}if tri_n!=next_tri {counters.insert("tri",tri_n)?;}
 rev.insert(row,Record::new(id,tris,new).encode().as_slice())?;
 Ok(old.map(|o|o.stats(row)))
}
/// Removes one row; returns its old counters.
pub(super) fn remove(tx:&redb::WriteTransaction,d:&Manifest,row:&str)->Result<Option<RowStats>> {
 let mut rev=tx.open_table(TableDefinition::<&str,&[u8]>::new(&d.reverse()))?;
 let old=rev.remove(row)?.map(|v|Record::decode(v.value())).transpose()?;let Some(o)=old else{return Ok(None)};
 let mut posts=tx.open_table(TableDefinition::<&[u8],&[u8]>::new(&d.entries()))?;let mut ids=tx.open_table(TableDefinition::<u64,&str>::new(&ids_name(d)))?;
 for t in &o.tris {remove_posting(&mut posts,*t,o.id)?;}ids.remove(o.id)?;Ok(Some(o.stats(row)))
}

/// Reads the posting blocks of one trigram of the needle (empty when the trigram never occurred).
pub(super) fn read(index:&redb::ReadTransaction,d:&Manifest,gram:&str,work:&mut super::execution::Work)->Result<Vec<u64>> {
 let dict=index.open_table(TableDefinition::<&str,u32>::new(&dict_name(d)))?;let Some(tri)=dict.get(gram)?.map(|v|v.value()) else{return Ok(vec![])};
 let posts=index.open_table(TableDefinition::<&[u8],&[u8]>::new(&d.entries()))?;let (lo,hi)=(post_key(tri,0),post_key(tri,u64::MAX));let mut out=Vec::new();
 for r in posts.range::<&[u8]>(lo.as_slice()..=hi.as_slice())? {let (k,v)=r?;work.bytes+=(k.value().len()+v.value().len()) as u64;decode_block(k.value(),v.value(),&mut out)?;}
 work.entries+=out.len() as u64;Ok(out)
}
/// Row keys of the given row numbers, in row-number order; a number without a key is skipped.
pub(super) fn names(index:&redb::ReadTransaction,d:&Manifest,numbers:&[u64])->Result<Vec<String>> {
 let ids=index.open_table(TableDefinition::<u64,&str>::new(&ids_name(d)))?;let mut out=Vec::with_capacity(numbers.len());
 for n in numbers {if let Some(v)=ids.get(*n)? {out.push(v.value().to_owned());}}Ok(out)
}

/// What a `Builder` write-out covers: only the rows (reverse map and row numbers: always in ascending key order, so they are appended and a write-out can
/// happen at any time), or everything held (dictionary and postings too: written in trigram order, so best done once).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Flush {Rows,All}
/// Every reservation that grows with the data being built is made through `memory` under this name.
const SITE:&str="index.trigram_build";
/// The postings of one trigram while building: finished blocks in the table format, and the block being filled.
#[derive(Default)]
struct PostList {blocks:Vec<(u64,Vec<u8>)>,first:u64,last:u64,value:Vec<u8>,open:bool}
impl PostList {
 fn push(&mut self,id:u64)->Result<()> {
  if !self.open {self.first=id;self.last=id;self.open=true;return Ok(())}
  let delta=id-self.last;
  if self.value.len()+varint_len(delta)>BLOCK_MAX {let block=(self.first,std::mem::take(&mut self.value));crate::memory::push(SITE,&mut self.blocks,block)?;self.first=id;}
  else {crate::memory::reserve(SITE,&mut self.value,10)?;put_varint(&mut self.value,delta);}
  self.last=id;Ok(())
 }
 fn take(&mut self)->Result<Vec<(u64,Vec<u8>)>> {
  let mut out=std::mem::take(&mut self.blocks);
  if self.open {crate::memory::push(SITE,&mut out,(self.first,std::mem::take(&mut self.value)))?;}
  self.open=false;Ok(out)
 }
}
/// Bulk build of a fresh generation: rows are numbered in the order they arrive (ascending row key). Each row's reverse record and row number go to a
/// buffer that is appended to the tables every `ROWS_FLUSH_BYTES`; postings are kept in memory already as the table's blocks (about 2 bytes per posting)
/// together with the dictionary, and are written once, in trigram order, when the rows are done. Only a table so large that its postings reach
/// `POSTS_FLUSH_BYTES` is written in more than one pass: a later pass inserts between keys written earlier, and redb's file then grows more.
pub(super) struct Builder {
 next_row:u64,next_tri:u32,dict:HashMap<String,u32>,new_grams:Vec<(String,u32)>,posts:Vec<PostList>,post_bytes:usize,
 ids:Vec<(u64,String)>,reverse:Vec<(String,Vec<u8>)>,rows_bytes:usize,rows_limit:usize,posts_limit:usize,
 mode:Flush,stage:u8,pos:usize,
}
impl Default for Builder {fn default()->Self {Self::with_limits(ROWS_FLUSH_BYTES,POSTS_FLUSH_BYTES)}}
impl Builder {
 pub fn with_limits(rows_limit:usize,posts_limit:usize)->Self {Builder{next_row:0,next_tri:0,dict:HashMap::new(),new_grams:Vec::new(),posts:Vec::new(),post_bytes:0,ids:Vec::new(),reverse:Vec::new(),rows_bytes:0,rows_limit,posts_limit,mode:Flush::All,stage:0,pos:0}}
 /// Adds one row. The first row of a segment asks the system for the memory a segment starts with; every later reservation is made before the row is
 /// added. A refusal is `OutOfMemory`, and the build is left as it was before the row.
 pub fn add(&mut self,row:&str,grams:&BTreeSet<String>,stats:&RowStats)->Result<()> {
  if self.rows_bytes==0&&self.post_bytes==0 {crate::memory::probe(SITE,PROBE_BYTES)?;}
  crate::memory::reserve(SITE,&mut self.ids,1)?;crate::memory::reserve(SITE,&mut self.reverse,1)?;
  crate::memory::reserve_map(SITE,&mut self.dict,grams.len())?;crate::memory::reserve(SITE,&mut self.new_grams,grams.len())?;crate::memory::reserve(SITE,&mut self.posts,grams.len())?;
  let (name,name_again)=(crate::memory::copy_str(SITE,row)?,crate::memory::copy_str(SITE,row)?);
  let id=self.next_row;let mut tris=crate::memory::vec_with_capacity::<u32>(SITE,grams.len())?;
  for g in grams {
   let t=match self.dict.get(g.as_str()) {
    Some(t)=>*t,
    None=>{let t=self.next_tri;let (key,again)=(crate::memory::copy_str(SITE,g)?,crate::memory::copy_str(SITE,g)?);self.dict.insert(key,t);self.new_grams.push((again,t));self.posts.push(PostList::default());self.next_tri+=1;self.post_bytes+=2*g.len()+200;t}
   };
   tris.push(t);self.posts[t as usize].push(id)?;self.post_bytes+=3;
  }
  self.next_row+=1;tris.sort_unstable();let record=Record::new(id,tris,stats).encode();self.rows_bytes+=2*row.len()+record.len()+96;
  self.ids.push((id,name));self.reverse.push((name_again,record));Ok(())
 }
 /// The write-out the held data calls for now, if any.
 pub fn due(&self)->Option<Flush> {if self.post_bytes>=self.posts_limit {Some(Flush::All)} else if self.rows_bytes>=self.rows_limit {Some(Flush::Rows)} else {None}}
 pub fn begin(&mut self,flush:Flush) {self.mode=flush;self.stage=0;self.pos=0;}
 /// Writes a bounded part of what `begin` chose. Returns true once all of it is written; the builder then holds nothing of it any more.
 pub fn flush_some(&mut self,tx:&redb::WriteTransaction,d:&Manifest,budget:usize,limit:std::time::Duration)->Result<bool> {
  let started=std::time::Instant::now();let mut spent=0usize;
  macro_rules! run{($table:expr,$first:expr,$items:expr)=>{{
   let append=$table.last()?.is_none_or(|(k,_)|k.value()<$first);
   if append {let mut cursor=$table.lower_bound_mut(std::ops::Bound::Included($first))?;for (k,v) in $items {cursor.insert_before(k,v).map_err(redb::Error::from)?;}cursor.close()?;}
   else {for (k,v) in $items {$table.insert(k,v)?;}}
  }}}
  loop {
   match self.stage {
    0=>{
     if self.pos>=self.ids.len() {self.ids=Vec::new();self.stage=1;self.pos=0;continue}
     let from=self.pos;loop {spent+=self.ids[self.pos].1.len()+8;self.pos+=1;if self.pos>=self.ids.len()||spent>=budget||started.elapsed()>=limit {break}}
     let part=&self.ids[from..self.pos];let mut t=tx.open_table(TableDefinition::<u64,&str>::new(&ids_name(d)))?;
     run!(t,part[0].0,part.iter().map(|(n,r)|(*n,r.as_str())));
    }
    1=>{
     if self.pos>=self.reverse.len() {
      self.reverse=Vec::new();self.rows_bytes=0;
      if self.mode==Flush::Rows {self.stage=0;self.pos=0;return Ok(true)}
      self.new_grams.sort_unstable();self.stage=2;self.pos=0;continue
     }
     let from=self.pos;loop {spent+=self.reverse[self.pos].0.len()+self.reverse[self.pos].1.len();self.pos+=1;if self.pos>=self.reverse.len()||spent>=budget||started.elapsed()>=limit {break}}
     let part=&self.reverse[from..self.pos];let mut t=tx.open_table(TableDefinition::<&str,&[u8]>::new(&d.reverse()))?;
     run!(t,part[0].0.as_str(),part.iter().map(|(r,v)|(r.as_str(),v.as_slice())));
    }
    2=>{
     if self.pos>=self.new_grams.len() {self.new_grams=Vec::new();self.stage=3;self.pos=0;continue}
     let from=self.pos;loop {spent+=self.new_grams[self.pos].0.len()+8;self.pos+=1;if self.pos>=self.new_grams.len()||spent>=budget||started.elapsed()>=limit {break}}
     let part=&self.new_grams[from..self.pos];let mut t=tx.open_table(TableDefinition::<&str,u32>::new(&dict_name(d)))?;
     run!(t,part[0].0.as_str(),part.iter().map(|(g,n)|(g.as_str(),*n)));
    }
    3=>{
     if self.pos>=self.posts.len() {self.stage=4;self.pos=0;self.post_bytes=self.posts.len()*160;continue}
     let mut part:Vec<([u8;12],Vec<u8>)>=Vec::new();
     loop {
      let tri=self.pos as u32;self.pos+=1;
      for (first,value) in self.posts[tri as usize].take()? {spent+=12+value.len();part.push((post_key(tri,first),value));}
      if self.pos>=self.posts.len()||spent>=budget||started.elapsed()>=limit {break}
     }
     if part.is_empty() {continue}
     let mut t=tx.open_table(TableDefinition::<&[u8],&[u8]>::new(&d.entries()))?;
     run!(t,part[0].0.as_slice(),part.iter().map(|(k,v)|(k.as_slice(),v.as_slice())));
    }
    _=>{
     let mut t=tx.open_table(TableDefinition::<&str,u64>::new(&counters_name(d)))?;t.insert("row",self.next_row)?;t.insert("tri",u64::from(self.next_tri))?;
     self.stage=0;self.pos=0;return Ok(true)
    }
   }
   if spent>=budget||started.elapsed()>=limit {return Ok(false)}
  }
 }
}

#[cfg(test)] mod tests {
 use super::*;use redb::{Database,ReadableDatabase,ReadableTableMetadata};use std::collections::{BTreeMap,BTreeSet};
 fn lcg(s:&mut u64)->u64 {*s=s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);*s>>33}
 fn all(db:&Database)->BTreeMap<u32,Vec<u64>> {
  let tx=db.begin_read().unwrap();let t=tx.open_table(TableDefinition::<&[u8],&[u8]>::new("posts")).unwrap();let mut out=BTreeMap::<u32,Vec<u64>>::new();
  for r in t.iter().unwrap() {let (k,v)=r.unwrap();let tri=u32::from_be_bytes(k.value()[..4].try_into().unwrap());decode_block(k.value(),v.value(),out.entry(tri).or_default()).unwrap();}out
 }
 #[test] fn blocks_stay_sorted_split_and_follow_a_model_under_random_adds_and_removes() {
  let path=std::env::temp_dir().join(format!("{}.redb",uuid::Uuid::new_v4()));let db=Database::create(&path).unwrap();
  let mut model=BTreeMap::<u32,BTreeSet<u64>>::new();let mut s=7u64;
  for round in 0..40 {
   let tx=db.begin_write().unwrap();{let mut t=tx.open_table(TableDefinition::<&[u8],&[u8]>::new("posts")).unwrap();
    for _ in 0..600 {let tri=(lcg(&mut s)%5) as u32;let row=lcg(&mut s)%(if round<20{3000}else{60});
     if lcg(&mut s)%3==0 {remove_posting(&mut t,tri,row).unwrap();model.entry(tri).or_default().remove(&row);}else{add_posting(&mut t,tri,row).unwrap();model.entry(tri).or_default().insert(row);}}}
   tx.commit().unwrap();
   let got=all(&db);for (tri,rows) in &model {assert_eq!(got.get(tri).cloned().unwrap_or_default(),rows.iter().copied().collect::<Vec<_>>(),"round {round} trigram {tri}");}
  }
  let tx=db.begin_read().unwrap();let t=tx.open_table(TableDefinition::<&[u8],&[u8]>::new("posts")).unwrap();
  assert!(t.iter().unwrap().all(|r|r.unwrap().1.value().len()<=BLOCK_MAX),"no block exceeds the limit");
  drop(t);drop(tx);drop(db);let _=std::fs::remove_file(path);
 }
 #[test] fn record_round_trips() {
  let s=RowStats{key:"k".into(),missing:1,nulls:0,fanout:3,json_bytes:12345,key_bytes:1,values:vec![],unorderable:1};
  let r=Record::new(99_999,vec![0,1,5,300,70_000],&s);let back=Record::decode(&r.encode()).unwrap();
  assert_eq!((back.id,&back.tris,back.flags,back.fanout,back.json),(99_999,&vec![0,1,5,300,70_000],r.flags,3,12345));
  let st=back.stats("kk");assert_eq!((st.missing,st.nulls,st.unorderable,st.key_bytes),(1,0,1,2));
  let bytes=r.encode();for cut in 1..bytes.len() {let _=Record::decode(&bytes[..cut]);}assert!(Record::decode(&bytes[..3]).is_err());
 }
 fn manifest()->Manifest {
  let def=Definition{table:"t".into(),paths:vec![],kind:Kind::Trigram,directions:vec![]};
  Manifest{id:1,canonical:def.canonical().unwrap(),definition:def,generation:1,ready:false,state:IndexState::Active,reason:String::new(),last_use_ms:0,interval_ms:0,build_ms:0.,reads:0,matched:0,bytes:0,waste:0,replacement:None,estimated_ms:0.,actual_ms:0.,summary:None,orderable:false,prefix_only_reads:0,verified_prefixes:vec![]}
 }
 /// A build whose limits force several row write-outs and a second pass over the postings still equals the model: every trigram's rows, the row numbers, the reverse map and the counters.
 #[test] fn builder_with_small_limits_writes_rows_in_pieces_and_postings_in_two_passes() {
  let d=manifest();let path=std::env::temp_dir().join(format!("{}.redb",uuid::Uuid::new_v4()));let db=Database::create(&path).unwrap();
  {let tx=db.begin_write().unwrap();create(&tx,&d).unwrap();tx.commit().unwrap();}
  let pool=(0..60).map(|i|format!("g{i:02}")).collect::<Vec<_>>();let mut seed=3u64;
  let mut model=BTreeMap::<String,BTreeSet<u64>>::new();
  let mut b=Builder::with_limits(2_000,9_000);let (mut rows_flushes,mut all_flushes)=(0,0);
  let finish=|b:&mut Builder,f:Flush|{b.begin(f);loop{let tx=db.begin_write().unwrap();let done=b.flush_some(&tx,&d,4096,std::time::Duration::from_secs(5)).unwrap();tx.commit().unwrap();if done{break}}};
  for i in 0..3000u64 {
   let grams=(0..1+lcg(&mut seed)%10).map(|_|pool[(lcg(&mut seed)%(1+(i/50).min(59))) as usize].clone()).collect::<BTreeSet<_>>();
   for g in &grams {model.entry(g.clone()).or_default().insert(i);}
   let stats=RowStats::new(&format!("r{i:05}"),100,&[]).unwrap();
   b.add(&format!("r{i:05}"),&grams,&stats).unwrap();
   if let Some(f)=b.due() {if f==Flush::All {all_flushes+=1} else {rows_flushes+=1}finish(&mut b,f);}
  }
  finish(&mut b,Flush::All);
  assert!(rows_flushes>=2&&all_flushes>=1,"the limits must force several write-outs (rows {rows_flushes}, all {all_flushes})");
  let rtx=db.begin_read().unwrap();let dict=rtx.open_table(TableDefinition::<&str,u32>::new(&dict_name(&d))).unwrap();
  assert_eq!(dict.len().unwrap() as usize,model.len());
  for (gram,rows) in &model {let mut work=super::super::execution::Work::default();assert_eq!(read(&rtx,&d,gram,&mut work).unwrap(),rows.iter().copied().collect::<Vec<_>>(),"postings of {gram}");}
  let ids=rtx.open_table(TableDefinition::<u64,&str>::new(&ids_name(&d))).unwrap();let rev=rtx.open_table(TableDefinition::<&str,&[u8]>::new(&d.reverse())).unwrap();
  assert_eq!((ids.len().unwrap(),rev.len().unwrap()),(3000,3000));
  assert_eq!(ids.get(1234).unwrap().unwrap().value(),"r01234");
  let record=Record::decode(rev.get("r02999").unwrap().unwrap().value()).unwrap();assert_eq!(record.id,2999);
  assert_eq!(record.tris.len(),model.values().filter(|r|r.contains(&2999)).count());
  let counters=rtx.open_table(TableDefinition::<&str,u64>::new(&counters_name(&d))).unwrap();assert_eq!((counters.get("row").unwrap().unwrap().value(),counters.get("tri").unwrap().unwrap().value()),(3000,model.len() as u64));
  drop((ids,rev,counters,dict,rtx,db));let _=std::fs::remove_file(path);
 }
}
