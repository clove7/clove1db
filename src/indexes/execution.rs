use super::{Pair,planner::Node,format::*};
use crate::{fields::{Value,codec},units::{Result,ClError}};
use redb::{ReadableTable,TableDefinition};use std::collections::BTreeSet;
#[derive(Default)]pub(super) struct Work {pub entries:u64,pub bytes:u64}
fn range(pair:&Pair,d:&Manifest,lower:Option<&[u8]>,upper:Option<&[u8]>,work:&mut Work,mut visit:impl FnMut(&str)->Result<bool>)->Result<()> {
 if lower.zip(upper).is_some_and(|(a,b)|a>=b){return Ok(())}
 let table=pair.index.open_table(TableDefinition::<&[u8],&str>::new(&d.entries()))?;let bound=lower.map(std::ops::Bound::Included).unwrap_or(std::ops::Bound::Unbounded);let mut cursor=table.lower_bound(bound)?;
 while let Some((key,row))=cursor.next()?{if upper.is_some_and(|upper|key.value()>=upper){break}work.entries+=1;work.bytes+=(key.value().len()+row.value().len()) as u64;if !visit(row.value())?{break}}
 Ok(())
}
/// The index whose trigram postings are every leaf of `node`: their row numbers can then be combined as numbers, and turned into row keys once.
fn pure(node:&Node)->Option<&Manifest> {
 match node {Node::Postings{definition,..}=>Some(definition),Node::Intersection(a,b)|Node::Union(a,b)=>{let x=pure(a)?;(x.id==pure(b)?.id).then_some(x)},_=>None}
}
fn intersect(a:&[u64],b:&[u64])->Vec<u64> {
 let (small,large)=if a.len()<=b.len(){(a,b)}else{(b,a)};
 if small.len().saturating_mul(16)<large.len() {return small.iter().copied().filter(|n|large.binary_search(n).is_ok()).collect()}
 let (mut i,mut j,mut out)=(0,0,Vec::with_capacity(small.len()));
 while i<a.len()&&j<b.len() {match a[i].cmp(&b[j]) {std::cmp::Ordering::Less=>i+=1,std::cmp::Ordering::Greater=>j+=1,std::cmp::Ordering::Equal=>{out.push(a[i]);i+=1;j+=1}}}out
}
fn union(a:&[u64],b:&[u64])->Vec<u64> {
 let (mut i,mut j,mut out)=(0,0,Vec::with_capacity(a.len()+b.len()));
 while i<a.len()||j<b.len() {if j>=b.len()||(i<a.len()&&a[i]<b[j]){out.push(a[i]);i+=1}else if i>=a.len()||b[j]<a[i]{out.push(b[j]);j+=1}else{out.push(a[i]);i+=1;j+=1}}out
}
fn numbers(pair:&Pair,node:&Node,work:&mut Work)->Result<Vec<u64>> {
 Ok(match node {
  Node::Postings{definition,term}=>super::trigram::read(&pair.index,definition,term,work)?,
  Node::Intersection(a,b)=>{let a=numbers(pair,a,work)?;if a.is_empty(){return Ok(a)}let b=numbers(pair,b,work)?;intersect(&a,&b)},
  Node::Union(a,b)=>{let a=numbers(pair,a,work)?;let b=numbers(pair,b,work)?;union(&a,&b)},
  _=>return Err(ClError::Validation("trigram node expected".into())),
 })
}
fn set(pair:&Pair,node:&Node,work:&mut Work)->Result<BTreeSet<String>> {
 if let Some(definition)=pure(node) {let rows=numbers(pair,node,work)?;return Ok(super::trigram::names(&pair.index,definition,&rows)?.into_iter().collect())}
 Ok(match node {
  Node::Postings{..}=>unreachable!("a lone postings node is pure"),
  Node::Range{definition,lower,upper,..}=>{let mut out=BTreeSet::new();range(pair,definition,lower.as_deref(),upper.as_deref(),work,|row|{out.insert(row.into());Ok(true)})?;out},
  Node::Intersection(a,b)=>{let a=set(pair,a,work)?;let b=set(pair,b,work)?;a.intersection(&b).cloned().collect()},
  Node::Union(a,b)=>{let mut a=set(pair,a,work)?;a.extend(set(pair,b,work)?);a},
  Node::Fuzzy{definition,term,distance}=>{
   let table=pair.index.open_table(FST)?;let bytes=table.get(definition.id)?.ok_or_else(||ClError::Validation("missing token dictionary".into()))?;let dictionary=fst::Set::new(bytes.value().to_vec()).map_err(|_|ClError::Validation("invalid token dictionary".into()))?;let mut out=BTreeSet::new();
   let mut posting=|token:&[u8]|->Result<()> {let token=std::str::from_utf8(token)?;let key=codec::encode_equality(&Value::String(token.into()))?;let mut upper=key.clone();for i in(0..upper.len()).rev(){if upper[i]!=255{upper[i]+=1;upper.truncate(i+1);break}}range(pair,definition,Some(&key),Some(&upper),work,|row|{out.insert(row.into());Ok(true)})};
   use fst::{IntoStreamer,Streamer};
   if let Ok(automaton)=fst::automaton::Levenshtein::new(term,*distance as u32){let mut stream=dictionary.search(automaton).into_stream();while let Some(token)=stream.next(){posting(token)?;}}
   else {let mut stream=dictionary.stream();while let Some(token)=stream.next(){if strsim::levenshtein(std::str::from_utf8(token)?,term)<=*distance as usize{posting(token)?;}}}
   out
  },
  Node::Ordered{..}=>{let mut out=BTreeSet::new();ordered(pair,node,work,|row|{out.insert(row.into());Ok(true)})?;out}
 })
}
fn ordered(pair:&Pair,node:&Node,work:&mut Work,mut visit:impl FnMut(&str)->Result<bool>)->Result<()> {
 let Node::Ordered{definition,lower,upper,reverse,allowed,limit}=node else {unreachable!()};
 if *limit==Some(0){return Ok(())}
 let allowed=allowed.as_ref().map(|node|set(pair,node,work)).transpose()?;let mut accepted=0;
 let mut accept=|row:&str|->Result<bool>{if allowed.as_ref().is_some_and(|a|!a.contains(row)){return Ok(true)}accepted+=1;if !visit(row)?{return Ok(false)}Ok(limit.is_none_or(|limit|accepted<limit))};
 if !reverse {return range(pair,definition,lower.as_deref(),upper.as_deref(),work,accept)}
 // Descending values retain ascending row-key ties. Find a value group from
 // its end, then walk that group forward; a limit never reverses tie order.
 let table=pair.index.open_table(TableDefinition::<&[u8],&str>::new(&definition.entries()))?;let mut next_upper=upper.clone();
 loop {
  let bound=next_upper.as_ref().map(|b|std::ops::Bound::Excluded(b.as_slice())).unwrap_or(std::ops::Bound::Unbounded);let mut back=table.upper_bound(bound)?;let Some((key,row))=back.prev()?else{break};if lower.as_ref().is_some_and(|lo|key.value()<lo.as_slice()){break}
  let suffix=codec::encode(&Value::String(row.value().into()))?;if !key.value().ends_with(&suffix){return Err(ClError::Validation("corrupt index row suffix".into()))}
  let prefix=key.value()[..key.value().len()-suffix.len()].to_vec();drop(key);drop(row);drop(back);
  let mut forward=table.lower_bound(std::ops::Bound::Included(prefix.as_slice()))?;
  while let Some((key,row))=forward.next()?{if !key.value().starts_with(&prefix)||upper.as_ref().is_some_and(|hi|key.value()>=hi.as_slice()){break}work.entries+=1;work.bytes+=(key.value().len()+row.value().len()) as u64;if !accept(row.value())?{return Ok(())}}
  next_upper=Some(prefix);
 }Ok(())
}
pub(super) fn keys(pair:&Pair,node:&Node)->Result<(Vec<String>,Work)> {let mut work=Work::default();let keys=if matches!(node,Node::Ordered{..}){let mut keys=vec![];ordered(pair,node,&mut work,|row|{keys.push(row.into());Ok(true)})?;keys}else{set(pair,node,&mut work)?.into_iter().collect()};Ok((keys,work))}
pub(super) fn count(pair:&Pair,node:&Node)->Result<(u64,Work)> {
 let mut work=Work::default();if let Node::Range{definition,lower,upper,dedup:false}=node{let mut count=0;range(pair,definition,lower.as_deref(),upper.as_deref(),&mut work,|_|{count+=1;Ok(true)})?;Ok((count,work))}else{let keys=set(pair,node,&mut work)?;Ok((keys.len() as u64,work))}
}
