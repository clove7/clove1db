use super::{format::*,planner::{Recipe,Node,equality_terms}};
use crate::{fields::{Expr,Value,codec},query::{OrderSource,Direction,Asc},units::Result};
fn end(p:&[u8])->Option<Vec<u8>>{let mut p=p.to_vec();for i in(0..p.len()).rev(){if p[i]!=255{p[i]+=1;p.truncate(i+1);return Some(p)}}None}
fn component(value:&Value,direction:Direction)->Result<Vec<u8>>{let mut bytes=codec::encode_equality(value)?;if direction!=Asc{for b in &mut bytes{*b=!*b}}Ok(bytes)}
pub(super) fn candidates(defs:&[Manifest],table:&str,expr:Option<&Expr>,order:&[(OrderSource,Direction)],limit:Option<usize>,rows:f64,estimated:f64,filters:&[Recipe])->Result<Vec<Recipe>> {
 use crate::query::optimizer::Plan;
 let(eq,all_equal)=equality_terms(expr);let mut out=vec![];
 let complete_filter=filters.iter().filter(|f|f.covered).min_by(|a,b|a.index_entries.total_cmp(&b.index_entries));
 for d in defs.iter().filter(|d|d.ready&&d.state==IndexState::Active&&d.definition.table==table&&matches!(d.definition.kind,Kind::Value|Kind::LastWrite)) {
  let compound=d.definition.paths.len()>1;let mut prefix=if compound{vec![8]}else{vec![]};let mut equality_count=0;
  for(i,path)in d.definition.paths.iter().enumerate(){let Some((_,value))=eq.iter().find(|(p,_)|p==path)else{break};let value=codec::interpret(value.clone(),&path.kind)?;prefix.extend(component(&value,d.definition.directions.get(i).copied().unwrap_or(Asc))?);equality_count+=1;}
  let has_prefix=equality_count>0;
  let lower=has_prefix.then(||prefix.clone());let upper=if has_prefix{end(&prefix)}else{None};
  let prefix_covers=all_equal&&equality_count==eq.len();
  // A multi-field equality prefix is a useful standalone access path even if
  // its stored order cannot satisfy the requested sort.
  if compound&&has_prefix {
   out.push(Recipe{node:Node::Range{definition:d.clone(),lower:lower.clone(),upper:upper.clone(),dedup:false},plan:if order.is_empty(){Plan::IndexEquality}else{Plan::IndexErs},ids:vec![d.id],covered:prefix_covers,ordered:false,estimated_rows:estimated,index_entries:estimated});
  }
  if order.is_empty()||!d.orderable{continue}
  let mut desired=vec![];let mut field_order=true;
  for(source,direction)in order{match source{OrderSource::Field(path)=>{if !eq.iter().any(|(p,_)|p==path){desired.push((path.clone(),*direction));}},_=>field_order=false}}
  let (matches,reverse)=if d.definition.kind==Kind::LastWrite {(order.len()==1&&matches!(order[0].0,OrderSource::LastWrite),order[0].1!=Asc)}
   else if d.definition.paths.len()==1&&field_order {if equality_count==1{(desired.is_empty(),false)}else{(desired.len()==1&&desired[0].0==d.definition.paths[0],desired.first().is_some_and(|(_,dir)|*dir!=Asc))}}
   else if compound&&field_order {let remaining=&d.definition.paths[equality_count..];(remaining.len()==desired.len()&&remaining.iter().zip(&desired).enumerate().all(|(j,(path,(wanted,direction)))|path==wanted&&d.definition.directions.get(equality_count+j).copied().unwrap_or(Asc)==*direction),false)}
   else {(false,false)};
  if !matches{continue}
  let covered=expr.is_none()||prefix_covers||complete_filter.is_some();
  let allowed=if expr.is_some()&&!prefix_covers {complete_filter.map(|r|Box::new(r.node.clone()))}else{None};
  let used=if allowed.is_some(){let mut ids=complete_filter.unwrap().ids.clone();ids.push(d.id);ids.sort_unstable();ids.dedup();ids}else{vec![d.id]};
  let early=covered.then_some(limit).flatten();
  let read_rows=if prefix_covers {early.map(|n|n as f64).unwrap_or(estimated).min(estimated)}else{early.map(|n|(n as f64*rows/estimated.max(1.)).min(rows)).unwrap_or(rows)};
  let entries=read_rows+if allowed.is_some(){complete_filter.unwrap().index_entries}else{0.};
  out.push(Recipe{node:Node::Ordered{definition:d.clone(),lower,upper,reverse,allowed,limit:early},plan:if compound{Plan::IndexEsr}else{Plan::IndexOrder},ids:used,covered,ordered:true,estimated_rows:early.map(|n|(n as f64).min(estimated)).unwrap_or(estimated),index_entries:entries});
 }
 Ok(out)
}
