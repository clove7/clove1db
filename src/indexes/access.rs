use super::{format::*,Shared};
use crate::{fields::{Expr,Compare,Path,Step,Value},query::{OrderSource,Direction,optimizer::{Plan,Explain,Alternative}},units::Result};
use redb::TableDefinition;
use std::{collections::BTreeSet,time::Instant};
#[derive(Clone)] pub(crate) struct Access {pub keys:Vec<String>,pub plan:Plan,pub sequence:u64,pub age_ms:u64,pub covered:bool,pub ids:Vec<u64>,pub count:Option<u64>,pub planning_micros:u64}
fn suitable(p:&Path)->bool {!p.steps.iter().any(|s|matches!(s,Step::All))}
pub(super) fn wanted(table:&str,expr:Option<&Expr>,order:&[(OrderSource,Direction)])->Vec<Definition> {
 fn visit(e:&Expr,table:&str,out:&mut Vec<Definition>) {match e {
  Expr::Compare{path,op,values} if suitable(path)=>{
   let kind=match op {Compare::Text|Compare::Fuzzy(_)=>Kind::Token,Compare::Parts=>Kind::Parts,Compare::Contains=>{if !matches!(values.first(),Some(Value::String(s)) if s.chars().count()>=3){return}Kind::Trigram},_=>Kind::Value};out.push(Definition{table:table.into(),paths:vec![path.clone()],kind,directions:vec![]});
  },Expr::Presence{path,..} if suitable(path)=>out.push(Definition{table:table.into(),paths:vec![path.clone()],kind:Kind::Value,directions:vec![]}),
  Expr::And(a,b)|Expr::Or(a,b)=>{visit(a,table,out);visit(b,table,out)},_=>()
 }}
 let mut defs=vec![];if let Some(e)=expr{visit(e,table,&mut defs)}for(o,_)in order {match o {OrderSource::Field(p) if suitable(p)=>defs.push(Definition{table:table.into(),paths:vec![p.clone()],kind:Kind::Value,directions:vec![]}),OrderSource::LastWrite=>defs.push(Definition{table:table.into(),paths:vec![],kind:Kind::LastWrite,directions:vec![]}),_=>()}}
 defs.extend(super::planner::definitions(table,expr,order));
 let mut distinct=vec![];for d in defs {if !distinct.contains(&d){distinct.push(d)}}distinct
}
pub(super) fn trigrams(s:&str)->Vec<String> {s.chars().collect::<Vec<_>>().windows(3).map(|w|w.iter().collect()).collect::<BTreeSet<_>>().into_iter().collect()}
impl Shared {
 pub(crate) fn access(&self,table:&str,view:&crate::ReadView,expr:Option<&Expr>,order:&[(OrderSource,Direction)],stale:bool,explain:&mut Explain,count:bool,limit:Option<usize>,runtime:&crate::query::optimizer::Shared,forced:Option<&crate::query::PlanHint>)->Result<Option<Access>> {
  if forced.is_some_and(|hint|hint.is_scan()){return Ok(None)}
  let planning=Instant::now();
  let Some(pair)=self.pair()else{return Ok(None)};if pair.ready==0||(!stale&&pair.primary.head!=view.head)||pair.primary.database_uuid!=view.database_uuid{return Ok(None)}
  if super::worker::identity(view)?!=metadata(&pair.index)?.identity{return Ok(None)}
  let defs=definitions(&pair.index)?;
  use redb::ReadableTableMetadata;
  let rows=view.tx.open_table(TableDefinition::<&str,&[u8]>::new(table))?.len()? as f64;
  let recipes=super::planner::candidates(&pair,&defs,table,expr,order,limit,rows,explain.estimated_rows)?;
  let multipliers=crate::query::optimizer::index_multipliers(runtime);
  let scan=explain.alternatives.iter().map(|a|a.estimated_ms).fold(f64::INFINITY,f64::min);
  let mut best=None;let mut best_cost=scan;
  for recipe in recipes {
   let covering=count&&recipe.covered&&pair.primary.head==view.head;
   let plan=if covering{Plan::IndexCount}else{recipe.plan};
   let sort=if !recipe.ordered&&!order.is_empty(){recipe.estimated_rows*(limit.unwrap_or(recipe.estimated_rows as usize).max(1) as f64).log2()*0.00001}else{0.};
   let mut cost=0.01+recipe.index_entries*0.00004+if covering{0.}else{recipe.estimated_rows*0.0003}+sort;
   if matches!(recipe.plan,Plan::IndexFuzzy){cost+=0.15;}
   cost*=multipliers[plan as usize];
   explain.alternatives.push(Alternative{plan,estimated_ms:cost,estimated_rows:recipe.estimated_rows,wait_ms:0.,index_ids:recipe.ids.clone()});
   let matches_forced=if let Some(hint)=forced{hint.plan==plan&&hint.index_ids==recipe.ids&&hint.signature==super::planner::signature(&recipe.node)?}else{false};
   if matches_forced||(forced.is_none()&&cost<best_cost){best_cost=cost;best=Some((recipe,plan,covering));if matches_forced{break}}
  }
  let Some((recipe,plan,covering))=best else{if forced.is_some(){return Err(crate::units::ClError::Validation("verification index plan is unavailable".into()))}return Ok(None)};
  let planning_micros=planning.elapsed().as_micros() as u64;
  let (keys,exact_count,_work)=if covering{let(n,work)=super::execution::count(&pair,&recipe.node)?;(vec![],Some(n),work)}else{let(keys,work)=super::execution::keys(&pair,&recipe.node)?;(keys,None,work)};
  explain.selected=plan;explain.estimated_rows=recipe.estimated_rows;explain.reason="lowest index/scan cost including entries, fetches and sort";
  Ok(Some(Access{keys,count:exact_count,plan,sequence:pair.primary.head,age_ms:pair.published.elapsed().as_millis() as u64,covered:recipe.covered,ids:recipe.ids,planning_micros}))
 }
}

#[cfg(any(test,feature="crash-inject"))]
impl Shared {
 pub(crate) fn hints(&self,table:&str,view:&crate::ReadView,expr:Option<&Expr>,order:&[(OrderSource,Direction)],stale:bool,count:bool,limit:Option<usize>)->Result<Vec<crate::query::PlanHint>> {
  let Some(pair)=self.pair()else{return Ok(vec![])};if (!stale&&pair.primary.head!=view.head)||super::worker::identity(view)?!=metadata(&pair.index)?.identity{return Ok(vec![])}
  use redb::ReadableTableMetadata;let rows=view.tx.open_table(TableDefinition::<&str,&[u8]>::new(table))?.len()? as f64;let defs=definitions(&pair.index)?;
  super::planner::candidates(&pair,&defs,table,expr,order,limit,rows,rows*0.25)?.into_iter().map(|recipe|Ok(crate::query::PlanHint{plan:if count&&recipe.covered&&pair.primary.head==view.head{Plan::IndexCount}else{recipe.plan},index_ids:recipe.ids,signature:super::planner::signature(&recipe.node)?})).collect()
 }
}
