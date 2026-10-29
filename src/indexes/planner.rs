use super::{format::*,Pair};
use crate::{fields::{Expr,Compare,Presence,Path,Step,Value,codec},query::{Direction,OrderSource,Asc,optimizer::Plan},units::Result};
#[derive(Clone)]pub(super) enum Node {
 Range{definition:Manifest,lower:Option<Vec<u8>>,upper:Option<Vec<u8>>,dedup:bool},
 /// The rows whose text has this trigram, from a trigram index (`trigram.rs`).
 Postings{definition:Manifest,term:String},
 Intersection(Box<Node>,Box<Node>),Union(Box<Node>,Box<Node>),
 Fuzzy{definition:Manifest,term:String,distance:u8},
 Ordered{definition:Manifest,lower:Option<Vec<u8>>,upper:Option<Vec<u8>>,reverse:bool,allowed:Option<Box<Node>>,limit:Option<usize>},
}
#[derive(Clone)]pub(super) struct Recipe {pub node:Node,pub plan:Plan,pub ids:Vec<u64>,pub covered:bool,pub ordered:bool,pub estimated_rows:f64,pub index_entries:f64}
fn end(p:&[u8])->Option<Vec<u8>> {let mut p=p.to_vec();for i in(0..p.len()).rev(){if p[i]!=255{p[i]+=1;p.truncate(i+1);return Some(p)}}None}
fn scalar_path(path:&Path)->bool {!path.steps.iter().any(|s|matches!(s,Step::Any|Step::All))}
fn eligible<'a>(defs:&'a[Manifest],table:&str)->impl Iterator<Item=&'a Manifest> {defs.iter().filter(move|d|d.ready&&d.state==IndexState::Active&&d.definition.table==table)}
fn ids(a:&[u64],b:&[u64])->Vec<u64>{let mut out=a.to_vec();out.extend(b);out.sort_unstable();out.dedup();out}
fn node(d:&Manifest,lo:Option<Vec<u8>>,hi:Option<Vec<u8>>,dedup:bool)->Node {Node::Range{definition:d.clone(),lower:lo,upper:hi,dedup}}
fn estimate(pair:&Pair,table:&str,path:&Path,op:&Compare,values:&[Value],rows:f64)->Result<f64> {
 if let Some((_,_,s))=pair.statistics.iter().find(|(t,p,_)|t==table&&p==path){let v=values.first().unwrap_or(&Value::Missing);let fraction=match op {Compare::Eq=>s.equality(v)?,Compare::Ne=>1.-s.equality(v)?,Compare::In=>values.iter().map(|v|s.equality(v)).collect::<Result<Vec<_>>>()?.iter().sum::<f64>().min(1.),Compare::Lt|Compare::Le=>s.range(v)?,Compare::Gt|Compare::Ge=>1.-s.range(v)?,Compare::Between=>(s.range(values.get(1).unwrap_or(v))?-s.range(v)?).max(0.),_=>0.25};return Ok((rows*fraction).clamp(0.,rows));}Ok(rows*0.25)
}
fn leaf(pair:&Pair,defs:&[Manifest],table:&str,path:&Path,op:&Compare,values:&[Value],rows:f64)->Result<Vec<Recipe>> {
 if path.steps.iter().any(|s|matches!(s,Step::All)){return Ok(vec![])}
 let values=values.iter().map(|v|codec::interpret(v.clone(),&path.kind)).collect::<Result<Vec<_>>>()?;let Some(first)=values.first()else{return Ok(vec![])};
 if matches!(op,Compare::Lt|Compare::Le|Compare::Gt|Compare::Ge|Compare::Between)&&values.iter().any(|v|codec::encode(v).is_err()){return Ok(vec![])}
 let kind=match op {Compare::Text|Compare::Fuzzy(_)=>Kind::Token,Compare::Contains=>Kind::Trigram,Compare::Parts=>Kind::Parts,_=>Kind::Value};let mut out=vec![];
 for d in eligible(defs,table).filter(|d|d.definition.kind==kind&&d.definition.paths.first()==Some(path)) {
  let compound=d.definition.paths.len()>1;
  if compound&&(kind!=Kind::Value||d.definition.directions.first().is_some_and(|d|*d!=Asc)){continue}
  let prefix=if compound{vec![8]}else{vec![]};let encode=|v:&Value|->Result<Vec<u8>>{let mut k=prefix.clone();k.extend(codec::encode_equality(v)?);Ok(k)};
  let k=encode(first)?;let mut type_prefix=prefix.clone();type_prefix.push(codec::encode_equality(first)?[0]);let all_end=if compound{end(&prefix)}else{None};
  let any=!scalar_path(path);let estimated=estimate(pair,table,path,op,&values,rows)?;
  let(eq_lo,eq_hi)=(Some(k.clone()),end(&k));
  let (n,plan,covered,entries)=match op {
   Compare::Eq=>(node(d,eq_lo,eq_hi,false),Plan::IndexEquality,true,estimated),
   Compare::Ne=>(Node::Union(Box::new(node(d,Some(type_prefix.clone()),Some(k.clone()),any)),Box::new(node(d,end(&k),end(&type_prefix),any))),Plan::IndexUnion,true,estimated),
   Compare::Gt=>(node(d,end(&k),end(&type_prefix),any),if compound{Plan::IndexErs}else{Plan::IndexRange},true,estimated),
   Compare::Ge=>(node(d,Some(k),end(&type_prefix),any),if compound{Plan::IndexErs}else{Plan::IndexRange},true,estimated),
   Compare::Lt=>(node(d,Some(type_prefix),Some(k),any),if compound{Plan::IndexErs}else{Plan::IndexRange},true,estimated),
   Compare::Le=>(node(d,Some(type_prefix),end(&k),any),if compound{Plan::IndexErs}else{Plan::IndexRange},true,estimated),
   Compare::Between=>{let Some(upper)=values.get(1)else{continue};(node(d,Some(k),Some(encode(upper)?),any),if compound{Plan::IndexErs}else{Plan::IndexRange},std::mem::discriminant(first)==std::mem::discriminant(upper),estimated)},
   Compare::In=>{let mut nodes=values.iter().map(|v|{let k=encode(v)?;Ok(node(d,Some(k.clone()),end(&k),false))}).collect::<Result<Vec<_>>>()?.into_iter();let Some(mut n)=nodes.next()else{continue};for next in nodes{n=Node::Union(Box::new(n),Box::new(next));}(n,Plan::IndexUnion,true,estimated)},
   Compare::Prefix=>{if !matches!(first,Value::String(_)){continue}let p=&k[..k.len()-2];(node(d,Some(p.to_vec()),end(p),any),Plan::IndexPrefix,true,estimated)},
   Compare::Text|Compare::Contains=>{let Value::String(term)=first else{continue};let terms=if *op==Compare::Text{crate::query::eval::tokens(term)}else{super::access::trigrams(term)};if terms.is_empty()||terms.len()>64{continue}let mut nodes=terms.iter().map(|term|{if *op==Compare::Contains{return Ok(Node::Postings{definition:d.clone(),term:term.clone()})}let k=codec::encode_equality(&Value::String(term.clone()))?;Ok(node(d,Some(k.clone()),end(&k),false))}).collect::<Result<Vec<_>>>()?.into_iter();let Some(mut n)=nodes.next()else{continue};for next in nodes{n=Node::Intersection(Box::new(n),Box::new(next));}(n,if *op==Compare::Text{Plan::IndexText}else{Plan::IndexContains},*op==Compare::Text&&!any,estimated*terms.len() as f64)},
   // The fingerprints of the parts of a protected value: every term of the condition must be among the terms of the row, read from posting blocks like `Contains`.
   // The rows are checked against the condition again (`covered` is false), so a count is the number of rows that have all the terms.
   Compare::Parts=>{let Value::String(term)=first else{continue};let terms=crate::query::eval::tokens(term);if terms.is_empty()||terms.len()>64{continue}let mut nodes=terms.iter().map(|term|Node::Postings{definition:d.clone(),term:term.clone()}).collect::<Vec<_>>().into_iter();let Some(mut n)=nodes.next()else{continue};for next in nodes{n=Node::Intersection(Box::new(n),Box::new(next));}(n,Plan::IndexContains,false,estimated*terms.len() as f64)},
   Compare::Fuzzy(distance)=>{let Value::String(term)=first else{continue};(Node::Fuzzy{definition:d.clone(),term:term.clone(),distance:*distance},Plan::IndexFuzzy,true,estimated)},
  };let _=all_end;out.push(Recipe{node:n,plan,ids:vec![d.id],covered,ordered:false,estimated_rows:estimated,index_entries:entries});
 }
 Ok(out)
}
fn filters(pair:&Pair,defs:&[Manifest],table:&str,e:&Expr,rows:f64)->Result<Vec<Recipe>> {
 Ok(match e {
  Expr::Compare{values,..} if values.iter().any(Value::is_empty)=>vec![],
  Expr::Compare{path,op,values}=>leaf(pair,defs,table,path,op,values,rows)?,
  Expr::Presence{path,op}=>{
   let (compare,values)=match op{Presence::Null=>(Compare::Eq,vec![Value::Null]),Presence::Missing=>(Compare::Eq,vec![Value::Missing]),Presence::Empty=>(Compare::In,vec![Value::Missing,Value::Null]),Presence::Exists=>(Compare::Gt,vec![Value::Missing])};
   // Presence exists spans every type after Missing; comparison ranges normally
   // stay inside a type's tag, so its upper bound is deliberately removed.
   let mut recipes=leaf(pair,defs,table,path,&compare,&values,rows)?;
   if *op==Presence::Exists {for recipe in &mut recipes {if let Node::Range{definition,upper,..}=&mut recipe.node{*upper=if definition.definition.paths.len()>1{Some(vec![9])}else{None};}recipe.estimated_rows=rows*0.9;recipe.index_entries=rows*0.9;}}
   recipes
  },
  Expr::And(a,b)=>{let left=filters(pair,defs,table,a,rows)?;let right=filters(pair,defs,table,b,rows)?;let mut out=vec![];for a in &left{let mut r=a.clone();r.covered=false;out.push(r);}for b in &right{let mut r=b.clone();r.covered=false;out.push(r);}for a in &left{for b in &right {out.push(Recipe{node:Node::Intersection(Box::new(a.node.clone()),Box::new(b.node.clone())),plan:Plan::IndexIntersection,ids:ids(&a.ids,&b.ids),covered:a.covered&&b.covered,ordered:false,estimated_rows:(a.estimated_rows*b.estimated_rows/rows.max(1.)).min(rows),index_entries:a.index_entries+b.index_entries});}}out},
  Expr::Or(a,b)=>{let left=filters(pair,defs,table,a,rows)?;let right=filters(pair,defs,table,b,rows)?;let mut out=vec![];for a in &left{for b in &right{out.push(Recipe{node:Node::Union(Box::new(a.node.clone()),Box::new(b.node.clone())),plan:Plan::IndexUnion,ids:ids(&a.ids,&b.ids),covered:a.covered&&b.covered,ordered:false,estimated_rows:(a.estimated_rows+b.estimated_rows).min(rows),index_entries:a.index_entries+b.index_entries});}}out},
  _=>vec![]
 })
}
pub(super) fn candidates(pair:&Pair,defs:&[Manifest],table:&str,expr:Option<&Expr>,order:&[(OrderSource,Direction)],limit:Option<usize>,rows:f64,estimated:f64)->Result<Vec<Recipe>> {
 let mut recipes=expr.map(|e|filters(pair,defs,table,e,rows)).transpose()?.unwrap_or_default();
 recipes.extend(super::ordered::candidates(defs,table,expr,order,limit,rows,estimated,&recipes)?);
 for recipe in &mut recipes {recipe.estimated_rows=recipe.estimated_rows.clamp(0.,rows);recipe.index_entries=recipe.index_entries.max(0.);}
 Ok(recipes)
}
pub(super) fn equality_terms(e:Option<&Expr>)->(Vec<(Path,Value)>,bool){fn walk(e:&Expr,out:&mut Vec<(Path,Value)>)->bool{match e{Expr::Compare{path,op:Compare::Eq,values} if scalar_path(path)&&values.len()==1=>{if let Some((_,existing))=out.iter().find(|(p,_)|p==path){existing==&values[0]}else{out.push((path.clone(),values[0].clone()));true}},Expr::And(a,b)=>{let a=walk(a,out);let b=walk(b,out);a&&b},_=>false}}let mut out=vec![];let all=e.is_none_or(|e|walk(e,&mut out));(out,all)}
pub(super) fn definitions(table:&str,expr:Option<&Expr>,order:&[(OrderSource,Direction)])->Vec<Definition>{
 let(eq,_)=equality_terms(expr);let mut paths=eq.iter().map(|(p,_)|p.clone()).collect::<Vec<_>>();let mut directions=vec![Asc;paths.len()];let mut sortable=true;
 for(source,direction)in order{if let OrderSource::Field(path)=source{if !scalar_path(path){sortable=false;break}if !paths.contains(path){paths.push(path.clone());directions.push(*direction);}}else{sortable=false;break}}
 let mut out=vec![];if sortable&&paths.len()>1&&paths.len()<=8{out.push(Definition{table:table.into(),paths:paths.clone(),kind:Kind::Value,directions:directions.clone()});}
 fn ranges(e:&Expr,out:&mut Vec<Path>){match e{Expr::Compare{path,op:Compare::Gt|Compare::Ge|Compare::Lt|Compare::Le|Compare::Between, ..} if scalar_path(path)=>out.push(path.clone()),Expr::And(a,b)=>{ranges(a,out);ranges(b,out)},_=>()}}
 if sortable&&!order.is_empty(){let mut range=vec![];if let Some(e)=expr{ranges(e,&mut range)}for range in range{let mut p=eq.iter().map(|(p,_)|p.clone()).collect::<Vec<_>>();let mut d=vec![Asc;p.len()];if !p.contains(&range){p.push(range);d.push(Asc);}for(source,dir)in order{if let OrderSource::Field(path)=source{if !p.contains(path){p.push(path.clone());d.push(*dir);}}}if p.len()>1&&p.len()<=8{let candidate=Definition{table:table.into(),paths:p,kind:Kind::Value,directions:d};if !out.contains(&candidate){out.push(candidate);}}}}
 out
}

pub(super) fn signature(node:&Node)->Result<Vec<u8>> {
 Ok(match node {
  Node::Range{definition,lower,upper,dedup}=>serde_json::to_vec(&(0u8,definition.id,&definition.canonical,lower,upper,dedup))?,
  Node::Intersection(a,b)=>serde_json::to_vec(&(1u8,signature(a)?,signature(b)?))?,
  Node::Union(a,b)=>serde_json::to_vec(&(2u8,signature(a)?,signature(b)?))?,
  Node::Postings{definition,term}=>serde_json::to_vec(&(5u8,definition.id,&definition.canonical,term))?,
  Node::Fuzzy{definition,term,distance}=>serde_json::to_vec(&(3u8,definition.id,&definition.canonical,term,distance))?,
  Node::Ordered{definition,lower,upper,reverse,allowed,limit}=>serde_json::to_vec(&(4u8,definition.id,&definition.canonical,lower,upper,reverse,allowed.as_ref().map(|n|signature(n)).transpose()?,limit))?,
 })
}
