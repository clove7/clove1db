//! Snapshot-consistent typed queries. No entity cache participates in execution.
pub(crate) mod eval;
mod sum;
pub use sum::{MAX_SUM_DIGITS, MAX_SUM_EXPONENT, Sum};
pub mod optimizer;
pub mod stats;
use crate::{
    entity::Entity,
    fields::{Compare, Expr, Field, Path, Predicate, Value, codec},
    journal::ReadView,
    repository::DatabaseManager,
    units::{ClError, Result},
};
pub use eval::TOKENIZER_VERSION;
pub(crate) use eval::path_value;
use redb::{ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BinaryHeap},
    marker::PhantomData,
    time::Instant,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Asc,
    Desc,
}
pub use Direction::{Asc, Desc};
#[derive(Debug, Clone, Copy)]
pub struct LastWrite;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderSource {
    Field(Path),
    LastWrite,
    Similarity {path:Path,term:String},
}
pub struct Similarity<E> {path:Path,term:String,marker:PhantomData<fn(E)>}
impl<E> Similarity<E> {pub(crate) fn new(path:Path,term:String)->Self {Self{path,term,marker:PhantomData}}}
impl<E> OrderField<E> for Similarity<E> {fn order_source(self)->OrderSource {OrderSource::Similarity{path:self.path,term:self.term}}}
pub trait OrderField<E> {
    fn order_source(self) -> OrderSource;
}
impl<E, V> OrderField<E> for Field<E, V> {
    fn order_source(self) -> OrderSource {
        OrderSource::Field(self.path())
    }
}
impl<E> OrderField<E> for LastWrite {
    fn order_source(self) -> OrderSource {
        OrderSource::LastWrite
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cursor {
    fingerprint: Vec<u8>,
    order: Vec<Vec<u8>>,
    key: String,
    pub sequence: u64,
    database: Vec<u8>,
}
/// Opaque verification-only plan identity; contains no printable literals.
#[doc(hidden)]
#[derive(Clone)]
pub struct PlanHint {pub plan:optimizer::Plan,pub index_ids:Vec<u64>,pub(crate) signature:Vec<u8>}
impl std::fmt::Debug for PlanHint {fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.debug_struct("PlanHint").field("plan",&self.plan).field("index_ids",&self.index_ids).finish()}}
impl PlanHint {pub(crate) fn is_scan(&self)->bool {(self.plan as usize)<5}}
pub struct Page<E> {
    pub items: Vec<E>,
    pub next: Option<Cursor>,
    pub sequence: u64,
    pub index_sequence:Option<u64>,
    pub index_age:Option<std::time::Duration>,
    pub stale:bool,
}
#[derive(Clone)]
pub struct Query<E> {
    db: DatabaseManager,
    table: String,
    predicate: Option<Predicate<E>>,
    order: Vec<(OrderSource, Direction)>,
    limit: Option<usize>,
    after: Option<Cursor>,
    allow_stale: bool,
    forced:Option<PlanHint>,
    /// Set when the entity has protected fields: rows read are tied to their place.
    #[cfg(feature = "encryption")]
    sealed: Option<std::sync::Arc<crate::field_crypto::SealedHooks<E>>>,
    marker: PhantomData<E>,
}
pub struct GroupQuery<E> {
    query: Query<E>,
    path: Path,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupCount {
    pub value: Value,
    pub count: u64,
}
#[derive(Eq, PartialEq)]
struct Row {
    order: Vec<Vec<u8>>,
    key: String,
    bytes: Vec<u8>,
}
impl Ord for Row {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        (&self.order, &self.key).cmp(&(&o.order, &o.key))
    }
}
impl PartialOrd for Row {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl<E: Entity> Query<E> {
    pub(crate) fn new(db: DatabaseManager, table: String) -> Self {
        Self {
            db,
            table,
            predicate: None,
            order: vec![],
            limit: None,
            after: None,
            allow_stale: false,
            forced:None,
            #[cfg(feature = "encryption")]
            sealed: None,
            marker: PhantomData,
        }
    }
    #[cfg(feature = "encryption")]
    pub(crate) fn with_sealed(mut self, sealed: Option<std::sync::Arc<crate::field_crypto::SealedHooks<E>>>) -> Self {
        self.sealed = sealed;
        self
    }
    /// The entity of stored row `key`; protected fields stay closed and are tied to this row.
    fn decode_row(&self, key: &str, bytes: &[u8]) -> Result<E> {
        #[cfg(feature = "encryption")]
        let mut value: E = serde_json::from_slice(bytes)?;
        #[cfg(not(feature = "encryption"))]
        let value: E = {
            let _ = key;
            serde_json::from_slice(bytes)?
        };
        #[cfg(feature = "encryption")]
        if let Some(hooks) = &self.sealed {
            hooks.bind(key, &mut value);
        }
        Ok(value)
    }
    pub fn filter(mut self, p: Predicate<E>) -> Self {
        self.predicate = Some(if let Some(old) = self.predicate.take() {
            old.and(p)
        } else {
            p
        });
        self
    }
    pub fn order_by(mut self, f: impl OrderField<E>, d: Direction) -> Self {
        self.order = vec![(f.order_source(), d)];
        self
    }
    pub fn then_by(mut self, f: impl OrderField<E>, d: Direction) -> Self {
        self.order.push((f.order_source(), d));
        self
    }
    pub fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }
    /// Permit older index candidates, rechecked against a current primary view.
    /// An older index can omit newly matching rows. See Page's index metadata.
    pub fn allow_stale(mut self)->Self {self.allow_stale=true;self}
    pub fn after(mut self, cursor: Cursor) -> Self {
        self.after = Some(cursor);
        self
    }
    /// A protected field holds sealed text, so it cannot be used to filter, order, group or
    /// aggregate: the stored text says nothing about the value. Refused when the query runs.
    #[cfg(not(feature = "encryption"))]
    fn refuse_protected(&self, _paths: &[Path]) -> Result<()> {
        Ok(())
    }
    #[cfg(feature = "encryption")]
    fn refuse_protected(&self, paths: &[Path]) -> Result<()> {
        let Some(hooks) = &self.sealed else {
            return Ok(());
        };
        for path in paths {
            if let Some(crate::fields::Step::Key(first)) = path.steps.first()
                && hooks.protects(first)
            {
                return Err(ClError::Validation(format!(
                    "`{first}` is a protected field: it cannot be used to filter, order, group or aggregate"
                )));
            }
        }
        Ok(())
    }
    /// The filter and the order of this query against the protected fields: the order may not use
    /// one, and the filter may use a fingerprinted field only through the conditions its handle built
    /// with a search grant (see `field_crypto::check_filter`). Nothing of a refused value has been
    /// fingerprinted yet when this runs.
    #[cfg(not(feature = "encryption"))]
    fn refuse_protected_query(&self) -> Result<()> {
        Ok(())
    }
    #[cfg(feature = "encryption")]
    fn refuse_protected_query(&self) -> Result<()> {
        let Some(hooks) = &self.sealed else {
            return Ok(());
        };
        self.refuse_protected(&optimizer::paths(None, &self.order))?;
        if let Some(p) = &self.predicate {
            crate::field_crypto::check_filter(hooks.specs(), &p.expression, p.printed())?;
        }
        Ok(())
    }
    fn fingerprint(&self) -> Result<Vec<u8>> {
        self.refuse_protected_query()?;
        let pred = self
            .predicate
            .as_ref()
            .map(Predicate::fingerprint)
            .transpose()?;
        Ok(serde_json::to_vec(&(
            1u8,
            TOKENIZER_VERSION,
            &self.table,
            pred,
            &self.order,
        ))?)
    }
    fn point_key(&self, view: &ReadView) -> Option<String> {
        let declared = E::id_field()?;
        if !crate::id_contract::enforced(&view.tx, &self.table, &declared.path()) {return None;}
        match self.predicate.as_ref()?.expression {
            Expr::Compare {
                ref path,
                op: Compare::Eq,
                ref values,
            } if path == &declared.path() && path.transforms.is_empty() => {
                match values.as_slice() {
                    [Value::String(s)] => Some(s.clone()),
                    _ => None,
                }
            }
            _ => None,
        }
    }
    fn context<'a>(
        &'a self,
        view: &'a ReadView,
        canonical: &'a [u8],
        aggregate: bool,
    ) -> optimizer::Context<'a> {
        optimizer::Context {
            tx: &view.tx,
            table: &self.table,
            expr: self.predicate.as_ref().map(|p| &p.expression),
            order: if aggregate { &[] } else { &self.order },
            limit: if aggregate { None } else { self.limit },
            point: self.point_key(view).is_some(),
            canonical,
            schema: optimizer::fingerprint(std::any::type_name::<E>().as_bytes()),
        }
    }
    pub fn explain(&self) -> Result<optimizer::Explain> {
        let view = self.db.indexes.view(&self.db,self.allow_stale)?;
        let mut canonical = self.fingerprint()?;
        canonical.push(0);
        let mut explain=optimizer::prepare_indexed(
            &self.db.query_runtime,
            &self.context(&view, &canonical, false),
            false,&self.db.indexes.field_statistics(&self.table,&view),
        )?;
        self.db.indexes.access(&self.table,&view,self.predicate.as_ref().map(|p|&p.expression),&self.order,self.allow_stale,&mut explain,false,if self.after.is_none(){self.limit}else{None},&self.db.query_runtime,self.forced.as_ref())?;
        if let Some(hint)=self.forced.as_ref().filter(|h|h.is_scan()){self.validate_scan_hint(hint,&view,false)?;explain.selected=hint.plan;}
        Ok(explain)
    }
    pub fn statistics<V>(&self, field: Field<E, V>) -> Result<stats::Statistics> {
        self.refuse_protected(&[field.path()])?;
        let view = self.db.indexes.view(&self.db,self.allow_stale)?;
        let canonical = self.fingerprint()?;
        if let Some((_,stats))=self.db.indexes.field_statistics(&self.table,&view).into_iter().find(|(path,_)|*path==field.path()){return Ok(stats.summary.clone())}
        optimizer::statistics(
            &self.db.query_runtime,
            &self.context(&view, &canonical, true),
            field.path(),
        )
    }

    fn rows(
        &self,
        view: &ReadView,
        aggregate: bool,
        mut visit: impl FnMut(&str, &[u8], &mut eval::RowEvaluation<'_>) -> Result<bool>,
    ) -> Result<Option<(u64,u64)>> {
        let fingerprint = self.fingerprint()?;
        if let Some(c) = &self.after
            && (c.fingerprint != fingerprint
                || c.database != view.database_uuid()?
                || c.sequence > view.head)
        {
            return Err(ClError::InvalidCursor);
        }
        let mut canonical = fingerprint;
        canonical.push(u8::from(aggregate));
        let start = Instant::now();
        let mut explain = optimizer::prepare_indexed(
            &self.db.query_runtime,
            &self.context(view, &canonical, aggregate),
            true,&self.db.indexes.field_statistics(&self.table,view),
        )?;
        if let Some(hint)=self.forced.as_ref().filter(|h|h.is_scan()){self.validate_scan_hint(hint,view,aggregate)?;explain.selected=hint.plan;if !explain.alternatives.iter().any(|a|a.plan==hint.plan){let rows=view.tx.open_table(TableDefinition::<&str,&[u8]>::new(&self.table))?.len()? as f64;explain.alternatives.push(optimizer::Alternative{plan:hint.plan,estimated_ms:0.001+rows*0.0003,estimated_rows:rows,wait_ms:0.,index_ids:vec![]});}}
        let optimizer_micros=start.elapsed().as_micros() as u64;
        let indexed=self.db.indexes.access(&self.table,view,self.predicate.as_ref().map(|p|&p.expression),if aggregate {&[]}else{&self.order},self.allow_stale,&mut explain,false,if self.after.is_none(){self.limit}else{None},&self.db.query_runtime,self.forced.as_ref())?;
        let table = view
            .tx
            .open_table(TableDefinition::<&str, &[u8]>::new(&self.table))?;
        let mut work = optimizer::Work {
            rows: 0,
            bytes: 0,
            matches: 0,
            micros: 0,
        };
        let paths = if aggregate || self.order.is_empty() {
            vec![]
        } else {
            optimizer::paths(self.predicate.as_ref().map(|p| &p.expression), &self.order)
        };
        let mut process = |key: &str, bytes: &[u8]| -> Result<bool> {
            work.rows += 1;
            work.bytes += key.len() as u64 + bytes.len() as u64;
            let mut evaluation = eval::RowEvaluation::new(bytes, &paths);
            if self
                .predicate
                .as_ref()
                .map(|p| evaluation.matches(&p.expression))
                .unwrap_or(Ok(true))?
            {
                work.matches += 1;
                visit(key, bytes, &mut evaluation)
            } else {
                Ok(true)
            }
        };
        if explain.selected == optimizer::Plan::PointLookup {
            if let Some(key) = self.point_key(view)
                && let Some(v) = table.get(key.as_str())?
            {
                process(&key, v.value())?;
            }
        } else if let Some(indexed)=&indexed {
            for key in &indexed.keys {if let Some(value)=table.get(key.as_str())? {if !process(key,value.value())? {break}}}
        } else {
            for row in table.iter()? {
                let (k, v) = row?;
                if !process(k.value(), v.value())? {
                    break;
                }
            }
        }
        let elapsed = start.elapsed();
        work.micros = elapsed.as_micros() as u64;
        if let Some(indexed)=&indexed {let predicted=explain.alternatives.iter().find(|a|a.plan==explain.selected).map(|a|a.estimated_ms).unwrap_or(0.);self.db.indexes.used(&indexed.ids,work.matches,predicted,elapsed.as_secs_f64()*1000.);}
        self.db
            .query_runtime
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .feedback(&explain, work);
        if self.forced.is_none()&&explain.selected!=optimizer::Plan::PointLookup {let mut observed=work;observed.micros=observed.micros.saturating_sub(optimizer_micros).saturating_sub(indexed.as_ref().map(|a|a.planning_micros).unwrap_or(0));let source_rows=table.len()?;observed.bytes=if work.rows==0{0}else{work.bytes.saturating_mul(source_rows)/work.rows};observed.rows=source_rows;self.db.indexes.observe(&self.table,self.predicate.as_ref().map(|p|&p.expression),if aggregate {&[]}else{&self.order},observed);}
        self.db.event_sink.emit(&crate::LibraryEvent::Query {
            plan: explain.selected,
            estimated_rows: explain.estimated_rows,
            actual_rows: work.rows,
            bytes: work.bytes,
            elapsed,
            fingerprint: explain.fingerprint,
        });
        if elapsed >= self.db.slow_query_threshold {
            self.db.event_sink.emit(&crate::LibraryEvent::SlowQuery {
                plan: explain.selected,
                estimated_rows: explain.estimated_rows,
                actual_rows: work.rows,
                elapsed,
                fingerprint: explain.fingerprint,
            });
        }
        Ok(indexed.as_ref().map(|a|(a.sequence,a.age_ms)))
    }
    fn row(
        &self,
        view: &ReadView,
        key: &str,
        evaluation: &mut eval::RowEvaluation<'_>,
    ) -> Result<Row> {
        let mut order = Vec::with_capacity(self.order.len());
        for (f, d) in &self.order {
            let mut encoded = match f {
                OrderSource::Field(p) => codec::encode(evaluation.value(p)?)?,
                OrderSource::Similarity{path,term}=>{let score=match evaluation.value(path)? {Value::String(value)=>strsim::normalized_levenshtein(value,term),_=>0.};codec::encode(&Value::Number(score.to_string()))?},
                OrderSource::LastWrite => codec::encode(&Value::Number(
                    crate::lastwrite::get(&view.tx, &self.table, key)?.to_string(),
                ))?,
            };
            if *d == Desc {
                for b in &mut encoded {
                    *b = !*b
                }
            }
            order.push(encoded);
        }
        Ok(Row {
            order,
            key: key.into(),
            bytes: vec![],
        })
    }
    pub fn page(&self) -> Result<Page<E>> {
        let view = self.db.indexes.view(&self.db,self.allow_stale)?;
        self.page_in(&view)
    }
    pub fn page_in(&self, view: &ReadView) -> Result<Page<E>> {
        let start = Instant::now();
        let limit = self.limit.unwrap_or(usize::MAX);
        let mut heap = BinaryHeap::new();
        let mut rows = vec![];
        let mut matched = 0u64;
        let index_info=self.rows(view, false, |key, bytes, evaluation| {
            let mut row = self.row(view, key, evaluation)?;
            if self
                .after
                .as_ref()
                .is_some_and(|c| (&row.order, row.key.as_str()) <= (&c.order, c.key.as_str()))
            {
                return Ok(true);
            }
            matched += 1;
            if limit == 0 {
                return Ok(false);
            }
            if self.order.is_empty() {
                row.bytes = crate::memory::copy_bytes("query.collect_rows", bytes)?;
                crate::memory::push("query.collect_rows", &mut rows, row)?;
                return Ok(rows.len() < limit);
            }
            if heap.len() < limit || heap.peek().is_some_and(|max| &row < max) {
                row.bytes = crate::memory::copy_bytes("query.collect_rows", bytes)?;
                crate::memory::reserve_heap("query.collect_rows", &mut heap, 1)?;
                heap.push(row);
                if heap.len() > limit {
                    heap.pop();
                }
            }
            Ok(true)
        })?;
        if !self.order.is_empty() {
            rows = heap.into_sorted_vec()
        }
        let next = rows
            .last()
            .map(|r| -> Result<Cursor> {
                Ok(Cursor {
                    fingerprint: self.fingerprint()?,
                    order: r.order.clone(),
                    key: r.key.clone(),
                    sequence: view.head,
                    database: view.database_uuid()?,
                })
            })
            .transpose()?;
        let mut items = crate::memory::vec_with_capacity("query.collect_rows", rows.len())?;
        for r in rows {
            items.push(self.decode_row(&r.key, &r.bytes)?);
        }
        let _ = (start, matched);
        Ok(Page {
            items,
            next,
            sequence: view.head,
            index_sequence:index_info.map(|i|i.0),
            index_age:index_info.map(|i|std::time::Duration::from_millis(i.1)),
            stale:index_info.is_some_and(|i|i.0<view.head),
        })
    }
    pub fn collect(&self) -> Result<Vec<E>> {
        Ok(self.page()?.items)
    }
    pub fn collect_in(&self, view: &ReadView) -> Result<Vec<E>> {
        Ok(self.page_in(view)?.items)
    }
    /// Checks the complete filtered set, independent of pagination.
    pub fn one(&self) -> Result<Option<E>> {
        let view = self.db.indexes.view(&self.db,self.allow_stale)?;
        let mut count = 0;
        let mut item = None;
        self.rows(&view, true, |key, bytes, _| {
            count += 1;
            if count == 1 {
                item = Some(self.decode_row(key, bytes)?)
            }
            Ok(true)
        })?;
        if count > 1 {
            self.db.event_sink.emit(&crate::LibraryEvent::NonUnique {
                count,
                fingerprint: optimizer::fingerprint(&self.fingerprint()?),
            });
            return Err(ClError::NonUnique { count });
        }
        Ok(item)
    }
    /// Aggregates apply to the complete filtered set; limit/cursor are page controls.
    pub fn count(&self) -> Result<u64> {
        let view = self.db.indexes.view(&self.db,self.allow_stale)?;
        // A fully covered predicate can count distinct row postings without
        // fetching primary JSON. Stale candidates still require rechecking.
        let started=Instant::now();let mut canonical=self.fingerprint()?;canonical.push(1);
        let mut explain=optimizer::prepare_indexed(&self.db.query_runtime,&self.context(&view,&canonical,true),true,&self.db.indexes.field_statistics(&self.table,&view))?;
        if let Some(access)=self.db.indexes.access(&self.table,&view,self.predicate.as_ref().map(|p|&p.expression),&[],self.allow_stale,&mut explain,true,None,&self.db.query_runtime,self.forced.as_ref())? {
            if access.covered&&access.sequence==view.head&&self.after.is_none() {
                let count=access.count.unwrap_or(access.keys.len() as u64);let elapsed=started.elapsed();self.db.indexes.used(&access.ids,count,explain.alternatives.iter().find(|a|a.plan==access.plan).map(|a|a.estimated_ms).unwrap_or(0.),elapsed.as_secs_f64()*1000.);
                self.db.event_sink.emit(&crate::LibraryEvent::Query{plan:optimizer::Plan::IndexCount,estimated_rows:count as f64,actual_rows:0,bytes:0,elapsed,fingerprint:explain.fingerprint});
                if elapsed>=self.db.slow_query_threshold {self.db.event_sink.emit(&crate::LibraryEvent::SlowQuery{plan:optimizer::Plan::IndexCount,estimated_rows:count as f64,actual_rows:0,elapsed,fingerprint:explain.fingerprint});}return Ok(count)
            }
        }
        let mut n = 0;
        self.rows(&view, true, |_, _, _| {
            n += 1;
            Ok(true)
        })?;
        Ok(n)
    }
    pub fn exists(&self) -> Result<bool> {
        let view = self.db.indexes.view(&self.db,self.allow_stale)?;
        let mut found = false;
        self.rows(&view, true, |_, _, _| {
            found = true;
            Ok(false)
        })?;
        Ok(found)
    }
    fn values(&self, path: &Path, mut f: impl FnMut(Value) -> Result<()>) -> Result<()> {
        self.refuse_protected(std::slice::from_ref(path))?;
        let view = self.db.indexes.view(&self.db,self.allow_stale)?;
        self.rows(&view, true, |_, b, _| {
            f(eval::path_value(b, path)?)?;
            Ok(true)
        }).map(|_|())
    }
    pub fn distinct<V>(&self, field: Field<E, V>) -> Result<Vec<Value>> {
        let mut v = BTreeMap::new();
        self.values(&field.path(), |x| {
            v.insert(codec::encode_equality(&x)?, x);
            Ok(())
        })?;
        Ok(v.into_values().collect())
    }
    pub fn min<V>(&self, field: Field<E, V>) -> Result<Option<Value>> {
        self.extreme(field.path(), false)
    }
    pub fn max<V>(&self, field: Field<E, V>) -> Result<Option<Value>> {
        self.extreme(field.path(), true)
    }
    fn extreme(&self, path: Path, max: bool) -> Result<Option<Value>> {
        let mut result = None;
        let mut key = None;
        self.values(&path, |v| {
            if !v.is_empty() {
                let k = codec::encode(&v)?;
                if key
                    .as_ref()
                    .is_none_or(|old| if max { k > *old } else { k < *old })
                {
                    key = Some(k);
                    result = Some(v)
                }
            }
            Ok(())
        })?;
        Ok(result)
    }
    /// Exact sum from raw decimal tokens; integer overflow and precision limits
    /// are explicit errors. Missing/null are ignored.
    pub fn sum<V>(&self, field: Field<E, V>) -> Result<Sum> {
        let mut sum = sum::Accumulator::default();
        self.values(&field.path(), |v| {
            if v.is_empty() {
                return Ok(());
            }
            let Value::Number(n) = v else {
                return Err(ClError::UnsupportedSum);
            };
            sum.add(&n)
        })?;
        sum.finish()
    }
    pub fn group_by<V>(self, field: Field<E, V>) -> GroupQuery<E> {
        GroupQuery {
            query: self,
            path: field.path(),
        }
    }
}
impl<E: Entity> GroupQuery<E> {
    pub fn count(&self) -> Result<Vec<GroupCount>> {
        let mut groups = BTreeMap::<Vec<u8>, GroupCount>::new();
        self.query.values(&self.path, |v| {
            let g = groups
                .entry(codec::encode_equality(&v)?)
                .or_insert(GroupCount { value: v, count: 0 });
            g.count += 1;
            Ok(())
        })?;
        Ok(groups.into_values().collect())
    }
}

#[cfg(all(test, feature = "derive"))]
mod tests;

impl<E:Entity> Query<E> {
 fn validate_scan_hint(&self,hint:&PlanHint,view:&ReadView,aggregate:bool)->Result<()> {use optimizer::Plan;let valid=match hint.plan {Plan::FullScan|Plan::SelectiveScan=>true,Plan::PointLookup=>self.point_key(view).is_some(),Plan::TopK=>!aggregate&&!self.order.is_empty()&&self.limit.is_some(),Plan::EarlyStop=>!aggregate&&self.order.is_empty()&&self.limit.is_some(),_=>false};if valid{Ok(())}else{Err(ClError::Validation("verification plan is not applicable".into()))}}
 #[cfg(any(test,feature="crash-inject"))]
 #[doc(hidden)]
 pub fn test_force_plan(mut self,hint:PlanHint)->Self {self.forced=Some(hint);self}
 #[cfg(any(test,feature="crash-inject"))]
 #[doc(hidden)]
 pub fn test_plans(&self,count:bool)->Result<Vec<PlanHint>> {
  let view=self.db.indexes.view(&self.db,self.allow_stale)?;let _=self.fingerprint()?;let mut out=vec![PlanHint{plan:optimizer::Plan::FullScan,index_ids:vec![],signature:vec![]},PlanHint{plan:optimizer::Plan::SelectiveScan,index_ids:vec![],signature:vec![]}];
  if self.point_key(&view).is_some(){out.push(PlanHint{plan:optimizer::Plan::PointLookup,index_ids:vec![],signature:vec![]});}
  if !count&&self.limit.is_some(){out.push(PlanHint{plan:if self.order.is_empty(){optimizer::Plan::EarlyStop}else{optimizer::Plan::TopK},index_ids:vec![],signature:vec![]});}
  out.extend(self.db.indexes.hints(&self.table,&view,self.predicate.as_ref().map(|p|&p.expression),if count{&[]}else{&self.order},self.allow_stale,count,if count||self.after.is_some(){None}else{self.limit})?);Ok(out)
 }
 #[cfg(any(test,feature="crash-inject"))]
 #[doc(hidden)]
 pub fn test_build_indexes(&self)->Result<()> {
  let definitions=self.db.indexes.request_verification_indexes(&self.table,self.predicate.as_ref().map(|p|&p.expression),&self.order)?;
  let started=Instant::now();loop {if self.db.indexes.definitions_ready(&definitions)? {return Ok(())}if started.elapsed()>std::time::Duration::from_secs(30){return Err(ClError::Validation("verification index build timed out".into()))}std::thread::sleep(std::time::Duration::from_millis(2));}
 }
}
