//! Cost-based plan selection, bounded LRU, online feedback and snapshot trials.
use super::{
    OrderSource, eval,
    stats::{Bank, FieldStats},
};
use crate::{
    fields::{Compare, Expr, Path, Value},
    units::Result,
};
use redb::{ReadableTable, ReadableTableMetadata, TableDefinition};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
pub const CACHE_BYTES: usize = 256 * 1024;
pub const TRIAL_BUDGET: Duration = Duration::from_millis(5);
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Plan {
    FullScan,
    SelectiveScan,
    PointLookup,
    TopK,
    EarlyStop,
    IndexEquality,IndexRange,IndexUnion,IndexIntersection,IndexPrefix,IndexContains,IndexText,IndexOrder,IndexCount,IndexFuzzy,IndexEsr,IndexErs,
}
#[derive(Debug, Clone)]
pub struct Alternative {
    pub plan: Plan,
    pub estimated_ms: f64,
    pub estimated_rows: f64,
    pub wait_ms: f64,
    pub index_ids:Vec<u64>,
}
#[derive(Debug, Clone)]
pub struct Explain {
    pub selected: Plan,
    pub alternatives: Vec<Alternative>,
    pub estimated_rows: f64,
    pub reason: &'static str,
    pub cache_hit: bool,
    pub statistics_generation: u64,
    pub trial_micros: u64,
    pub fingerprint: u64,
}
#[derive(Debug, Clone, Copy)]
pub(crate) struct Work {
    pub rows: u64,
    pub bytes: u64,
    pub matches: u64,
    pub micros: u64,
}
#[derive(Clone)]
struct Cached {
    key: Vec<u8>,
    explain: Explain,
    ewma: Option<Work>,
    errors: u8,
    touched: u64,
    source_rows: u64,
}
#[derive(Clone, Copy)]
struct Costs {
    scan: f64,
    selective: f64,
    point: f64,
}
impl Default for Costs {
    fn default() -> Self {
        Self {
            scan: 0.000587564,
            selective: 0.0003064,
            point: 0.00670375,
        }
    }
}
pub(crate) struct Runtime {
    pub bank: Bank,
    cache: VecDeque<Cached>,
    bytes: usize,
    costs: Costs,
    calibrated: bool,
    schema: Option<u64>,
    tick: u64,
    refresh: bool,
    multipliers: [f64; 17],
}
impl Default for Runtime {
    fn default() -> Self {
        Self {
            bank: Bank::default(),
            cache: VecDeque::new(),
            bytes: 0,
            costs: Costs::default(),
            calibrated: false,
            schema: None,
            tick: 0,
            refresh: false,
            multipliers: [1.; 17],
        }
    }
}
impl std::fmt::Debug for Runtime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueryRuntime")
            .field("cache_bytes", &self.bytes)
            .finish()
    }
}
pub(crate) type Shared = Arc<Mutex<Runtime>>;
pub(crate) fn fingerprint(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325, |h, b| {
        (h ^ *b as u64).wrapping_mul(0x100000001b3)
    })
}
pub(super) fn paths(expr: Option<&Expr>, order: &[(OrderSource, super::Direction)]) -> Vec<Path> {
    fn walk(e: &Expr, v: &mut Vec<Path>) {
        match e {
            Expr::Compare { path, .. } | Expr::Presence { path, .. } => v.push(path.clone()),
            Expr::And(a, b) | Expr::Or(a, b) => {
                walk(a, v);
                walk(b, v)
            }
            Expr::Not(a) => walk(a, v),
            Expr::ElemMatch { path, .. } => v.push(path.clone()),
            _ => (),
        }
    }
    let mut v = vec![];
    if let Some(e) = expr {
        walk(e, &mut v)
    }
    for (o, _) in order {
        if let OrderSource::Field(p) | OrderSource::Similarity{path:p,..} = o {
            v.push(p.clone())
        }
    }
    let mut out = vec![];
    for p in v {
        if !out.contains(&p) {
            out.push(p)
        }
    }
    out
}
fn selectivity(e: &Expr, stats: &[(Path, Arc<FieldStats>)]) -> Result<f64> {
    Ok(match e {
        Expr::Compare { path, op, values } => {
            if let Some((_, s)) = stats.iter().find(|(p, _)| p == path) {
                let first = values.first().unwrap_or(&Value::Missing);
                match op {
                    Compare::Eq => s.equality(first)?,
                    Compare::Ne => 1. - s.equality(first)?,
                    Compare::In => values
                        .iter()
                        .map(|v| s.equality(v))
                        .collect::<Result<Vec<_>>>()?
                        .iter()
                        .sum::<f64>()
                        .min(1.),
                    Compare::Lt | Compare::Le => s.range(first)?,
                    Compare::Gt | Compare::Ge => 1. - s.range(first)?,
                    Compare::Between => {
                        (s.range(values.get(1).unwrap_or(first))? - s.range(first)?).max(0.)
                    }
                    _ => 0.25,
                }
            } else {
                0.25
            }
        }
        Expr::And(a, b) => selectivity(a, stats)? * selectivity(b, stats)?,
        Expr::Or(a, b) => {
            let a = selectivity(a, stats)?;
            let b = selectivity(b, stats)?;
            a + b - a * b
        }
        Expr::Not(a) => 1. - selectivity(a, stats)?,
        Expr::Never => 0.,
        _ => 0.5,
    })
}
pub(crate) struct Context<'a> {
    pub tx: &'a redb::ReadTransaction,
    pub table: &'a str,
    pub expr: Option<&'a Expr>,
    pub order: &'a [(OrderSource, super::Direction)],
    pub limit: Option<usize>,
    pub point: bool,
    pub canonical: &'a [u8],
    pub schema: u64,
}
/// Candidate generation is separate from selection/execution so index paths can
/// compete in the next phase without changing snapshot/result semantics.
trait CandidateSource {
    fn candidates(&self, rows: f64, matches: f64, costs: Costs) -> Vec<Alternative>;
}
impl CandidateSource for Context<'_> {
    fn candidates(&self, rows: f64, matches: f64, c: Costs) -> Vec<Alternative> {
        let alt = |plan, estimated_ms, estimated_rows| Alternative {
            plan,
            estimated_ms,
            estimated_rows,
            wait_ms: 0.,index_ids:vec![],
        };
        let mut v = vec![alt(Plan::FullScan, c.scan * rows, matches)];
        if self.order.is_empty() || self.limit.is_none() {
            v.push(alt(Plan::SelectiveScan, c.selective * rows, matches));
        }
        if self.point {
            return vec![alt(Plan::PointLookup, c.point, matches.min(1.))];
        }
        if let Some(limit) = self.limit {
            if self.order.is_empty() {
                v.push(alt(
                    Plan::EarlyStop,
                    c.selective * rows * (limit as f64 / matches.max(1.)).min(1.),
                    matches.min(limit as f64),
                ))
            } else {
                v.push(alt(
                    Plan::TopK,
                    c.selective * rows + matches * (limit.max(1) as f64).log2() * 0.00001,
                    matches,
                ))
            }
        }
        v
    }
}
fn snapshot(c: &Context<'_>) -> Result<(u64, u64)> {
    let table =
        c.tx.open_table(TableDefinition::<&str, &[u8]>::new(c.table))?;
    let meta = c.tx.open_table(TableDefinition::<&str, &[u8]>::new(
        crate::metadata::types::META_TABLE,
    ))?;
    let schema = meta
        .get(crate::metadata::types::META_KEY)?
        .map(|v| fingerprint(v.value()))
        .unwrap_or(0);
    Ok((table.len()?, schema))
}
fn fields(
    shared: &Shared,
    c: &Context<'_>,
    requested: Vec<Path>,
    rows: u64,
    schema: u64,
) -> Result<Vec<(Path, Arc<FieldStats>)>> {
    let mut fields = vec![];
    for path in requested {
        let cached = {
            let mut r = shared.lock().unwrap_or_else(|e| e.into_inner());
            r.setup(schema);
            r.bank.lookup(c.table, &path, rows)?
        };
        let stats = if let Some(cached) = cached {
            cached
        } else {
            // No runtime guard survives into extraction, sampling or database I/O.
            let value = super::stats::sample(c.tx, c.table, &path)?;
            let mut r = shared.lock().unwrap_or_else(|e| e.into_inner());
            r.setup(schema);
            if let Some(existing) = r.bank.lookup(c.table, &path, rows)? {
                existing
            } else {
                r.bank.insert(c.table, &path, value)?
            }
        };
        fields.push((path, stats));
    }
    Ok(fields)
}
pub(crate) fn statistics(
    shared: &Shared,
    c: &Context<'_>,
    path: Path,
) -> Result<super::stats::Statistics> {
    let (rows, schema) = snapshot(c)?;
    let mut summary = fields(shared, c, vec![path], rows, schema)?
        .remove(0)
        .1
        .summary
        .clone();
    summary.rows = rows;
    Ok(summary)
}
pub(crate) fn prepare(shared: &Shared, c: &Context<'_>, trial: bool) -> Result<Explain> {
    let (rows, schema) = snapshot(c)?;
    let calibrate = {
        let mut r = shared.lock().unwrap_or_else(|e| e.into_inner());
        r.setup(schema);
        if let Some(explain) = r.cached(c, rows, schema)? {
            return Ok(explain);
        }
        !r.calibrated
    };
    let mut costs = Costs::default();
    let t =
        c.tx.open_table(TableDefinition::<&str, &[u8]>::new(c.table))?;
    if calibrate {
        let mut count = 0;
        let start = Instant::now();
        for row in t.iter()?.take(32) {
            let (_, v) = row?;
            let _ = crate::fields::extract(v.value(), &[])?;
            if let Some(e) = c.expr {
                eval::matches(v.value(), e)?;
            }
            count += 1;
        }
        let full = start.elapsed().as_secs_f64() * 1000.;
        let timer = Instant::now();
        for row in t.iter()?.take(32) {
            let (_, v) = row?;
            if let Some(e) = c.expr {
                eval::matches(v.value(), e)?;
            }
        }
        if count > 0 {
            costs.scan = (full / count as f64).max(0.00001);
            costs.selective = (timer.elapsed().as_secs_f64() * 1000. / count as f64).max(0.00001);
        }
    }

    let stats = fields(shared, c, paths(c.expr, c.order), rows, schema)?;
    let mut explain = {
        let mut r = shared.lock().unwrap_or_else(|e| e.into_inner());
        r.setup(schema);
        if calibrate && !r.calibrated {
            r.costs = costs;
            r.calibrated = true;
        }
        r.plan(c, rows as f64, schema, &stats)?
    };
    if trial && !explain.cache_hit {
        run_trial(c, &mut explain)?;
        let mut r = shared.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(cached) = r.cache.iter_mut().rev().find(|v| {
            v.explain.fingerprint == explain.fingerprint
                && v.explain.statistics_generation == explain.statistics_generation
        }) {
            cached.explain = explain.clone();
        }
    }
    Ok(explain)
}
fn run_trial(c: &Context<'_>, explain: &mut Explain) -> Result<()> {
    let t =
        c.tx.open_table(TableDefinition::<&str, &[u8]>::new(c.table))?;
    if explain.alternatives.len() > 1 {
        let a = &explain.alternatives[0];
        let b = &explain.alternatives[1];
        if b.estimated_ms <= a.estimated_ms * 1.25 + 0.00001 && !c.point {
            let start = Instant::now();
            let deadline = start + TRIAL_BUDGET;
            let mut measurements = vec![];
            for (i, a) in explain.alternatives.iter().take(2).enumerate() {
                let until = if i == 0 {
                    start + TRIAL_BUDGET / 2
                } else {
                    deadline
                };
                let timer = Instant::now();
                let mut n = 0u64;
                for row in t.iter()? {
                    if Instant::now() >= until {
                        break;
                    }
                    let (_, v) = row?;
                    if a.plan == Plan::FullScan {
                        let _ = crate::fields::extract(v.value(), &[])?;
                    }
                    if let Some(e) = c.expr {
                        eval::matches(v.value(), e)?;
                    }
                    n += 1;
                }
                if n > 0 {
                    measurements.push((timer.elapsed().as_secs_f64() / n as f64, a.plan));
                }
                if Instant::now() >= deadline {
                    break;
                }
            }
            if let Some((_, p)) = measurements.into_iter().min_by(|a, b| a.0.total_cmp(&b.0)) {
                explain.selected = p;
                explain.reason = "bounded same-snapshot trial";
            }
            explain.trial_micros = start.elapsed().as_micros() as u64;
        }
    }
    Ok(())
}
impl Runtime {
    #[cfg(test)]
    pub(super) fn test_clear(&mut self) {
        self.cache.clear();
        self.bytes = 0;
    }
    #[cfg(test)]
    pub(super) fn test_cache_bytes(&self) -> usize {
        self.bytes
    }
    #[cfg(test)]
    pub(super) fn test_equal_costs(&mut self) {
        self.test_clear();
        self.calibrated = true;
        self.costs.scan = 0.01;
        self.costs.selective = 0.01;
    }
    #[cfg(test)]
    pub(super) fn test_force(&mut self, c: &Context<'_>, p: Plan) -> Result<()> {
        let _ = c;
        let cached = self.cache.back_mut().unwrap();
        let old_weight = Self::weight(cached);
        cached.explain.selected = p;
        cached.explain.alternatives.push(Alternative {
            plan: p,
            estimated_ms: 1.,
            estimated_rows: 1.,
            wait_ms: 0.,index_ids:vec![],
        });
        self.bytes += Self::weight(cached) - old_weight;
        Ok(())
    }
    fn setup(&mut self, schema: u64) {
        if self.schema != Some(schema) || self.refresh {
            self.schema = Some(schema);
            self.refresh = false;
            self.bank.invalidate();
            self.cache.clear();
            self.bytes = 0;
        }
    }
    fn cached(&mut self, c: &Context<'_>, rows: u64, schema: u64) -> Result<Option<Explain>> {
        let mut prefix = c.canonical.to_vec();
        prefix.extend(serde_json::to_vec(&(c.limit, c.point))?);
        prefix.extend(c.schema.to_be_bytes());
        prefix.extend(schema.to_be_bytes());
        prefix.extend(self.bank.generation.to_be_bytes());
        let Some(i) = self.cache.iter().position(|v| {
            v.key.len() == prefix.len() + 1
                && v.key.starts_with(&prefix)
                && v.source_rows.abs_diff(rows) <= (v.source_rows / 5).max(1)
        }) else {
            return Ok(None);
        };
        // The last byte remains the selectivity bucket. A canonical expression
        // has one bucket in an unchanged statistics generation, so a hit needs
        // no field sampling, extraction, or second traversal of the statistics.
        self.tick += 1;
        let mut cached = self.cache.remove(i).unwrap();
        cached.touched = self.tick;
        let mut e = cached.explain.clone();
        e.cache_hit = true;
        self.cache.push_back(cached);
        Ok(Some(e))
    }
    fn plan(
        &mut self,
        c: &Context<'_>,
        rows: f64,
        schema: u64,
        stats: &[(Path, Arc<FieldStats>)],
    ) -> Result<Explain> {
        self.tick += 1;
        let fraction = c
            .expr
            .map(|e| selectivity(e, stats))
            .transpose()?
            .unwrap_or(1.)
            .clamp(0., 1.);
        let estimated = rows * fraction;
        let bucket = if fraction >= 0.05 { 1u8 } else { 0 };
        let mut key = c.canonical.to_vec();
        key.extend(serde_json::to_vec(&(c.limit, c.point))?);
        key.extend(c.schema.to_be_bytes());
        key.extend(schema.to_be_bytes());
        key.extend(self.bank.generation.to_be_bytes());
        key.push(bucket);
        if let Some(i) = self.cache.iter().position(|x| x.key == key) {
            let mut cached = self.cache.remove(i).unwrap();
            cached.touched = self.tick;
            let mut e = cached.explain.clone();
            e.cache_hit = true;
            self.cache.push_back(cached);
            return Ok(e);
        }
        let mut alternatives = c.candidates(rows, estimated, self.costs);
        for a in &mut alternatives {
            a.estimated_ms *= self.multipliers[a.plan as usize];
        }
        let explain = self.choose(alternatives, self.bank.generation, fingerprint(c.canonical));
        let item = Cached {
            key,
            explain: explain.clone(),
            ewma: None,
            errors: 0,
            touched: self.tick,
            source_rows: rows as u64,
        };
        let weight = Self::weight(&item);
        while self.bytes + weight > CACHE_BYTES {
            if let Some(old) = self.cache.pop_front() {
                self.bytes -= Self::weight(&old)
            } else {
                break;
            }
        }
        if weight <= CACHE_BYTES {
            self.bytes += weight;
            self.cache.push_back(item)
        }
        Ok(explain)
    }
    fn weight(c: &Cached) -> usize {
        c.key.len() + 512 + c.explain.alternatives.len() * 64
    }
    fn choose(
        &self,
        mut alternatives: Vec<Alternative>,
        generation: u64,
        fingerprint: u64,
    ) -> Explain {
        alternatives.sort_by(|a, b| {
            a.estimated_ms
                .total_cmp(&b.estimated_ms)
                .then(a.plan.cmp(&b.plan))
        });
        let a = &alternatives[0];
        Explain {
            selected: a.plan,
            estimated_rows: a.estimated_rows,
            alternatives,
            reason: "lowest calibrated estimated cost",
            cache_hit: false,
            statistics_generation: generation,
            trial_micros: 0,
            fingerprint,
        }
    }
    pub fn feedback(&mut self, e: &Explain, w: Work) {
        let Some(i) = self.cache.iter().rposition(|c| {
            c.explain.fingerprint == e.fingerprint
                && c.explain.statistics_generation == e.statistics_generation
        }) else {
            return;
        };
        let c = &mut self.cache[i];
        let predicted = e
            .alternatives
            .iter()
            .find(|a| a.plan == e.selected)
            .unwrap();
        let bad = w.matches as f64 > e.estimated_rows.max(1.) * 4.
            || w.micros as f64 > predicted.estimated_ms.max(0.01) * 1000. * 4.;
        c.errors = if bad { c.errors.saturating_add(1) } else { 0 };
        c.ewma = Some(if let Some(old) = c.ewma {
            Work {
                rows: (old.rows * 3 + w.rows) / 4,
                bytes: (old.bytes * 3 + w.bytes) / 4,
                matches: (old.matches * 3 + w.matches) / 4,
                micros: (old.micros * 3 + w.micros) / 4,
            }
        } else {
            w
        });
        if c.errors >= 3 {
            let observed =
                c.ewma.unwrap().micros as f64 / (predicted.estimated_ms.max(0.001) * 1000.);
            self.multipliers[e.selected as usize] =
                (self.multipliers[e.selected as usize] * 0.75 + observed * 0.25).clamp(0.1, 1000.);
            self.refresh = true;
            let old = self.cache.remove(i).unwrap();
            self.bytes -= Self::weight(&old);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn a(p: Plan, c: f64) -> Alternative {
        Alternative {
            plan: p,
            estimated_ms: c,
            estimated_rows: 1.,
            wait_ms: 0.,index_ids:vec![],
        }
    }
    #[test]
    fn injected_costs_and_learning() {
        let mut r = Runtime::default();
        let e = r.choose(
            vec![a(Plan::FullScan, 1.), a(Plan::SelectiveScan, 2.)],
            0,
            1,
        );
        assert_eq!(e.selected, Plan::FullScan);
        let c = Cached {
            key: vec![],
            explain: e.clone(),
            ewma: None,
            errors: 0,
            touched: 0,
            source_rows: 100,
        };
        r.bytes = Runtime::weight(&c);
        r.cache.push_back(c);
        for _ in 0..3 {
            r.feedback(
                &e,
                Work {
                    rows: 100,
                    bytes: 1000,
                    matches: 100,
                    micros: 100_000,
                },
            )
        }
        assert!(r.cache.is_empty());
        assert!(r.refresh);
        assert!(r.multipliers[Plan::FullScan as usize] > 2.);
        let e = r.choose(
            vec![
                a(Plan::FullScan, r.multipliers[0]),
                a(Plan::SelectiveScan, 2.),
            ],
            0,
            1,
        );
        assert_eq!(e.selected, Plan::SelectiveScan);
    }
}

pub(crate) fn prepare_indexed(shared:&Shared,c:&Context<'_>,trial:bool,indexed:&[(Path,Arc<FieldStats>)])->Result<Explain> {
 if !indexed.is_empty(){let(_,schema)=snapshot(c)?;let mut runtime=shared.lock().unwrap_or_else(|e|e.into_inner());runtime.setup(schema);for(path,stats)in indexed{runtime.bank.insert_shared(c.table,path,stats.clone())?;}}
 prepare(shared,c,trial)
}

pub(crate) fn index_multipliers(shared:&Shared)->[f64;17] {shared.lock().unwrap_or_else(|e|e.into_inner()).multipliers}
