use crate::{
    fields::{Compare, Expr, Path, Presence, Step, Value, codec, extract, transforms},
    units::{ClError, Result},
};
use std::cmp::Ordering;

pub const TOKENIZER_VERSION: u8 = 1;
pub fn tokens(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .map(str::to_lowercase)
        .collect()
}
pub fn path_value(bytes: &[u8], path: &Path) -> Result<Value> {
    transforms::apply(
        codec::interpret(extract(bytes, &path.steps)?, &path.kind)?,
        &path.transforms,
    )
}
pub fn compare(a: &Value, b: &Value) -> Result<Option<Ordering>> {
    if std::mem::discriminant(a) != std::mem::discriminant(b) || a.is_empty() || b.is_empty() {
        return Ok(None);
    }
    Ok(Some(
        codec::encode_equality(a)?.cmp(&codec::encode_equality(b)?),
    ))
}
fn scalar(v: &Value, op: &Compare, values: &[Value]) -> Result<bool> {
    let Some(first) = values.first() else {
        return Ok(false);
    };
    let c = compare(v, first)?;
    if c.is_some()
        && matches!(
            op,
            Compare::Gt | Compare::Ge | Compare::Lt | Compare::Le | Compare::Between
        )
    {
        codec::encode(v)?;
        for value in values {
            codec::encode(value)?;
        }
    }
    Ok(match op {
        Compare::Eq => c == Some(Ordering::Equal),
        Compare::Ne => c.is_some_and(|c| c != Ordering::Equal),
        Compare::Gt => c == Some(Ordering::Greater),
        Compare::Ge => c.is_some_and(|c| c != Ordering::Less),
        Compare::Lt => c == Some(Ordering::Less),
        Compare::Le => c.is_some_and(|c| c != Ordering::Greater),
        Compare::Between => {
            c.is_some_and(|c| c != Ordering::Less)
                && values.get(1).map(|b| compare(v, b)).transpose()?.flatten()
                    == Some(Ordering::Less)
        }
        Compare::In => {
            for b in values {
                if compare(v, b)? == Some(Ordering::Equal) {
                    return Ok(true);
                }
            }
            false
        }
        Compare::Prefix | Compare::Contains | Compare::Text | Compare::Fuzzy(_) | Compare::Parts => {
            if let (Value::String(a), Value::String(b)) = (v, first) {
                match op {
                    Compare::Prefix => a.starts_with(b),
                    Compare::Contains => a.contains(b),
                    Compare::Fuzzy(distance)=>tokens(a).iter().any(|token|strsim::levenshtein(token,b)<=*distance as usize),
                    _ => {
                        let a = tokens(a);
                        let b = tokens(b);
                        !b.is_empty() && b.iter().all(|v| a.contains(v))
                    }
                }
            } else {
                false
            }
        }
    })
}
// Walk quantifiers structurally: nested any/all must retain their own scope.
fn quantified(bytes: &[u8], path: &Path, leaf: &impl Fn(&Value) -> Result<bool>) -> Result<bool> {
    if let Some(i) = path
        .steps
        .iter()
        .position(|s| matches!(s, Step::Any | Step::All))
    {
        let prefix = &path.steps[..i];
        let Value::Array(items) = extract(bytes, prefix)? else {
            return Ok(false);
        };
        let all = matches!(path.steps[i], Step::All);
        for n in 0..items.len() {
            let mut next = path.clone();
            next.steps[i] = Step::Index(n);
            let yes = quantified(bytes, &next, leaf)?;
            if yes != all {
                return Ok(!all);
            }
        }
        Ok(all)
    } else {
        leaf(&path_value(bytes, path)?)
    }
}
pub(super) struct RowEvaluation<'a> {
    bytes: &'a [u8],
    paths: &'a [Path],
    values: Vec<Option<Value>>,
    scratch: Option<Value>,
}
impl<'a> RowEvaluation<'a> {
    pub fn new(bytes: &'a [u8], paths: &'a [Path]) -> Self {
        Self {
            bytes,
            paths,
            values: vec![None; paths.len()],
            scratch: None,
        }
    }
    pub fn value(&mut self, path: &Path) -> Result<&Value> {
        if let Some(i) = self.paths.iter().position(|p| p == path) {
            if self.values[i].is_none() {
                self.values[i] = Some(path_value(self.bytes, path)?)
            }
            Ok(self.values[i].as_ref().unwrap())
        } else {
            self.scratch = Some(path_value(self.bytes, path)?);
            Ok(self.scratch.as_ref().unwrap())
        }
    }
    pub fn matches(&mut self, expr: &Expr) -> Result<bool> {
        match expr {
            Expr::Compare { path, op, values } => {
                let values = values
                    .iter()
                    .map(|v| codec::interpret(v.clone(), &path.kind))
                    .collect::<Result<Vec<_>>>()?;
                if path
                    .steps
                    .iter()
                    .any(|s| matches!(s, Step::Any | Step::All))
                {
                    quantified(self.bytes, path, &|v| scalar(v, op, &values))
                } else {
                    scalar(self.value(path)?, op, &values)
                }
            }
            Expr::Presence { path, op } => {
                let test = |v: &Value| {
                    Ok(match op {
                        Presence::Exists => v.exists(),
                        Presence::Null => v.is_null(),
                        Presence::Missing => v.is_missing(),
                        Presence::Empty => v.is_empty(),
                    })
                };
                if path
                    .steps
                    .iter()
                    .any(|s| matches!(s, Step::Any | Step::All))
                {
                    quantified(self.bytes, path, &test)
                } else {
                    test(self.value(path)?)
                }
            }
            Expr::And(a, b) => Ok(self.matches(a)? && self.matches(b)?),
            Expr::Or(a, b) => Ok(self.matches(a)? || self.matches(b)?),
            Expr::Not(a) => Ok(!self.matches(a)?),
            Expr::ElemMatch { path, inner } => {
                let Value::Array(items) = self.value(path)? else {
                    return Ok(false);
                };
                for item in items {
                    if matches(&json_bytes(item)?, inner)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Expr::Never => Ok(false),
            Expr::Invalid(_) => Err(ClError::Validation("invalid query expression".into())),
        }
    }
}
pub fn matches(bytes: &[u8], expr: &Expr) -> Result<bool> {
    RowEvaluation::new(bytes, &[]).matches(expr)
}

fn json_bytes(v: &Value) -> Result<Vec<u8>> {
    // Re-emit exact numeric tokens for element-local evaluation.
    Ok(match v {
        Value::Number(n) => n.as_bytes().to_vec(),
        Value::Missing => b"null".to_vec(),
        Value::Null => b"null".to_vec(),
        Value::Bool(b) => b.to_string().into_bytes(),
        Value::String(s) => serde_json::to_vec(s)?,
        Value::Array(a) => {
            let p = a.iter().map(json_bytes).collect::<Result<Vec<_>>>()?;
            [b"[".as_slice(), &p.join(&b','), b"]"].concat()
        }
        Value::Object(o) => {
            let p = o
                .iter()
                .map(|(k, v)| Ok([serde_json::to_vec(k)?, vec![b':'], json_bytes(v)?].concat()))
                .collect::<Result<Vec<_>>>()?;
            [b"{".as_slice(), &p.join(&b','), b"}"].concat()
        }
        Value::Time(_) => return Err(ClError::Validation("time value is not raw JSON".into())),
    })
}
