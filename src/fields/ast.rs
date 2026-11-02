use super::*;
use crate::units::{ClError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
/// An exact JSON value. Number tokens retain their decimal spelling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Value {
    Missing,
    Null,
    Bool(bool),
    Number(String),
    Time(i128),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}
impl Value {
    pub fn from_json(value: serde_json::Value) -> Self {
        match value {
            serde_json::Value::Null => Self::Null,
            serde_json::Value::Bool(v) => Self::Bool(v),
            serde_json::Value::Number(v) => Self::Number(v.to_string()),
            serde_json::Value::String(v) => Self::String(v),
            serde_json::Value::Array(v) => {
                Self::Array(v.into_iter().map(Self::from_json).collect())
            }
            serde_json::Value::Object(v) => Self::Object(
                v.into_iter()
                    .map(|(k, v)| (k, Self::from_json(v)))
                    .collect(),
            ),
        }
    }
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
    pub fn is_missing(&self) -> bool {
        matches!(self, Self::Missing)
    }
    pub fn is_empty(&self) -> bool {
        self.is_missing() || self.is_null()
    }
    pub fn exists(&self) -> bool {
        !self.is_missing()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransformKind {
    Trim,
    Lowercase,
    NormalizeArabic,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transform {
    pub kind: TransformKind,
    pub version: u8,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Path {
    pub steps: Vec<Step>,
    pub kind: ValueKind,
    pub transforms: Vec<Transform>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Compare {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    Between,
    In,
    Prefix,
    Contains,
    Text,
    Fuzzy(u8),
    /// Every term of the (space separated) value is among the terms of the stored field. Built only by
    /// the handle of a field with fingerprints of parts (`field_crypto`), which is the one that can
    /// make the terms; the index for it is kept as posting blocks.
    Parts,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Presence {
    Exists,
    Null,
    Missing,
    Empty,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Expr {
    Compare {
        path: Path,
        op: Compare,
        values: Vec<Value>,
    },
    Presence {
        path: Path,
        op: Presence,
    },
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    ElemMatch {
        path: Path,
        inner: Box<Expr>,
    },
    Never,
    Invalid(String),
}
/// A typed, serializable predicate tree; it does not execute a query.
pub struct Predicate<E> {
    pub expression: Expr,
    /// The fingerprints that a field handle with a search grant put in this predicate. A condition on a
    /// protected field is accepted by a query only if its values are in this list; nothing outside the
    /// crate can add to it.
    printed: Vec<String>,
    marker: PhantomData<fn(E)>,
}
impl<E> Clone for Predicate<E> {
    fn clone(&self) -> Self {
        Self { expression: self.expression.clone(), printed: self.printed.clone(), marker: PhantomData }
    }
}
impl<E> std::fmt::Debug for Predicate<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.expression.fmt(f)
    }
}
impl<E> PartialEq for Predicate<E> {
    fn eq(&self, o: &Self) -> bool {
        self.expression == o.expression
    }
}
impl<E> Eq for Predicate<E> {}
impl<E> Predicate<E> {
    fn new(expression: Expr) -> Self {
        Self {
            expression,
            printed: Vec::new(),
            marker: PhantomData,
        }
    }
    /// A predicate built by the handle of a fingerprinted field: `printed` are the fingerprints in it.
    #[cfg_attr(not(any(test, feature = "encryption")), allow(dead_code))]
    pub(crate) fn with_printed(expression: Expr, printed: Vec<String>) -> Self {
        Self { expression, printed, marker: PhantomData }
    }
    #[cfg_attr(not(feature = "encryption"), allow(dead_code))]
    pub(crate) fn printed(&self) -> &[String] {
        &self.printed
    }
    pub fn and(self, other: Self) -> Self {
        let mut printed = self.printed;
        printed.extend(other.printed);
        Self {
            expression: Expr::And(Box::new(self.expression), Box::new(other.expression)),
            printed,
            marker: PhantomData,
        }
    }
    pub fn or(self, other: Self) -> Self {
        let mut printed = self.printed;
        printed.extend(other.printed);
        Self {
            expression: Expr::Or(Box::new(self.expression), Box::new(other.expression)),
            printed,
            marker: PhantomData,
        }
    }
    #[allow(clippy::should_implement_trait)]
    pub fn not(self) -> Self {
        Self { expression: Expr::Not(Box::new(self.expression)), printed: self.printed, marker: PhantomData }
    }
    pub fn fingerprint(&self) -> Result<Vec<u8>> {
        fn check(e: &Expr) -> Result<()> {
            match e {
                Expr::Compare{op:Compare::Fuzzy(distance),..} if *distance>2=>Err(ClError::Validation("fuzzy distance exceeds 2".into())),
                Expr::Invalid(v) => Err(ClError::Validation(v.clone())),
                Expr::And(a, b) | Expr::Or(a, b) => {
                    check(a)?;
                    check(b)
                }
                Expr::Not(a) | Expr::ElemMatch { inner: a, .. } => check(a),
                _ => Ok(()),
            }
        }
        check(&self.expression)?;
        fn value(v: &mut Value) -> Result<()> {
            match v {
                Value::Number(n) => *n = super::codec::canonical_number(n)?,
                Value::Array(a) => {
                    for v in a {
                        value(v)?;
                    }
                }
                Value::Object(o) => {
                    for v in o.values_mut() {
                        value(v)?;
                    }
                }
                _ => (),
            }
            Ok(())
        }
        fn normalize(e: &mut Expr) -> Result<()> {
            match e {
                Expr::Compare { path, values, .. } => {
                    for v in values {
                        *v = super::codec::interpret(v.clone(), &path.kind)?;
                        value(v)?;
                    }
                }
                Expr::And(a, b) | Expr::Or(a, b) => {
                    normalize(a)?;
                    normalize(b)?;
                }
                Expr::Not(a) | Expr::ElemMatch { inner: a, .. } => normalize(a)?,
                _ => (),
            }
            Ok(())
        }
        let mut expression = self.expression.clone();
        normalize(&mut expression)?;
        let mut bytes = vec![1, super::codec::VERSION];
        bytes.extend(serde_json::to_vec(&expression)?);
        Ok(bytes)
    }
}
/// Type-checked literal accepted by a field.
pub trait FieldInput<V> {
    fn field_value(self) -> Result<Value>;
}
impl<V: Serialize> FieldInput<V> for V {
    fn field_value(self) -> Result<Value> {
        {
            let value = serde_json::to_value(self)?;
            if value.is_null() && matches!(std::any::type_name::<V>(), "f64" | "f32") {
                return Err(ClError::Validation(
                    "NaN and infinity are not orderable".into(),
                ));
            }
            Ok(Value::from_json(value))
        }
    }
}
impl FieldInput<String> for &str {
    fn field_value(self) -> Result<Value> {
        Ok(Value::String(self.into()))
    }
}
impl FieldInput<Json> for serde_json::Value {
    fn field_value(self) -> Result<Value> {
        Ok(Value::from_json(self))
    }
}
impl<Tz: chrono::TimeZone> FieldInput<Time> for chrono::DateTime<Tz> {
    fn field_value(self) -> Result<Value> {
        Ok(Value::Time(
            self.timestamp() as i128 * 1_000_000_000 + self.timestamp_subsec_nanos() as i128,
        ))
    }
}
impl FieldInput<Time> for chrono::NaiveDateTime {
    fn field_value(self) -> Result<Value> {
        self.and_utc().field_value()
    }
}
impl FieldInput<Time> for chrono::NaiveDate {
    fn field_value(self) -> Result<Value> {
        self.and_hms_opt(0, 0, 0).unwrap().field_value()
    }
}
impl<E, V> Field<E, V> {
    pub fn path(&self) -> Path {
        Path {
            steps: self.steps(),
            kind: self.kind.clone(),
            transforms: self.transforms.clone(),
        }
    }
    fn compare<I: FieldInput<V>>(
        self,
        op: Compare,
        values: impl IntoIterator<Item = I>,
    ) -> Predicate<E> {
        let values = values
            .into_iter()
            .map(FieldInput::field_value)
            .collect::<Result<Vec<_>>>();
        Predicate::new(match values {
            Ok(mut values) => {
                if op == Compare::In {
                    values.retain(|v| !v.is_empty());
                }
                if values.is_empty() || values.iter().any(Value::is_empty) {
                    Expr::Never
                } else {
                    Expr::Compare {
                        path: self.path(),
                        op,
                        values,
                    }
                }
            }
            Err(e) => Expr::Invalid(e.to_string()),
        })
    }

    pub fn eq<I: FieldInput<V>>(self, v: I) -> Predicate<E> {
        self.compare(Compare::Eq, [v])
    }
    pub fn ne<I: FieldInput<V>>(self, v: I) -> Predicate<E> {
        self.compare(Compare::Ne, [v])
    }
    pub fn gt<I: FieldInput<V>>(self, v: I) -> Predicate<E> {
        self.compare(Compare::Gt, [v])
    }
    pub fn ge<I: FieldInput<V>>(self, v: I) -> Predicate<E> {
        self.compare(Compare::Ge, [v])
    }
    pub fn lt<I: FieldInput<V>>(self, v: I) -> Predicate<E> {
        self.compare(Compare::Lt, [v])
    }
    pub fn le<I: FieldInput<V>>(self, v: I) -> Predicate<E> {
        self.compare(Compare::Le, [v])
    }
    /// Half-open range: lower inclusive, upper exclusive.
    pub fn between<I: FieldInput<V>>(self, lower: I, upper: I) -> Predicate<E> {
        self.compare(Compare::Between, [lower, upper])
    }
    pub fn in_<I: FieldInput<V>>(self, values: impl IntoIterator<Item = I>) -> Predicate<E> {
        self.compare(Compare::In, values)
    }
    fn presence(self, op: Presence) -> Predicate<E> {
        Predicate::new(Expr::Presence {
            path: self.path(),
            op,
        })
    }
    pub fn exists(self) -> Predicate<E> {
        self.presence(Presence::Exists)
    }
    pub fn is_null(self) -> Predicate<E> {
        self.presence(Presence::Null)
    }
    pub fn is_missing(self) -> Predicate<E> {
        self.presence(Presence::Missing)
    }
    pub fn is_empty(self) -> Predicate<E> {
        self.presence(Presence::Empty)
    }
    fn navigate<W>(self, step: Step) -> Field<E, W> {
        let kind = if matches!(step, Step::Length) {
            ValueKind::Auto
        } else {
            self.kind.clone()
        };
        let mut steps = self.steps();
        steps.push(step);
        Field {
            first: None,
            steps,
            kind,
            transforms: Vec::new(),
            marker: PhantomData,
        }
    }
}
impl<E, T> Field<E, Vec<T>> {
    pub fn any(self) -> Field<E, T> {
        self.navigate(Step::Any)
    }
    pub fn all(self) -> Field<E, T> {
        self.navigate(Step::All)
    }
    pub fn at(self, index: usize) -> Field<E, T> {
        self.navigate(Step::Index(index))
    }
    pub fn len(self) -> Field<E, u64> {
        self.navigate(Step::Length)
    }
    pub fn elem_match(self, p: Predicate<T>) -> Predicate<E> {
        Predicate::new(Expr::ElemMatch {
            path: self.path(),
            inner: Box::new(p.expression),
        })
    }
}
impl<E, T> Field<E, std::collections::HashMap<String, T>> {
    pub fn key(self, key: impl Into<String>) -> Field<E, T> {
        self.navigate(Step::Key(key.into()))
    }
}
impl<E> Field<E, Json> {
    pub fn key(self, key: impl Into<String>) -> Self {
        self.navigate(Step::Key(key.into()))
    }
    pub fn at(self, index: usize) -> Self {
        self.navigate(Step::Index(index))
    }
}
impl<E> Field<E, String> {
    /// Match a tokenizer-v1 token at Unicode Levenshtein distance at most two.
    pub fn fuzzy(self,term:impl Into<String>,max_distance:u8)->Predicate<E> {
        let term=term.into();
        if max_distance>2 || crate::query::eval::tokens(&term).len()!=1 {return Predicate::new(Expr::Invalid("fuzzy requires one token and distance <= 2".into()))}
        self.compare(Compare::Fuzzy(max_distance),[crate::query::eval::tokens(&term).remove(0)])
    }
    /// Rank the transformed field by strsim normalized Levenshtein similarity.
    pub fn similarity(self,term:impl Into<String>)->crate::query::Similarity<E> {crate::query::Similarity::new(self.path(),term.into())}

    fn transform(mut self, kind: TransformKind) -> Self {
        self.transforms.push(Transform { kind, version: 1 });
        self
    }
    pub fn trim(self) -> Self {
        self.transform(TransformKind::Trim)
    }
    pub fn lowercase(self) -> Self {
        self.transform(TransformKind::Lowercase)
    }
    pub fn normalize_arabic(self) -> Self {
        self.transform(TransformKind::NormalizeArabic)
    }
    pub fn prefix(self, v: impl Into<String>) -> Predicate<E> {
        self.compare(Compare::Prefix, [v.into()])
    }
    pub fn contains(self, v: impl Into<String>) -> Predicate<E> {
        self.compare(Compare::Contains, [v.into()])
    }
    pub fn text(self, v: impl Into<String>) -> Predicate<E> {
        self.compare(Compare::Text, [v.into()])
    }
}

impl<E> Field<E, serde_json::Value> {
    pub fn key(self, key: impl Into<String>) -> Field<E, Json> {
        self.navigate(Step::Key(key.into()))
    }
    pub fn at(self, index: usize) -> Field<E, Json> {
        self.navigate(Step::Index(index))
    }
}
