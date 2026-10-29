//! Typed JSON field descriptors. Query execution is provided separately.
#![doc = include_str!("compile_checks.md")]
use std::marker::PhantomData;
/// Derive-generated marker for structures whose fields can be navigated.
pub trait CloveFields {
    #[doc(hidden)]
    const CHECK_FIELDS: () = ();
}
macro_rules! scalar_shapes {($($t:ty),* $(,)?) => {$(impl CloveFields for $t {})*};}
scalar_shapes!(
    String,
    str,
    bool,
    i8,
    i16,
    i32,
    i64,
    i128,
    isize,
    u8,
    u16,
    u32,
    u64,
    u128,
    usize,
    f32,
    f64,
    serde_json::Value,
    Json,
    Time,
    uuid::Uuid
);
impl<T: CloveFields> CloveFields for Vec<T> {}
impl<T: CloveFields> CloveFields for Option<T> {}
impl<T: CloveFields> CloveFields for Box<T> {}
impl<T: CloveFields + ?Sized> CloveFields for &T {}
impl<T: CloveFields, const N: usize> CloveFields for [T; N] {}
impl<T: CloveFields> CloveFields for std::collections::HashMap<String, T> {}
impl<T: CloveFields> CloveFields for std::collections::BTreeMap<String, T> {}
impl<A: CloveFields, B: CloveFields> CloveFields for (A, B) {}
impl<A: CloveFields, B: CloveFields, C: CloveFields> CloveFields for (A, B, C) {}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ValueKind {
    Auto,
    DateTime,
    Date,
    NaiveDateTime,
    EpochSeconds,
    EpochMillis,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Step {
    Key(String),
    Index(usize),
    Any,
    All,
    Length,
}
/// A typed field. Optional storage values expose their non-null value type.
pub struct Field<E, V> {
    first: Option<&'static str>,
    steps: Vec<Step>,
    kind: ValueKind,
    transforms: Vec<Transform>,
    marker: PhantomData<fn(E) -> V>,
}
impl<E, V> Clone for Field<E, V> {
    fn clone(&self) -> Self {
        Self {
            first: self.first,
            steps: self.steps.clone(),
            kind: self.kind.clone(),
            transforms: self.transforms.clone(),
            marker: PhantomData,
        }
    }
}
impl<E, V> Field<E, V> {
    #[doc(hidden)]
    pub const fn new(first: &'static str, kind: ValueKind) -> Self {
        Self {
            first: Some(first),
            steps: Vec::new(),
            kind,
            transforms: Vec::new(),
            marker: PhantomData,
        }
    }
    #[doc(hidden)]
    pub const fn flattened(kind: ValueKind) -> Self {
        Self {
            first: None,
            steps: Vec::new(),
            kind,
            transforms: Vec::new(),
            marker: PhantomData,
        }
    }
    pub fn steps(&self) -> Vec<Step> {
        let mut s = Vec::new();
        if let Some(first) = self.first {
            s.push(Step::Key(first.into()));
        }
        s.extend(self.steps.clone());
        s
    }
    pub fn json_path(&self) -> Vec<String> {
        self.steps()
            .into_iter()
            .filter_map(|s| match s {
                Step::Key(k) => Some(k),
                Step::Index(i) => Some(i.to_string()),
                _ => None,
            })
            .collect()
    }
    pub fn then<W>(self, child: Field<V, W>) -> Field<E, W>
    where
        V: CloveFields,
    {
        let mut steps = self.steps();
        steps.extend(child.steps());
        Field {
            first: None,
            steps,
            kind: child.kind,
            transforms: child.transforms,
            marker: PhantomData,
        }
    }
}
/// Typed dynamic JSON navigation target.
pub struct Json;
/// Chronological field value, accepting chrono date and datetime inputs.
pub struct Time;

mod ast;
pub use ast::*;
mod extract;
pub use extract::extract;
pub mod codec;
pub(crate) mod transforms;
pub use transforms::transform;
