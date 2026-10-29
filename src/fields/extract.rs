//! Selective traversal delegates JSON syntax and validation to serde_json.
use super::{Field, Step, Value};
use crate::units::Result;
use serde::{
    Deserialize,
    de::{IgnoredAny, MapAccess, SeqAccess, Visitor},
};
use serde_json::value::RawValue;
struct Key<'a>(&'a str);
impl<'de> Visitor<'de> for Key<'_> {
    type Value = Option<&'de RawValue>;
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("an object")
    }
    fn visit_map<M: MapAccess<'de>>(
        self,
        mut map: M,
    ) -> std::result::Result<Self::Value, M::Error> {
        let mut found = None;
        while let Some(key) = map.next_key::<String>()? {
            if key == self.0 {
                found = Some(map.next_value::<&RawValue>()?);
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(found)
    }
}
struct Index(usize);
impl<'de> Visitor<'de> for Index {
    type Value = Option<&'de RawValue>;
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("an array")
    }
    fn visit_seq<S: SeqAccess<'de>>(
        self,
        mut seq: S,
    ) -> std::result::Result<Self::Value, S::Error> {
        let mut found = None;
        let mut i = 0;
        loop {
            if i == self.0 {
                match seq.next_element::<&RawValue>()? {
                    Some(v) => found = Some(v),
                    None => break,
                }
            } else if seq.next_element::<IgnoredAny>()?.is_none() {
                break;
            }
            i += 1;
        }
        Ok(found)
    }
}
fn materialize(raw: &RawValue) -> Result<Value> {
    let text = raw.get();
    Ok(match text.as_bytes()[0] {
        b'n' => Value::Null,
        b't' => Value::Bool(true),
        b'f' => Value::Bool(false),
        b'"' => Value::String(serde_json::from_str(text)?),
        b'[' => Value::Array(
            serde_json::from_str::<Vec<&RawValue>>(text)?
                .into_iter()
                .map(materialize)
                .collect::<Result<_>>()?,
        ),
        b'{' => Value::Object(
            serde_json::from_str::<std::collections::BTreeMap<String, &RawValue>>(text)?
                .into_iter()
                .map(|(k, v)| Ok((k, materialize(v)?)))
                .collect::<Result<_>>()?,
        ),
        _ => Value::Number(text.into()),
    })
}
fn select(raw: &RawValue, path: &[Step]) -> Result<Value> {
    use serde::Deserializer;
    let Some((first, rest)) = path.split_first() else {
        return materialize(raw);
    };
    let text = raw.get();
    let mut de = serde_json::Deserializer::from_str(text);
    let value = match first {
        Step::Key(k) if text.starts_with('{') => de.deserialize_map(Key(k))?,
        Step::Index(i) if text.starts_with('[') => de.deserialize_seq(Index(*i))?,
        Step::Any | Step::All if text.starts_with('[') => {
            let values = Vec::<&RawValue>::deserialize(&mut de)?;
            return Ok(Value::Array(
                values
                    .into_iter()
                    .map(|v| select(v, rest))
                    .collect::<Result<_>>()?,
            ));
        }
        Step::Length if text.starts_with('[') => {
            let values = Vec::<&RawValue>::deserialize(&mut de)?;
            return Ok(Value::Number(values.len().to_string()));
        }
        _ => return Ok(Value::Missing),
    };
    value.map(|v| select(v, rest)).unwrap_or(Ok(Value::Missing))
}
/// Select a field from valid stored JSON, preserving exact numeric tokens.
pub fn extract(bytes: &[u8], path: &[Step]) -> Result<Value> {
    let raw: &RawValue = serde_json::from_slice(bytes)?;
    select(raw, path)
}
impl<E, V> Field<E, V> {
    pub fn extract(&self, bytes: &[u8]) -> Result<Value> {
        super::transforms::apply(
            super::codec::interpret(extract(bytes, &self.steps())?, &self.kind)?,
            &self.transforms,
        )
    }
}
