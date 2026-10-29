//! Version 1 ordered keys: Missing, Null, false, true, Number, Time, String, Array.
//! Objects have canonical equality keys only. Numeric exponent range is i128.
use super::{Value, ValueKind};
use crate::units::{ClError, Result};
pub const VERSION: u8 = 1;
fn error(message: &str) -> ClError {
    ClError::Validation(message.into())
}
#[derive(Debug)]
pub(crate) struct Decimal {
    pub(crate) negative: bool,
    pub(crate) digits: String,
    pub(crate) exponent: i128,
}
impl Decimal {
    pub(crate) fn parse(token: &str) -> Result<Self> {
        let raw = serde_json::value::RawValue::from_string(token.into())?;
        if !matches!(raw.get().as_bytes().first(), Some(b'-' | b'0'..=b'9')) {
            return Err(error("expected a finite JSON number"));
        }
        let token = raw.get();
        let negative = token.starts_with('-');
        let token = token.strip_prefix('-').unwrap_or(token);
        let (mantissa, exp) = token.split_once(['e', 'E']).unwrap_or((token, "0"));
        let exp = exp
            .parse::<i128>()
            .map_err(|_| error("numeric exponent exceeds i128"))?;
        let (integer, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
        let digits = format!("{integer}{fraction}");
        let leading = digits.len() - digits.trim_start_matches('0').len();
        let exponent = exp
            .checked_add(integer.len() as i128)
            .and_then(|v| v.checked_sub(leading as i128))
            .ok_or_else(|| error("numeric exponent exceeds i128"))?;
        let digits = digits.trim_matches('0').to_string();
        if digits.is_empty() {
            return Ok(Self {
                negative: false,
                digits,
                exponent: 0,
            });
        }
        Ok(Self {
            negative,
            digits,
            exponent,
        })
    }
    fn canonical(&self) -> Result<String> {
        if self.digits.is_empty() {
            return Ok("0".into());
        }
        let power = self
            .exponent
            .checked_sub(self.digits.len() as i128)
            .ok_or_else(|| error("numeric exponent exceeds i128"))?;
        Ok(format!(
            "{}{}e{power}",
            if self.negative { "-" } else { "" },
            self.digits
        ))
    }
    fn integer_scaled(&self, scale: i128) -> Result<i128> {
        if self.digits.is_empty() {
            return Ok(0);
        }
        let power = self
            .exponent
            .checked_sub(self.digits.len() as i128)
            .and_then(|v| v.checked_add(scale))
            .ok_or_else(|| error("timestamp outside supported range"))?;
        if power < 0 {
            return Err(error("timestamp precision exceeds nanoseconds"));
        }
        let exponent =
            u32::try_from(power).map_err(|_| error("timestamp outside supported range"))?;
        let mut value = self
            .digits
            .parse::<i128>()
            .map_err(|_| error("timestamp outside supported range"))?;
        value = value
            .checked_mul(
                10i128
                    .checked_pow(exponent)
                    .ok_or_else(|| error("timestamp outside supported range"))?,
            )
            .ok_or_else(|| error("timestamp outside supported range"))?;
        Ok(if self.negative { -value } else { value })
    }
}
/// One spelling for all equal finite decimal values, without passing through f64.
pub fn canonical_number(token: &str) -> Result<String> {
    Decimal::parse(token)?.canonical()
}
pub(crate) fn integer(token:&str)->Result<i128>{
    let d=Decimal::parse(token)?;
    if d.digits.is_empty(){return Ok(0)}
    let power=d.exponent.checked_sub(d.digits.len()as i128).ok_or(ClError::SumOverflow)?;
    if power<0{return Err(ClError::UnsupportedSum)}
    if power>38{return Err(ClError::SumOverflow)}
    format!("{}{}{}",if d.negative{"-"}else{""},d.digits,"0".repeat(power as usize)).parse().map_err(|_|ClError::SumOverflow)
}

pub fn number_from_f64(value: f64) -> Result<Value> {
    if !value.is_finite() {
        return Err(error("NaN and infinity are not orderable"));
    }
    Ok(Value::Number(value.to_string()))
}
fn signed(value: i128) -> [u8; 16] {
    ((value as u128) ^ (1u128 << 127)).to_be_bytes()
}
fn text(bytes: &[u8], out: &mut Vec<u8>) {
    for &b in bytes {
        if b == 0 {
            out.extend([0, 255]);
        } else {
            out.push(b);
        }
    }
    out.extend([0, 0]);
}
fn append(value: &Value, out: &mut Vec<u8>, objects: bool) -> Result<()> {
    match value {
        Value::Missing => out.push(1),
        Value::Null => out.push(2),
        Value::Bool(false) => out.push(3),
        Value::Bool(true) => out.push(4),
        Value::Number(token) => {
            let n = Decimal::parse(token)?;
            out.push(5);
            if n.digits.is_empty() {
                out.push(1);
            } else {
                out.push(if n.negative { 0 } else { 2 });
                let mut part = signed(n.exponent).to_vec();
                part.extend(n.digits.bytes());
                part.push(0);
                if n.negative {
                    for b in &mut part {
                        *b = !*b;
                    }
                }
                out.extend(part);
            }
        }
        Value::Time(n) => {
            out.push(6);
            out.extend(signed(*n));
        }
        Value::String(v) => {
            out.push(7);
            text(v.as_bytes(), out);
        }
        Value::Array(v) => {
            out.push(8);
            for value in v {
                append(value, out, objects)?;
            }
            out.push(0);
        }
        Value::Object(v) if objects => {
            out.push(9);
            for (key, value) in v {
                out.push(7);
                text(key.as_bytes(), out);
                append(value, out, true)?;
            }
            out.push(0);
        }
        Value::Object(_) => {
            return Err(error(
                "objects support canonical equality only, not ordering",
            ));
        }
    }
    Ok(())
}
/// Ordered, self-delimiting components. The caller's definition fingerprint carries VERSION.
pub fn encode(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    append(value, &mut out, false)?;
    Ok(out)
}
pub fn encode_equality(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    append(value, &mut out, true)?;
    Ok(out)
}
pub fn encode_tuple(values: &[Value]) -> Result<Vec<u8>> {
    encode(&Value::Array(values.to_vec()))
}
/// Apply a declared temporal interpretation; ordinary strings stay strings.
pub fn interpret(value: Value, kind: &ValueKind) -> Result<Value> {
    if value.is_empty() || matches!(kind, ValueKind::Auto) {
        return Ok(value);
    }
    if matches!(value, Value::Time(_)) {
        return Ok(value);
    }
    if let Value::Array(values) = value {
        return Ok(Value::Array(
            values
                .into_iter()
                .map(|v| interpret(v, kind))
                .collect::<Result<_>>()?,
        ));
    }
    if let Value::Object(values) = value {
        return Ok(Value::Object(
            values
                .into_iter()
                .map(|(k, v)| Ok((k, interpret(v, kind)?)))
                .collect::<Result<_>>()?,
        ));
    }
    let time = match (kind, value) {
        (ValueKind::EpochSeconds, Value::Number(v)) => Decimal::parse(&v)?.integer_scaled(9)?,
        (ValueKind::EpochMillis, Value::Number(v)) => Decimal::parse(&v)?.integer_scaled(6)?,
        (ValueKind::DateTime, Value::String(v)) => {
            let t = chrono::DateTime::parse_from_rfc3339(&v)
                .map_err(|_| error("invalid RFC3339 datetime"))?;
            t.timestamp() as i128 * 1_000_000_000 + t.timestamp_subsec_nanos() as i128
        }
        (ValueKind::Date, Value::String(v)) => {
            let t = chrono::NaiveDate::parse_from_str(&v, "%Y-%m-%d")
                .map_err(|_| error("invalid date"))?
                .and_hms_opt(0, 0, 0)
                .unwrap()
                .and_utc();
            t.timestamp() as i128 * 1_000_000_000
        }
        (ValueKind::NaiveDateTime, Value::String(v)) => {
            let t = chrono::NaiveDateTime::parse_from_str(&v, "%Y-%m-%dT%H:%M:%S%.f")
                .or_else(|_| chrono::NaiveDateTime::parse_from_str(&v, "%Y-%m-%d %H:%M:%S%.f"))
                .map_err(|_| error("invalid naive datetime"))?
                .and_utc();
            t.timestamp() as i128 * 1_000_000_000 + t.timestamp_subsec_nanos() as i128
        }
        _ => {
            return Err(error(
                "value does not match declared temporal representation",
            ));
        }
    };
    Ok(Value::Time(time))
}
