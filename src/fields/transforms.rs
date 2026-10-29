use super::{Transform, TransformKind, Value};
use crate::units::{ClError, Result};
/// Version 1 Unicode and Arabic transformations. Their versions are part of Path.
pub fn transform(text: &str, kind: &TransformKind) -> String {
    match kind {
        TransformKind::Trim => text.trim().into(),
        TransformKind::Lowercase => text.to_lowercase(),
        TransformKind::NormalizeArabic => text
            .chars()
            .filter_map(|c| {
                Some(match c {
                    'أ' | 'إ' | 'آ' | 'ٱ' => 'ا',
                    'ة' => 'ه',
                    'ى' => 'ي',
                    'ؤ' => 'و',
                    'ئ' => 'ي',
                    '\u{064B}'..='\u{0652}' | '\u{0670}' | '\u{0640}' => return None,
                    '٠'..='٩' => char::from_u32('0' as u32 + c as u32 - '٠' as u32).unwrap(),
                    '۰'..='۹' => char::from_u32('0' as u32 + c as u32 - '۰' as u32).unwrap(),
                    _ => c,
                })
            })
            .collect(),
    }
}
pub(crate) fn apply(mut value: Value, transforms: &[Transform]) -> Result<Value> {
    if transforms.is_empty() || value.is_empty() {
        return Ok(value);
    }
    if let Value::Array(values) = value {
        return Ok(Value::Array(
            values
                .into_iter()
                .map(|v| apply(v, transforms))
                .collect::<Result<_>>()?,
        ));
    }
    for t in transforms {
        if t.version != 1 {
            return Err(ClError::Validation(
                "unsupported text transformation version".into(),
            ));
        }
        let Value::String(v) = value else {
            return Err(ClError::Validation(
                "text transformation requires a string".into(),
            ));
        };
        value = Value::String(transform(&v, &t.kind));
    }
    Ok(value)
}
