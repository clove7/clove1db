use clove1db::{
    CloveFields,
    fields::{TransformKind, Value, transform},
};
#[derive(CloveFields)]
struct Note {
    title: String,
}
#[test]
fn unicode_and_arabic_transforms_are_versioned_and_idempotent() {
    assert_eq!(transform("  Aé \u{2003}", &TransformKind::Trim), "Aé");
    assert_eq!(transform("ÄBC Σ", &TransformKind::Lowercase), "äbc σ");
    for (from, to) in [
        ("أإآٱ", "اااا"),
        ("ةىؤئ", "هيوي"),
        ("بًٌٍَُِّْٰـ", "ب"),
        ("٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹", "01234567890123456789"),
        ("Plain é漢字", "Plain é漢字"),
    ] {
        assert_eq!(transform(from, &TransformKind::NormalizeArabic), to);
        assert_eq!(
            transform(
                &transform(from, &TransformKind::NormalizeArabic),
                &TransformKind::NormalizeArabic
            ),
            to
        );
    }
    assert_eq!(
        Note::title
            .trim()
            .lowercase()
            .extract("{\"title\":\"  ÄBC  \"}".as_bytes())
            .unwrap(),
        Value::String("äbc".into())
    );
}
