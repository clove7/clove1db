//! What becomes of each protected field of a table when its protection is changed, decided from the
//! description the table has (what it was made with) and the fields the code declares now. Nothing is
//! read or written here: a change that cannot be made is an error before any file is touched.
//!
//! The rules:
//! * a field can be sealed, given or stripped of fingerprints, or have them made again;
//! * a hash or a fingerprint-only field can never be turned back (its value is not kept), and cannot
//!   be made again with other settings;
//! * a change that loses the original (to a hash, or to a fingerprint alone) needs the program to say
//!   so with `confirm_one_way`.
use crate::field_crypto::{Method, SealedField, SealedSpec};
use crate::units::{ClError, Result};

/// What happens to one field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StepKind {
    /// Nothing changes in the rows: the field is copied as it is. For a field with settings behind a
    /// keyed fingerprint (`check`) the run still compares them: see [`settled`].
    Keep,
    /// A plain value is sealed (with the fingerprints the new method has).
    Seal,
    /// A plain value becomes a verification hash. One way.
    Hash,
    /// A plain value becomes a search fingerprint and is not kept. One way.
    PrintOnly,
    /// A sealed value gets fingerprints it did not have.
    AddPrints,
    /// A sealed value's fingerprints are all made again (other settings, or a method that drops some).
    RemakePrints,
    /// A sealed value loses its fingerprints. Needs no key.
    DropPrints,
    /// A sealed value becomes plain.
    Open,
    /// A sealed value becomes a verification hash. One way.
    OpenToHash,
    /// A sealed value becomes a search fingerprint and is not kept. One way.
    OpenToPrintOnly,
}

impl StepKind {
    pub(crate) fn one_way(self) -> bool {
        matches!(self, StepKind::Hash | StepKind::PrintOnly | StepKind::OpenToHash | StepKind::OpenToPrintOnly)
    }
}

/// One field of one table and what is done to it.
#[derive(Clone, Debug)]
pub(crate) struct FieldStep {
    pub id: u32,
    pub key: String,
    pub from: Option<SealedField>,
    pub to: Option<SealedSpec>,
    pub kind: StepKind,
}

impl FieldStep {
    /// Whether the value is opened (the read key is needed) to do this.
    fn opens(&self) -> bool {
        matches!(
            self.kind,
            StepKind::AddPrints | StepKind::RemakePrints | StepKind::Open | StepKind::OpenToHash | StepKind::OpenToPrintOnly
        )
    }

    /// Whether a new value is sealed (the read key is needed).
    fn seals(&self) -> bool {
        matches!(self.kind, StepKind::Seal | StepKind::AddPrints | StepKind::RemakePrints)
    }

    fn hashes(&self) -> bool {
        matches!(self.kind, StepKind::Hash | StepKind::OpenToHash)
    }

    /// Whether fingerprints are made (the search key is needed).
    fn prints(&self) -> bool {
        match self.kind {
            StepKind::PrintOnly | StepKind::OpenToPrintOnly | StepKind::AddPrints | StepKind::RemakePrints => true,
            StepKind::Seal => self.to.is_some_and(|t| t.method.has_stored_print()),
            _ => false,
        }
    }
}

/// What the program has to hold to make a change.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Needs {
    pub read: bool,
    pub search: bool,
    /// Some value is lost for good: the program has to confirm it.
    pub one_way: bool,
}

/// What happens to a table.
#[derive(Clone, Debug)]
pub(crate) struct TablePlan {
    pub table: String,
    pub steps: Vec<FieldStep>,
    /// The table had no protected field and gets its first: it gets an identity.
    pub new_table_id: bool,
    /// The table has no protected field after the change: its identity goes.
    pub drop_table_id: bool,
}

impl TablePlan {
    /// Whether any row has to be rewritten.
    pub(crate) fn changes_rows(&self) -> bool {
        self.steps.iter().any(|s| s.kind != StepKind::Keep)
    }

    pub(crate) fn needs(&self) -> Needs {
        let mut needs = Needs::default();
        for step in &self.steps {
            needs.read |= step.opens() || step.seals() || step.hashes();
            needs.search |= step.prints();
            needs.one_way |= step.kind.one_way();
        }
        needs
    }
}

fn refuse(table: &str, key: &str, why: &str) -> ClError {
    ClError::MigrationError(format!("table '{table}': field '{key}' {why}. Nothing was changed"))
}

fn sealing(method: u8) -> bool {
    Method::from_code(method).is_some_and(Method::is_sealing)
}

/// What becomes of one field: it has `from` in the table's description (if it had one) and the code
/// declares `to` now (if it does).
pub(crate) fn decide(table: &str, key: &str, from: Option<&SealedField>, to: Option<&SealedSpec>) -> Result<StepKind> {
    let Some(old) = from else {
        // no protection before
        return Ok(match to {
            None => StepKind::Keep,
            Some(t) => match t.method {
                Method::Encrypt | Method::EncryptFullPrint | Method::EncryptPartPrints => StepKind::Seal,
                Method::Hash => StepKind::Hash,
                Method::SearchPrint => StepKind::PrintOnly,
            },
        });
    };
    let Some(was) = Method::from_code(old.method) else {
        return Err(refuse(table, key, "was made by a method this version does not know"));
    };
    let Some(t) = to else {
        return match was {
            Method::Hash => Err(refuse(table, key, "is a verification hash: it cannot be removed or turned back, its value is not kept")),
            Method::SearchPrint => Err(refuse(table, key, "is a search fingerprint: it cannot be removed or turned back, its value is not kept")),
            _ => Ok(StepKind::Open),
        };
    };
    if old.id != t.id || old.name != t.key {
        return Err(refuse(table, key, "changes its number or its key: that is not part of this change"));
    }
    match (was, t.method) {
        (Method::Hash, Method::Hash) | (Method::SearchPrint, Method::SearchPrint) => Ok(StepKind::Keep),
        (Method::Hash, _) => Err(refuse(table, key, "is a verification hash: it cannot be turned into anything else")),
        (Method::SearchPrint, _) => Err(refuse(table, key, "is a search fingerprint: it cannot be turned into anything else")),
        (_, Method::Hash) => Ok(StepKind::OpenToHash),
        (_, Method::SearchPrint) => Ok(StepKind::OpenToPrintOnly),
        (a, b) if a == b => {
            let (window, bits) = if b.has_parts() { (Some(t.window), Some(t.bits)) } else { (None, None) };
            if (old.window, old.bits) != (window, bits) {
                Ok(StepKind::RemakePrints)
            } else {
                Ok(StepKind::Keep)
            }
        }
        (_, Method::Encrypt) => Ok(StepKind::DropPrints),
        (Method::Encrypt, _) => Ok(StepKind::AddPrints),
        (Method::EncryptFullPrint, Method::EncryptPartPrints) => Ok(StepKind::AddPrints),
        // parts to a whole-value fingerprint only: the fingerprint may have other settings, so all are made again
        (Method::EncryptPartPrints, Method::EncryptFullPrint) => Ok(StepKind::RemakePrints),
        _ => unreachable!("every pair of methods is decided above"),
    }
}

/// A field kept as it is, whose settings sit behind a keyed fingerprint: once the keys are open the
/// run compares the stored `check` with what the new settings make. `same` is that comparison.
/// A fingerprint that is sealed alongside its value can be made again; one that stands alone cannot.
pub(crate) fn settled(table: &str, step: &FieldStep, same: bool) -> Result<StepKind> {
    if same {
        return Ok(StepKind::Keep);
    }
    let Some(to) = step.to else { return Ok(StepKind::Keep) };
    match to.method {
        Method::EncryptFullPrint | Method::EncryptPartPrints => Ok(StepKind::RemakePrints),
        Method::Hash => Err(refuse(table, &step.key, "has other hash settings than it was made with: a hash cannot be made again without the secret")),
        Method::SearchPrint => Err(refuse(table, &step.key, "has other normalisation than it was made with: a fingerprint alone cannot be made again, its value is not kept")),
        Method::Encrypt => Ok(StepKind::Keep),
    }
}

/// The plan of one table: `old` is its stored description, `new` the fields the code declares now.
pub(crate) fn plan_table(table: &str, old: &[SealedField], new: &[SealedSpec]) -> Result<TablePlan> {
    for (i, a) in new.iter().enumerate() {
        if new[i + 1..].iter().any(|b| b.id == a.id) {
            return Err(ClError::MigrationError(format!(
                "table '{table}': field number {} is used by more than one protected field. Nothing was changed",
                a.id
            )));
        }
        if a.method.has_parts() && !crate::field_crypto::parts_are_set_up(a) {
            return Err(refuse(table, a.key, "has part fingerprints that are not set up (the length of a part or the bits kept)"));
        }
        if a.method == Method::Hash && a.hash.is_none() {
            return Err(refuse(table, a.key, "is a hash with no hash setting"));
        }
    }
    let mut steps = Vec::new();
    for field in old {
        let to = new.iter().find(|s| s.id == field.id);
        // a field the code no longer declares is a removal; a field the code declares under another
        // number is a new field and the old number is a removal (decided below by `decide`)
        let kind = decide(table, &field.name, Some(field), to)?;
        steps.push(FieldStep { id: field.id, key: field.name.clone(), from: Some(field.clone()), to: to.copied(), kind });
    }
    for spec in new.iter().filter(|s| !old.iter().any(|f| f.id == s.id)) {
        let kind = decide(table, spec.key, None, Some(spec))?;
        steps.push(FieldStep { id: spec.id, key: spec.key.to_string(), from: None, to: Some(*spec), kind });
    }
    steps.sort_by_key(|s| s.id);
    let after = new.len();
    Ok(TablePlan { table: table.to_string(), steps, new_table_id: old.is_empty() && after > 0, drop_table_id: !old.is_empty() && after == 0 })
}

/// Whether a stored method code is one that seals its value (used by reports).
pub(crate) fn seals_value(method: u8) -> bool {
    sealing(method)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field_crypto::HashAlgo;

    fn spec(id: u32, key: &'static str, method: Method) -> SealedSpec {
        let hash = (method == Method::Hash).then_some(HashAlgo::Argon2id);
        let (window, bits) = if method.has_parts() { (3, 12) } else { (0, 0) };
        SealedSpec { id, key, method, hash, normalize: &[], window, bits }
    }

    fn stored(s: SealedSpec) -> SealedField {
        SealedField::from_spec(&s)
    }

    const M: [Method; 5] =
        [Method::Encrypt, Method::EncryptFullPrint, Method::EncryptPartPrints, Method::Hash, Method::SearchPrint];

    fn kind(from: Option<Method>, to: Option<Method>) -> Result<StepKind> {
        let f = from.map(|m| stored(spec(1, "v", m)));
        let t = to.map(|m| spec(1, "v", m));
        decide("t", "v", f.as_ref(), t.as_ref())
    }

    #[test]
    fn a_plain_field_can_be_given_any_protection() {
        let want = [StepKind::Seal, StepKind::Seal, StepKind::Seal, StepKind::Hash, StepKind::PrintOnly];
        for (m, k) in M.iter().zip(want) {
            assert_eq!(kind(None, Some(*m)).unwrap(), k, "{m:?}");
        }
        assert_eq!(kind(None, None).unwrap(), StepKind::Keep);
    }

    #[test]
    fn a_sealed_field_changes_among_the_sealing_methods_by_adding_remaking_or_dropping_fingerprints() {
        use Method::*;
        let cases = [
            (Encrypt, Encrypt, StepKind::Keep),
            (Encrypt, EncryptFullPrint, StepKind::AddPrints),
            (Encrypt, EncryptPartPrints, StepKind::AddPrints),
            (EncryptFullPrint, Encrypt, StepKind::DropPrints),
            (EncryptFullPrint, EncryptFullPrint, StepKind::Keep),
            (EncryptFullPrint, EncryptPartPrints, StepKind::AddPrints),
            (EncryptPartPrints, Encrypt, StepKind::DropPrints),
            (EncryptPartPrints, EncryptFullPrint, StepKind::RemakePrints),
            (EncryptPartPrints, EncryptPartPrints, StepKind::Keep),
        ];
        for (from, to, want) in cases {
            assert_eq!(kind(Some(from), Some(to)).unwrap(), want, "{from:?} to {to:?}");
        }
        // other settings of the parts: all made again
        let f = stored(spec(1, "v", EncryptPartPrints));
        for (window, bits) in [(4, 12), (3, 10)] {
            let t = SealedSpec { window, bits, ..spec(1, "v", EncryptPartPrints) };
            assert_eq!(decide("t", "v", Some(&f), Some(&t)).unwrap(), StepKind::RemakePrints);
        }
    }

    #[test]
    fn a_sealed_field_opens_or_becomes_one_way() {
        for m in [Method::Encrypt, Method::EncryptFullPrint, Method::EncryptPartPrints] {
            assert_eq!(kind(Some(m), None).unwrap(), StepKind::Open);
            assert_eq!(kind(Some(m), Some(Method::Hash)).unwrap(), StepKind::OpenToHash);
            assert_eq!(kind(Some(m), Some(Method::SearchPrint)).unwrap(), StepKind::OpenToPrintOnly);
        }
        for k in [StepKind::Hash, StepKind::PrintOnly, StepKind::OpenToHash, StepKind::OpenToPrintOnly] {
            assert!(k.one_way());
        }
        for k in [StepKind::Keep, StepKind::Seal, StepKind::AddPrints, StepKind::RemakePrints, StepKind::DropPrints, StepKind::Open] {
            assert!(!k.one_way());
        }
    }

    #[test]
    fn a_hash_or_a_fingerprint_alone_never_goes_back_and_never_changes() {
        for held in [Method::Hash, Method::SearchPrint] {
            assert_eq!(kind(Some(held), Some(held)).unwrap(), StepKind::Keep);
            assert!(kind(Some(held), None).is_err(), "{held:?} removed");
            for other in M.iter().filter(|m| **m != held) {
                let err = kind(Some(held), Some(*other)).unwrap_err().to_string();
                assert!(err.contains("cannot be turned into anything else") && err.contains("Nothing was changed"), "{held:?} to {other:?}: {err}");
            }
        }
    }

    #[test]
    fn a_field_that_changes_its_number_or_its_key_is_refused() {
        let f = stored(spec(1, "phone", Method::Encrypt));
        for t in [spec(2, "phone", Method::Encrypt), spec(1, "mobile", Method::Encrypt)] {
            assert!(decide("t", "phone", Some(&f), Some(&t)).is_err());
        }
        // an unknown method code in the description
        let mut odd = f.clone();
        odd.method = 99;
        assert!(decide("t", "phone", Some(&odd), Some(&spec(1, "phone", Method::Encrypt))).is_err());
    }

    #[test]
    fn settings_behind_a_check_are_compared_once_the_keys_are_open() {
        let step = |m| FieldStep { id: 1, key: "v".into(), from: Some(stored(spec(1, "v", m))), to: Some(spec(1, "v", m)), kind: StepKind::Keep };
        for m in M {
            assert_eq!(settled("t", &step(m), true).unwrap(), StepKind::Keep);
        }
        assert_eq!(settled("t", &step(Method::EncryptFullPrint), false).unwrap(), StepKind::RemakePrints);
        assert_eq!(settled("t", &step(Method::EncryptPartPrints), false).unwrap(), StepKind::RemakePrints);
        assert!(settled("t", &step(Method::Hash), false).is_err());
        assert!(settled("t", &step(Method::SearchPrint), false).is_err());
        assert_eq!(settled("t", &step(Method::Encrypt), false).unwrap(), StepKind::Keep);
    }

    #[test]
    fn a_table_is_planned_field_by_field_and_says_what_the_program_must_hold() {
        use Method::*;
        let old = [stored(spec(1, "a", Encrypt)), stored(spec(2, "b", EncryptFullPrint))];
        let new = [spec(1, "a", EncryptFullPrint), spec(2, "b", Encrypt), spec(3, "c", Hash)];
        let plan = plan_table("people", &old, &new).unwrap();
        let kinds: Vec<_> = plan.steps.iter().map(|s| (s.id, s.kind)).collect();
        assert_eq!(kinds, [(1, StepKind::AddPrints), (2, StepKind::DropPrints), (3, StepKind::Hash)]);
        assert!(plan.changes_rows() && !plan.new_table_id && !plan.drop_table_id);
        assert_eq!(plan.needs(), Needs { read: true, search: true, one_way: true });
        // dropping prints alone needs no key at all
        let drop = plan_table("t", &[stored(spec(1, "a", EncryptFullPrint))], &[spec(1, "a", Encrypt)]).unwrap();
        assert_eq!(drop.needs(), Needs::default());
        // a fingerprint alone needs the search key and not the read key
        let print = plan_table("t", &[], &[spec(1, "a", SearchPrint)]).unwrap();
        assert_eq!(print.needs(), Needs { read: false, search: true, one_way: true });
        // sealing needs the read key, and the search key only with fingerprints
        assert_eq!(plan_table("t", &[], &[spec(1, "a", Encrypt)]).unwrap().needs(), Needs { read: true, search: false, one_way: false });
        assert_eq!(plan_table("t", &[], &[spec(1, "a", EncryptPartPrints)]).unwrap().needs(), Needs { read: true, search: true, one_way: false });
    }

    #[test]
    fn the_identity_of_a_table_follows_its_first_and_last_protected_field() {
        let first = plan_table("t", &[], &[spec(1, "a", Method::Encrypt)]).unwrap();
        assert!(first.new_table_id && !first.drop_table_id);
        let last = plan_table("t", &[stored(spec(1, "a", Method::Encrypt))], &[]).unwrap();
        assert!(last.drop_table_id && !last.new_table_id);
        let none = plan_table("t", &[], &[]).unwrap();
        assert!(!none.changes_rows() && !none.new_table_id && !none.drop_table_id);
        let same = plan_table("t", &[stored(spec(1, "a", Method::Encrypt))], &[spec(1, "a", Method::Encrypt)]).unwrap();
        assert!(!same.changes_rows());
    }

    #[test]
    fn a_hash_cannot_be_dropped_with_the_rest_of_the_table() {
        let err = plan_table("people", &[stored(spec(1, "pw", Method::Hash))], &[]).unwrap_err().to_string();
        assert!(err.contains("people") && err.contains("pw") && err.contains("Nothing was changed"), "{err}");
    }

    #[test]
    fn declarations_that_cannot_work_are_refused_up_front() {
        let dup = [spec(1, "a", Method::Encrypt), spec(1, "b", Method::Encrypt)];
        assert!(plan_table("t", &[], &dup).is_err());
        let unset = SealedSpec { bits: 0, ..spec(1, "a", Method::EncryptPartPrints) };
        assert!(plan_table("t", &[], &[unset]).is_err());
        let no_hash = SealedSpec { hash: None, ..spec(1, "a", Method::Hash) };
        assert!(plan_table("t", &[], &[no_hash]).is_err());
        assert!(seals_value(1) && seals_value(3) && !seals_value(4) && !seals_value(5));
    }
}
