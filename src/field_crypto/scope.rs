//! Marks the span in which the storage layer is encoding a row, so that a new protected value
//! may be written as a placeholder there and refused everywhere else.
use std::cell::Cell;

thread_local! {
    static DEPTH: Cell<u32> = const { Cell::new(0) };
}

/// Entered right before a row is turned into JSON and left right after, on the same thread and
/// with no await between. Dropping it ends the span, also when an error unwinds the call.
pub(crate) struct SealScope(());

impl SealScope {
    pub(crate) fn enter() -> Self {
        DEPTH.with(|d| d.set(d.get() + 1));
        SealScope(())
    }
}

impl Drop for SealScope {
    fn drop(&mut self) {
        DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
    }
}

pub(crate) fn active() -> bool {
    DEPTH.with(|d| d.get() > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_is_off_outside_and_on_inside() {
        assert!(!active());
        {
            let _outer = SealScope::enter();
            assert!(active());
            {
                let _inner = SealScope::enter();
                assert!(active());
            }
            assert!(active());
        }
        assert!(!active());
    }

    #[test]
    fn scope_ends_when_the_call_panics() {
        let result = std::panic::catch_unwind(|| {
            let _scope = SealScope::enter();
            panic!("boom");
        });
        assert!(result.is_err());
        assert!(!active());
    }
}
