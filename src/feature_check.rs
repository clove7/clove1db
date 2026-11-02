//! The macro `#[derive(CloveFields)]` cannot see which features of `clove1db` are on. For a field
//! marked `#[clove(encrypt)]`, `hash` or `search_print` it calls this macro, which is empty with the
//! `encryption` feature and stops the build with a clear message without it.

/// Called by the code `#[derive(CloveFields)]` writes for protected fields. Not for direct use.
#[doc(hidden)]
#[macro_export]
#[cfg(feature = "encryption")]
macro_rules! __require_encryption {
    () => {};
}

/// Called by the code `#[derive(CloveFields)]` writes for protected fields. Not for direct use.
#[doc(hidden)]
#[macro_export]
#[cfg(not(feature = "encryption"))]
macro_rules! __require_encryption {
    () => {
        compile_error!(
            "enable the `encryption` feature of clove1db to use #[clove(encrypt)], hash or search_print"
        );
    };
}
