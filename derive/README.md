# clove1db-derive

The derive macro of [clove1db](https://github.com/clove7/clove1db), an embedded database framework for Rust built on redb.

`#[derive(CloveFields)]` generates, for each stored field of a struct, a typed constant that queries and indexes use, and the sealing code for fields marked `#[clove(encrypt)]`.

Do not depend on this crate directly. Use it through `clove1db` by enabling its `derive` feature:

```toml
clove1db = { version = "0.1", features = ["derive"] }
```

Licensed under the MIT license.
