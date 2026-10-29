Typed field construction rejects these programs at compile time.

A missing field is rejected.
```compile_fail
use clove1db::CloveFields;
use serde::Serialize;
#[derive(CloveFields)] struct Note { name:String }
let _=Note::missing.eq("x");
```

A comparison uses the field value type.
```compile_fail
use clove1db::CloveFields;
use serde::Serialize;
#[derive(CloveFields)] struct Note { count:i64 }
let _=Note::count.eq("wrong");
```

Nested fields must belong to the nested type.
```compile_fail
use clove1db::CloveFields;
use serde::Serialize;
#[derive(CloveFields)] struct Child { name:String }
#[derive(CloveFields)] struct Other { name:String }
#[derive(CloveFields)] struct Note { child:Child }
let _=Note::child.then(Other::name);
```

Only lists support any.
```compile_fail
use clove1db::CloveFields;
use serde::Serialize;
#[derive(CloveFields)] struct Note { count:i64 }
let _=Note::count.any();
```

Only maps or dynamic JSON support key.
```compile_fail
use clove1db::CloveFields;
use serde::Serialize;
#[derive(CloveFields)] struct Note { count:i64 }
let _=Note::count.key("x");
```

Only text supports trim.
```compile_fail
use clove1db::CloveFields;
use serde::Serialize;
#[derive(CloveFields)] struct Note { count:i64 }
let _=Note::count.trim();
```

Custom serialization needs an explicit representation.
```compile_fail
use clove1db::CloveFields;
use serde::Serialize;
fn custom<S:serde::Serializer>(v:&i64,s:S)->Result<S::Ok,S::Error>{s.serialize_str(&v.to_string())}
#[derive(Serialize,CloveFields)] struct Note { #[serde(serialize_with="custom")] count:i64 }
```

Tuple structures have no named JSON fields.
```compile_fail
use clove1db::CloveFields;
use serde::Serialize;
#[derive(CloveFields)] struct Note(String);
```

Unit structures have no named JSON fields.
```compile_fail
use clove1db::CloveFields;
use serde::Serialize;
#[derive(CloveFields)] struct Note;
```

Skipped fields have no descriptor.
```compile_fail
use clove1db::CloveFields;
use serde::Serialize;
#[derive(CloveFields)] struct Note { #[clove(skip)] secret:String }
let _=Note::secret;
```


A custom serde module requires an explicit representation too.
```compile_fail
use clove1db::CloveFields;
use serde::Serialize;
mod custom {pub fn serialize<S:serde::Serializer>(v:&i64,s:S)->Result<S::Ok,S::Error>{s.serialize_i64(*v)}}
#[derive(Serialize,CloveFields)] struct Note {#[serde(with="custom")] n:i64}
```

Data enums without an internal tag need an explicitly declared field shape.
```compile_fail
use clove1db::CloveFields;
#[derive(CloveFields)] enum Payload { Item { n:i64 } }
```

An opaque data enum cannot silently bypass the declared stored shape.
```compile_fail
use clove1db::CloveFields;
use serde::Serialize;
#[derive(Serialize)] enum External { Item { n:i64 } }
#[derive(CloveFields)] struct Note { payload:External }
```
