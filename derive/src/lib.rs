use proc_macro::TokenStream;
use quote::quote;
use syn::{Attribute, Data, DeriveInput, Fields, LitStr, Type, parse_macro_input};
#[derive(Default)]
struct Options {
    rename: Option<String>,
    rule: Option<String>,
    skip: bool,
    flatten: bool,
    custom: bool,
    as_type: Option<Type>,
    epoch: Option<String>,
    tag: bool,
    content: bool,
    encrypt: bool,
    hash: Option<String>,
    search_print: bool,
    field_id: Option<u32>,
    print: Option<String>,
    normalize: Option<Vec<String>>,
    window: Option<u8>,
    grade: Option<String>,
    bits: Option<u8>,
}
impl Options {
    /// Whether any attribute of the protected-field family is present.
    fn protected(&self) -> bool {
        self.encrypt
            || self.hash.is_some()
            || self.search_print
            || self.field_id.is_some()
            || self.print.is_some()
            || self.normalize.is_some()
            || self.window.is_some()
            || self.grade.is_some()
            || self.bits.is_some()
    }
}
enum Slot {
    Encrypt,
    Hash,
    Print,
}
struct Protected {
    slot: Slot,
    method: proc_macro2::TokenStream,
    hash: proc_macro2::TokenStream,
    normalize: proc_macro2::TokenStream,
    id: u32,
    /// Whether the field has a whole-value fingerprint, so its constant is a search handle.
    handle: bool,
    /// For `print = "parts"`: the length of a part and the bits kept of its fingerprint; 0 otherwise.
    window: u8,
    bits: u8,
}
/// Resolves the protection attributes of one field, or rejects an impossible combination.
fn protection(o: &Options, f: &syn::Field) -> syn::Result<Option<Protected>> {
    if !o.protected() {
        return Ok(None);
    }
    let bad = |m: &str| Err(syn::Error::new_spanned(f, m));
    let chosen = u8::from(o.encrypt) + u8::from(o.hash.is_some()) + u8::from(o.search_print);
    if chosen == 0 {
        return bad("`id` and `print` need one of `encrypt`, `hash = \"..\"` or `search_print`");
    }
    if chosen > 1 {
        return bad("a field has exactly one protection method: `encrypt`, `hash = \"..\"` or `search_print`");
    }
    if o.skip {
        return bad("a protected field cannot also be `clove(skip)` or `serde(skip)`");
    }
    if o.flatten {
        return bad("a protected field cannot be flattened");
    }
    if o.custom {
        return bad("a protected field cannot use a custom serde representation");
    }
    if o.as_type.is_some() || o.epoch.is_some() {
        return bad("`as` and `epoch` cannot be combined with a protection method");
    }
    let Some(id) = o.field_id else {
        return bad("a protected field needs a stable number: `id = N`");
    };
    if o.print.is_some() && !o.encrypt {
        return bad("`print` is only valid together with `encrypt`");
    }
    if o.normalize.is_some() && !(o.search_print || (o.encrypt && o.print.is_some())) {
        return bad("`normalize` is only valid together with `search_print` or with `encrypt` and `print`");
    }
    let parts = o.encrypt && o.print.as_deref() == Some("parts");
    if (o.window.is_some() || o.grade.is_some() || o.bits.is_some()) && !parts {
        return bad("`window`, `grade` and `bits` are only valid with `encrypt` and `print = \"parts\"`");
    }
    if o.grade.is_some() && o.bits.is_some() {
        return bad("`grade` and `bits` both set how many bits of a part's fingerprint are kept: use one");
    }
    let window = if parts { o.window.unwrap_or(3) } else { 0 };
    // The grades keep 64, 12 and 8 bits; `bits` sets the number directly.
    let bits = if parts {
        match (o.bits, o.grade.as_deref()) {
            (Some(bits), _) => bits,
            (None, Some("fast")) => 64,
            (None, Some("protected")) => 8,
            _ => 12,
        }
    } else {
        0
    };
    let normalize = {
        let kinds = o.normalize.iter().flatten().map(|name| {
            let ident = syn::Ident::new(
                match name.as_str() {
                    "trim" => "Trim",
                    "lowercase" => "Lowercase",
                    _ => "NormalizeArabic",
                },
                proc_macro2::Span::call_site(),
            );
            quote!(::clove1db::fields::TransformKind::#ident)
        });
        quote!(&[#(#kinds),*])
    };
    let m = |name: &str| {
        let ident = syn::Ident::new(name, proc_macro2::Span::call_site());
        quote!(::clove1db::field_crypto::Method::#ident)
    };
    let none = quote!(::core::option::Option::None);
    let algo = |name: &str| {
        let ident = syn::Ident::new(name, proc_macro2::Span::call_site());
        quote!(::core::option::Option::Some(::clove1db::field_crypto::HashAlgo::#ident))
    };
    Ok(Some(if o.encrypt {
        let method = match o.print.as_deref() {
            None => m("Encrypt"),
            Some("full") => m("EncryptFullPrint"),
            _ => m("EncryptPartPrints"),
        };
        Protected { slot: Slot::Encrypt, method, hash: none, normalize, id, handle: o.print.is_some(), window, bits }
    } else if let Some(kind) = &o.hash {
        let hash = if kind == "argon2id" { algo("Argon2id") } else { algo("Scrypt") };
        Protected { slot: Slot::Hash, method: m("Hash"), hash, normalize, id, handle: false, window, bits }
    } else {
        Protected { slot: Slot::Print, method: m("SearchPrint"), hash: none, normalize, id, handle: true, window, bits }
    }))
}
fn ignore(meta: syn::meta::ParseNestedMeta<'_>) -> syn::Result<()> {
    if meta.input.peek(syn::Token![=]) {
        let _: syn::Expr = meta.value()?.parse()?;
    } else if meta.input.peek(syn::token::Paren) {
        meta.parse_nested_meta(ignore)?;
    }
    Ok(())
}
fn options(attrs: &[Attribute]) -> syn::Result<Options> {
    let mut out = Options::default();
    for attr in attrs {
        if attr.path().is_ident("serde") {
            attr.parse_nested_meta(|m| {
                if m.path.is_ident("rename") || m.path.is_ident("rename_all") {
                    let mut value = None;
                    if m.input.peek(syn::Token![=]) {
                        value = Some(m.value()?.parse::<LitStr>()?.value());
                    } else {
                        m.parse_nested_meta(|n| {
                            let v = n.value()?.parse::<LitStr>()?.value();
                            if n.path.is_ident("serialize") {
                                value = Some(v);
                            }
                            Ok(())
                        })?;
                    }
                    if m.path.is_ident("rename") {
                        out.rename = value;
                    } else {
                        out.rule = value;
                    }
                } else if m.path.is_ident("skip") || m.path.is_ident("skip_serializing") {
                    out.skip = true;
                } else if m.path.is_ident("flatten") {
                    out.flatten = true;
                } else if m.path.is_ident("tag") {
                    out.tag = true;
                    ignore(m)?;
                } else if m.path.is_ident("content") {
                    out.content = true;
                    ignore(m)?;
                } else if m.path.is_ident("serialize_with")
                    || m.path.is_ident("with")
                    || m.path.is_ident("serialize")
                {
                    out.custom = true;
                    ignore(m)?;
                } else {
                    ignore(m)?;
                }
                Ok(())
            })?;
        }
        if attr.path().is_ident("clove") {
            attr.parse_nested_meta(|m| {
                if m.path.is_ident("skip") {
                    out.skip = true;
                } else if m.path.is_ident("as") {
                    out.as_type = Some(m.value()?.parse()?);
                } else if m.path.is_ident("epoch") {
                    let value = m.value()?.parse::<LitStr>()?.value();
                    if value != "s" && value != "ms" {
                        return Err(m.error("epoch must be s or ms"));
                    }
                    out.epoch = Some(value);
                } else if m.path.is_ident("encrypt") {
                    out.encrypt = true;
                } else if m.path.is_ident("search_print") {
                    out.search_print = true;
                } else if m.path.is_ident("hash") {
                    let value = m.value()?.parse::<LitStr>()?.value();
                    if value != "argon2id" && value != "scrypt" {
                        return Err(m.error("hash must be \"argon2id\" or \"scrypt\""));
                    }
                    out.hash = Some(value);
                } else if m.path.is_ident("normalize") {
                    let value = m.value()?.parse::<LitStr>()?.value();
                    let mut kinds = Vec::new();
                    for part in value.split(',').map(str::trim) {
                        if !["trim", "lowercase", "arabic"].contains(&part) {
                            return Err(m.error("normalize is a comma list of \"trim\", \"lowercase\", \"arabic\""));
                        }
                        kinds.push(part.to_string());
                    }
                    out.normalize = Some(kinds);
                } else if m.path.is_ident("window") {
                    let number: syn::LitInt = m.value()?.parse()?;
                    let window = number.base10_parse::<u8>()?;
                    if !(1..=8).contains(&window) {
                        return Err(m.error("window is a number of characters from 1 to 8"));
                    }
                    out.window = Some(window);
                } else if m.path.is_ident("bits") {
                    let number: syn::LitInt = m.value()?.parse()?;
                    let bits = number.base10_parse::<u8>()?;
                    if !(4..=64).contains(&bits) {
                        return Err(m.error("bits is a number from 4 to 64"));
                    }
                    out.bits = Some(bits);
                } else if m.path.is_ident("grade") {
                    let value = m.value()?.parse::<LitStr>()?.value();
                    if !["fast", "balanced", "protected"].contains(&value.as_str()) {
                        return Err(m.error("grade is \"fast\", \"balanced\" or \"protected\""));
                    }
                    out.grade = Some(value);
                } else if m.path.is_ident("print") {
                    let value = m.value()?.parse::<LitStr>()?.value();
                    if value != "full" && value != "parts" {
                        return Err(m.error("print must be \"full\" or \"parts\""));
                    }
                    out.print = Some(value);
                } else if m.path.is_ident("id") {
                    let number: syn::LitInt = m.value()?.parse()?;
                    out.field_id = Some(number.base10_parse::<u32>()?);
                } else {
                    return Err(m.error("unknown clove attribute"));
                }
                Ok(())
            })?;
        }
    }
    Ok(out)
}
fn renamed(name: &str, rule: &str) -> syn::Result<String> {
    let pascal = || {
        let mut out = String::new();
        let mut upper = true;
        for c in name.chars() {
            if c == '_' {
                upper = true;
            } else {
                out.push(if upper { c.to_ascii_uppercase() } else { c });
                upper = false;
            }
        }
        out
    };
    Ok(match rule {
        "" | "lowercase" | "snake_case" => name.into(),
        "UPPERCASE" | "SCREAMING_SNAKE_CASE" => name.to_ascii_uppercase(),
        "PascalCase" => pascal(),
        "camelCase" => {
            let mut v = pascal();
            if let Some(first) = v.get_mut(..1) {
                first.make_ascii_lowercase();
            }
            v
        }
        "kebab-case" => name.replace('_', "-"),
        "SCREAMING-KEBAB-CASE" => name.to_ascii_uppercase().replace('_', "-"),
        _ => {
            return Err(syn::Error::new(
                proc_macro2::Span::call_site(),
                "unknown serde rename_all rule",
            ));
        }
    })
}
fn value_type(ty: &Type) -> Type {
    let Type::Path(path) = ty else {
        return ty.clone();
    };
    let Some(last) = path.path.segments.last() else {
        return ty.clone();
    };
    let name = last.ident.to_string();
    if name == "Option"
        && let syn::PathArguments::AngleBracketed(args) = &last.arguments
        && let Some(syn::GenericArgument::Type(inner)) = args.args.first()
    {
        return value_type(inner);
    }
    if ["DateTime", "NaiveDate", "NaiveDateTime"].contains(&name.as_str()) {
        return syn::parse_quote!(::clove1db::fields::Time);
    }
    let mut mapped = path.clone();
    if let Some(last) = mapped.path.segments.last_mut()
        && let syn::PathArguments::AngleBracketed(args) = &mut last.arguments
    {
        for arg in &mut args.args {
            if let syn::GenericArgument::Type(ty) = arg {
                *ty = value_type(ty);
            }
        }
    }
    Type::Path(mapped)
}

fn expand(input: DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let opts = options(&input.attrs)?;
    let name = &input.ident;
    let mut generics = input.generics.clone();
    for parameter in generics.type_params_mut() {
        parameter
            .bounds
            .push(syn::parse_quote!(::clove1db::fields::CloveFields));
    }
    let (ig, tg, wc) = generics.split_for_impl();
    let fields = match &input.data {
        Data::Struct(s) => match &s.fields {
            Fields::Named(n) => &n.named,
            _ => {
                return Err(syn::Error::new_spanned(
                    name,
                    "CloveFields requires a named-field struct; tuple and unit structs are unsupported",
                ));
            }
        },
        Data::Enum(e) => {
            let tagged = opts.tag && !opts.content;
            if !tagged && e.variants.iter().any(|v| !matches!(v.fields, Fields::Unit)) {
                return Err(syn::Error::new_spanned(
                    name,
                    "data enums require an internal serde tag; use clove(as = Type) or clove(skip) on the field",
                ));
            }
            let mut shapes = Vec::new();
            for variant in &e.variants {
                if options(&variant.attrs)?.skip {
                    continue;
                }
                for field in &variant.fields {
                    let settings = options(&field.attrs)?;
                    if settings.protected() {
                        return Err(syn::Error::new_spanned(
                            field,
                            "protected fields are supported on structs only",
                        ));
                    }
                    if settings.skip {
                        continue;
                    }
                    if settings.custom && settings.as_type.is_none() {
                        return Err(syn::Error::new_spanned(
                            field,
                            "custom serialization requires clove(skip) or clove(as = Type)",
                        ));
                    }
                    shapes.push(value_type(settings.as_type.as_ref().unwrap_or(&field.ty)));
                }
            }
            return Ok(
                quote!(impl #ig ::clove1db::fields::CloveFields for #name #tg #wc {
                    const CHECK_FIELDS: () = { fn check<T: ::clove1db::fields::CloveFields>() {} #(let _=check::<#shapes>;)* };
                }),
            );
        }
        _ => {
            return Err(syn::Error::new_spanned(
                name,
                "CloveFields does not support unions",
            ));
        }
    };
    let mut constants = Vec::new();
    let mut shapes = Vec::new();
    let mut sealed: Vec<(syn::Ident, String, Protected)> = Vec::new();
    for f in fields {
        let o = options(&f.attrs)?;
        let protected = protection(&o, f)?;
        if o.skip && protected.is_none() {
            continue;
        }
        if (o.custom || opts.custom) && o.as_type.is_none() {
            return Err(syn::Error::new_spanned(
                f,
                "custom serialization requires #[clove(skip)] or #[clove(as = Type)]",
            ));
        }
        let ident = f.ident.as_ref().unwrap();
        let original = ident.to_string().trim_start_matches("r#").to_string();
        let path = if o.flatten {
            String::new()
        } else if let Some(v) = o.rename {
            v
        } else {
            renamed(&original, opts.rule.as_deref().unwrap_or(""))?
        };
        let mut handle = None;
        // A protected field with no fingerprint cannot be searched: a sealed one can be scanned (`scan_sealed`), a
        // verification hash can only be verified. Neither has an ordinary field's `eq` and the rest, so a search
        // on one does not compile.
        let mut closed: Option<(u32, bool)> = None;
        if let Some(p) = protected {
            if sealed.iter().any(|(_, _, q)| q.id == p.id) {
                return Err(syn::Error::new_spanned(
                    f,
                    "two protected fields use the same `id`",
                ));
            }
            if p.handle {
                handle = Some((p.id, p.method.clone(), p.normalize.clone(), p.window, p.bits, matches!(p.slot, Slot::Encrypt)));
            } else {
                closed = Some((p.id, matches!(p.slot, Slot::Hash)));
            }
            sealed.push((ident.clone(), path.clone(), p));
        }
        let ty = value_type(o.as_type.as_ref().unwrap_or(&f.ty));
        shapes.push(ty.clone());
        let raw = quote!(#ty).to_string();
        let original_ty = o.as_type.as_ref().unwrap_or(&f.ty);
        let actual = quote!(#original_ty).to_string();
        let kind = match o.epoch.as_deref() {
            Some("s") => quote!(EpochSeconds),
            Some("ms") => quote!(EpochMillis),
            _ => {
                if raw.contains("fields :: Time") {
                    if actual.contains("NaiveDateTime") {
                        quote!(NaiveDateTime)
                    } else if actual.contains("NaiveDate") {
                        quote!(Date)
                    } else {
                        quote!(DateTime)
                    }
                } else {
                    quote!(Auto)
                }
            }
        };
        let init = if o.flatten {
            quote!(::clove1db::fields::Field::flattened(::clove1db::fields::ValueKind::#kind))
        } else {
            quote!(::clove1db::fields::Field::new(#path,::clove1db::fields::ValueKind::#kind))
        };
        if let Some((id, method, normalize, window, bits, sealed_text)) = handle {
            // A field with a whole-value fingerprint is searched through a handle and a search
            // grant, not through an ordinary field: it has no `eq` of its own. The handle also knows
            // how to look at the sealed text of the field in an entity, to confirm a search by parts.
            let view = if sealed_text {
                quote!(|e: &Self| e.#ident.closed_view())
            } else {
                quote!(|_e: &Self| ::core::option::Option::None)
            };
            constants.push(quote!(#[allow(non_upper_case_globals)] pub const #ident: ::clove1db::field_crypto::PrintHandle<Self> = ::clove1db::field_crypto::PrintHandle::new(#path, #id, #method, #normalize, #window, #bits, #view);));
        } else if let Some((id, is_hash)) = closed {
            if is_hash {
                constants.push(quote!(#[allow(non_upper_case_globals)] pub const #ident: ::clove1db::field_crypto::HashHandle<Self> = ::clove1db::field_crypto::HashHandle::new(#path, #id);));
            } else {
                constants.push(quote!(#[allow(non_upper_case_globals)] pub const #ident: ::clove1db::field_crypto::ScanHandle<Self> = ::clove1db::field_crypto::ScanHandle::new(#path, #id, |e: &Self| e.#ident.closed_view());));
            }
        } else {
            constants.push(quote!(#[allow(non_upper_case_globals)] pub const #ident: ::clove1db::fields::Field<Self,#ty> =  #init;));
        }
    }
    let protected_impl = if sealed.is_empty() {
        quote!()
    } else {
        let specs = sealed.iter().map(|(_, key, p)| {
            let (id, method, hash, normalize) = (p.id, &p.method, &p.hash, &p.normalize);
            let (window, bits) = (p.window, p.bits);
            quote!(::clove1db::field_crypto::SealedSpec { id: #id, key: #key, method: #method, hash: #hash, normalize: #normalize, window: #window, bits: #bits })
        });
        let slot = |p: &Protected| match p.slot {
            Slot::Encrypt => quote!(::clove1db::field_crypto::EncryptSlot),
            Slot::Hash => quote!(::clove1db::field_crypto::HashSlot),
            Slot::Print => quote!(::clove1db::field_crypto::PrintSlot),
        };
        let binds = sealed.iter().map(|(ident, key, p)| {
            let (id, slot) = (p.id, slot(p));
            let (hash, normalize) = (&p.hash, &p.normalize);
            quote!(#slot::bind(&mut self.#ident, row.field_named(#id, #key).with_hash(#hash).with_normalize(#normalize));)
        });
        let parts = sealed.iter().map(|(ident, _, p)| {
            let slot = slot(p);
            quote!(#slot::part(&self.#ident)?)
        });
        quote!(impl #ig ::clove1db::field_crypto::SealedFields for #name #tg #wc {
            const SEALED: &'static [::clove1db::field_crypto::SealedSpec] = &[#(#specs),*];
            fn bind_sealed(&mut self, row: &::clove1db::field_crypto::RowBinding) {
                #(#binds)*
            }
            fn sealed_parts(&self) -> ::clove1db::units::Result<::std::vec::Vec<::clove1db::field_crypto::Part<'_>>> {
                ::core::result::Result::Ok(::std::vec![#(#parts),*])
            }
        })
    };
    // A protected field needs the `encryption` feature of clove1db, which this macro cannot see:
    // clove1db's own macro stops the build with a clear message when the feature is off.
    let require_encryption = if sealed.is_empty() {
        quote!()
    } else {
        quote!(::clove1db::__require_encryption!();)
    };
    Ok(
        quote!(#require_encryption impl #ig ::clove1db::fields::CloveFields for #name #tg #wc {
        const CHECK_FIELDS: () = { fn check<T: ::clove1db::fields::CloveFields>() {} #(let _=check::<#shapes>;)* };
    } impl #ig #name #tg #wc {#(#constants)*} #protected_impl),
    )
}
#[proc_macro_derive(CloveFields, attributes(serde, clove))]
pub fn derive_fields(input: TokenStream) -> TokenStream {
    match expand(parse_macro_input!(input as DeriveInput)) {
        Ok(v) => v.into(),
        Err(e) => e.into_compile_error().into(),
    }
}
