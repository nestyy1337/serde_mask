use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{DeriveInput, ItemStruct};
use syn::{parse_macro_input, parse_quote};

#[proc_macro_attribute]
pub fn anonymize(_args: TokenStream, input: TokenStream) -> proc_macro::TokenStream {
    let ast = parse_macro_input!(input as ItemStruct);
    expand_anonymize(ast)
        .unwrap_or_else(|e| e.to_compile_error().into())
        .into()
}

#[derive(Debug)]
enum SupportedType {
    String,
    Signed,
    Unsigned,
    Option(Box<SupportedType>),
    Vec(Box<SupportedType>),
    HashMap(Box<SupportedType>, Box<SupportedType>),
}

impl SupportedType {
    fn is_dynamic(&self) -> bool {
        match self {
            SupportedType::Vec(_) => true,
            SupportedType::HashMap(_, _) => true,
            SupportedType::Option(inner) => inner.is_dynamic(),
            _ => false,
        }
    }

    fn is_anonymizable(&self) -> bool {
        match self {
            SupportedType::String => true,
            SupportedType::Signed => true,
            SupportedType::Unsigned => true,
            SupportedType::Option(inner) => inner.is_anonymizable(),
            SupportedType::Vec(inner) => inner.is_anonymizable(),
            SupportedType::HashMap(inner_k, inner_v) => {
                inner_k.is_anonymizable() && inner_v.is_anonymizable()
            }
        }
    }
}

fn generate_default_init(
    field_name: &syn::Ident,
    field_type: &SupportedType,
    index: usize,
    config: &AnonConfig,
) -> proc_macro2::TokenStream {
    match field_type {
        SupportedType::String => {
            if let Some(pattern) = &config.pattern {
                quote! { #pattern.to_string() }
            } else {
                quote! {
                    format!("ANON_{}_{}_{}",
                        stringify!(#field_name),
                        #index,
                        fastrand::usize(100000..999999)
                    )
                }
            }
        }
        SupportedType::Unsigned => {
            let (min, max) = config.range.unwrap_or((100, 999));
            let (min, max) = (
                usize::try_from(min).expect("Invalid minimum for unsigned type"),
                usize::try_from(max).expect("Invalid maximum for unsigned type"),
            );
            quote! {
                format!("ANON_{}_{}",
                    stringify!(#field_name),
                    fastrand::usize(#min..#max)
                )
            }
        }
        SupportedType::Signed => {
            let (min, max) = config.range.unwrap_or((-99, 99));
            quote! {
                format!("ANON_{}_{}",
                    stringify!(#field_name),
                    fastrand::isize(#min as isize..#max as isize)
                )
            }
        }
        SupportedType::Option(inner_type) => {
            let inner_init = generate_default_init(field_name, inner_type, index, config);
            quote! { Some(#inner_init) }
        }
        SupportedType::Vec(_) => {
            quote! { vec![] }
        }
        SupportedType::HashMap(_, _) => {
            quote! { std::collections::HashMap::new() }
        }
    }
}

fn generate_value_to_string(
    var_name: &proc_macro2::Ident,
    ty: &SupportedType,
) -> syn::Result<proc_macro2::TokenStream> {
    match ty {
        SupportedType::String | SupportedType::Signed | SupportedType::Unsigned => {
            Ok(quote! { #var_name.to_string() })
        }
        SupportedType::Option(inner) => match **inner {
            SupportedType::String | SupportedType::Signed | SupportedType::Unsigned => {
                Ok(quote! { #var_name.as_ref().map(|v| v.to_string()) })
            }
            _ => Err(syn::Error::new_spanned(
                var_name,
                "Nested Option not supported in deanonymization",
            )),
        },
        SupportedType::Vec(_) => Err(syn::Error::new_spanned(
            var_name,
            "Vec inside patterns not supported",
        )),
        SupportedType::HashMap(_, _) => Err(syn::Error::new_spanned(
            var_name,
            "HashMap inside patterns not supported",
        )),
    }
}

fn generate_option_value_to_string(
    var_name: &proc_macro2::Ident,
    ty: &SupportedType,
) -> syn::Result<proc_macro2::TokenStream> {
    match ty {
        SupportedType::String | SupportedType::Signed | SupportedType::Unsigned => {
            Ok(quote! { #var_name.clone().unwrap().to_string() })
        }
        SupportedType::Option(inner) => match **inner {
            SupportedType::String | SupportedType::Signed | SupportedType::Unsigned => {
                Ok(quote! { #var_name.as_ref().map(|v| v.to_string()) })
            }
            _ => Err(syn::Error::new_spanned(
                var_name,
                "Nested Option not supported in deanonymization",
            )),
        },
        SupportedType::Vec(_) => Err(syn::Error::new_spanned(
            var_name,
            "Vec inside patterns not supported",
        )),
        SupportedType::HashMap(_, _) => Err(syn::Error::new_spanned(
            var_name,
            "HashMap inside patterns not supported",
        )),
    }
}

fn generate_prepare_logic(
    field: &syn::Field,
    index: usize,
    config: &AnonConfig,
) -> proc_macro2::TokenStream {
    let field_type = is_type(&field.ty).expect("Failed to determine field type");
    let name = field.ident.as_ref().expect("Field must have an identifier");

    println!("Matching on field type: {:?}", field_type);
    match field_type {
        SupportedType::Vec(inner) => {
            match inner.as_ref() {
                SupportedType::Option(_) => {
                    // For Vec<Option<T>>, preserve None values
                    let element = generate_default_init(name, &*inner, index, config);
                    quote! {
                        state.#name = self.#name.iter()
                            .map(|v| if v.is_some() { #element } else { None })
                            .collect();
                    }
                }
                _ => {
                    let element = generate_default_init(name, &*inner, index, config);
                    quote! {
                        state.#name = self.#name.iter().map(|_| #element).collect();
                    }
                }
            }
        }
        SupportedType::HashMap(key_type, value_type) => {
            let key_init = generate_default_init(name, &*key_type, index, config);
            let value_init = generate_default_init(name, &*value_type, index, config);
            quote! {
                state.#name = self.#name.iter()
                    .map(|(_k, _v)| (#key_init, #value_init))
                    .collect();
            }
        }
        SupportedType::Option(inner) => {
            let inner_init = generate_default_init(name, &*inner, index, config);
            quote! {
                    if self.#name.is_some() {
                        state.#name = Some(#inner_init);
                }
            }
        }
        _ => quote! {},
    }
}

#[derive(Default)]
struct AnonConfig {
    range: Option<(isize, isize)>,
    pattern: Option<String>,
}

#[derive(Default)]
struct SerdeConfig {
    rename: Option<String>,
    skip: bool,
    skip_serializing: bool,
}

fn parse_serde_attr(field: &syn::Field) -> SerdeConfig {
    let mut config = SerdeConfig::default();

    for attr in &field.attrs {
        if !attr.path().is_ident("serde") {
            continue;
        }

        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("rename") {
                if let Ok(value) = meta.value() {
                    if let Ok(lit) = value.parse::<syn::LitStr>() {
                        config.rename = Some(lit.value());
                    }
                }
            } else if meta.path.is_ident("skip") {
                config.skip = true;
            } else if meta.path.is_ident("skip_serializing") {
                config.skip_serializing = true;
            }
            Ok(())
        });
    }

    config
}

fn parse_anon_attr(attr: &syn::Attribute) -> syn::Result<AnonConfig> {
    let mut config = AnonConfig::default();

    if let syn::Meta::Path(_) = &attr.meta {
        return Ok(config);
    }

    // Parse #[anon(key = "value", ...)]
    if let syn::Meta::List(_) = &attr.meta {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("range") {
                let value: syn::LitStr = meta.value()?.parse()?;

                let range_str = value.value();
                let parts: Vec<&str> = range_str.split("..").collect();
                if parts.len() == 2 {
                    let min = parts[0]
                        .parse()
                        .map_err(|_| syn::Error::new_spanned(&value, "Invalid range minimum"))?;
                    let max = parts[1]
                        .parse()
                        .map_err(|_| syn::Error::new_spanned(&value, "Invalid range maximum"))?;
                    config.range = Some((min, max));
                }
                Ok(())
            } else if meta.path.is_ident("pattern") {
                let value: syn::LitStr = meta.value()?.parse()?;
                config.pattern = Some(value.value());
                Ok(())
            } else {
                Err(meta.error("unsupported attribute argument"))
            }
        })?;
    }

    Ok(config)
}

fn is_type(ty: &syn::Type) -> Result<SupportedType, syn::Error> {
    println!("is_type called with type: {:?}", ty);
    match ty {
        syn::Type::Path(type_path) => {
            let segment = &type_path.path.segments.last().ok_or_else(|| {
                syn::Error::new_spanned(ty, "Expected a type path with at least one segment")
            })?;
            match segment.ident.to_string().as_str() {
                "String" => Ok(SupportedType::String),
                "isize" => Ok(SupportedType::Signed),
                "i8" => Ok(SupportedType::Signed),
                "i16" => Ok(SupportedType::Signed),
                "i32" => Ok(SupportedType::Signed),
                "i64" => Ok(SupportedType::Signed),
                "usize" => Ok(SupportedType::Unsigned),
                "u8" => Ok(SupportedType::Unsigned),
                "u16" => Ok(SupportedType::Unsigned),
                "u32" => Ok(SupportedType::Unsigned),
                "u64" => Ok(SupportedType::Unsigned),
                "Vec" => {
                    if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                        if let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first() {
                            let inner_type = is_type(inner_ty)?;
                            Ok(SupportedType::Vec(Box::new(inner_type)))
                        } else {
                            Err(syn::Error::new_spanned(
                                ty,
                                "Unsupported type for anonymization",
                            ))
                        }
                    } else {
                        Err(syn::Error::new_spanned(
                            ty,
                            "Unsupported type for anonymization",
                        ))
                    }
                }
                "Option" => {
                    if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                        if let Some(syn::GenericArgument::Type(inner_ty)) = args.args.first() {
                            let inner_type = is_type(inner_ty)?;
                            Ok(SupportedType::Option(Box::new(inner_type)))
                        } else {
                            Err(syn::Error::new_spanned(
                                ty,
                                "Unsupported type for anonymization",
                            ))
                        }
                    } else {
                        Err(syn::Error::new_spanned(
                            ty,
                            "Unsupported type for anonymization",
                        ))
                    }
                }
                "HashMap" => {
                    if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                        let mut args_iter = args.args.iter();
                        if let (
                            Some(syn::GenericArgument::Type(key_ty)),
                            Some(syn::GenericArgument::Type(value_ty)),
                        ) = (args_iter.next(), args_iter.next())
                        {
                            let key_type = is_type(key_ty)?;
                            let value_type = is_type(value_ty)?;
                            Ok(SupportedType::HashMap(
                                Box::new(key_type),
                                Box::new(value_type),
                            ))
                        } else {
                            Err(syn::Error::new_spanned(
                                ty,
                                "Unsupported type for anonymization",
                            ))
                        }
                    } else {
                        Err(syn::Error::new_spanned(
                            ty,
                            "Unsupported type for anonymization",
                        ))
                    }
                }

                _ => Err(syn::Error::new_spanned(
                    ty,
                    "Unsupported type for anonymization",
                )),
            }
        }
        _ => Err(syn::Error::new_spanned(
            ty,
            "Unsupported type for anonymization",
        )),
    }
}

fn stringified_type(ty: &syn::Type) -> syn::Result<syn::Type> {
    let field_type = is_type(ty)?;
    Ok(match field_type {
        SupportedType::String => parse_quote! { String },
        SupportedType::Signed | SupportedType::Unsigned => parse_quote! { String },
        SupportedType::Option(inner) => {
            let inner_str = stringified_type_from_supported(&*inner)?;
            parse_quote! { Option<#inner_str> }
        }
        SupportedType::Vec(inner) => {
            let inner_str = stringified_type_from_supported(&*inner)?;
            parse_quote! { Vec<#inner_str> }
        }
        SupportedType::HashMap(k, v) => {
            let key_str = stringified_type_from_supported(&*k)?;
            let val_str = stringified_type_from_supported(&*v)?;
            parse_quote! { std::collections::HashMap<#key_str, #val_str> }
        }
    })
}

fn stringified_type_from_supported(ty: &SupportedType) -> syn::Result<syn::Type> {
    Ok(match ty {
        SupportedType::String => parse_quote! { String },
        SupportedType::Signed | SupportedType::Unsigned => parse_quote! { String },
        SupportedType::Option(inner) => {
            let inner_str = stringified_type_from_supported(&*inner)?;
            parse_quote! { Option<#inner_str> }
        }
        SupportedType::Vec(inner) => {
            let inner_str = stringified_type_from_supported(&*inner)?;
            parse_quote! { Vec<#inner_str> }
        }
        SupportedType::HashMap(k, v) => {
            let key_str = stringified_type_from_supported(&*k)?;
            let val_str = stringified_type_from_supported(&*v)?;
            parse_quote! { std::collections::HashMap<#key_str, #val_str> }
        }
    })
}

fn expand_anonymize(mut ast: ItemStruct) -> syn::Result<proc_macro::TokenStream> {
    // let generics = ast.generics.clone();
    // let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let to_anonymize = &ast
        .fields
        .iter()
        .filter_map(|f| {
            if f.attrs.iter().any(|attr| attr.path().is_ident("anon")) {
                // Conversion to stringified type is needed, since aho_corasick works with strings
                // for a type like usize a pattern would be for example '47', given another field
                // has a substring '47' in it, it would replace it with the anonymized value
                // breaking the matching logic for deanonymization.
                let stringified_ty = stringified_type(&f.ty).ok()?;
                let field = syn::Field {
                    attrs: vec![],
                    vis: f.vis.clone(),
                    mutability: f.mutability.clone(),
                    ident: f.ident.clone(),
                    colon_token: f.colon_token,
                    ty: stringified_ty,
                };
                Some(field)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let struct_name = format_ident!("__state_{}", ast.ident);
    let anonymized_fields = ast
        .fields
        .iter()
        .enumerate()
        .filter_map(|(i, f)| {
            let anon_attr = f.attrs.iter().find(|attr| attr.path().is_ident("anon"))?;
            let config = parse_anon_attr(anon_attr).ok()?;
            let field_type = is_type(&f.ty).ok()?;
            let name = f.ident.as_ref()?;
            let init = generate_default_init(name, &field_type, i, &config);
            Some(quote! { #name: #init })
        })
        .collect::<Vec<_>>();

    let state_struct: ItemStruct = parse_quote! {
        #[derive(Debug)]
        #[allow(non_camel_case_types)]
        struct #struct_name {
            #(#to_anonymize),*
        }

    };

    let state_impls = quote! {
        impl std::default::Default for #struct_name {
            fn default() -> Self {
                Self {
                    #(#anonymized_fields),*
                }
            }
        }
    };

    let mut fields = ast.fields.clone();
    if let syn::Fields::Named(syn::FieldsNamed { ref mut named, .. }) = fields {
        let field: syn::Field = parse_quote! { __state: std::sync::OnceLock<#struct_name> };
        named.push(field);
    }
    ast.fields = fields;

    let result = quote! { #ast
        #state_struct
        #state_impls
    };

    Ok(result.into())
}

#[proc_macro_derive(Anonymize, attributes(anon, serde))]
pub fn derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);

    return expand_macro(ast)
        .unwrap_or_else(|e| e.to_compile_error().into())
        .into();
}

fn inner_state(fields_named: &syn::FieldsNamed) -> Option<syn::Field> {
    fields_named
        .named
        .iter()
        .find(|f| {
            if let Some(ident) = &f.ident {
                if ident.to_string().starts_with("__state") {
                    true
                } else {
                    false
                }
            } else {
                false
            }
        })
        .cloned()
}

fn filter_serde_attrs(field: &syn::Field) -> bool {
    if let Some(field_name) = &field.ident {
        if field_name.to_string().starts_with("__state") {
            return true;
        }
    }

    // Parse serde attributes
    let serde_config = parse_serde_attr(field);

    // Skip if marked with #[serde(skip)] or #[serde(skip_serializing)]
    if serde_config.skip || serde_config.skip_serializing {
        return true;
    }
    return false;
}

fn serialize_field(field: &syn::Field, is_anon: bool) -> syn::Result<proc_macro2::TokenStream> {
    let field_name = field
        .ident
        .as_ref()
        .ok_or_else(|| syn::Error::new_spanned(field, "Expected named fields for serialization"))?;
    let serde_config = parse_serde_attr(field);

    // Use renamed field name if specified
    let serialize_name = serde_config
        .rename
        .as_ref()
        .map(|s| quote! { #s })
        .unwrap_or_else(|| quote! { stringify!(#field_name) });

    if is_anon {
        Ok(quote! {
            state.serialize_field(#serialize_name, &anon.#field_name)?;
        })
    } else {
        Ok(quote! {
            state.serialize_field(#serialize_name, &self.#field_name)?;
        })
    }
}

fn expand_macro(ast: DeriveInput) -> syn::Result<proc_macro::TokenStream> {
    let name = &ast.ident;
    let generics = ast.generics.clone();
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    match &ast.data {
        syn::Data::Struct(data_struct) => {
            if let syn::Fields::Named(fields_named) = &data_struct.fields {
                if let Some(_state_field) = inner_state(fields_named) {
                    let filtered_fields = fields_named
                        .named
                        .iter()
                        .filter(|f| !filter_serde_attrs(f))
                        .collect::<Vec<_>>();

                    let field_serializers = filtered_fields
                        .iter()
                        .map(|f| {
                            serialize_field(
                                &f,
                                f.attrs.iter().any(|attr| attr.path().is_ident("anon")),
                            )
                        })
                        .collect::<syn::Result<Vec<_>>>()?;

                    let field_count = filtered_fields
                        .iter()
                        .filter(|f| {
                            !f.ident
                                .as_ref()
                                .expect("only named fields supported")
                                .to_string()
                                .starts_with("__state")
                        })
                        .count();
                    let state_name = format_ident!("__state_{}", name);

                    let anon_fields = filtered_fields
                        .iter()
                        .filter(|f| f.attrs.iter().any(|attr| attr.path().is_ident("anon")))
                        .collect::<Vec<_>>();
                    let mut patterns_and_replacements: Vec<proc_macro2::TokenStream> = vec![];
                    for f in &anon_fields {
                        let fname = f.ident.as_ref().expect("Field must have an ident");
                        let field_type = is_type(&f.ty)?;

                        if !field_type.is_anonymizable() {
                            continue;
                        }

                        let pattern = match &field_type {
                            SupportedType::Vec(inner) => {
                                let anon_ident = format_ident!("anon");
                                let orig_ident = format_ident!("orig");
                                let anon_to_str = generate_value_to_string(&anon_ident, inner)?;
                                let orig_to_str = generate_value_to_string(&orig_ident, inner)?;

                                match **inner {
                                    SupportedType::Option(_) => {
                                        quote! {
                                            __state_ref.get().unwrap().#fname.iter()
                                                .zip(self.#fname.iter())
                                                .filter_map(|(anon, orig)| {
                                                    match (#anon_to_str, #orig_to_str) {
                                                        (Some(a), Some(o)) => Some((a, o)),
                                                        _ => None
                                                    }
                                                })
                                                .collect::<Vec<_>>()
                                        }
                                    }
                                    _ => {
                                        quote! {
                                            __state_ref.get().unwrap().#fname.iter()
                                                .zip(self.#fname.iter())
                                                .map(|(anon, orig)| (#anon_to_str, #orig_to_str))
                                                .collect::<Vec<_>>()
                                        }
                                    }
                                }
                            }
                            SupportedType::HashMap(key_type, value_type) => {
                                let anon_key_ident = format_ident!("anon_key");
                                let anon_value_ident = format_ident!("anon_value");
                                let orig_key_ident = format_ident!("orig_key");
                                let orig_value_ident = format_ident!("orig_value");

                                let anon_key_to_str =
                                    generate_value_to_string(&anon_key_ident, &key_type)?;
                                let anon_value_to_str =
                                    generate_value_to_string(&anon_value_ident, &value_type)?;
                                let orig_key_to_str =
                                    generate_value_to_string(&orig_key_ident, &key_type)?;
                                let orig_value_to_str =
                                    generate_value_to_string(&orig_value_ident, &value_type)?;

                                match **value_type {
                                    SupportedType::Option(_) => {
                                        quote! {
                                            {
                                                let mut pairs = Vec::new();
                                                for ((anon_key, anon_value), (orig_key, orig_value)) in
                                                    __state_ref.get().unwrap().#fname.iter().zip(self.#fname.iter())
                                                {
                                                    pairs.push((#anon_key_to_str, #orig_key_to_str));

                                                    if let (Some(anon_str), Some(orig_str)) =
                                                        (#anon_value_to_str, #orig_value_to_str)
                                                    {
                                                        pairs.push((anon_str, orig_str));
                                                    }
                                                }
                                                pairs
                                            }
                                        }
                                    }
                                    _ => {
                                        quote! {
                                            {
                                                let mut pairs = Vec::new();
                                                for ((anon_key, anon_value), (orig_key, orig_value)) in
                                                    __state_ref.get().unwrap().#fname.iter().zip(self.#fname.iter())
                                                {
                                                    pairs.push((#anon_key_to_str, #orig_key_to_str));
                                                    pairs.push((#anon_value_to_str, #orig_value_to_str));
                                                }
                                                pairs
                                            }
                                        }
                                    }
                                }
                            }
                            SupportedType::Option(inner_type) => {
                                let state_ref = quote! { __state_ref.get().unwrap().#fname };
                                let orig_ref = quote! { self.#fname };
                                let state_ident = format_ident!("__anon_temp");
                                let orig_ident = format_ident!("__orig_temp");

                                let anon_to_str =
                                    generate_option_value_to_string(&state_ident, &*inner_type)?;
                                let orig_to_str =
                                    generate_option_value_to_string(&orig_ident, &*inner_type)?;

                                quote! {
                                    {
                                        let #state_ident = &#state_ref;
                                        let #orig_ident = &#orig_ref;
                                        match (#state_ident.as_ref(), #orig_ident.as_ref()) {
                                            (Some(a), Some(o)) => vec![(#anon_to_str, #orig_to_str)],
                                            _ => vec![],
                                        }
                                    }
                                }
                            }
                            _ => {
                                let state_ref = quote! { __state_ref.get().unwrap().#fname };
                                let orig_ref = quote! { self.#fname };
                                let state_ident = format_ident!("__anon_temp");
                                let orig_ident = format_ident!("__orig_temp");

                                let anon_to_str =
                                    generate_value_to_string(&state_ident, &field_type)?;
                                let orig_to_str =
                                    generate_value_to_string(&orig_ident, &field_type)?;

                                quote! {
                                    {
                                        let #state_ident = &#state_ref;
                                        let #orig_ident = &#orig_ref;
                                        vec![(#anon_to_str, #orig_to_str)]
                                    }
                                }
                            }
                        };

                        patterns_and_replacements.push(pattern);
                    }

                    let patterns_and_replacements_iter = patterns_and_replacements.iter();
                    let deanonymize = quote! {
                        pub fn deanonymize(&self, text: &str) -> String {
                            let __state_ref = &self.__state;
                            let mut all_pairs: Vec<_> = Vec::new();

                            #(all_pairs.extend(#patterns_and_replacements_iter);)*

                            let patterns: Vec<_> = all_pairs.iter().map(|(p, _)| p.as_str()).collect();
                            let replacements: Vec<_> = all_pairs.iter().map(|(_, r)| r.as_str()).collect();
                            println!("Patterns: {:?}", patterns);
                            println!("Replacements: {:?}", replacements);

                            let ac = ::aho_corasick::AhoCorasick::new(&patterns).unwrap();
                            ac.replace_all(text, &replacements)
                        }
                    };
                    // Generate logic for dynamic fields for which secret state cannot
                    // be initalized by default constructor, such fields are Vec or HashMap.
                    let prepare_logic = anon_fields.iter().enumerate().filter_map(|(i, f)| {
                        let anon_attr = f.attrs.iter().find(|attr| attr.path().is_ident("anon"))?;
                        let config = parse_anon_attr(anon_attr).ok()?;
                        let field_type = is_type(&f.ty).ok()?;

                        if field_type.is_dynamic() {
                            Some(generate_prepare_logic(f, i, &config))
                        } else {
                            None
                        }
                    });

                    let serialize = quote! {
                        use serde::ser::SerializeStruct;
                        impl #impl_generics serde::Serialize for #name #ty_generics #where_clause {
                            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                            where
                                S: serde::Serializer,
                            {
                                let mut state = serializer.serialize_struct(stringify!(#name), #field_count)?;
                                let anon = self.anonymize();
                                #(#field_serializers)*
                                state.end()
                            }
                        }

                        impl #impl_generics #name #ty_generics #where_clause {
                            pub fn anonymize(&self) -> &#state_name {
                                let mut state = self.__state.get_or_init(||{
                                    let mut state = #state_name::default();
                                    #(#prepare_logic)*
                                    state
                                });
                                state
                            }

                            #deanonymize
                        }
                    };
                    return Ok(serialize.into());
                }
            }
        }
        _ => {}
    }

    Ok(TokenStream::new())
}
