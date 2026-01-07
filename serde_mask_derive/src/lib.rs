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

fn expand_anonymize(mut ast: ItemStruct) -> syn::Result<proc_macro::TokenStream> {
    let to_anonymize = &ast
        .fields
        .iter()
        .filter_map(|f| {
            if f.attrs.iter().any(|attr| attr.path().is_ident("anon")) {
                let field_ty = &f.ty;
                let state_ty = parse_quote! { <#field_ty as AnonymizeTrait>::State };
                let field = syn::Field {
                    attrs: vec![],
                    vis: f.vis.clone(),
                    mutability: f.mutability.clone(),
                    ident: f.ident.clone(),
                    colon_token: f.colon_token,
                    ty: state_ty,
                };
                Some(field)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let struct_name = format_ident!("__state_{}", ast.ident);
    let state_struct: ItemStruct = parse_quote! {
        #[derive(Debug)]
        #[allow(non_camel_case_types)]
        struct #struct_name {
            #(#to_anonymize),*
        }

    };

    let mut fields = ast.fields.clone();
    if let syn::Fields::Named(syn::FieldsNamed { ref mut named, .. }) = fields {
        let field: syn::Field = parse_quote! { __state: std::sync::OnceLock<#struct_name> };
        named.push(field);
    }
    ast.fields = fields;

    let result = quote! {
        #ast
        #state_struct
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

                    let deanonymize_impls = anon_fields
                        .iter()
                        .map(|f| {
                            let fname = &f.ident;
                            quote! {
                                text = self.#fname.deanonymize(__state_ref.#fname.clone(), &text);
                            }
                        })
                        .collect::<Vec<_>>();

                    let deanonymize = quote! {
                        pub fn deanonymize(&self, mut text: String) -> String {
                            let __state_ref = &self.__state.get().unwrap();
                            #(#deanonymize_impls)*
                            text
                        }
                    };

                    let inner_state_fields = anon_fields.iter().map(|f| {
                        let fname = &f.ident;
                        quote! {
                            #fname: self.#fname.anonymize()
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
                                    let mut state = #state_name {
                                        #(#inner_state_fields),*
                                    };
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
