use proc_macro::TokenStream;
use quote::quote;
use syn::{DeriveInput, parse_macro_input};

#[derive(Default)]
struct SerdeConfig {
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
            if meta.path.is_ident("skip") {
                config.skip = true;
            } else if meta.path.is_ident("skip_serializing") {
                config.skip_serializing = true;
            }
            Ok(())
        });
    }

    config
}

#[proc_macro_derive(Anonymize, attributes(anon, serde))]
pub fn derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    expand_macro(ast).unwrap_or_else(|e| e.to_compile_error().into())
}

fn expand_macro(ast: DeriveInput) -> syn::Result<TokenStream> {
    let name = &ast.ident;
    let generics = ast.generics.clone();
    let (_impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    if let syn::Data::Struct(data_struct) = &ast.data
        && let syn::Fields::Named(fields_named) = &data_struct.fields
    {
        let anon_fields: Vec<_> = fields_named
            .named
            .iter()
            .filter(|f| {
                let serde = parse_serde_attr(f);
                if serde.skip || serde.skip_serializing {
                    return false;
                }
                f.attrs.iter().any(|attr| attr.path().is_ident("anon"))
            })
            .collect();

        let mask_assignments = anon_fields.iter().map(|f| {
            let fname = &f.ident;
            quote! {
                masked.#fname = serde_mask::AnonymizeTrait::anonymize(&self.#fname, &mut builder);
            }
        });

        let output = quote! {
            impl #name #ty_generics #where_clause {
                pub fn mask(&self) -> serde_mask::Masked<#name #ty_generics> {
                    let mut builder = serde_mask::MaskStateBuilder::new();
                    let mut masked = self.clone();
                    #(#mask_assignments)*
                    serde_mask::Masked::new(masked, builder.build())
                }
            }
        };

        return Ok(output.into());
    } else {
        return Err(syn::Error::new_spanned(
            ast,
            "Anonymize can only be derived for structs with named fields",
        ));
    }
}
