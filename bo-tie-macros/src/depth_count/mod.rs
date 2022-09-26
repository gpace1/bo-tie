//! Implementation of the proc_macro_derive `DepthCount`

use crate::depth_count::depth_counter::{FromDepthConsts, FromDepthMatchArms, GetDepthCounter};
use proc_macro2::{Span, TokenStream};
use quote::ToTokens;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{parse_quote, parse_quote_spanned};

mod depth_counter;

pub fn depth_count(input: syn::DeriveInput) -> proc_macro::TokenStream {
    if !input.generics.params.is_empty() {
        return proc_macro::TokenStream::from(
            syn::Error::new(
                Span::call_site(),
                "`DepthCount` cannot be derived for types with generics",
            )
            .into_compile_error(),
        );
    }

    match input.data {
        syn::Data::Struct(_) => {
            syn::Error::new(Span::call_site(), "`DepthCount` cannot be derived for a struct").into_compile_error()
        }
        syn::Data::Union(_) => {
            syn::Error::new(Span::call_site(), "`DepthCount` cannot be derived for a union").into_compile_error()
        }
        syn::Data::Enum(enumeration) => match process_enum(input.ident, enumeration) {
            Ok(ts) => ts,
            Err(e) => e.into_compile_error(),
        },
    }
    .into()
}

fn process_enum(enum_name: syn::Ident, enumeration: syn::DataEnum) -> Result<TokenStream, syn::Error> {
    let enum_kinds = enumeration
        .variants
        .into_iter()
        .map(|variant| get_next_enum(variant))
        .try_fold(Vec::new(), |mut enum_kinds, maybe_enum_kind| {
            enum_kinds.push(maybe_enum_kind?);
            Ok::<_, syn::Error>(enum_kinds)
        })?;

    let impl_get_depth = impl_get_depth(&enum_kinds)?;

    let impl_full_depth = impl_full_depth(&enum_kinds)?;

    let impl_from_depth = impl_from_depth(&enum_kinds)?;

    let impl_depth_count = quote::quote! {
        impl #enum_name {
            #impl_full_depth

            #impl_get_depth

            #impl_from_depth
        }
    };

    Ok(impl_depth_count)
}

fn get_next_enum(variant: syn::Variant) -> Result<EnumKind, syn::Error> {
    let ident = variant.ident.clone();

    match variant.fields {
        syn::Fields::Named(fields_named) => process_named_fields(ident, fields_named),
        syn::Fields::Unnamed(fields_unnamed) => process_fields_unnamed(ident, fields_unnamed),
        syn::Fields::Unit => Ok(EnumKind::Unit(ident)),
    }
}

enum EnumKind {
    Unit(syn::Ident),
    Unnamed { ident: syn::Ident, paths: Vec<syn::Path> },
}

/// Process an enumeration that contains named fields
///
/// Named fields are not supported.
///
/// If it was supported it would be for processing enumeration `Bar`
/// ```
/// enum Xxx {}
///
/// enum Foo {
///     Bar { x: Xxx, }
/// }
/// ```
fn process_named_fields(_ident: syn::Ident, fields_named: syn::FieldsNamed) -> Result<EnumKind, syn::Error> {
    Err(syn::Error::new(
        fields_named.span(),
        "named fields are not supported for deriving `DepthCount`",
    ))
}

/// Process an enumeration that contains unnamed fields
///
/// This is used to process enumerations that contain unnamed fields such as `Bar`
/// ```
/// enum Xxx {}
///
/// enum Foo {
///     Bar(Xxx)
/// }
fn process_fields_unnamed(ident: syn::Ident, fields_unnamed: syn::FieldsUnnamed) -> Result<EnumKind, syn::Error> {
    let mut paths = Vec::new();

    for unnamed in fields_unnamed.unnamed {
        match unnamed.ty {
            syn::Type::Path(type_path) => paths.push(type_path.path),
            _ => {
                return Err(syn::Error::new(
                    unnamed.ty.span(),
                    "only paths are supported for types for `DepthCount`",
                ))
            }
        }
    }

    Ok(EnumKind::Unnamed { ident, paths })
}

/// Create the token stream implementing method `get_depth`
fn impl_get_depth(enum_kinds: &[EnumKind]) -> Result<TokenStream, syn::Error> {
    let depth_counter = &mut GetDepthCounter::new();

    let match_arm_iter = enum_kinds
        .into_iter()
        .map(|enum_kind| match enum_kind {
            EnumKind::Unit(ident) => impl_get_depth_for_unit(depth_counter, ident),
            EnumKind::Unnamed { ident, paths } => impl_get_depth_for_unnamed(depth_counter, ident, paths),
        })
        .collect::<TokenStream>();

    let method = quote::quote! {
        #[doc(hidden)]
        pub const fn get_depth(&self) -> usize {
            match self {
                #match_arm_iter
            }
        }
    };

    Ok(method)
}

/// Used in [`impl_get_depth`](impl_get_depth)
fn impl_get_depth_for_unit(depth_counter: &mut GetDepthCounter, ident: &syn::Ident) -> TokenStream {
    let unit_depth = depth_counter.unit_depth();

    let ts = quote::quote! {
        Self :: #ident => #unit_depth,
    };

    drop(unit_depth);

    depth_counter.inc_unit_count();

    ts
}

/// Used in [`impl_get_depth`](impl_get_depth)
fn impl_get_depth_for_unnamed(
    depth_counter: &mut GetDepthCounter,
    ident: &syn::Ident,
    paths: &[syn::Path],
) -> TokenStream {
    let input_pairs = paths
        .iter()
        .enumerate()
        .map(|(c, path)| {
            let ident = syn::Ident::new(&format!("u{}", c), Span::call_site());

            (path.clone(), ident)
        })
        .collect::<Vec<_>>();

    let unnamed_types = input_pairs
        .iter()
        .map(|(_, ident)| -> syn::Ident { ident.clone() })
        .collect::<Punctuated<syn::Ident, syn::Token!(,)>>();

    let unnamed_depth = depth_counter.unnamed_depth(input_pairs);

    let ts = quote::quote! {
        Self :: #ident ( #unnamed_types ) => #unnamed_depth,
    };

    drop(unnamed_depth);

    depth_counter.inc_types_used(paths.to_vec());

    ts
}

/// Create the token stream implementing function `full_depth`
fn impl_full_depth(enum_kinds: &[EnumKind]) -> Result<TokenStream, syn::Error> {
    let mut calculation = enum_kinds
        .iter()
        .map(|enum_kind| -> syn::Expr {
            match enum_kind {
                EnumKind::Unit(_) => parse_quote!(1),
                EnumKind::Unnamed { paths, .. } => {
                    let size = paths
                        .iter()
                        .map(|path| -> syn::Expr { parse_quote_spanned!(path.span()=> #path :: full_depth()) })
                        .collect::<Punctuated<syn::Expr, syn::Token![*]>>();

                    parse_quote!(( #size ))
                }
            }
        })
        .collect::<Punctuated<syn::Expr, syn::Token![+]>>();

    calculation.push(parse_quote!(0));

    let ts = quote::quote! {
        #[doc(hidden)]
        pub const fn full_depth() -> usize {
            #calculation
        }
    };

    Ok(ts)
}

fn impl_from_depth(enum_kinds: &[EnumKind]) -> Result<TokenStream, syn::Error> {
    let matched: syn::Ident = syn::parse_quote!(depth);

    let constants = impl_consts_for_from_depth(enum_kinds)?;
    let matches = impl_match_arms_for_from_depth(enum_kinds, matched.clone())?;

    let ts = quote::quote! {
        #[doc(hidden)]
        pub const fn from_depth(#matched: usize) -> Self {
            #constants

            match #matched {
                #matches

                _ => panic!("cannot create enumeration at this depth")
            }
        }
    };

    Ok(ts)
}

fn impl_consts_for_from_depth(enum_kinds: &[EnumKind]) -> Result<TokenStream, syn::Error> {
    let mut from_depth = FromDepthConsts::new();

    let ts = enum_kinds
        .iter()
        .map(|kind| match kind {
            EnumKind::Unit(name) => {
                let ts = from_depth.unit_depth_const(name.clone()).into_token_stream();

                from_depth.inc_unit_count();

                ts
            }
            EnumKind::Unnamed { ident, paths } => {
                let ts = from_depth
                    .unnamed_depth_const(ident.clone(), paths.clone())
                    .into_token_stream();

                from_depth.inc_types_used(paths.clone());

                ts
            }
        })
        .collect::<TokenStream>();

    Ok(ts)
}

fn impl_match_arms_for_from_depth(enum_kinds: &[EnumKind], matched: syn::Ident) -> Result<TokenStream, syn::Error> {
    let match_depth = FromDepthMatchArms::new();

    let ts = enum_kinds
        .iter()
        .map(|kind| match kind {
            EnumKind::Unit(name) => match_depth.unit_match_arm(name.clone()).into_token_stream(),
            EnumKind::Unnamed { ident, paths } => match_depth
                .unnamed_match_arm(ident.clone(), matched.clone(), paths.clone())
                .into_token_stream(),
        })
        .collect::<TokenStream>();

    Ok(ts)
}
