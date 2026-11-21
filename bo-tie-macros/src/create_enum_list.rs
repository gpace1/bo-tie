//! Implementation for the `CreateEnumList` proc-macro derive

use syn::spanned::Spanned;

pub(super) fn create_enum_list(derive_input: syn::DeriveInput) -> proc_macro::TokenStream {
    let enum_data = match &derive_input.data {
        syn::Data::Enum(e) => e,
        syn::Data::Struct(s) => {
            return syn::Error::new(s.struct_token.span(), "expected an enum")
                .to_compile_error()
                .into()
        }
        syn::Data::Union(u) => {
            return syn::Error::new(u.union_token.span(), "expected an enum")
                .to_compile_error()
                .into()
        }
    };

    let name = &derive_input.ident;

    let generics = &derive_input.generics;

    let list = enum_data.variants.iter().map(|variant| &variant.ident);

    let count = enum_data.variants.len();

    quote::quote! {
        impl #generics #name {
            fn create_enum_list() -> &'static [#name; #count] {
                &[#(#name :: #list),*]
            }
        }
    }
    .into()
}
