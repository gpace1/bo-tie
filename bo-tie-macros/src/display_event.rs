//! Methods for proc macro `display_enum`

use convert_case::{Case, Casing};
use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;

/// Parse an identifier into a literal string
///
/// see the library level proc macro [`display_event`](crate::display_event) for more details
pub fn display_enum_ident(pattern: syn::Ident) -> TokenStream {
    let name = pattern.to_string().to_case(Case::Title);

    let displayed = "event ".to_string() + &name;

    let lit_str = syn::LitStr::new(&displayed, Span::call_site());

    let expanded = quote! {
        #lit_str
    };

    TokenStream::from(expanded)
}
