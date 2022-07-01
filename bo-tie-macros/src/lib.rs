//! Procedural macros for package bo-tie
//!
//! These proc macro's are not intended for usage outside of this workspace, but it is a free-ish
//! world and no license restricts you from using them.

extern crate proc_macro;

mod display_enum;

use proc_macro::TokenStream;

/// Procedural macro for converting event enums into something displayable
///
/// Something like the enum `MyEnumVariant` would be displayed as "event My Enum Variant"
/// ```
/// use bo_tie_macros::display_event;
/// enum MyEnum {
///     MyEnumVariant
/// }
///
/// assert_eq!("My Enum Variant", display_event!(MyEnum::MyEnumVariant))
/// ```
#[proc_macro]
pub fn display_hci_event(enumeration: TokenStream) -> TokenStream {
    let enumeration = syn::parse_macro_input!(enumeration as syn::Ident);

    display_enum::display_enum_ident(enumeration)
}
