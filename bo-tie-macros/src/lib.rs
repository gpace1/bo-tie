//! Procedural macros for package bo-tie
//!
//! These proc macro's are not intended for usage outside of this workspace, but it is a free-ish
//! world and no license restricts you from using them.

extern crate proc_macro;

mod depth_count;
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

/// Procedural macro to count (in depth) the enumerations of an enum
///
/// This macro is intended to be used internally for library `bo-tie-hci-host`.
///
/// # Implemented Methods
/// This implements methods onto the type. These methods are not part of a trait, instead they are
/// implemented directly for the type.
///
/// ### Method `get_depth`
/// This method retuns the depth of the enumeration. An enumeration's depth is the accumulated count
/// of the enumerations above it. The depth value always starts at zero for the first enumeration.
///
/// ```
/// use bo_tie_macros::DepthCount;
///
/// #[derive(DepthCount)]
/// enum Foo { A, B, C }
///
/// assert!(Foo::A.get_depth(), 0);
/// assert!(Foo::B.get_depth(), 1);
/// assert!(Foo::C.get_depth(), 2);
///
/// #[derive(DepthCount)]
/// enum Bar { A, Foo(Foo), Z }
///
/// assert!(Bar::A.get_depth(), 0);
///
/// assert!(Bar::Foo(Foo::A).get_depth(), 1);
///
/// assert!(Bar::Foo(Foo::C).get_depth(), 3);
///
/// assert!(Bar::Z.get_depth(), 4);
/// ```
///
///
/// ### Method `full_depth`
/// This function returns the full depth size of the enumeration.
///
/// ```
/// use bo_tie_macros::DepthCount;
///
/// #[derive(DepthCount)]
/// enum Foo { A, B, C }
///
/// #[derive(DepthCount)]
/// enum Bar { A, Foo(Foo), Z }
///
/// assert_eq!(Foo::full_depth(), 3);
///
/// assert_eq!(Foo::full_depth(), 5);
/// ```
#[proc_macro_derive(DepthCount)]
pub fn depth_count(r#enum: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(r#enum as syn::DeriveInput);

    depth_count::depth_count(input)
}
