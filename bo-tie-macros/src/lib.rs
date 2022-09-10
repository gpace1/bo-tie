//! Procedural macros for package bo-tie
//!
//! These proc macro's are not intended for usage outside of this workspace, but it is a free-ish
//! world and no license restricts you from using them.

extern crate proc_macro;

mod depth_count;
mod display_event;

use proc_macro::TokenStream;

/// Procedural macro for converting event enums into something displayable
///
/// Something like the enum `MyEnumVariant` would be displayed as "event My Enum Variant"
/// ```
/// assert_eq!("event My Event Name", bo_tie_macros::display_hci_event!(MyEventName))
/// ```
#[proc_macro]
pub fn display_hci_event(enumeration: TokenStream) -> TokenStream {
    let enumeration = syn::parse_macro_input!(enumeration as syn::Ident);

    display_event::display_enum_ident(enumeration)
}

/// Procedural macro to count (in depth) the enumerations of an enum
///
/// This macro is intended to be used internally for library `bo-tie-hci-util`.
///
/// ## Method `get_depth`
/// This method retuns the depth of the enumeration. An enumeration's depth is the accumulated count
/// of the enumerations above it. The depth value always starts at zero for the first enumeration.
///
/// ```
/// use bo_tie_macros::DepthCount;
///
/// #[derive(DepthCount)]
/// enum Foo { A, B, C }
///
/// assert_eq!(Foo::A.get_depth(), 0);
/// assert_eq!(Foo::B.get_depth(), 1);
/// assert_eq!(Foo::C.get_depth(), 2);
///
/// #[derive(DepthCount)]
/// enum Bar { A, Foo(Foo), Z }
///
/// assert_eq!(Bar::A.get_depth(), 0);
///
/// assert_eq!(Bar::Foo(Foo::A).get_depth(), 1);
///
/// assert_eq!(Bar::Foo(Foo::C).get_depth(), 3);
///
/// assert_eq!(Bar::Z.get_depth(), 4);
/// ```
///
/// ## Method `full_depth`
/// This function returns the full depth size of the enumeration.
///
/// ```
/// # use bo_tie_macros::DepthCount;
///
/// #[derive(DepthCount)]
/// enum Foo { A, B, C }
///
/// #[derive(DepthCount)]
/// enum Bar { A, Foo(Foo), Z }
///
/// assert_eq!(Foo::full_depth(), 3);
///
/// assert_eq!(Bar::full_depth(), 5);
///
/// ```
///
/// ### Unnamed Fileds
/// Multiple fields within an enum are supported so long as they also implement `DepthCount`. But
/// since `DepthCount` can only be derived for enums, these unnamed fields must also be enums.
/// Having multiple unnamed fields within an enumeration can cause the `full_depth` value to
/// exponentially increatse, although that should not ever really matter.
///
/// ```
/// # use bo_tie_macros::DepthCount;
///
/// #[derive(DepthCount)]
/// enum TestEnum1 {
///     A,
///     B,
///     C,
/// }
///
/// #[derive(DepthCount)]
/// enum TestEnum2 {
///     A,
///     Ta(TestEnum1),
///     Tb(TestEnum1, TestEnum1, TestEnum1),
///     B,
/// }
///
/// // the enum `Tb` in `TestEnum2` causes the depth of
/// // `TestEnum2` to be much larger than `TestEnum1`.
/// assert_eq!(TestEnum1::full_depth(), 3);
/// assert_eq!(TestEnum2::full_depth(), 32);
///
/// # assert_eq!(TestEnum1::A.get_depth(), 0);
/// # assert_eq!(TestEnum1::B.get_depth(), 1);
/// # assert_eq!(TestEnum1::C.get_depth(), 2);
/// # assert_eq!(TestEnum2::A.get_depth(), 0);
/// # assert_eq!(TestEnum2::Ta(TestEnum1::C).get_depth(), 3);
/// # assert_eq!(TestEnum2::Tb(TestEnum1::C, TestEnum1::B, TestEnum1::A).get_depth(), 9);
/// # assert_eq!(TestEnum2::Tb(TestEnum1::C, TestEnum1::C, TestEnum1::C).get_depth(), 30);
/// # assert_eq!(TestEnum2::B.get_depth(), 31);
/// ```
#[proc_macro_derive(DepthCount)]
pub fn depth_count(r#enum: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(r#enum as syn::DeriveInput);

    depth_count::depth_count(input)
}
