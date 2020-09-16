//! Procedural macros for package bo-tie
//!
//! These macros are not intended for use outside of this package, but there is no restriction in
//! using them (unless said specifically in the macros documentation). Their main purpose is to do
//! what procedural macros were intended for, facilitating and refactoring the code base.
extern crate proc_macro;

mod hi;

use proc_macro::TokenStream;

/// The attribute used in conjunction with `HostInterface`
///
/// A `HostInterface` has different generic inputs depending on the features enabled for the `hci`
/// bo-tie library. Instead of manually creating all the alternative versions of `HostInterface`
/// items for each feature, this macro will create the different versions within reason. It can be
/// used wherever the added feature specific generics do not affect the item beyond being in the
/// list of generics.
#[proc_macro_attribute]
pub fn host_interface(_: TokenStream, item: TokenStream) -> TokenStream {
    hi::parse_item(item).expect("host_interface cannot parse item")
}