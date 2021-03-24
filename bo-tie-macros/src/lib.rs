//! Procedural macros for package bo-tie
//!
//! These macros are not intended for use outside of this package, but there is no restriction in
//! using them (unless said specifically in the macros documentation). Their main purpose is to do
//! what procedural macros were intended for, facilitating and refactoring the code base.
//!
//! Instead of inserting multiple versions of a token stream for each possible feature of bo-tie,
//! this proc-macro library has its own features which mirror those of bo-tie. When compiling for
//! those feature, bo-tie invokes features of the same name within this library. Of course only
//! features that require the use of proc-macros are mirrored within this library.
//!
//! # host_interface
//! A [`HostInterface`](bo_tie::hci::HostInterface) has different generic inputs depending on the
//! features enabled for the `hci` bo-tie library. Instead of manually creating all the alternative
//! versions of items that use `HostInterface` for each feature, this macro will create the
//! different versions. It can be used wherever the added feature specific generics do not affect
//! the item beyond being in the list of generics. Feature specific items will still need to be
//! feature gated by the appropriate feature.
//!
//! The host_interface modifies the token tree only when the feature "flow-ctrl" is enabled within
//! this library. This feature mirrors the "flow-ctrl" feature of bo-tie.

extern crate proc_macro;

#[cfg(feature = "flow-ctrl")]
mod hi;

use proc_macro::TokenStream;

/// The attribute used in conjunction with `HostInterface`
///
/// # Arguments
/// When compiling with "flow-ctrl", the host_interface proc-macro attribute does not require an
/// argument input. When no argument is given, the default is to insert the generic type `F` into
/// *all* places where it *may be* required. It doesn't do this intelligently and arguments can be
/// given to the attribute to restrict and modify this implementation.
///
/// All arguments are are are named values. They must be in the form of *name* = "val" where *name*
/// is either "flow_ctrl_generic" or "flow_ctrl_concrete".
/// `[host_interface(flow_ctrl_generic = "FlowController"]` is an example of the full attribute
/// with "flow_ctrl_generic" as an argument.
///
/// ## flow_ctrl_concrete
/// Instead of using a generic, append a defined type to the generic parameter. The str assigned
/// the the "flow_ctrl_concrete" arg is assumed to be a concrete type, some type that is defined
/// within or imported into the scope of the module. Places that do not need the concrete type, such
/// as generic argument lists after `impl`, will not have the type inserted into. This concrete type
/// is not modified and used as-is.
#[cfg(feature = "flow-ctrl")]
#[proc_macro_attribute]
pub fn host_interface(args: TokenStream, item: TokenStream) -> TokenStream {
    let args = syn::parse_macro_input!(args as syn::AttributeArgs);

    let mut parsed_item = syn::parse_macro_input!(item as syn::Item);

    hi::parse_item(&args, &mut parsed_item).expect("host_interface cannot parse item")
}

/// The featureless version
///
/// When no features are enabled within bo-tie-macros, the `host_interface` attribute does nothing.
#[cfg(not(any(feature = "flow-ctrl")))]
#[proc_macro_attribute]
pub fn host_interface(_: TokenStream, ts: TokenStream) -> TokenStream {
    ts
}
