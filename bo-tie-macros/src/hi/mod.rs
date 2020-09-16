//! `host_interface` procedural macro attribute processing methods
//!
//! This module provides the methods for walking the token tree of an item that has the
//! `host_interface` attribute assigned to it. It looks for instances of the `HostInterface` struct
//! and inserts generics required by the different versions of `HostInterface` required for the
//! features for bo-tie's HCI.
//!
//! This isn't intended to meet every use case for where changing features will effect items that
//! contain a `HostInterface` somewhere within their token tree. Only the use cases required for
//! the bo-tie crate are implemented.

use proc_macro::TokenStream;
use quote::ToTokens;

macro_rules! return_invalid {
    ($invalid:literal, $token_type:literal $(, $reason:literal)? ) => {
        return Err( std::string::ToString::to_string( concat!(
            "'",
            $invalid,
            "' is not a valid ",
            $token_type,
            " for the host_interface attribute"
            $(, $reason)?
        )))
    }
}
macro_rules! invalid_item {
    ($item:literal $(, $reason:literal)? ) => { return_invalid!($item,"item" $(, $reason)? ) }
}

macro_rules! ret {
    () => {
        std::result::Result<(), String>
    }
}

macro_rules! invalid_type {
    ($type_:literal $(, $reason:literal)? ) => { return_invalid!($type_,"type" $(, $reason)? )}
}

mod flow_control;

const IDENTITY_NAME: &'static str = "HostInterface";

/// Generics to modify `HostInterface` with the enabling and disabling of features
#[derive(Clone,Copy)]
enum FeatureGenerics {
    /// No feature generics to add. Either implement for no features enabled or there is no
    /// `HostInterface` within the token tree
    None,
    /// Flow control generics
    FlowControl,
}

/// The information required for
struct Bubble {
    has_hi: bool,
    extra_generics: FeatureGenerics
}

impl Bubble {

    fn new(ex: FeatureGenerics) -> Self {
        Self {
            has_hi: false,
            extra_generics: ex,
        }
    }

    /// Check an identity against `name`
    ///
    /// If the identity matches the `name` the the `has_hi` flag is set to true. This returns the
    /// comparison result between `name` and the identity.
    fn check_ident(&mut self, ident: &syn::Ident) -> bool {
        let cmp = ident == IDENTITY_NAME;

        if cmp { self.has_hi = true }

        cmp
    }

    fn generic_change(&self) -> FeatureGenerics {
        match (self.has_hi, self.extra_generics) {
            (false, _) | (true, FeatureGenerics::None) => FeatureGenerics::None,

            (true, FeatureGenerics::FlowControl) => FeatureGenerics::FlowControl,
        }
    }
}

pub fn parse_item(item: TokenStream) -> Result<TokenStream,String> {

    let parsed_item: syn::Item = syn::parse(item.clone()).unwrap();

    let mut flow_control_item = parsed_item.clone();

    let bubble = &mut Bubble::new(FeatureGenerics::FlowControl);

    match &mut flow_control_item {

        syn::Item::Const(_) => invalid_item!("const"),

        syn::Item::Enum(item_enum) => parse_enum_item(item_enum, bubble)?,

        syn::Item::ExternCrate(_) => invalid_item!("extern crate"),

        syn::Item::Fn(item_fn) => parse_fn_item(item_fn, bubble)?,

        syn::Item::ForeignMod(_) => invalid_item!("extern \"C\""),

        syn::Item::Impl(item_impl) => parse_impl_item(item_impl, bubble)?,

        syn::Item::Macro(_) => invalid_item!("macro"),

        syn::Item::Macro2(_) => invalid_item!("proc macro (macro 2.0)"),

        syn::Item::Mod(_) => invalid_item!("mod"),

        syn::Item::Static(_) => invalid_item!("static"),

        syn::Item::Struct(item_struct) => parse_struct_item(item_struct, bubble)?,

        syn::Item::Trait(_) => invalid_item!("trait"),

        syn::Item::TraitAlias(_) => invalid_item!("trait alias"),

        syn::Item::Type(_) => invalid_item!("type alias"),

        syn::Item::Union(_) =>
            invalid_item!("union", "attribute host_interface is not implemented for a union"),

        syn::Item::Use(_) => invalid_item!("use"),

        syn::Item::Verbatim(v) => inconsequential(v, bubble)?,

        _ => return Err("Exhaustive pattern for 'item' reached".into()),
    }

    Ok( quote::quote! {
        #[cfg(not(feature = "flow-ctrl"))]
        #parsed_item

        #[cfg(feature = "flow-ctrl")]
        #flow_control_item
    }.into() )
}

/// Tokens that are not effected by `HostInterface` structure changes
#[inline]
fn inconsequential<'a, P: 'a + ToTokens>(_: P, _: &mut Bubble) -> ret!() { Ok(()) }

fn parse_enum_item(item_enum: &mut syn::ItemEnum, bubble: &mut Bubble) -> ret!() {
    item_enum.variants.iter_mut().try_for_each(|variant| parse_enum_variant(variant, bubble) )?;

    match bubble.generic_change() {
        FeatureGenerics::None => (),
        FeatureGenerics::FlowControl => {
            item_enum.generics.params.push(flow_control::generic_param())
        }
    }

    Ok(())
}

fn parse_fn_item(item_fn: &mut syn::ItemFn, bubble: &mut Bubble) -> ret!() {
    item_fn.sig.inputs.iter_mut().try_for_each(|arg| if let syn::FnArg::Typed(t) = arg {
        parse_type(&mut t.ty, bubble)
    } else {
        Ok(())
    })?;

    parse_return(&mut item_fn.sig.output, bubble)?;

    match bubble.generic_change() {
        FeatureGenerics::None => (),
        FeatureGenerics::FlowControl => {
            item_fn.sig.generics.params.push(flow_control::generic_param());
        }
    }

    Ok(())
}

/// Parse `ImplItem`
///
/// This only checks the self-type of the declaration and not the items of the `ImplItem`.
fn parse_impl_item(item_impl: &mut syn::ItemImpl, bubble: &mut Bubble) -> ret!() {
    parse_type(&mut item_impl.self_ty, bubble)?;

    match bubble.generic_change() {
        FeatureGenerics::None => (),
        FeatureGenerics::FlowControl => {
            item_impl.generics.params.push(flow_control::generic_param());
        },
    }

    Ok(())
}

fn parse_struct_item(item_struct: &mut syn::ItemStruct, bubble: &mut Bubble) -> ret!() {
    if ! bubble.check_ident(&item_struct.ident) {
        parse_fields( &mut item_struct.fields, bubble )?
    }

    match bubble.generic_change() {
        FeatureGenerics::None => (),
        FeatureGenerics::FlowControl => {
            item_struct.generics.params.push(flow_control::generic_param());
        }
    }

    Ok(())
}

fn parse_type(t: &mut syn::Type, bubble: &mut Bubble) -> ret!() {
    
    match t {
        syn::Type::Array(array) => parse_typed_array(array, bubble),

        syn::Type::BareFn(bare_fn) => parse_bare_fn(bare_fn, bubble),

        syn::Type::Group(group) => parse_type(&mut group.elem, bubble),

        syn::Type::ImplTrait(impl_trait) => inconsequential(impl_trait, bubble),

        syn::Type::Infer(infer) => inconsequential(infer, bubble),

        syn::Type::Macro(_) => invalid_type!("macro"),

        syn::Type::Never(never) => inconsequential(never, bubble),

        syn::Type::Paren(parenthesis) => parse_paren(parenthesis, bubble),

        syn::Type::Path(path) => inconsequential(path, bubble),

        syn::Type::Ptr(pointer) => parse_ptr(pointer, bubble),

        syn::Type::Reference(reference) => parse_ref(reference, bubble),

        syn::Type::Slice(slice) => parse_slice(slice, bubble),

        syn::Type::TraitObject(trait_obj) => parse_trait_object(trait_obj, bubble),

        syn::Type::Tuple(tuple) => parse_tuple(tuple, bubble),

        syn::Type::Verbatim(v) => inconsequential(v, bubble),

        _ => Err("Exhaustive pattern for 'type' reached".into()),
    }
}

fn parse_typed_array(array: &mut syn::TypeArray, bubble: &mut Bubble) -> ret!() {
    parse_type(&mut array.elem, bubble)
}

fn parse_bare_fn(bare_fn: &mut syn::TypeBareFn, bubble: &mut Bubble) -> ret!() {
    bare_fn.inputs.iter_mut().try_for_each(|arg| parse_type(&mut arg.ty, bubble))
}

fn parse_paren(paren: &mut syn::TypeParen, bubble: &mut Bubble) -> ret!() {
    parse_type(&mut paren.elem, bubble)
}

fn parse_ptr(ptr: &mut syn::TypePtr, bubble: &mut Bubble) -> ret!() {
    parse_type(&mut ptr.elem, bubble)
}

fn parse_ref(reference: &mut syn::TypeReference, bubble: &mut Bubble) -> ret!() {
    parse_type(&mut reference.elem, bubble)
}

fn parse_slice(slice: &mut syn::TypeSlice, bubble: &mut Bubble) -> ret!() {
    parse_type(&mut slice.elem, bubble)
}

fn parse_trait_object(trait_object: &mut syn::TypeTraitObject, bubble: &mut Bubble) -> ret!() {
    trait_object.bounds.iter_mut().try_for_each(|bound| {
        match bound {
            syn::TypeParamBound::Trait(trait_bound) => parse_trait_bound(trait_bound, bubble),
            _ => Ok(())
        }
    })
}

fn parse_tuple(tuple: &mut syn::TypeTuple, bubble: &mut Bubble) -> ret!() {
    tuple.elems.iter_mut().try_for_each(|elem| parse_type(elem, bubble) )
}

fn parse_trait_bound(trait_bound: &mut syn::TraitBound, bubble: &mut Bubble) -> ret!() {
    parse_path(&mut trait_bound.path, bubble)
}

/// Parses a path
///
/// A path may contain the identity looked for by the host_interface attribute. If it is found
/// within the path, it will modify the `HostInterface` structure according to the requirements of
/// the feature.
fn parse_path(path: &mut syn::Path, bubble: &mut Bubble) -> ret!() {
    path.segments.iter_mut().try_for_each( |segment| {
        if bubble.check_ident(&segment.ident) {
            match &bubble.generic_change() {
                FeatureGenerics::None => (),
                FeatureGenerics::FlowControl => flow_control::modify_path_segment(segment, bubble)?,
            }
        }
        Ok(())
    })
}

fn parse_enum_variant(variant: &mut syn::Variant, bubble: &mut Bubble) -> ret!() {
    parse_fields(&mut variant.fields, bubble)
}

fn parse_fields(fields: &mut syn::Fields, bubble: &mut Bubble) -> ret!() {
    match fields {
        syn::Fields::Unit => Ok(()),
        syn::Fields::Named(named_fields) => parse_fields_named(named_fields, bubble),
        syn::Fields::Unnamed(unnamed_fields) => parse_fields_unnamed(unnamed_fields, bubble),
    }
}

fn parse_fields_named(fields: &mut syn::FieldsNamed, bubble: &mut Bubble) -> ret!() {
    fields.named.iter_mut().try_for_each(|field| parse_type(&mut field.ty, bubble))
}

fn parse_fields_unnamed(fields: &mut syn::FieldsUnnamed, bubble: &mut Bubble) -> ret!() {
    fields.unnamed.iter_mut().try_for_each(|field| parse_type(&mut field.ty, bubble))
}

fn parse_return(ret: &mut syn::ReturnType, bubble: &mut Bubble) -> ret!() {
    match ret {
        syn::ReturnType::Default => Ok(()),
        syn::ReturnType::Type(_, ty) => parse_type(ty, bubble),
    }
}