//! Flow Control modification methods
//!
//! These functions modify a token tree for the 'flow-ctrl' feature.

pub fn generic_param() -> syn::GenericParam {
    syn::parse_quote!(F)
}

/// Check that the generics are not already implemented
///
/// Returns true if the `generic_name` in `bubble` is found within `generic_args`
fn check_generic_args<'a>(
    mut generic_args: impl Iterator<Item = &'a mut syn::GenericArgument>,
    bubble: &super::Bubble
) -> bool {
    generic_args.any(|ga| match ga {
        syn::GenericArgument::Type(syn::Type::Path(syn::TypePath {
            path: syn::Path {segments, ..}, .. })) =>
        {
            segments.first().map(|first| first.ident == bubble.generic_name.as_ref() )
                .unwrap_or_default()
        }
        _ => false
    })
}

/// Check that the generics are not already implemented
///
/// Returns true if the `generic_name` in `bubble` is found within `params`
pub(super) fn already_has_generic<'a>(
    mut params: impl Iterator<Item=&'a mut syn::GenericParam>,
    bubble: &super::Bubble
) -> bool {
    params.any( |gp| match gp {
        syn::GenericParam::Type(syn::TypeParam { ident, ..}) =>
            ident == bubble.generic_name.as_ref(),
        _ => false
    })
}

pub(super) fn modify_path_segment( segment: &mut syn::PathSegment, bubble: &mut super::Bubble, )
-> ret!()
{
    match &mut segment.arguments {
        syn::PathArguments::None => segment.arguments =
            syn::PathArguments::AngleBracketed(syn::parse_quote!(::<F>)),

        syn::PathArguments::AngleBracketed(ab) => {
            if !check_generic_args(ab.args.iter_mut(), bubble) {
                match &bubble.cfg {
                    super::args::AttributeConfig::FlowCtrlGeneric(generic) => {
                        ab.args.push(syn::parse_str(&generic).unwrap())
                    }
                    super::args::AttributeConfig::FlowCtrlConcrete(concrete) => {
                        ab.args.push(syn::parse_str(&concrete).unwrap())
                    }
                    _ => ab.args.push(syn::parse_quote!(F)),
                }

            }
        },

        syn::PathArguments::Parenthesized(_) => {
            return Err("Parenthesized path segments are not implemented for flow-control for \
            attribute host_interface".into())
        },
    };

    Ok(())
}

pub(super) fn modify_where_clause( clause: &mut Option<syn::WhereClause>, bubble: &mut super::Bubble )
-> ret!()
{
    use std::mem::take;

    if let super::args::AttributeConfig::FlowCtrlBounds(bounds) = take(&mut bubble.cfg) {
        match clause {
            Some(clause) => {
                let mut bounded_type: syn::WherePredicate = syn::parse_quote!(F:);

                if let syn::WherePredicate::Type(predicate_type) = &mut bounded_type {
                    bounds.into_iter().for_each(|bound| predicate_type.bounds.push(bound));
                } else {
                    return Err("Failed to parse 'F' into `WherePredicate`".into())
                }

                clause.predicates.push(bounded_type)
            },
            None => (),
        }
    }

    Ok(())
}