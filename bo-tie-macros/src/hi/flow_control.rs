//! Flow Control modification methods
//!
//! These functions modify a token tree for the 'flow-ctrl' feature.

pub fn generic_param() -> syn::GenericParam {
    syn::parse_quote!(F)
}

pub(super) fn modify_path_segment(segment: &mut syn::PathSegment, bubble: &mut super::Bubble )
-> ret!()
{
    match &mut segment.arguments {
        syn::PathArguments::None => segment.arguments =
            syn::PathArguments::AngleBracketed(syn::parse_quote!(::<F>)),

        syn::PathArguments::AngleBracketed(ab) => ab.args.push( syn::parse_quote!(F) ),

        syn::PathArguments::Parenthesized(par) => {
            par.inputs.iter_mut().try_for_each(|input| super::parse_type(input, bubble) )?;

            super::parse_return(&mut par.output, bubble)?
        },
    };

    Ok(())
}