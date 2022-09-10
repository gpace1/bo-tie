//! Module for [`DepthCounter`]

use proc_macro2::{Delimiter, Group, Literal, Punct, Spacing, Span, TokenStream};
use quote::{ToTokens, TokenStreamExt};
use syn::punctuated::{Pair, Punctuated};
use syn::spanned::Spanned;

/// `DepthCounter` is use to generate the `Tokenstream` used for calculating the depth of an
/// enumeration within an enum. It is used to print out the expression that comes after the `=>`
/// within the implementation of method `get_depth`.
pub struct GetDepthCounter {
    unit_count: usize,
    types_used: Vec<DepthType>,
}

impl GetDepthCounter {
    pub fn new() -> Self {
        let unit_count = 0;
        let types_used = Vec::new();

        GetDepthCounter { unit_count, types_used }
    }

    pub fn inc_unit_count(&mut self) {
        self.unit_count += 1;
    }

    pub fn inc_types_used(&mut self, paths: Vec<syn::Path>) {
        let depth_type = DepthType { paths };

        self.types_used.push(depth_type);
    }

    /// Create the depth calculation for a unit enumeration
    ///
    /// This is used to create the expression for calculating the dept of a unit enumeration
    pub fn unit_depth(&self) -> impl ToTokens + '_ {
        struct Unit<'a>(&'a GetDepthCounter);

        impl ToTokens for Unit<'_> {
            fn to_tokens(&self, tokens: &mut TokenStream) {
                if !self.0.types_used.is_empty() {
                    tokens.append_separated(self.0.types_used.iter(), Punct::new('+', Spacing::Alone));

                    tokens.append(Punct::new('+', Spacing::Alone));
                }

                tokens.append(Literal::usize_suffixed(self.0.unit_count));
            }
        }

        Unit(self)
    }

    /// Create the depth calculation for an enumeration with unnamed fields
    ///
    /// This is used to create the expression for calculating the depth of an enumeration with
    /// unnamed fields.
    pub fn unnamed_depth<'a>(&'a self, t: Vec<(syn::Path, syn::Ident)>) -> impl ToTokens + 'a {
        struct Unnamed<'a>(&'a GetDepthCounter, Vec<(syn::Path, syn::Ident)>);

        impl ToTokens for Unnamed<'_> {
            fn to_tokens(&self, tokens: &mut TokenStream) {
                let iter = self.1.iter().enumerate().map(|(cnt, (path, ident))| {
                    let get_depth_call = quote::quote_spanned!(path.span()=> #ident . get_depth());

                    let multipliers = self
                        .1
                        .get(0..cnt)
                        .into_iter()
                        .flatten()
                        .map(|(path, _)| {
                            let full_depth_call: syn::Expr =
                                syn::parse_quote_spanned!(path.span()=> #path :: full_depth());

                            let token = syn::Token!(*)(Span::call_site());

                            Pair::Punctuated(full_depth_call, token)
                        })
                        .collect::<Punctuated<syn::Expr, syn::token::Star>>();

                    quote::quote! {
                        ( #multipliers #get_depth_call )
                    }
                });

                tokens.append_separated(iter, Punct::new('+', Spacing::Alone));

                tokens.append(Punct::new('+', Spacing::Alone));

                if !self.0.types_used.is_empty() {
                    tokens.append_separated(self.0.types_used.iter(), Punct::new('+', Spacing::Alone));

                    tokens.append(Punct::new('+', Spacing::Alone));
                }

                tokens.append(Literal::usize_suffixed(self.0.unit_count))
            }
        }

        Unnamed(self, t)
    }
}

pub struct FromDepthConsts {
    unit_count: usize,
    prior_types: Vec<DepthType>,
}

impl FromDepthConsts {
    pub fn new() -> Self {
        let unit_count = 0;
        let prior_types = Vec::new();

        FromDepthConsts {
            unit_count,
            prior_types,
        }
    }

    pub fn inc_unit_count(&mut self) {
        self.unit_count += 1;
    }

    pub fn inc_types_used(&mut self, paths: Vec<syn::Path>) {
        let depth_type = DepthType { paths };

        self.prior_types.push(depth_type);
    }

    /// Construct the constant for the depth of a unit enum
    pub fn unit_depth_const(&self, name: syn::Ident) -> impl ToTokens + '_ {
        struct Unit<'a> {
            const_name: String,
            depth_counter: &'a FromDepthConsts,
        }

        impl ToTokens for Unit<'_> {
            fn to_tokens(&self, tokens: &mut TokenStream) {
                let const_name = syn::Ident::new(&self.const_name, Span::call_site());

                tokens.extend(quote::quote!( const #const_name : usize = ));

                if !self.depth_counter.prior_types.is_empty() {
                    tokens.append_separated(self.depth_counter.prior_types.iter(), Punct::new('+', Spacing::Alone));

                    tokens.append(Punct::new('+', Spacing::Alone));
                }

                tokens.append(Literal::usize_suffixed(self.depth_counter.unit_count));

                tokens.extend(quote::quote!(;));
            }
        }

        let const_name = name.to_string() + "_DEPTH";

        Unit {
            const_name,
            depth_counter: self,
        }
    }

    /// Construct the constant for the depth of a unnamed field enum
    pub fn unnamed_depth_const(&self, name: syn::Ident, t: Vec<syn::Path>) -> impl ToTokens + '_ {
        struct Unnamed<'a> {
            const_name_lower: String,
            const_name_upper: String,
            depth_counter: &'a FromDepthConsts,
            unnamed_fields: Vec<syn::Path>,
        }

        impl Unnamed<'_> {
            fn to_tokens_lower(&self, tokens: &mut TokenStream) {
                let const_name = syn::Ident::new(&self.const_name_lower, Span::call_site());

                tokens.extend(quote::quote!( const #const_name : usize = ));

                if !self.depth_counter.prior_types.is_empty() {
                    tokens.append_separated(self.depth_counter.prior_types.iter(), Punct::new('+', Spacing::Alone));

                    tokens.append(Punct::new('+', Spacing::Alone));
                }

                tokens.append(Literal::usize_suffixed(self.depth_counter.unit_count));

                tokens.extend(quote::quote!(;));
            }

            fn to_tokens_upper(&self, tokens: &mut TokenStream) {
                let const_name = syn::Ident::new(&self.const_name_upper, Span::call_site());

                tokens.extend(quote::quote!( const #const_name : usize = ));

                if !self.depth_counter.prior_types.is_empty() {
                    tokens.append_separated(self.depth_counter.prior_types.iter(), Punct::new('+', Spacing::Alone));

                    tokens.append(Punct::new('+', Spacing::Alone));
                }

                let multipliers = self
                    .unnamed_fields
                    .iter()
                    .map(|path| -> syn::Expr { syn::parse_quote_spanned!(path.span()=> #path :: full_depth()) })
                    .collect::<Punctuated<syn::Expr, syn::token::Star>>();

                tokens.append(Group::new(Delimiter::Parenthesis, multipliers.into_token_stream()));

                tokens.extend(quote::quote!(-1usize));

                tokens.extend(quote::quote!(+));

                tokens.append(Literal::usize_suffixed(self.depth_counter.unit_count));

                tokens.extend(quote::quote!(;))
            }
        }

        impl ToTokens for Unnamed<'_> {
            fn to_tokens(&self, tokens: &mut TokenStream) {
                self.to_tokens_lower(tokens);
                self.to_tokens_upper(tokens);
            }
        }

        let const_name_lower = name.to_string() + "_DEPTH_LOWER_BOUND";
        let const_name_upper = name.to_string() + "_DEPTH_UPPER_BOUND";

        Unnamed {
            const_name_lower,
            const_name_upper,
            depth_counter: self,
            unnamed_fields: t,
        }
    }
}

pub struct FromDepthMatchArms;

impl FromDepthMatchArms {
    pub fn new() -> Self {
        Self
    }

    pub fn unit_match_arm(&self, name: syn::Ident) -> impl ToTokens {
        struct Unit {
            enumeration: syn::Ident,
            const_name: syn::Ident,
        }

        impl ToTokens for Unit {
            fn to_tokens(&self, tokens: &mut TokenStream) {
                let enumeration = self.enumeration.clone();
                let const_name = self.const_name.clone();

                tokens.extend(quote::quote!( #const_name => Self :: #enumeration, ));
            }
        }

        let const_name = syn::Ident::new(&(name.to_string() + "_DEPTH"), Span::call_site());

        Unit {
            enumeration: name.clone(),
            const_name,
        }
    }

    pub fn unnamed_match_arm(&self, name: syn::Ident, paths: Vec<syn::Path>) -> impl ToTokens {
        struct Unnamed {
            enumeration: syn::Ident,
            const_name_lower: syn::Ident,
            const_name_upper: syn::Ident,
            paths: Vec<syn::Path>,
        }

        impl ToTokens for Unnamed {
            fn to_tokens(&self, tokens: &mut TokenStream) {
                let enumeration = self.enumeration.clone();
                let const_name_lower = self.const_name_lower.clone();
                let const_name_upper = self.const_name_upper.clone();

                let unnamed = self
                    .paths
                    .iter()
                    .enumerate()
                    .map(|(cnt, path)| -> syn::Expr {
                        // The is the modulator for the depth of an unnamed field
                        //
                        // Any number larger than the significance of the unnamed
                        // field is scrubbed.
                        let modulator = quote::quote!( #path :: full_depth() );

                        if cnt == 0 || self.paths.is_empty() {
                            syn::parse_quote_spanned! {path.span()=>
                                #path :: from_depth( (val - #const_name_lower) % #modulator )
                            }
                        } else {
                            // This is the divisor for the depth of an unnamed field
                            //
                            // The prior unnamed fields depth is multiplied toghether
                            // to get the depth divisor. For example say the full
                            // depth of each of the two prior unnamed fiels are both
                            // 10.  Then the divisor for the thrid unnamed field will
                            // be 100.
                            let divisor = self
                                .paths
                                .get(0..cnt)
                                .into_iter()
                                .flatten()
                                .map(|path| -> syn::Expr {
                                    syn::parse_quote_spanned!(path.span()=> #path :: full_depth() )
                                })
                                .collect::<Punctuated<syn::Expr, syn::Token![*]>>();

                            // this is the calculation used for supplying each named
                            // field with the correct number to call the method
                            // from_depth with. Variable `val` here will be from the
                            // pattern (its type is a usize).
                            syn::parse_quote_spanned! {path.span()=>
                                #path :: from_depth( ( (val - #const_name_lower) / ( #divisor ) ) % #modulator )
                            }
                        }
                    })
                    .collect::<Punctuated<syn::Expr, syn::Token![,]>>();

                tokens.extend(
                    quote::quote!( val @ #const_name_lower ..= #const_name_upper => Self :: #enumeration ( #unnamed ), ),
                );
            }
        }

        let enumeration = name.clone();

        let const_name_lower = syn::Ident::new(&(name.to_string() + "_DEPTH_LOWER_BOUND"), Span::call_site());

        let const_name_upper = syn::Ident::new(&(name.to_string() + "_DEPTH_UPPER_BOUND"), Span::call_site());

        Unnamed {
            enumeration,
            const_name_lower,
            const_name_upper,
            paths,
        }
    }
}

struct DepthType {
    paths: Vec<syn::Path>,
}

impl ToTokens for DepthType {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let mut ts = TokenStream::new();

        ts.append_separated(
            self.paths
                .iter()
                .map(|path| quote::quote_spanned!(path.span()=> #path :: full_depth())),
            Punct::new('*', Spacing::Alone),
        );

        tokens.append(Group::new(Delimiter::Parenthesis, ts));
    }
}
