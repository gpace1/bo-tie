//! Processing of the args of the host_interface

const FLOW_CTRL_GENERIC: &'static str = "flow_ctrl_generic";
const FLOW_CTRL_CONCRETE: &'static str = "flow_ctrl_concrete";
const FLOW_CTRL_BOUNDS: &'static str = "flow_ctrl_bounds";

pub enum AttributeConfig {
    None,
    FlowCtrlGeneric(String),
    FlowCtrlConcrete(String),
    FlowCtrlBounds(Vec<syn::TypeParamBound>),
}

impl Default for AttributeConfig {
    fn default() -> Self {
        AttributeConfig::None
    }
}
impl AttributeConfig {
    pub fn is_concrete(&self) -> bool {
        match self {
            Self::FlowCtrlConcrete(_) => true,
            _ => false
        }
    }
}

pub fn process_args(args: &syn::AttributeArgs) -> Result<AttributeConfig, String> {
    args.into_iter().try_fold(AttributeConfig::None, |mut cfg, nested_meta| {
        match nested_meta {
            syn::NestedMeta::Meta(meta) => process_meta(&meta, &mut cfg)?,
            syn::NestedMeta::Lit(lit) => process_lit(&lit, &mut cfg)?,
        }

        Ok(cfg)
    })
}

fn process_meta(meta: &syn::Meta, cfg: &mut AttributeConfig) -> Result<(), String> {
    match meta {
        syn::Meta::Path(path) => process_only_path(path, cfg),
        syn::Meta::List(meta_list) => process_list(meta_list, cfg),
        syn::Meta::NameValue(meta_named_val) => process_named_val(meta_named_val, cfg),
    }
}

fn process_lit(_: &syn::Lit, _: &mut AttributeConfig) -> Result<(), String> {
    Err( "Pure literal are not supported as attribute args for attribute host_interface".into() )
}

fn process_only_path(_: &syn::Path, _: &mut AttributeConfig) -> Result<(), String> {
    Err( "Unexpected lone arg".into() )
}

fn process_list(list: &syn::MetaList, cfg: &mut AttributeConfig) -> Result<(), String> {
    list.nested.iter().try_for_each(|nested| process_nested(nested, cfg) )
}

fn process_nested(nested: &syn::NestedMeta, cfg: &mut AttributeConfig) -> Result<(), String> {
    match nested {
        syn::NestedMeta::Meta(meta) => process_meta(meta, cfg),
        syn::NestedMeta::Lit(lit) => process_lit(lit, cfg),
    }
}

fn process_named_val(named_val: &syn::MetaNameValue, cfg: &mut AttributeConfig)
-> Result<(), String> {
    if named_val.path.get_ident().map(|i| i == FLOW_CTRL_GENERIC).unwrap_or_default()  {
        process_flow_ctrl_generic(&named_val.lit, cfg)

    } else if named_val.path.get_ident().map(|i| i == FLOW_CTRL_CONCRETE).unwrap_or_default() {
        process_flow_ctrl_concrete(&named_val.lit, cfg)

    } else if named_val.path.get_ident().map(|i| i == FLOW_CTRL_BOUNDS).unwrap_or_default() {
        process_flow_ctrl_bounds(&named_val.lit, cfg)

    } else {
        Err("Unrecognized named val in host_interface attribute".into())
    }
}

fn process_str_lit(lit: &syn::Lit) -> Result<String, String> {
    if let syn::Lit::Str(str) = lit {
        Ok( str.value() )
    } else {
        return Err("host_interface only accepts strings for the values of assigned inputs".into())
    }
}

fn process_flow_ctrl_generic(lit: &syn::Lit, cfg: &mut AttributeConfig) -> Result<(), String> {
    let generic = process_str_lit(lit)?;

    match cfg {
        AttributeConfig::None => *cfg = AttributeConfig::FlowCtrlGeneric(generic),
        _ => return Err("Conflicting inputs for host_interface, only one is supported".into()),
    }

    Ok(())
}

fn process_flow_ctrl_concrete(lit: &syn::Lit, cfg: &mut AttributeConfig) -> Result<(), String> {
    let concrete = process_str_lit(lit)?;

    match cfg {
        AttributeConfig::None => *cfg = AttributeConfig::FlowCtrlConcrete(concrete),
        _ => return Err("Conflicting inputs for host_interface, only one is supported".into()),
    }

    Ok(())
}

fn process_flow_ctrl_bounds(lit: &syn::Lit, cfg: &mut AttributeConfig) -> Result<(), String> {

    let bound_list = process_str_lit(lit)?.split('+')
        .try_fold( Vec::new(), |mut v,s| {
            if let Ok(p) = syn::parse_str(&s) {
                v.push(p);
                Ok(v)
            } else {
                Err(format!("failed to parse bound {} in arg",s))
            }
        })?;

    match cfg {
        AttributeConfig::None => *cfg = AttributeConfig::FlowCtrlBounds(bound_list),
        _ => return Err("Conflicting inputs for host_interface, only one is supported".into()),
    }

    Ok(())
}