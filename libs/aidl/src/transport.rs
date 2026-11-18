// SPDX-License-Identifier: Apache-2.0

use quote::{format_ident, quote};
use std::io;
use syn::{parse_quote, Expr, Ident, Item, Pat, Stmt};

fn name(ident: &Ident) -> String {
    ident.to_string().trim_start_matches("r#").to_owned()
}

pub(super) fn variant(method: &Ident) -> Ident {
    let method = name(method);
    let mut chars = method.chars();
    format_ident!("{}{}", chars.next().expect("SDK method").to_ascii_uppercase(), chars.as_str())
}

pub(super) fn field(ident: &Ident) -> io::Result<Ident> {
    let argument = name(ident);
    let argument = argument.strip_prefix("_arg_").expect("SDK argument name");
    let mut result = String::new();
    for ch in argument.chars() {
        if ch.is_ascii_uppercase() {
            result.push('_');
            result.push(ch.to_ascii_lowercase());
        } else {
            result.push(ch);
        }
    }
    syn::parse_str(&result)
        .or_else(|_| syn::parse_str(&format!("r#{result}")))
        .map_err(io::Error::other)
}

/// Copy the official dispatcher reads, rather than reconstructing an AIDL wire schema.
pub(super) fn extend(file: &mut syn::File, request_type: &str) -> io::Result<()> {
    let request: syn::Path = syn::parse_str(request_type).map_err(io::Error::other)?;
    let dispatcher = file
        .items
        .iter()
        .find_map(|item| match item {
            Item::Fn(item) if item.sig.ident == "on_transact" => Some(item),
            _ => None,
        })
        .expect("SDK dispatcher");
    let [Stmt::Expr(Expr::Match(dispatch), None)] = dispatcher.block.stmts.as_slice() else {
        panic!("SDK dispatcher match");
    };
    let mut arms = Vec::new();
    let mut variants = Vec::new();
    for arm in &dispatch.arms {
        if matches!(&arm.pat, Pat::Wild(_)) {
            arms.push(quote!(#arm));
            continue;
        }
        let Pat::Path(pattern) = &arm.pat else { panic!("SDK transaction pattern") };
        let method = &pattern.path.segments.last().expect("SDK transaction").ident;
        let method_name = name(method);
        if matches!(method_name.as_str(), "getInterfaceVersion" | "getInterfaceHash") {
            continue;
        }
        let Expr::Block(body) = arm.body.as_ref() else { panic!("SDK transaction body") };
        let invocation = body.block.stmts.iter().position(|stmt| {
            matches!(stmt, Stmt::Local(local) if matches!(&local.pat, Pat::Ident(ident) if ident.ident == "_aidl_return"))
        }).expect("SDK service invocation");
        let reads = &body.block.stmts[..invocation];
        let mut fields = Vec::new();
        let mut bindings = Vec::new();
        for stmt in reads {
            let Stmt::Local(local) = stmt else { continue };
            let Pat::Type(typed) = &local.pat else { continue };
            let Pat::Ident(ident) = typed.pat.as_ref() else { panic!("SDK argument binding") };
            if !name(&ident.ident).starts_with("_arg_") {
                continue;
            }
            let field = field(&ident.ident)?;
            let ty = &typed.ty;
            let ident = &ident.ident;
            fields.push(quote!(#field: #ty));
            bindings.push(quote!(#field: #ident));
        }
        let variant = variant(method);
        let value = if fields.is_empty() {
            variants.push(quote!(#variant));
            quote!(#request::#variant)
        } else {
            variants.push(quote!(#variant { #(#fields),* }));
            quote!(#request::#variant { #(#bindings),* })
        };
        let pattern = &arm.pat;
        arms.push(quote!(#pattern => { #(#reads)* Ok(#value) }));
    }
    let request_name = &request.segments.last().expect("parsed request path").ident;
    file.items.push(parse_quote! {
        #[derive(Debug)]
        pub enum #request_name { #(#variants),* }
    });
    file.items.push(parse_quote! {
        pub mod transport {
            use super::transactions;

            pub fn read_request(
                _aidl_code: binder::binder_impl::TransactionCode,
                _aidl_data: &binder::binder_impl::BorrowedParcel<'_>,
            ) -> std::result::Result<#request, binder::StatusCode> {
                match _aidl_code { #(#arms),* }
            }
        }
    });
    Ok(())
}

pub(super) fn rpc_mapping(
    file: &mut syn::File,
    peer: &syn::File,
    peer_path: &str,
) -> io::Result<()> {
    use quote::ToTokens;
    use std::collections::BTreeMap;
    type Signature = (Ident, Vec<syn::Type>, syn::ReturnType);
    fn methods(file: &syn::File) -> io::Result<BTreeMap<String, Signature>> {
        let dispatcher = file
            .items
            .iter()
            .find_map(|item| match item {
                Item::Fn(item) if item.sig.ident == "on_transact" => Some(item),
                _ => None,
            })
            .ok_or_else(|| io::Error::other("SDK dispatcher missing"))?;
        let [Stmt::Expr(Expr::Match(dispatch), None)] = dispatcher.block.stmts.as_slice() else {
            return Err(io::Error::other("SDK dispatcher shape changed"));
        };
        let transactions: std::collections::BTreeSet<_> = dispatch
            .arms
            .iter()
            .filter_map(|arm| {
                let Pat::Path(pattern) = &arm.pat else { return None };
                Some(name(&pattern.path.segments.last()?.ident))
            })
            .collect();
        let interface = file.items.iter().find_map(|item| match item {
            Item::Trait(item) if item.supertraits.iter().any(|bound| matches!(bound, syn::TypeParamBound::Trait(bound) if bound.path.segments.last().is_some_and(|part| part.ident == "Interface"))) => Some(item),
            _ => None,
        }).ok_or_else(|| io::Error::other("SDK synchronous interface missing"))?;
        Ok(interface
            .items
            .iter()
            .filter_map(|item| {
                let syn::TraitItem::Fn(method) = item else { return None };
                let key = name(&method.sig.ident);
                if !transactions.contains(&key)
                    || matches!(key.as_str(), "getInterfaceVersion" | "getInterfaceHash")
                {
                    return None;
                }
                let args = method
                    .sig
                    .inputs
                    .iter()
                    .filter_map(|arg| match arg {
                        syn::FnArg::Typed(arg) => Some((*arg.ty).clone()),
                        _ => None,
                    })
                    .collect();
                Some((key, (method.sig.ident.clone(), args, method.sig.output.clone())))
            })
            .collect())
    }
    let caller: syn::Type =
        parse_quote!(Option<&crate::mangled::_3_top_7_qwq2333_11_ohmykeymint_10_CallerInfo>);
    let peer_methods = methods(peer)?;
    let peer_path: syn::Path = syn::parse_str(peer_path).map_err(io::Error::other)?;
    let mut arms = Vec::new();
    for (key, (method, args, result)) in methods(file)? {
        let (peer_method, peer_args, peer_result) = peer_methods
            .get(&key)
            .ok_or_else(|| io::Error::other(format!("RPC method {key} missing")))?;
        let has_caller = peer_args.len() == args.len() + 1;
        let matched = if has_caller { &peer_args[1..] } else { peer_args.as_slice() };
        if matched.len() != args.len()
            || args.iter().zip(matched).any(|(left, right)| {
                left.to_token_stream().to_string() != right.to_token_stream().to_string()
            })
            || result.to_token_stream().to_string() != peer_result.to_token_stream().to_string()
            || (has_caller
                && peer_args[0].to_token_stream().to_string()
                    != caller.to_token_stream().to_string())
        {
            return Err(io::Error::other(format!("RPC signature mismatch for {key}")));
        }
        arms.push(quote!(transactions::#method => Some((#peer_path::transactions::#peer_method, #has_caller))));
    }
    transport_module(file).push(parse_quote! {
        pub fn rpc_transaction(code: u32) -> Option<(u32, bool)> {
            match code { #(#arms,)* _ => None }
        }
    });
    Ok(())
}

fn transport_module(file: &mut syn::File) -> &mut Vec<Item> {
    let index = file
        .items
        .iter()
        .position(|item| matches!(item, Item::Mod(item) if item.ident == "transport"));
    let index = index.unwrap_or_else(|| {
        file.items.push(parse_quote!(
            pub mod transport {
                use super::transactions;
            }
        ));
        file.items.len() - 1
    });
    let Item::Mod(module) = &mut file.items[index] else { unreachable!() };
    &mut module.content.as_mut().expect("inline transport module").1
}

pub(super) fn validate(file: &mut syn::File) -> io::Result<()> {
    let dispatcher = file
        .items
        .iter()
        .find_map(|item| match item {
            Item::Fn(item) if item.sig.ident == "on_transact" => Some(item),
            _ => None,
        })
        .ok_or_else(|| io::Error::other("SDK dispatcher missing"))?;
    let [Stmt::Expr(Expr::Match(dispatch), None)] = dispatcher.block.stmts.as_slice() else {
        return Err(io::Error::other("SDK dispatcher shape changed"));
    };
    let mut arms = Vec::new();
    for arm in &dispatch.arms {
        let Pat::Path(pattern) = &arm.pat else {
            arms.push(quote!(#arm));
            continue;
        };
        let method = &pattern.path.segments.last().expect("transaction").ident;
        if matches!(name(method).as_str(), "getInterfaceVersion" | "getInterfaceHash") {
            continue;
        }
        let Expr::Block(body) = arm.body.as_ref() else {
            return Err(io::Error::other("SDK transaction shape changed"));
        };
        let call = body.block.stmts.iter().position(|stmt| matches!(stmt, Stmt::Local(local) if matches!(&local.pat, Pat::Ident(ident) if ident.ident == "_aidl_return")))
            .ok_or_else(|| io::Error::other("SDK call missing"))?;
        let reads = &body.block.stmts[..call];
        let pattern = &arm.pat;
        arms.push(quote!(#pattern => { #(#reads)* Ok(()) }));
    }
    transport_module(file).push(parse_quote! {
        pub fn validate_request(_aidl_code: u32, _aidl_data: &binder::binder_impl::BorrowedParcel<'_>) -> std::result::Result<(), binder::StatusCode> {
            match _aidl_code { #(#arms),* }
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::ToTokens;

    #[test]
    fn rpc_mapping_requires_the_same_nullable_signature_and_only_maps_transactions() {
        let source = r#"
            pub trait Public: binder::Interface {
                fn method(&self, key: Option<&[u8]>) -> binder::Result<Vec<u8>>;
                fn try_as_async_server(&self) -> bool { false }
            }
            fn on_transact(service: &dyn Public, code: u32, data: &Parcel, reply: &mut Parcel) -> Result<()> {
                match code {
                    transactions::method => {
                        let _arg_key: Option<Vec<u8>> = data.read()?;
                        let _aidl_return = service.method(_arg_key.as_deref());
                        reply.write(&_aidl_return)?;
                        Ok(())
                    }
                    _ => Err(binder::StatusCode::UNKNOWN_TRANSACTION),
                }
            }
        "#;
        let private = source.replace("pub trait Public", "pub trait Private")
            .replace("fn method(&self,", "fn method(&self, caller: Option<&crate::mangled::_3_top_7_qwq2333_11_ohmykeymint_10_CallerInfo>,");
        let mut file = syn::parse_file(source).unwrap();
        let original = file.to_token_stream().to_string();
        rpc_mapping(&mut file, &syn::parse_file(&private).unwrap(), "crate::private").unwrap();
        let mapping = file.items.pop().unwrap().to_token_stream().to_string();
        assert_eq!(file.to_token_stream().to_string(), original);
        assert!(mapping.contains("crate :: private :: transactions :: method , true"));
        assert!(!mapping.contains("try_as_async_server"));
        let incompatible = private.replace("key: Option<&[u8]>", "key: &[u8]");
        assert!(rpc_mapping(&mut file, &syn::parse_file(&incompatible).unwrap(), "crate::private")
            .is_err());
    }

    const INPUT: &str = r#"
        mod transactions { const updateKey: u32 = 1; const abort: u32 = 2; }
        fn on_transact(_aidl_service: &dyn Test, _aidl_code: u32, _aidl_data: &Parcel, _aidl_reply: &mut Parcel) -> Result<()> {
            match _aidl_code {
                transactions::updateKey => {
                    let _arg_keyBlob: Option<Vec<u8>> = _aidl_data.read()?;
                    let _arg_flags: i32 = _aidl_data.read()?;
                    let _aidl_return = _aidl_service.updateKey(_arg_keyBlob.as_deref(), _arg_flags);
                    match _aidl_return { Ok(value) => {}, Err(error) => {} }
                    Ok(())
                }
                transactions::abort => {
                    let _aidl_return = _aidl_service.abort();
                    match _aidl_return { Ok(value) => {}, Err(error) => {} }
                    Ok(())
                }
                _ => Err(binder::StatusCode::UNKNOWN_TRANSACTION),
            }
        }
    "#;

    #[test]
    fn codec_retains_sdk_read_order_and_owned_types() {
        let mut file = syn::parse_file(INPUT).unwrap();
        extend(&mut file, "crate::Request").unwrap();
        let Item::Enum(request) = &file.items[file.items.len() - 2] else { panic!() };
        let fields = request.to_token_stream().to_string();
        assert!(fields.contains("key_blob : Option < Vec < u8 > >"));
        assert!(fields.contains("flags : i32"));
        assert_eq!(request.variants.len(), 2);
        let generated = file.items.last().unwrap().to_token_stream().to_string();
        assert!(generated.contains("let _arg_keyBlob : Option < Vec < u8 > >"));
        assert!(generated.contains("UpdateKey"));
        assert!(generated.contains("Request :: Abort"));
        assert!(
            generated.find("let _arg_keyBlob").unwrap() < generated.find("let _arg_flags").unwrap()
        );
    }
}
