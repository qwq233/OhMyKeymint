// SPDX-License-Identifier: Apache-2.0

use quote::{quote, ToTokens};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use syn::visit::{self, Visit};
use syn::visit_mut::{self, VisitMut};
use syn::{parse_quote, Expr, FnArg, GenericParam, ImplItem, Item, Pat, Signature, Stmt, Type};

struct BinderEnum {
    attributes: Vec<syn::Attribute>,
    name: syn::Ident,
    backing: Type,
    count: syn::LitInt,
    variants: syn::punctuated::Punctuated<syn::Variant, syn::Token![,]>,
}

impl syn::parse::Parse for BinderEnum {
    fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Self> {
        let attributes = input.call(syn::Attribute::parse_outer)?;
        let name = input.parse()?;
        input.parse::<syn::Token![:]>()?;
        let backing;
        syn::bracketed!(backing in input);
        let backing_type = backing.parse()?;
        backing.parse::<syn::Token![;]>()?;
        let count = backing.parse()?;
        let variants;
        syn::braced!(variants in input);
        Ok(Self {
            attributes,
            name,
            backing: backing_type,
            count,
            variants: variants.parse_terminated(syn::Variant::parse, syn::Token![,])?,
        })
    }
}

type HelperKey = (Vec<String>, String, String);

pub(super) fn prepare(
    source: &str,
    request_type: Option<&str>,
    union_guard: Option<&str>,
    inject_metadata: bool,
) -> io::Result<String> {
    let mut file = syn::parse_file(source).map_err(|error| io::Error::other(error.to_string()))?;
    let mut injectable_metadata = false;
    if inject_metadata {
        for item in &mut file.items {
            let Item::Trait(interface) = item else { continue };
            let is_interface = interface.supertraits.iter().any(|bound| {
                let syn::TypeParamBound::Trait(bound) = bound else { return false };
                bound.path.segments.last().is_some_and(|segment| segment.ident == "Interface")
            });
            if !is_interface {
                continue;
            }
            let mut metadata = 0;
            for item in &mut interface.items {
                let syn::TraitItem::Fn(method) = item else { continue };
                if method.default.is_none() {
                    continue;
                }
                let value: Expr = match method.sig.ident.to_string().trim_start_matches("r#") {
                    "getInterfaceVersion" => parse_quote!(
                        INJECTED_INTERFACE_METADATA.get().copied().unwrap_or((VERSION, HASH)).0
                    ),
                    "getInterfaceHash" => parse_quote!(INJECTED_INTERFACE_METADATA
                        .get()
                        .copied()
                        .unwrap_or((VERSION, HASH))
                        .1
                        .into()),
                    _ => continue,
                };
                let asynchronous = match &method.sig.output {
                    syn::ReturnType::Type(_, ty) => match ty.as_ref() {
                        Type::Path(path) => path
                            .path
                            .segments
                            .last()
                            .is_some_and(|segment| segment.ident == "BoxFuture"),
                        _ => false,
                    },
                    _ => false,
                };
                method.default = Some(if asynchronous {
                    parse_quote!({ Box::pin(async move { Ok(#value) }) })
                } else {
                    parse_quote!({ Ok(#value) })
                });
                metadata += 1;
            }
            if metadata == 2 {
                injectable_metadata = true;
            } else if metadata != 0 {
                return Err(io::Error::other("SDK metadata getters must be generated as a pair"));
            }
        }
    }
    if injectable_metadata {
        file.items.push(parse_quote! {
            static INJECTED_INTERFACE_METADATA: std::sync::OnceLock<(i32, &'static str)> = std::sync::OnceLock::new();
        });
        file.items.push(parse_quote! {
            /// Set this interface's metadata before publishing services; conflicting pairs are rejected.
            pub fn inject_interface_metadata(pair: (i32, &'static str)) -> bool {
                *INJECTED_INTERFACE_METADATA.get_or_init(|| pair) == pair
            }
        });
    }
    if let Some(guard) = union_guard {
        restrict_keymint_union(&mut file, guard)?;
    }
    if let Some(request_type) = request_type {
        super::transport::extend(&mut file, request_type)?;
    }
    file.attrs.retain(|attribute| {
        !(attribute.path().is_ident("cfg_attr")
            && matches!(&attribute.meta, syn::Meta::List(meta) if meta.tokens.to_string() == "rustfmt , rustfmt_skip"))
    });
    normalize_items(&mut file.items);
    let mut helpers = Helpers::default();
    helpers.visit_file(&file);
    let mut normalizer =
        Normalize { helpers: helpers.methods, modules: Vec::new(), self_type: String::new() };
    normalizer.visit_file_mut(&mut file);
    Ok(file.into_token_stream().to_string())
}

fn restrict_keymint_union(file: &mut syn::File, guard: &str) -> io::Result<()> {
    let guard: Expr = syn::parse_str(guard).map_err(io::Error::other)?;
    let mut matched = 0;
    for item in &mut file.items {
        let Item::Impl(item) = item else { continue };
        if !matches!(&*item.self_ty, Type::Path(value) if value.path.segments.last().is_some_and(|segment| segment.ident.to_string().trim_start_matches("r#") == "KeyParameterValue"))
            || !item.trait_.as_ref().is_some_and(|(path, _)| {
                path.segments.last().is_some_and(|segment| segment.ident == "Parcelable")
            })
        {
            continue;
        }
        for method in &mut item.items {
            let ImplItem::Fn(method) = method else { continue };
            if method.sig.ident != "read_from_parcel" {
                continue;
            }
            for statement in &mut method.block.stmts {
                let Stmt::Expr(Expr::Match(value), _) = statement else { continue };
                if !matches!(&*value.expr, Expr::Path(path) if path.path.is_ident("tag"))
                    || !value.arms.iter().any(|arm| {
                        matches!(&arm.pat, Pat::Wild(_))
                            && arm
                                .body
                                .to_token_stream()
                                .to_string()
                                .contains("StatusCode :: BAD_VALUE")
                    })
                {
                    continue;
                }
                for arm in &mut value.arms {
                    if matches!(&arm.pat, Pat::Lit(value) if matches!(&value.lit, syn::Lit::Int(value) if value.base10_digits() == "15"))
                        && arm.body.to_token_stream().to_string().contains("Self :: MlDsaVariant")
                    {
                        arm.pat = parse_quote!(15 if #guard);
                        matched += 1;
                    }
                }
            }
        }
    }
    if matched != 1 {
        return Err(io::Error::other("SDK KeyParameterValue read_from_parcel shape changed"));
    }
    Ok(())
}

fn default_value(expression: &Expr) -> bool {
    match expression {
        Expr::Lit(value) => match &value.lit {
            syn::Lit::Int(value) => value.base10_digits() == "0",
            syn::Lit::Float(value) => value.base10_parse::<f64>().is_ok_and(|value| value == 0.0),
            syn::Lit::Bool(value) => !value.value,
            syn::Lit::Char(value) => value.value() == '\0',
            _ => false,
        },
        Expr::Path(value) => value.path.is_ident("None"),
        Expr::Call(value) if value.args.is_empty() => {
            let path = value.func.to_token_stream().to_string();
            matches!(path.as_str(), "Default :: default" | "Vec :: new" | "String :: new")
        }
        Expr::Macro(value) => {
            value.mac.path.to_token_stream().to_string() == "alloc :: vec"
                && value.mac.tokens.is_empty()
        }
        _ => false,
    }
}

fn normalize_items(items: &mut Vec<Item>) {
    let mut defaults = BTreeMap::new();
    for item in items.iter() {
        let Item::Impl(item) = item else { continue };
        if !matches!(&item.trait_, Some((path, _)) if path.is_ident("Default"))
            || !item.generics.params.is_empty()
            || item.items.len() != 1
        {
            continue;
        }
        let Type::Path(target) = item.self_ty.as_ref() else { continue };
        let Some(target) = target.path.get_ident() else { continue };
        let ImplItem::Fn(method) = &item.items[0] else { continue };
        let [Stmt::Expr(Expr::Struct(value), None)] = method.block.stmts.as_slice() else {
            continue;
        };
        if method.sig.ident == "default"
            && value.path.is_ident("Self")
            && value.rest.is_none()
            && value.fields.iter().all(|field| default_value(&field.expr))
        {
            defaults.insert(
                target.to_string(),
                value
                    .fields
                    .iter()
                    .map(|field| field.member.to_token_stream().to_string())
                    .collect::<Vec<_>>(),
            );
        }
    }
    let mut derived = BTreeSet::new();
    for item in items.iter_mut() {
        if let Item::Struct(item) = item {
            let names = item
                .fields
                .iter()
                .filter_map(|field| field.ident.as_ref())
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            if defaults.get(&item.ident.to_string()) == Some(&names) {
                item.attrs.push(parse_quote!(#[derive(Default)]));
                derived.insert(item.ident.to_string());
            }
        }
        if let Item::Mod(item) = item {
            if let Some((_, items)) = &mut item.content {
                normalize_items(items);
            }
        }
    }
    items.retain(|item| {
        !matches!(item, Item::Impl(item)
            if matches!(&item.trait_, Some((path, _)) if path.is_ident("Default"))
            && matches!(item.self_ty.as_ref(), Type::Path(target) if target.path.get_ident().is_some_and(|name| derived.contains(&name.to_string()))))
    });

    items.retain(|item| {
        !matches!(item, Item::Use(item) if matches!(
            item.tree.to_token_stream().to_string().as_str(),
            "alloc :: boxed :: Box" | "alloc :: vec :: Vec" | "alloc :: string :: String"
                | "alloc :: string :: ToString" | "alloc :: borrow :: ToOwned"
        ))
    });
}

// Macro arguments are opaque to syn's path visitor.
fn std_macro_tokens(input: syn::parse::ParseStream<'_>) -> syn::Result<impl ToTokens> {
    let mut output = quote!();
    let mut segment = false;
    let mut qualified = false;
    while !input.is_empty() {
        if input.peek(syn::Ident) {
            let mut ident: syn::Ident = input.parse()?;
            if !qualified && ident == "alloc" && input.peek(syn::Token![::]) {
                ident = syn::Ident::new("std", ident.span());
            }
            ident.to_tokens(&mut output);
            segment = true;
        } else if input.peek(syn::Token![::]) {
            input.parse::<syn::Token![::]>()?.to_tokens(&mut output);
            qualified = segment;
        } else {
            if input.peek(syn::token::Brace) {
                let content;
                let delimiter = syn::braced!(content in input);
                let tokens = std_macro_tokens(&content)?;
                delimiter.surround(&mut output, |output| tokens.to_tokens(output));
            } else if input.peek(syn::token::Paren) {
                let content;
                let delimiter = syn::parenthesized!(content in input);
                let tokens = std_macro_tokens(&content)?;
                delimiter.surround(&mut output, |output| tokens.to_tokens(output));
            } else if input.peek(syn::token::Bracket) {
                let content;
                let delimiter = syn::bracketed!(content in input);
                let tokens = std_macro_tokens(&content)?;
                delimiter.surround(&mut output, |output| tokens.to_tokens(output));
            } else {
                input.step(|cursor| {
                    let (token, rest) =
                        cursor.token_tree().ok_or_else(|| cursor.error("macro token"))?;
                    token.to_tokens(&mut output);
                    Ok(((), rest))
                })?;
            }
            segment = false;
            qualified = false;
        }
    }
    Ok(output)
}

#[derive(Default)]
struct Helpers {
    modules: Vec<String>,
    methods: BTreeMap<HelperKey, Vec<Option<String>>>,
}

impl<'ast> Visit<'ast> for Helpers {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        self.modules.push(item.ident.to_string());
        visit::visit_item_mod(self, item);
        self.modules.pop();
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if item.trait_.is_none() {
            for method in &item.items {
                let ImplItem::Fn(method) = method else { continue };
                if matches!(method.vis, syn::Visibility::Inherited)
                    && method.sig.ident.to_string().starts_with("read_response_")
                    && method.sig.inputs.len() > 7
                {
                    let mut used = Identifiers::default();
                    used.visit_block(&method.block);
                    let arguments = method
                        .sig
                        .inputs
                        .iter()
                        .skip(1)
                        .map(|argument| {
                            let FnArg::Typed(argument) = argument else { return None };
                            let Pat::Ident(pattern) = argument.pat.as_ref() else { return None };
                            let name = pattern.ident.to_string();
                            (!used.0.contains(&name) && drop_free(&argument.ty)).then_some(name)
                        })
                        .collect();
                    self.methods.insert(
                        (
                            self.modules.clone(),
                            item.self_ty.to_token_stream().to_string(),
                            method.sig.ident.to_string(),
                        ),
                        arguments,
                    );
                }
            }
        }
        visit::visit_item_impl(self, item);
    }
}

#[derive(Default)]
struct Identifiers(BTreeSet<String>);

impl<'ast> Visit<'ast> for Identifiers {
    fn visit_ident(&mut self, name: &'ast syn::Ident) {
        self.0.insert(name.to_string());
    }
    fn visit_macro(&mut self, invocation: &'ast syn::Macro) {
        // Unknown macro grammar is treated conservatively, including identifiers in literals.
        self.0.extend(
            invocation
                .tokens
                .to_string()
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .filter(|word| !word.is_empty())
                .map(str::to_owned),
        );
    }
}

fn drop_free(value: &Type) -> bool {
    match value {
        Type::Reference(_) => true,
        Type::Path(value) => {
            let name = value.path.to_token_stream().to_string();
            if matches!(
                name.as_str(),
                "bool"
                    | "i8"
                    | "i16"
                    | "i32"
                    | "i64"
                    | "u8"
                    | "u16"
                    | "u32"
                    | "u64"
                    | "f32"
                    | "f64"
            ) {
                return true;
            }
            matches!(value.path.segments.last(), Some(segment)
                if segment.ident == "Option"
                && matches!(&segment.arguments, syn::PathArguments::AngleBracketed(arguments)
                    if arguments.args.len() == 1
                    && matches!(arguments.args.first(), Some(syn::GenericArgument::Type(Type::Reference(_))))))
        }
        _ => false,
    }
}

#[derive(Default)]
struct Lifetimes(BTreeMap<String, usize>);

impl<'ast> Visit<'ast> for Lifetimes {
    fn visit_lifetime(&mut self, lifetime: &'ast syn::Lifetime) {
        *self.0.entry(lifetime.ident.to_string()).or_default() += 1;
    }
}

fn elide_lifetimes(signature: &mut Signature, body: Option<&syn::Block>) {
    let mut inputs = Lifetimes::default();
    let mut receiver = None;
    for input in &signature.inputs {
        match input {
            FnArg::Receiver(value) => {
                if let syn::ReceiverKind::Reference(_, Some(lifetime), _) = &value.kind {
                    inputs.visit_lifetime(lifetime);
                    receiver = Some(lifetime.ident.to_string());
                }
            }
            FnArg::Typed(value) => inputs.visit_type(&value.ty),
        }
    }
    let mut outputs = Lifetimes::default();
    outputs.visit_return_type(&signature.output);
    let mut blocked = Lifetimes::default();
    if let Some(body) = body {
        blocked.visit_block(body);
    }
    if let Some(clause) = &signature.generics.where_clause {
        blocked.visit_where_clause(clause);
    }
    for parameter in &signature.generics.params {
        if let GenericParam::Lifetime(parameter) = parameter {
            if !parameter.bounds.is_empty() {
                blocked.visit_lifetime_param(parameter);
            }
        }
    }
    let mut remove = BTreeSet::new();
    for parameter in &signature.generics.params {
        let GenericParam::Lifetime(parameter) = parameter else { continue };
        let name = parameter.lifetime.ident.to_string();
        let input_count = inputs.0.get(&name).copied().unwrap_or(0);
        let output_count = outputs.0.get(&name).copied().unwrap_or(0);
        if input_count == 1
            && !blocked.0.contains_key(&name)
            && (output_count == 0 || (output_count == 1 && receiver.as_ref() == Some(&name)))
        {
            remove.insert(name);
        }
    }
    signature.generics.params = signature.generics.params.iter().filter(|parameter| {
        !matches!(parameter, GenericParam::Lifetime(parameter) if remove.contains(&parameter.lifetime.ident.to_string()))
    }).cloned().collect();
    struct Elide(BTreeSet<String>);
    impl VisitMut for Elide {
        fn visit_type_reference_mut(&mut self, value: &mut syn::TypeReference) {
            if value
                .lifetime
                .as_ref()
                .is_some_and(|lifetime| self.0.contains(&lifetime.ident.to_string()))
            {
                value.lifetime = None;
            }
            visit_mut::visit_type_reference_mut(self, value);
        }
        fn visit_receiver_mut(&mut self, value: &mut syn::Receiver) {
            if let syn::ReceiverKind::Reference(_, lifetime, _) = &mut value.kind {
                if lifetime
                    .as_ref()
                    .is_some_and(|lifetime| self.0.contains(&lifetime.ident.to_string()))
                {
                    *lifetime = None;
                }
            }
            visit_mut::visit_receiver_mut(self, value);
        }
        fn visit_lifetime_mut(&mut self, value: &mut syn::Lifetime) {
            if self.0.contains(&value.ident.to_string()) {
                *value = parse_quote!('_);
            }
        }
    }
    Elide(remove).visit_signature_mut(signature);
}

struct Normalize {
    helpers: BTreeMap<HelperKey, Vec<Option<String>>>,
    modules: Vec<String>,
    self_type: String,
}

impl Normalize {
    fn helper(&self, name: &str) -> Option<Vec<Option<String>>> {
        self.helpers.get(&(self.modules.clone(), self.self_type.clone(), name.to_owned())).cloned()
    }
}

impl VisitMut for Normalize {
    fn visit_path_mut(&mut self, path: &mut syn::Path) {
        if let Some(segment) = path.segments.first_mut().filter(|segment| segment.ident == "alloc")
        {
            segment.ident = syn::Ident::new("std", segment.ident.span());
        }
        visit_mut::visit_path_mut(self, path);
    }

    fn visit_item_use_mut(&mut self, item: &mut syn::ItemUse) {
        if let syn::UseTree::Path(path) = &mut item.tree {
            if path.ident == "alloc" {
                path.ident = syn::Ident::new("std", path.ident.span());
            }
        }
        visit_mut::visit_item_use_mut(self, item);
    }

    fn visit_item_mod_mut(&mut self, item: &mut syn::ItemMod) {
        self.modules.push(item.ident.to_string());
        visit_mut::visit_item_mod_mut(self, item);
        self.modules.pop();
    }

    fn visit_item_impl_mut(&mut self, item: &mut syn::ItemImpl) {
        item.attrs.retain(|attribute| {
            !matches!(&attribute.meta, syn::Meta::List(meta)
            if meta.path.is_ident("cfg") && meta.tokens.to_string() == "feature = \"std\"")
        });
        let old =
            std::mem::replace(&mut self.self_type, item.self_ty.to_token_stream().to_string());
        visit_mut::visit_item_impl_mut(self, item);
        self.self_type = old;
    }

    fn visit_impl_item_fn_mut(&mut self, method: &mut syn::ImplItemFn) {
        method.attrs.retain(|attribute| {
            !matches!(&attribute.meta, syn::Meta::List(meta)
            if meta.path.is_ident("cfg") && meta.tokens.to_string() == "feature = \"std\"")
        });
        elide_lifetimes(&mut method.sig, Some(&method.block));
        if let Some(arguments) = self.helper(&method.sig.ident.to_string()) {
            assert_eq!(method.sig.inputs.len(), arguments.len() + 1);
            method.sig.inputs = method
                .sig
                .inputs
                .iter()
                .enumerate()
                .filter(|(index, _)| *index == 0 || arguments[*index - 1].is_none())
                .map(|(_, argument)| argument.clone())
                .collect();
        }
        visit_mut::visit_impl_item_fn_mut(self, method);
    }

    fn visit_trait_item_fn_mut(&mut self, method: &mut syn::TraitItemFn) {
        elide_lifetimes(&mut method.sig, method.default.as_ref());
        visit_mut::visit_trait_item_fn_mut(self, method);
    }

    fn visit_item_fn_mut(&mut self, function: &mut syn::ItemFn) {
        elide_lifetimes(&mut function.sig, Some(&function.block));
        visit_mut::visit_item_fn_mut(self, function);
    }

    fn visit_expr_method_call_mut(&mut self, call: &mut syn::ExprMethodCall) {
        if matches!(call.receiver.as_ref(), Expr::Path(value) if value.path.is_ident("self")) {
            if let Some(arguments) = self.helper(&call.method.to_string()) {
                assert_eq!(call.args.len(), arguments.len());
                call.args = call
                    .args
                    .iter()
                    .zip(arguments)
                    .filter_map(|(argument, removed)| {
                        if let Some(name) = removed {
                            assert!(
                                matches!(argument, Expr::Path(value) if value.path.is_ident(&name))
                                    || matches!(argument, Expr::Lit(_)),
                                "unused helper argument has side effects"
                            );
                            None
                        } else {
                            Some(argument.clone())
                        }
                    })
                    .collect();
            }
        }
        visit_mut::visit_expr_method_call_mut(self, call);
    }

    fn visit_attribute_mut(&mut self, attribute: &mut syn::Attribute) {
        if attribute.path().is_ident("deprecated") {
            let note = match &attribute.meta {
                syn::Meta::NameValue(value) => match &value.value {
                    Expr::Lit(value) => match &value.lit {
                        syn::Lit::Str(value) => format!("# Deprecated\n{}", value.value()),
                        _ => "# Deprecated".into(),
                    },
                    _ => "# Deprecated".into(),
                },
                _ => "# Deprecated".into(),
            };
            *attribute = parse_quote!(#[doc = #note]);
        }
        visit_mut::visit_attribute_mut(self, attribute);
    }

    fn visit_macro_mut(&mut self, invocation: &mut syn::Macro) {
        use syn::parse::Parser;
        invocation.tokens = (|input: syn::parse::ParseStream<'_>| std_macro_tokens(input))
            .parse2(invocation.tokens.clone())
            .expect("official SDK macro tokens")
            .into_token_stream();
        if invocation
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "declare_binder_enum")
        {
            let mut declaration: BinderEnum =
                syn::parse2(invocation.tokens.clone()).expect("official binder enum syntax");
            for attribute in &mut declaration.attributes {
                self.visit_attribute_mut(attribute);
            }
            for variant in &mut declaration.variants {
                for attribute in &mut variant.attrs {
                    self.visit_attribute_mut(attribute);
                }
            }
            let BinderEnum { attributes, name, backing, count, variants } = declaration;
            invocation.tokens = quote!(#(#attributes)* #name: [#backing; #count] { #variants });
        }
        visit_mut::visit_macro_mut(self, invocation);
    }

    fn visit_expr_mut(&mut self, expression: &mut Expr) {
        if let Expr::Binary(binary) = expression {
            if matches!(binary.op, syn::BinOp::Add(_))
                && matches!(binary.right.as_ref(), Expr::Lit(value) if matches!(&value.lit, syn::Lit::Int(value) if value.base10_digits() == "0"))
                && binary.left.to_token_stream().to_string()
                    == "binder :: binder_impl :: FIRST_CALL_TRANSACTION"
            {
                *expression = *binary.left.clone();
            }
        }
        visit_mut::visit_expr_mut(self, expression);
    }

    fn visit_block_mut(&mut self, block: &mut syn::Block) {
        if block.stmts.len() == 2 {
            let last = block.stmts[1].to_token_stream().to_string();
            if last == "Ok (aidl_data)" {
                if let Stmt::Local(local) = &mut block.stmts[0] {
                    if let Pat::Ident(pattern) = &mut local.pat {
                        if pattern.ident == "aidl_data" {
                            pattern.mutability = None;
                        }
                    }
                }
            }
        }
        visit_mut::visit_block_mut(self, block);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_preserves_public_calls_and_async_borrow_constraints() {
        let source = r#"
            pub trait Api {
                fn call<'a, 'b>(&'a self, value: &'b [u8]) -> Result<(), ()>;
                fn future<'a>(&'a self, value: &'a [u8]) -> BoxFuture<'a, ()>;
            }
            struct Proxy;
            impl Proxy {
                fn read_response_call(&self, a:u8,b:u8,c:u8,d:u8,e:u8,f:u8,reply:u8) -> u8 { reply }
            }
            impl Api for Proxy {
                fn call<'a,'b>(&'a self,value:&'b [u8])->Result<(),()> {
                    self.read_response_call(1,2,3,4,5,6,7); Ok(())
                }
                fn future<'a>(&'a self,value:&'a [u8])->BoxFuture<'a,()> { todo!() }
            }
            mod child {
                struct Proxy;
                impl Proxy {
                    fn read_response_call(&self,_owned:String,a:u8,b:u8,c:u8,d:u8,e:u8,reply:u8)->u8 { reply }
                    fn caller(&self,_owned:String) { self.read_response_call(_owned,2,3,4,5,6,7); }
                }
            }
        "#;
        let output = prepare(source, None, None, false).unwrap();
        let parsed = syn::parse_file(&output).unwrap();
        let Item::Trait(api) = &parsed.items[0] else { panic!() };
        let syn::TraitItem::Fn(call) = &api.items[0] else { panic!() };
        assert!(call.sig.generics.params.is_empty());
        assert_eq!(call.sig.inputs.len(), 2);
        let syn::TraitItem::Fn(future) = &api.items[1] else { panic!() };
        assert_eq!(future.sig.generics.params.len(), 1);
        assert!(output.contains("read_response_call (7)"));
        assert!(output.contains("read_response_call (_owned , 7)"));
    }

    #[test]
    fn defaults_and_sensitive_parcels_retain_nondefault_behavior() {
        let source = r#"
            use alloc::boxed::Box;
            struct Zero { value:u32 }
            impl Default for Zero { fn default()->Self { Self { value:0 } } }
            struct Seven { value:u32 }
            impl Default for Seven { fn default()->Self { Self { value:7 } } }
            struct Reordered { first:u32, second:u32 }
            impl Default for Reordered { fn default()->Self { Self { second:0, first:0 } } }
            fn sensitive() {
                let mut aidl_data = self.binder.prepare_transact()?;
                aidl_data.mark_sensitive(); Ok(aidl_data)
            }
            fn empty() { let mut aidl_data = self.binder.prepare_transact()?; Ok(aidl_data) }
        "#;
        let output = prepare(source, None, None, false).unwrap();
        assert!(output.contains("derive (Default)"));
        assert!(!output.contains("Default for Zero"));
        assert!(output.contains("Default for Seven"));
        assert!(output.contains("Default for Reordered"));
        assert!(output.contains("let mut aidl_data"));
        assert!(output.contains("mark_sensitive"));
        assert!(output.contains("let aidl_data"));
        assert!(!output.contains("use alloc :: boxed :: Box"));
    }

    #[test]
    fn fixed_std_output_does_not_require_the_alloc_crate() {
        let output = prepare(
            r#"
                use alloc::boxed::Box;
                use alloc::vec::Vec;
                use std::alloc::Layout;
                struct Value { bytes: Box<::alloc::vec::Vec<u8>> }
                fn bytes() -> Vec<u8> { alloc::vec![1, 2] }
                declare_binder_interface! {
                    Api["example.Api"] {
                        proxy: Proxy { hash: Option<alloc::string::String> = None },
                    }
                }
            "#,
            None,
            None,
            false,
        )
        .unwrap();
        assert!(!output.contains("use std :: boxed :: Box"));
        assert!(output.contains("std :: vec :: Vec"));
        assert!(output.contains("std :: vec !"));
        assert!(output.contains("std :: alloc :: Layout"));
        assert!(!output.contains("use alloc"));
        assert!(!output.contains(":: alloc :: vec"));
        assert!(!output.contains("alloc :: string"));
    }

    #[test]
    fn framework_union_guard_preserves_sdk_fallback_and_writer() {
        let source = r#"
            impl binder::Parcelable for r#KeyParameterValue {
                fn read_from_parcel(&mut self, parcel: &BorrowedParcel) -> Result<(), StatusCode> {
                    let tag: i32 = parcel.read()?;
                    match tag {
                        0 => { *self = Self::Invalid(parcel.read()?); Ok(()) },
                        15 => { let value = parcel.read()?; *self = Self::MlDsaVariant(value); Ok(()) },
                        _ => Err(binder::StatusCode::BAD_VALUE),
                    }
                }
                fn write_to_parcel(&self, parcel: &mut BorrowedParcel) -> Result<(), StatusCode> {
                    match self { Self::MlDsaVariant(value) => { parcel.write(&15i32)?; parcel.write(value) }, _ => Ok(()) }
                }
            }
        "#;
        let plain = prepare(source, None, None, false).unwrap();
        let guarded = prepare(source, None, Some("crate::framework_v5()"), false).unwrap();
        assert!(!plain.contains("15 if"));
        assert!(guarded.contains("15 if crate :: framework_v5 ()"));
        let plain = syn::parse_file(&plain).unwrap();
        let guarded = syn::parse_file(&guarded).unwrap();
        let Item::Impl(plain) = &plain.items[0] else { panic!() };
        let Item::Impl(guarded) = &guarded.items[0] else { panic!() };
        assert_eq!(
            plain.items[1].to_token_stream().to_string(),
            guarded.items[1].to_token_stream().to_string()
        );
        for changed in
            [source.replace("Self::MlDsaVariant(value)", "Self::Future(value)"), source.repeat(2)]
        {
            assert!(prepare(&changed, None, Some("true"), false).is_err());
        }
        assert!(prepare("struct Other;", None, Some("true"), false).is_err());
    }

    #[test]
    fn metadata_injection_preserves_proxy_dispatch_and_async_defaults() {
        let source = r#"
            pub trait ITest: binder::Interface + Send {
                fn getInterfaceVersion(&self) -> binder::Result<i32> { Ok(VERSION) }
                fn getInterfaceHash(&self) -> binder::Result<String> { Ok(HASH.into()) }
            }
            impl ITest for BpTest {
                fn getInterfaceVersion(&self) -> binder::Result<i32> { self.remote_version() }
                fn getInterfaceHash(&self) -> binder::Result<String> { self.remote_hash() }
            }
            pub trait ITestAsync<P>: binder::Interface + Send {
                fn getInterfaceVersion(&self) -> binder::BoxFuture<'_, binder::Result<i32>> { Box::pin(async move { Ok(VERSION) }) }
                fn getInterfaceHash(&self) -> binder::BoxFuture<'_, binder::Result<String>> { Box::pin(async move { Ok(HASH.into()) }) }
            }
            fn on_transact() { dispatch_metadata() }
        "#;
        let plain = syn::parse_file(source).unwrap();
        assert!(!prepare(source, None, None, false).unwrap().contains("inject_interface_metadata"));
        let output = prepare(source, None, None, true).unwrap();
        assert_eq!(output.matches("unwrap_or ((VERSION , HASH)) . 0").count(), 2);
        assert_eq!(output.matches("unwrap_or ((VERSION , HASH)) . 1").count(), 2);
        assert!(output.contains("pub fn inject_interface_metadata"));
        assert!(!output.contains("self . interface_metadata"));
        let output = syn::parse_file(&output).unwrap();
        assert_eq!(
            plain.items[1].to_token_stream().to_string(),
            output.items[1].to_token_stream().to_string()
        );
        assert_eq!(
            plain.items[3].to_token_stream().to_string(),
            output.items[3].to_token_stream().to_string()
        );
        assert!(prepare(
            &source.replace(
                "fn getInterfaceHash(&self) -> binder::Result<String> { Ok(HASH.into()) }",
                ""
            ),
            None,
            None,
            true
        )
        .is_err());
        assert!(!prepare("trait Plain: binder::Interface { fn call(&self); }", None, None, true)
            .unwrap()
            .contains("inject_interface_metadata"));
    }
}
