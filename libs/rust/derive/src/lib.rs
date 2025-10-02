// Copyright 2022, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Derive macro for `AsCborValue`.
use proc_macro2::TokenStream;
use quote::{format_ident, quote, quote_spanned};
use syn::{
    parse_macro_input, parse_quote, spanned::Spanned, Data, DeriveInput, Fields, GenericParam,
    Generics, Ident, Index,
};

/// Derive macro that implements the `AsCborValue` trait.  Using this macro requires
/// that `AsCborValue`, `CborError` and `cbor_type_error` are locally `use`d.
#[proc_macro_derive(AsCborValue)]
pub fn derive_as_cbor_value(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_as_cbor_value_internal(&input)
}

fn derive_as_cbor_value_internal(input: &DeriveInput) -> proc_macro::TokenStream {
    let name = &input.ident;

    // Add a bound `T: AsCborValue` for every type parameter `T`.
    let generics = add_trait_bounds(&input.generics);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let from_val = from_val_struct(&input.data);
    let to_val = to_val_struct(&input.data);
    let cddl = cddl_struct(name, &input.data);

    let expanded = quote! {
        // The generated impl
        impl #impl_generics AsCborValue for #name #ty_generics #where_clause {
            fn from_cbor_value(value: ciborium::value::Value) -> Result<Self, CborError> {
                #from_val
            }
            fn to_cbor_value(self) -> Result<ciborium::value::Value, CborError> {
                #to_val
            }
            fn cddl_typename() -> Option<String> {
                Some(stringify!(#name).to_string())
            }
            fn cddl_schema() -> Option<String> {
                #cddl
            }
        }
    };

    expanded.into()
}

/// Add a bound `T: AsCborValue` for every type parameter `T`.
fn add_trait_bounds(generics: &Generics) -> Generics {
    let mut generics = generics.clone();
    for param in &mut generics.params {
        if let GenericParam::Type(ref mut type_param) = *param {
            type_param.bounds.push(parse_quote!(AsCborValue));
        }
    }
    generics
}

/// Generate an expression to convert an instance of a compound type to `ciborium::value::Value`
fn to_val_struct(data: &Data) -> TokenStream {
    match *data {
        Data::Struct(ref data) => {
            match data.fields {
                Fields::Named(ref fields) => {
                    // Expands to an expression like
                    //
                    //     {
                    //         let mut v = Vec::new();
                    //         v.try_reserve(3).map_err(|_e| CborError::AllocationFailed)?;
                    //         v.push(AsCborValue::to_cbor_value(self.x)?);
                    //         v.push(AsCborValue::to_cbor_value(self.y)?);
                    //         v.push(AsCborValue::to_cbor_value(self.z)?);
                    //         Ok(ciborium::value::Value::Array(v))
                    //     }
                    let nfields = fields.named.len();
                    let recurse = fields.named.iter().map(|f| {
                        let name = &f.ident;
                        quote_spanned! {f.span()=>
                            v.push(AsCborValue::to_cbor_value(self.#name)?)
                        }
                    });
                    quote! {
                        {
                            let mut v = Vec::new();
                            v.try_reserve(#nfields).map_err(|_e| CborError::AllocationFailed)?;
                            #(#recurse; )*
                            Ok(ciborium::value::Value::Array(v))
                        }
                    }
                }
                Fields::Unnamed(ref fields) if fields.unnamed.len() == 1 => {
                    // For a newtype, expands to an expression
                    //
                    //     self.0.to_cbor_value()
                    quote! {
                        self.0.to_cbor_value()
                    }
                }
                Fields::Unnamed(ref fields) => {
                    // Expands to an expression like
                    //
                    //
                    //     {
                    //         let mut v = Vec::new();
                    //         v.try_reserve(3).map_err(|_e| CborError::AllocationFailed)?;
                    //         v.push(AsCborValue::to_cbor_value(self.0)?);
                    //         v.push(AsCborValue::to_cbor_value(self.1)?);
                    //         v.push(AsCborValue::to_cbor_value(self.2)?);
                    //         Ok(ciborium::value::Value::Array(v))
                    //     }
                    let nfields = fields.unnamed.len();
                    let recurse = fields.unnamed.iter().enumerate().map(|(i, f)| {
                        let index = Index::from(i);
                        quote_spanned! {f.span()=>
                            v.push(AsCborValue::to_cbor_value(self.#index)?)
                        }
                    });
                    quote! {
                        {
                            let mut v = Vec::new();
                            v.try_reserve(#nfields).map_err(|_e| CborError::AllocationFailed)?;
                            #(#recurse; )*
                            Ok(ciborium::value::Value::Array(v))
                        }
                    }
                }
                Fields::Unit => unimplemented!(),
            }
        }
        Data::Enum(_) => {
            quote! {
                let v: ciborium::value::Integer = (self as i32).into();
                Ok(ciborium::value::Value::Integer(v))
            }
        }
        Data::Union(_) => unimplemented!(),
    }
}

/// Generate an expression to convert a `ciborium::value::Value` into an instance of a compound
/// type.
fn from_val_struct(data: &Data) -> TokenStream {
    match data {
        Data::Struct(ref data) => {
            match data.fields {
                Fields::Named(ref fields) => {
                    // Expands to an expression like
                    //
                    //     let mut a = match value {
                    //         ciborium::value::Value::Array(a) => a,
                    //         _ => return cbor_type_error(&value, "arr"),
                    //     };
                    //     if a.len() != 3 {
                    //         return Err(CborError::UnexpectedItem("arr", "arr len 3"));
                    //     }
                    //     // Fields specified in reverse order to reduce shifting.
                    //     Ok(Self {
                    //         z: <ZType>::from_cbor_value(a.remove(2))?,
                    //         y: <YType>::from_cbor_value(a.remove(1))?,
                    //         x: <XType>::from_cbor_value(a.remove(0))?,
                    //     })
                    //
                    // but using fully qualified function call syntax.
                    let nfields = fields.named.len();
                    let recurse = fields.named.iter().enumerate().rev().map(|(i, f)| {
                        let name = &f.ident;
                        let index = Index::from(i);
                        let typ = &f.ty;
                        quote_spanned! {f.span()=>
                                        #name: <#typ>::from_cbor_value(a.remove(#index))?
                        }
                    });
                    quote! {
                        let mut a = match value {
                            ciborium::value::Value::Array(a) => a,
                            _ => return cbor_type_error(&value, "arr"),
                        };
                        if a.len() != #nfields {
                            return Err(CborError::UnexpectedItem(
                                "arr",
                                concat!("arr len ", stringify!(#nfields)),
                            ));
                        }
                        // Fields specified in reverse order to reduce shifting.
                        Ok(Self {
                            #(#recurse, )*
                        })
                    }
                }
                Fields::Unnamed(ref fields) if fields.unnamed.len() == 1 => {
                    // For a newtype, expands to an expression like
                    //
                    //     Ok(Self(<InnerType>::from_cbor_value(value)?))
                    let inner = fields.unnamed.first().unwrap();
                    let typ = &inner.ty;
                    quote! {
                        Ok(Self(<#typ>::from_cbor_value(value)?))
                    }
                }
                Fields::Unnamed(ref fields) => {
                    // Expands to an expression like
                    //
                    //     let mut a = match value {
                    //         ciborium::value::Value::Array(a) => a,
                    //         _ => return cbor_type_error(&value, "arr"),
                    //     };
                    //     if a.len() != 3 {
                    //         return Err(CborError::UnexpectedItem("arr", "arr len 3"));
                    //     }
                    //     // Fields specified in reverse order to reduce shifting.
                    //     let field_2 = <Type2>::from_cbor_value(a.remove(2))?;
                    //     let field_1 = <Type1>::from_cbor_value(a.remove(1))?;
                    //     let field_0 = <Type0>::from_cbor_value(a.remove(0))?;
                    //     Ok(Self(field_0, field_1, field_2))
                    let nfields = fields.unnamed.len();
                    let recurse1 = fields.unnamed.iter().enumerate().rev().map(|(i, f)| {
                        let typ = &f.ty;
                        let varname = format_ident!("field_{}", i);
                        quote_spanned! {f.span()=>
                                        let #varname = <#typ>::from_cbor_value(a.remove(#i))?;
                        }
                    });
                    let recurse2 = fields.unnamed.iter().enumerate().map(|(i, f)| {
                        let varname = format_ident!("field_{}", i);
                        quote_spanned! {f.span()=>
                                        #varname
                        }
                    });
                    quote! {
                        let mut a = match value {
                            ciborium::value::Value::Array(a) => a,
                            _ => return cbor_type_error(&value, "arr"),
                        };
                        if a.len() != #nfields {
                            return Err(CborError::UnexpectedItem("arr",
                                                                 concat!("arr len ",
                                                                         stringify!(#nfields))));
                        }
                        // Fields specified in reverse order to reduce shifting.
                        #(#recurse1)*

                        Ok(Self( #(#recurse2, )* ))
                    }
                }
                Fields::Unit => unimplemented!(),
            }
        }
        Data::Enum(enum_data) => {
            // This only copes with variants with no fields.
            // Expands to an expression like:
            //
            //     use core::convert::TryInto;
            //     let v: i32 = match value {
            //         ciborium::value::Value::Integer(i) => i.try_into().map_err(|_| {
            //             CborError::OutOfRangeIntegerValue
            //         })?,
            //         v => return cbor_type_error(&v, &"int"),
            //     };
            //     match v {
            //         x if x == Self::Variant1 as i32 => Ok(Self::Variant1),
            //         x if x == Self::Variant2 as i32 => Ok(Self::Variant2),
            //         x if x == Self::Variant3 as i32 => Ok(Self::Variant3),
            //         _ => Err( CborError::OutOfRangeIntegerValue),
            //     }
            let recurse = enum_data.variants.iter().map(|variant| {
                let vname = &variant.ident;
                quote_spanned! {variant.span()=>
                                x if x == Self::#vname as i32 => Ok(Self::#vname),
                }
            });

            quote! {
                use core::convert::TryInto;
                // First get the int value as an `i32`.
                let v: i32 = match value {
                    ciborium::value::Value::Integer(i) => i.try_into().map_err(|_| {
                        CborError::OutOfRangeIntegerValue
                    })?,
                    v => return cbor_type_error(&v, &"int"),
                };
                // Now match against enum possibilities.
                match v {
                    #(#recurse)*
                    _ => Err(
                        CborError::OutOfRangeIntegerValue
                    ),
                }
            }
        }
        Data::Union(_) => unimplemented!(),
    }
}

/// Generate an expression that expresses the CDDL schema for the type.
fn cddl_struct(name: &Ident, data: &Data) -> TokenStream {
    match *data {
        Data::Struct(ref data) => {
            match data.fields {
                Fields::Named(ref fields) => {
                    if fields.named.iter().next().is_none() {
                        return quote! {
                            Some(format!("[]"))
                        };
                    }
                    // Expands to an expression like
                    //
                    //     format!("[
                    //         x: {},
                    //         y: {},
                    //         z: {},
                    //     ]",
                    //         <TypeX>::cddl_ref(),
                    //         <TypeY>::cddl_ref(),
                    //         <TypeZ>::cddl_ref(),
                    //     )
                    let fmt_recurse = fields.named.iter().map(|f| {
                        let name = &f.ident;
                        quote_spanned! {f.span()=>
                                        concat!("    ", stringify!(#name), ": {},\n")
                        }
                    });
                    let fmt = quote! {
                        concat!("[\n",
                                #(#fmt_recurse, )*
                                "]")
                    };
                    let recurse = fields.named.iter().map(|f| {
                        let typ = &f.ty;
                        quote_spanned! {f.span()=>
                                        <#typ>::cddl_ref()
                        }
                    });
                    quote! {
                        Some(format!(
                            #fmt,
                            #(#recurse, )*
                        ))
                    }
                }
                Fields::Unnamed(ref fields) if fields.unnamed.len() == 1 => {
                    let inner = fields.unnamed.first().unwrap();
                    let typ = &inner.ty;
                    quote! {
                        Some(<#typ>::cddl_ref())
                    }
                }
                Fields::Unnamed(ref fields) => {
                    if fields.unnamed.iter().next().is_none() {
                        return quote! {
                            Some(format!("()"))
                        };
                    }
                    // Expands to an expression like
                    //
                    //     format!("[
                    //         {},
                    //         {},
                    //         {},
                    //     ]",
                    //         <TypeX>::cddl_ref(),
                    //         <TypeY>::cddl_ref(),
                    //         <TypeZ>::cddl_ref(),
                    //     )
                    //
                    let fmt_recurse = fields.unnamed.iter().map(|f| {
                        quote_spanned! {f.span()=>
                                        "    {},\n"
                        }
                    });
                    let fmt = quote! {
                        concat!("[\n",
                                 #(#fmt_recurse, )*
                                 "]")
                    };
                    let recurse = fields.unnamed.iter().map(|f| {
                        let typ = &f.ty;
                        quote_spanned! {f.span()=>
                                        <#typ>::cddl_ref()
                        }
                    });
                    quote! {
                        Some(format!(
                            #fmt,
                            #(#recurse, )*
                        ))
                    }
                }
                Fields::Unit => unimplemented!(),
            }
        }
        Data::Enum(ref enum_data) => {
            // This only copes with variants with no fields.
            // Expands to an expression like:
            //
            //     format!("&(
            //         EnumName_Variant1: {},
            //         EnumName_Variant2: {},
            //         EnumName_Variant3: {},
            //     )",
            //         Self::Variant1 as i32,
            //         Self::Variant2 as i32,
            //         Self::Variant3 as i32,
            //     )
            //
            let fmt_recurse = enum_data.variants.iter().map(|variant| {
                let vname = &variant.ident;
                quote_spanned! {variant.span()=>
                                concat!("    ",
                                        stringify!(#name),
                                        "_",
                                        stringify!(#vname),
                                        ": {},\n")
                }
            });
            let fmt = quote! {
                concat!("&(\n",
                         #(#fmt_recurse, )*
                         ")")
            };
            let recurse = enum_data.variants.iter().map(|variant| {
                let vname = &variant.ident;
                quote_spanned! {variant.span()=>
                                Self::#vname as i32
                }
            });
            quote! {
                Some(format!(
                    #fmt,
                    #(#recurse, )*
                ))
            }
        }
        Data::Union(_) => unimplemented!(),
    }
}

/// Derive macro that implements a `from_raw_tag_value` method for the `Tag` enum.
#[proc_macro_derive(FromRawTag)]
pub fn derive_from_raw_tag(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_from_raw_tag_internal(&input)
}

fn derive_from_raw_tag_internal(input: &DeriveInput) -> proc_macro::TokenStream {
    let name = &input.ident;
    let from_val = from_raw_tag(name, &input.data);
    let expanded = quote! {
        pub fn from_raw_tag_value(raw_tag: u32) -> #name {
            #from_val
        }
    };
    expanded.into()
}

/// Generate an expression to convert a `u32` into an instance of an fieldless enum.
/// Assumes the existence of an `Invalid` variant as a fallback, and assumes that a
/// `raw_tag_value` function is in scope.
fn from_raw_tag(name: &Ident, data: &Data) -> TokenStream {
    match data {
        Data::Enum(enum_data) => {
            let recurse = enum_data.variants.iter().map(|variant| {
                let vname = &variant.ident;
                quote_spanned! {variant.span()=>
                                x if x == raw_tag_value(#name::#vname) => #name::#vname,
                }
            });

            quote! {
                match raw_tag {
                    #(#recurse)*
                    _ => #name::Invalid,
                }
            }
        }
        _ => unimplemented!(),
    }
}

/// Derive macro that implements the `legacy::InnerSerialize` trait.  Using this macro requires
/// that `InnerSerialize` and `Error` from `kmr_wire::legacy` be locally `use`d.
#[proc_macro_derive(LegacySerialize)]
pub fn derive_legacy_serialize(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_legacy_serialize_internal(&input)
}

fn derive_legacy_serialize_internal(input: &DeriveInput) -> proc_macro::TokenStream {
    let name = &input.ident;

    let deserialize_val = deserialize_struct(&input.data);
    let serialize_val = serialize_struct(&input.data);

    let expanded = quote! {
        impl InnerSerialize for #name {
            fn deserialize(data: &[u8]) -> Result<(Self, &[u8]), Error> {
                #deserialize_val
            }
            fn serialize_into(&self, buf: &mut Vec<u8>) -> Result<(), Error> {
                #serialize_val
            }
        }
    };

    expanded.into()
}

fn deserialize_struct(data: &Data) -> TokenStream {
    match data {
        Data::Struct(ref data) => {
            match data.fields {
                Fields::Named(ref fields) => {
                    // Expands to an expression like
                    //
                    //     let (x, data) = <XType>::deserialize(data)?;
                    //     let (y, data) = <YType>::deserialize(data)?;
                    //     let (z, data) = <ZType>::deserialize(data)?;
                    //     Ok((Self {
                    //             x,
                    //             y,
                    //             z,
                    //     }, data))
                    //
                    let recurse1 = fields.named.iter().map(|f| {
                        let name = &f.ident;
                        let typ = &f.ty;
                        quote_spanned! {f.span()=>
                                        let (#name, data) = <#typ>::deserialize(data)?;
                        }
                    });
                    let recurse2 = fields.named.iter().map(|f| {
                        let name = &f.ident;
                        quote_spanned! {f.span()=>
                                        #name
                        }
                    });
                    quote! {
                        #(#recurse1)*
                        Ok((Self {
                            #(#recurse2, )*
                        }, data))
                    }
                }
                Fields::Unnamed(_) => unimplemented!(),
                Fields::Unit => unimplemented!(),
            }
        }
        Data::Enum(_) => unimplemented!(),
        Data::Union(_) => unimplemented!(),
    }
}

fn serialize_struct(data: &Data) -> TokenStream {
    match data {
        Data::Struct(ref data) => {
            match data.fields {
                Fields::Named(ref fields) => {
                    // Expands to an expression like
                    //
                    //     self.x.serialize_into(buf)?;
                    //     self.y.serialize_into(buf)?;
                    //     self.z.serialize_into(buf)?;
                    //     Ok(())
                    //
                    let recurse = fields.named.iter().map(|f| {
                        let name = &f.ident;
                        quote_spanned! {f.span()=>
                                        self.#name.serialize_into(buf)?;
                        }
                    });
                    quote! {
                        #(#recurse)*
                        Ok(())
                    }
                }
                Fields::Unnamed(_) => unimplemented!(),
                Fields::Unit => unimplemented!(),
            }
        }
        Data::Enum(_) => unimplemented!(),
        Data::Union(_) => unimplemented!(),
    }
}
