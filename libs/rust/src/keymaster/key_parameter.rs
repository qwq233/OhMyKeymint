// Copyright 2020, The Android Open Source Project
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

//! Key parameters are declared by KeyMint to describe properties of keys and operations.
//! During key generation and import, key parameters are used to characterize a key, its usage
//! restrictions, and additional parameters for attestation. During the lifetime of the key,
//! the key characteristics are expressed as set of key parameters. During cryptographic
//! operations, clients may specify additional operation specific parameters.
//! This module provides a Keystore 2.0 internal representation for key parameters and
//! implements traits to convert it from and into KeyMint KeyParameters and store it in
//! the SQLite database.
//!
//! ## Synopsis
//!
//! enum KeyParameterValue {
//!     Invalid,
//!     Algorithm(Algorithm),
//!     ...
//! }
//!
//! impl KeyParameterValue {
//!     pub fn get_tag(&self) -> Tag;
//!     pub fn new_from_sql(tag: Tag, data: &SqlField) -> Result<Self>;
//!     pub fn new_from_tag_primitive_pair<T: Into<Primitive>>(tag: Tag, v: T)
//!        -> Result<Self, PrimitiveError>;
//!     fn to_sql(&self) -> SqlResult<ToSqlOutput>
//! }
//!
//! use ...::keymint::KeyParameter as KmKeyParameter;
//! impl Into<KmKeyParameter> for KeyParameterValue {}
//! impl From<KmKeyParameter> for KeyParameterValue {}
//!
//! ## Implementation
//! Each of the six functions is implemented as match statement over each key parameter variant.
//! We bootstrap these function as well as the KeyParameterValue enum itself from a single list
//! of key parameters, that needs to be kept in sync with the KeyMint AIDL specification.
//!
//! The list resembles an enum declaration with a few extra fields.
//! enum KeyParameterValue {
//!    Invalid with tag INVALID and field Invalid,
//!    Algorithm(Algorithm) with tag ALGORITHM and field Algorithm,
//!    ...
//! }
//! The tag corresponds to the variant of the keymint::Tag, and the field corresponds to the
//! variant of the keymint::KeyParameterValue union. There is no one to one mapping between
//! tags and union fields, e.g., the values of both tags BOOT_PATCHLEVEL and VENDOR_PATCHLEVEL
//! are stored in the Integer field.
//!
//! The macros interpreting them all follow a similar pattern and follow the following fragment
//! naming scheme:
//!
//!    Algorithm(Algorithm) with tag ALGORITHM and field Algorithm,
//!    $vname $(($vtype ))? with tag $tag_name and field $field_name,
//!
//! Further, KeyParameterValue appears in the macro as $enum_name.
//! Note that $vtype is optional to accommodate variants like Invalid which don't wrap a value.
//!
//! In some cases $vtype is not part of the expansion, but we still have to modify the expansion
//! depending on the presence of $vtype. In these cases we recurse through the list following the
//! following pattern:
//!
//! (@<marker> <non repeating args>, [<out list>], [<in list>])
//!
//! These macros usually have four rules:
//!  * Two main recursive rules, of the form:
//!    (
//!        @<marker>
//!        <non repeating args>,
//!        [<out list>],
//!        [<one element pattern> <in tail>]
//!    ) => {
//!        macro!{@<marker> <non repeating args>, [<out list>
//!            <one element expansion>
//!        ], [<in tail>]}
//!    };
//!    They pop one element off the <in list> and add one expansion to the out list.
//!    The element expansion is kept on a separate line (or lines) for better readability.
//!    The two variants differ in whether or not $vtype is expected.
//!  * The termination condition which has an empty in list.
//!  * The public interface, which does not have @marker and calls itself with an empty out list.

use std::convert::TryInto;

use crate::keymaster::database::utils::SqlField;
use crate::keymaster::error::KsError as KeystoreError;

use crate::android::hardware::security::keymint::{
    Algorithm::Algorithm, BlockMode::BlockMode, Digest::Digest, EcCurve::EcCurve,
    HardwareAuthenticatorType::HardwareAuthenticatorType, KeyOrigin::KeyOrigin,
    KeyParameter::KeyParameter as KmKeyParameter,
    KeyParameterValue::KeyParameterValue as KmKeyParameterValue, KeyPurpose::KeyPurpose,
    PaddingMode::PaddingMode, SecurityLevel::SecurityLevel, Tag::Tag,
};
use crate::android::system::keystore2::Authorization::Authorization;
use anyhow::{Context, Result};
use rusqlite::types::{Null, ToSql, ToSqlOutput};
use rusqlite::Result as SqlResult;
use serde::de::Deserializer;
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

/// This trait is used to associate a primitive to any type that can be stored inside a
/// KeyParameterValue, especially the AIDL enum types, e.g., keymint::{Algorithm, Digest, ...}.
/// This allows for simplifying the macro rules, e.g., for reading from the SQL database.
/// An expression like `KeyParameterValue::Algorithm(row.get(0))` would not work because
/// a type of `Algorithm` is expected which does not implement `FromSql` and we cannot
/// implement it because we own neither the type nor the trait.
/// With AssociatePrimitive we can write an expression
/// `KeyParameter::Algorithm(<Algorithm>::from_primitive(row.get(0)))` to inform `get`
/// about the expected primitive type that it can convert into. By implementing this
/// trait for all inner types we can write a single rule to cover all cases (except where
/// there is no wrapped type):
/// `KeyParameterValue::$vname(<$vtype>::from_primitive(row.get(0)))`
trait AssociatePrimitive {
    type Primitive: Into<Primitive> + TryFrom<Primitive>;

    fn from_primitive(v: Self::Primitive) -> Self;
    fn to_primitive(&self) -> Self::Primitive;
}

/// Associates the given type with i32. The macro assumes that the given type is actually a
/// tuple struct wrapping i32, such as AIDL enum types.
macro_rules! implement_associate_primitive_for_aidl_enum {
    ($t:ty) => {
        impl AssociatePrimitive for $t {
            type Primitive = i32;

            fn from_primitive(v: Self::Primitive) -> Self {
                Self(v)
            }
            fn to_primitive(&self) -> Self::Primitive {
                self.0
            }
        }
    };
}

/// Associates the given type with itself.
macro_rules! implement_associate_primitive_identity {
    ($t:ty) => {
        impl AssociatePrimitive for $t {
            type Primitive = $t;

            fn from_primitive(v: Self::Primitive) -> Self {
                v
            }
            fn to_primitive(&self) -> Self::Primitive {
                self.clone()
            }
        }
    };
}

implement_associate_primitive_for_aidl_enum! {Algorithm}
implement_associate_primitive_for_aidl_enum! {BlockMode}
implement_associate_primitive_for_aidl_enum! {Digest}
implement_associate_primitive_for_aidl_enum! {EcCurve}
implement_associate_primitive_for_aidl_enum! {HardwareAuthenticatorType}
implement_associate_primitive_for_aidl_enum! {KeyOrigin}
implement_associate_primitive_for_aidl_enum! {KeyPurpose}
implement_associate_primitive_for_aidl_enum! {PaddingMode}
implement_associate_primitive_for_aidl_enum! {SecurityLevel}

implement_associate_primitive_identity! {Vec<u8>}
implement_associate_primitive_identity! {i64}
implement_associate_primitive_identity! {i32}

/// This enum allows passing a primitive value to `KeyParameterValue::new_from_tag_primitive_pair`
/// Usually, it is not necessary to use this type directly because the function uses
/// `Into<Primitive>` as a trait bound.
#[derive(Deserialize, Serialize)]
pub enum Primitive {
    /// Wraps an i64.
    I64(i64),
    /// Wraps an i32.
    I32(i32),
    /// Wraps a Vec<u8>.
    Vec(Vec<u8>),
}

impl From<i64> for Primitive {
    fn from(v: i64) -> Self {
        Self::I64(v)
    }
}
impl From<i32> for Primitive {
    fn from(v: i32) -> Self {
        Self::I32(v)
    }
}
impl From<Vec<u8>> for Primitive {
    fn from(v: Vec<u8>) -> Self {
        Self::Vec(v)
    }
}

/// This error is returned by `KeyParameterValue::new_from_tag_primitive_pair`.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PrimitiveError {
    /// Returned if this primitive is unsuitable for the given tag type.
    #[error("Primitive does not match the expected tag type.")]
    TypeMismatch,
    /// Return if the tag type is unknown.
    #[error("Unknown tag.")]
    UnknownTag,
}

impl TryFrom<Primitive> for i64 {
    type Error = PrimitiveError;

    fn try_from(p: Primitive) -> Result<i64, Self::Error> {
        match p {
            Primitive::I64(v) => Ok(v),
            _ => Err(Self::Error::TypeMismatch),
        }
    }
}
impl TryFrom<Primitive> for i32 {
    type Error = PrimitiveError;

    fn try_from(p: Primitive) -> Result<i32, Self::Error> {
        match p {
            Primitive::I32(v) => Ok(v),
            _ => Err(Self::Error::TypeMismatch),
        }
    }
}
impl TryFrom<Primitive> for Vec<u8> {
    type Error = PrimitiveError;

    fn try_from(p: Primitive) -> Result<Vec<u8>, Self::Error> {
        match p {
            Primitive::Vec(v) => Ok(v),
            _ => Err(Self::Error::TypeMismatch),
        }
    }
}

fn serialize_primitive<S, P>(v: &P, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    P: AssociatePrimitive,
{
    let primitive: Primitive = v.to_primitive().into();
    primitive.serialize(serializer)
}

fn deserialize_primitive<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: AssociatePrimitive,
{
    let primitive: Primitive = serde::de::Deserialize::deserialize(deserializer)?;
    Ok(T::from_primitive(
        primitive
            .try_into()
            .map_err(|_| serde::de::Error::custom("Type Mismatch"))?,
    ))
}

/// Expands the list of KeyParameterValue variants as follows:
///
/// Input:
/// Invalid with tag INVALID and field Invalid,
/// Algorithm(Algorithm) with tag ALGORITHM and field Algorithm,
///
/// Output:
/// ```
/// pub fn new_from_tag_primitive_pair<T: Into<Primitive>>(
///     tag: Tag,
///     v: T
/// ) -> Result<KeyParameterValue, PrimitiveError> {
///     let p: Primitive = v.into();
///     Ok(match tag {
///         Tag::INVALID => KeyParameterValue::Invalid,
///         Tag::ALGORITHM => KeyParameterValue::Algorithm(
///             <Algorithm>::from_primitive(p.try_into()?)
///         ),
///         _ => return Err(PrimitiveError::UnknownTag),
///     })
/// }
/// ```
macro_rules! implement_from_tag_primitive_pair {
    ($enum_name:ident; $($vname:ident$(($vtype:ty))? $tag_name:ident),*) => {
        /// Returns the an instance of $enum_name or an error if the given primitive does not match
        /// the tag type or the tag is unknown.
        pub fn new_from_tag_primitive_pair<T: Into<Primitive>>(
            tag: Tag,
            v: T
        ) -> Result<$enum_name, PrimitiveError> {
            let p: Primitive = v.into();
            Ok(match tag {
                $(Tag::$tag_name => $enum_name::$vname$((
                    <$vtype>::from_primitive(p.try_into()?)
                ))?,)*
                _ => return Err(PrimitiveError::UnknownTag),
            })
        }
    };
}

/// Expands the list of KeyParameterValue variants as follows:
///
/// Input:
/// pub enum KeyParameterValue {
///     Invalid with tag INVALID and field Invalid,
///     Algorithm(Algorithm) with tag ALGORITHM and field Algorithm,
/// }
///
/// Output:
/// ```
/// pub enum KeyParameterValue {
///     Invalid,
///     Algorithm(Algorithm),
/// }
/// ```
macro_rules! implement_enum {
    (
        $(#[$enum_meta:meta])*
        $enum_vis:vis enum $enum_name:ident {
             $($(#[$emeta:meta])* $vname:ident$(($vtype:ty))?),* $(,)?
        }
    ) => {
        $(#[$enum_meta])*
        $enum_vis enum $enum_name {
            $(
                $(#[$emeta])*
                $vname$(($vtype))?
            ),*
        }
    };
}

/// Expands the list of KeyParameterValue variants as follows:
///
/// Input:
/// Invalid with tag INVALID and field Invalid,
/// Algorithm(Algorithm) with tag ALGORITHM and field Algorithm,
///
/// Output:
/// ```
/// pub fn get_tag(&self) -> Tag {
///     match self {
///         KeyParameterValue::Invalid => Tag::INVALID,
///         KeyParameterValue::Algorithm(_) => Tag::ALGORITHM,
///     }
/// }
/// ```
macro_rules! implement_get_tag {
    (
        @replace_type_spec
        $enum_name:ident,
        [$($out:tt)*],
        [$vname:ident($vtype:ty) $tag_name:ident, $($in:tt)*]
    ) => {
        implement_get_tag!{@replace_type_spec $enum_name, [$($out)*
            $enum_name::$vname(_) => Tag::$tag_name,
        ], [$($in)*]}
    };
    (
        @replace_type_spec
        $enum_name:ident,
        [$($out:tt)*],
        [$vname:ident $tag_name:ident, $($in:tt)*]
    ) => {
        implement_get_tag!{@replace_type_spec $enum_name, [$($out)*
            $enum_name::$vname => Tag::$tag_name,
        ], [$($in)*]}
    };
    (@replace_type_spec $enum_name:ident, [$($out:tt)*], []) => {
        /// Returns the tag of the given instance.
        pub fn get_tag(&self) -> Tag {
            match self {
                $($out)*
            }
        }
    };

    ($enum_name:ident; $($vname:ident$(($vtype:ty))? $tag_name:ident),*) => {
        implement_get_tag!{@replace_type_spec $enum_name, [], [$($vname$(($vtype))? $tag_name,)*]}
    };
}

/// Expands the list of KeyParameterValue variants as follows:
///
/// Input:
/// Invalid with tag INVALID and field Invalid,
/// Algorithm(Algorithm) with tag ALGORITHM and field Algorithm,
///
/// Output:
/// ```
/// fn to_sql(&self) -> SqlResult<ToSqlOutput> {
///     match self {
///         KeyParameterValue::Invalid => Ok(ToSqlOutput::from(Null)),
///         KeyParameterValue::Algorithm(v) => Ok(ToSqlOutput::from(v.to_primitive())),
///     }
/// }
/// ```
macro_rules! implement_to_sql {
    (
        @replace_type_spec
        $enum_name:ident,
        [$($out:tt)*],
        [$vname:ident($vtype:ty), $($in:tt)*]
    ) => {
        implement_to_sql!{@replace_type_spec $enum_name, [ $($out)*
            $enum_name::$vname(v) => Ok(ToSqlOutput::from(v.to_primitive())),
        ], [$($in)*]}
    };
    (
        @replace_type_spec
        $enum_name:ident,
        [$($out:tt)*],
        [$vname:ident, $($in:tt)*]
    ) => {
        implement_to_sql!{@replace_type_spec $enum_name, [ $($out)*
            $enum_name::$vname => Ok(ToSqlOutput::from(Null)),
        ], [$($in)*]}
    };
    (@replace_type_spec $enum_name:ident, [$($out:tt)*], []) => {
        /// Converts $enum_name to be stored in a rusqlite database.
        fn to_sql(&self) -> SqlResult<ToSqlOutput> {
            match self {
                $($out)*
            }
        }
    };


    ($enum_name:ident; $($vname:ident$(($vtype:ty))?),*) => {
        impl ToSql for $enum_name {
            implement_to_sql!{@replace_type_spec $enum_name, [], [$($vname$(($vtype))?,)*]}
        }

    }
}

/// Expands the list of KeyParameterValue variants as follows:
///
/// Input:
/// Invalid with tag INVALID and field Invalid,
/// Algorithm(Algorithm) with tag ALGORITHM and field Algorithm,
///
/// Output:
/// ```
/// pub fn new_from_sql(
///     tag: Tag,
///     data: &SqlField,
/// ) -> Result<Self> {
///     Ok(match self {
///         Tag::Invalid => KeyParameterValue::Invalid,
///         Tag::ALGORITHM => {
///             KeyParameterValue::Algorithm(<Algorithm>::from_primitive(data
///                 .get()
///                 .map_err(|_| KeystoreError::Rc(ResponseCode::VALUE_CORRUPTED))
///                 .context(concat!("Failed to read sql data for tag: ", "ALGORITHM", "."))?
///             ))
///         },
///     })
/// }
/// ```
macro_rules! implement_new_from_sql {
    ($enum_name:ident; $($vname:ident$(($vtype:ty))? $tag_name:ident),*) => {
        /// Takes a tag and an SqlField and attempts to construct a KeyParameter value.
        /// This function may fail if the parameter value cannot be extracted from the
        /// database cell.
        pub fn new_from_sql(
            tag: Tag,
            data: &SqlField,
        ) -> Result<Self> {
            Ok(match tag {
                $(
                    Tag::$tag_name => {
                        $enum_name::$vname$((<$vtype>::from_primitive(data
                            .get()
                            .map_err(|_| KeystoreError::Rc(crate::android::system::keystore2::ResponseCode::ResponseCode::VALUE_CORRUPTED))
                            .context(concat!(
                                "Failed to read sql data for tag: ",
                                stringify!($tag_name),
                                "."
                            ))?
                        )))?
                    },
                )*
                _ => $enum_name::Invalid,
            })
        }
    };
}

/// This key parameter default is used during the conversion from KeyParameterValue
/// to keymint::KeyParameterValue. Keystore's version does not have wrapped types
/// for boolean tags and the tag Invalid. The AIDL version uses bool and integer
/// variants respectively. This default function is invoked in these cases to
/// homogenize the rules for boolean and invalid tags.
/// The bool variant returns true because boolean parameters are implicitly true
/// if present.
trait KpDefault {
    fn default() -> Self;
}

impl KpDefault for i32 {
    fn default() -> Self {
        0
    }
}

impl KpDefault for bool {
    fn default() -> Self {
        true
    }
}

/// Expands the list of KeyParameterValue variants as follows:
///
/// Input:
/// Invalid with tag INVALID and field Invalid,
/// Algorithm(Algorithm) with tag ALGORITHM and field Algorithm,
///
/// Output:
/// ```
/// impl From<KmKeyParameter> for KeyParameterValue {
///     fn from(kp: KmKeyParameter) -> Self {
///         match kp {
///             KmKeyParameter { tag: Tag::INVALID, value: KmKeyParameterValue::Invalid(_) }
///                 => $enum_name::$vname,
///             KmKeyParameter { tag: Tag::Algorithm, value: KmKeyParameterValue::Algorithm(v) }
///                 => $enum_name::Algorithm(v),
///             _ => $enum_name::Invalid,
///         }
///     }
/// }
///
/// impl Into<KmKeyParameter> for KeyParameterValue {
///     fn into(self) -> KmKeyParameter {
///         match self {
///             KeyParameterValue::Invalid => KmKeyParameter {
///                 tag: Tag::INVALID,
///                 value: KmKeyParameterValue::Invalid(KpDefault::default())
///             },
///             KeyParameterValue::Algorithm(v) => KmKeyParameter {
///                 tag: Tag::ALGORITHM,
///                 value: KmKeyParameterValue::Algorithm(v)
///             },
///         }
///     }
/// }
/// ```
macro_rules! implement_try_from_to_km_parameter {
    // The first three rules expand From<KmKeyParameter>.
    (
        @from
        $enum_name:ident,
        [$($out:tt)*],
        [$vname:ident($vtype:ty) $tag_name:ident $field_name:ident, $($in:tt)*]
    ) => {
        implement_try_from_to_km_parameter!{@from $enum_name, [$($out)*
            KmKeyParameter {
                tag: Tag::$tag_name,
                value: KmKeyParameterValue::$field_name(v)
            } => $enum_name::$vname(v),
        ], [$($in)*]
    }};
    (
        @from
        $enum_name:ident,
        [$($out:tt)*],
        [$vname:ident $tag_name:ident $field_name:ident, $($in:tt)*]
    ) => {
        implement_try_from_to_km_parameter!{@from $enum_name, [$($out)*
            KmKeyParameter {
                tag: Tag::$tag_name,
                value: KmKeyParameterValue::$field_name(_)
            } => $enum_name::$vname,
        ], [$($in)*]
    }};
    (@from $enum_name:ident, [$($out:tt)*], []) => {
        impl From<KmKeyParameter> for $enum_name {
            fn from(kp: KmKeyParameter) -> Self {
                match kp {
                    $($out)*
                    _ => $enum_name::Invalid,
                }
            }
        }
    };

    // The next three rules expand Into<KmKeyParameter>.
    (
        @into
        $enum_name:ident,
        [$($out:tt)*],
        [$vname:ident($vtype:ty) $tag_name:ident $field_name:ident, $($in:tt)*]
    ) => {
        implement_try_from_to_km_parameter!{@into $enum_name, [$($out)*
            $enum_name::$vname(v) => KmKeyParameter {
                tag: Tag::$tag_name,
                value: KmKeyParameterValue::$field_name(v)
            },
        ], [$($in)*]
    }};
    (
        @into
        $enum_name:ident,
        [$($out:tt)*],
        [$vname:ident $tag_name:ident $field_name:ident, $($in:tt)*]
    ) => {
        implement_try_from_to_km_parameter!{@into $enum_name, [$($out)*
            $enum_name::$vname => KmKeyParameter {
                tag: Tag::$tag_name,
                value: KmKeyParameterValue::$field_name(KpDefault::default())
            },
        ], [$($in)*]
    }};
    (@into $enum_name:ident, [$($out:tt)*], []) => {
        impl From<$enum_name> for KmKeyParameter {
            fn from(x: $enum_name) -> Self {
                match x {
                    $($out)*
                }
            }
        }
    };


    ($enum_name:ident; $($vname:ident$(($vtype:ty))? $tag_name:ident $field_name:ident),*) => {
        implement_try_from_to_km_parameter!(
            @from $enum_name,
            [],
            [$($vname$(($vtype))? $tag_name $field_name,)*]
        );
        implement_try_from_to_km_parameter!(
            @into $enum_name,
            [],
            [$($vname$(($vtype))? $tag_name $field_name,)*]
        );
    };
}

/// This is the top level macro. While the other macros do most of the heavy lifting, this takes
/// the key parameter list and passes it on to the other macros to generate all of the conversion
/// functions. In addition, it generates an important test vector for verifying that tag type of the
/// keymint tag matches the associated keymint KeyParameterValue field.
macro_rules! implement_key_parameter_value {
    (
        $(#[$enum_meta:meta])*
        $enum_vis:vis enum $enum_name:ident {
            $(
                $(#[$($emeta:tt)+])*
                $vname:ident$(($vtype:ty))?
            ),* $(,)?
        }
    ) => {
        implement_key_parameter_value!{
            @extract_attr
            $(#[$enum_meta])*
            $enum_vis enum $enum_name {
                []
                [$(
                    [] [$(#[$($emeta)+])*]
                    $vname$(($vtype))?,
                )*]
            }
        }
    };

    (
        @extract_attr
        $(#[$enum_meta:meta])*
        $enum_vis:vis enum $enum_name:ident {
            [$($out:tt)*]
            [
                [$(#[$mout:meta])*]
                [
                    #[key_param(tag = $tag_name:ident, field = $field_name:ident)]
                    $(#[$($mtail:tt)+])*
                ]
                $vname:ident$(($vtype:ty))?,
                $($tail:tt)*
            ]
        }
    ) => {
        implement_key_parameter_value!{
            @extract_attr
            $(#[$enum_meta])*
            $enum_vis enum $enum_name {
                [
                    $($out)*
                    $(#[$mout])*
                    $(#[$($mtail)+])*
                    $tag_name $field_name $vname$(($vtype))?,
                ]
                [$($tail)*]
            }
        }
    };

    (
        @extract_attr
        $(#[$enum_meta:meta])*
        $enum_vis:vis enum $enum_name:ident {
            [$($out:tt)*]
            [
                [$(#[$mout:meta])*]
                [
                    #[$front:meta]
                    $(#[$($mtail:tt)+])*
                ]
                $vname:ident$(($vtype:ty))?,
                $($tail:tt)*
            ]
        }
    ) => {
        implement_key_parameter_value!{
            @extract_attr
            $(#[$enum_meta])*
            $enum_vis enum $enum_name {
                [$($out)*]
                [
                    [
                        $(#[$mout])*
                        #[$front]
                    ]
                    [$(#[$($mtail)+])*]
                    $vname$(($vtype))?,
                    $($tail)*
                ]
            }
        }
    };

    (
        @extract_attr
        $(#[$enum_meta:meta])*
        $enum_vis:vis enum $enum_name:ident {
            [$($out:tt)*]
            []
        }
    ) => {
        implement_key_parameter_value!{
            @spill
            $(#[$enum_meta])*
            $enum_vis enum $enum_name {
                $($out)*
            }
        }
    };

    (
        @spill
        $(#[$enum_meta:meta])*
        $enum_vis:vis enum $enum_name:ident {
            $(
                $(#[$emeta:meta])*
                $tag_name:ident $field_name:ident $vname:ident$(($vtype:ty))?,
            )*
        }
    ) => {
        implement_enum!(
            $(#[$enum_meta])*
            $enum_vis enum $enum_name {
            $(
                $(#[$emeta])*
                $vname$(($vtype))?
            ),*
        });

        impl $enum_name {
            implement_new_from_sql!($enum_name; $($vname$(($vtype))? $tag_name),*);
            implement_get_tag!($enum_name; $($vname$(($vtype))? $tag_name),*);
            implement_from_tag_primitive_pair!($enum_name; $($vname$(($vtype))? $tag_name),*);

            #[cfg(test)]
            fn make_field_matches_tag_type_test_vector() -> Vec<KmKeyParameter> {
                vec![$(KmKeyParameter{
                    tag: Tag::$tag_name,
                    value: KmKeyParameterValue::$field_name(Default::default())}
                ),*]
            }

            #[cfg(test)]
            fn make_key_parameter_defaults_vector() -> Vec<KeyParameter> {
                vec![$(KeyParameter{
                    value: KeyParameterValue::$vname$((<$vtype as Default>::default()))?,
                    security_level: SecurityLevel(100),
                }),*]
            }
        }

        implement_try_from_to_km_parameter!(
            $enum_name;
            $($vname$(($vtype))? $tag_name $field_name),*
        );

        implement_to_sql!($enum_name; $($vname$(($vtype))?),*);
    };
}

implement_key_parameter_value! {
/// KeyParameterValue holds a value corresponding to one of the Tags defined in
/// the AIDL spec at hardware/interfaces/security/keymint
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
pub enum KeyParameterValue {
    /// Associated with Tag:INVALID
    #[key_param(tag = INVALID, field = Invalid)]
    Invalid,
    /// Set of purposes for which the key may be used
    #[serde(deserialize_with = "deserialize_primitive")]
    #[serde(serialize_with = "serialize_primitive")]
    #[key_param(tag = PURPOSE, field = KeyPurpose)]
    KeyPurpose(KeyPurpose),
    /// Cryptographic algorithm with which the key is used
    #[serde(deserialize_with = "deserialize_primitive")]
    #[serde(serialize_with = "serialize_primitive")]
    #[key_param(tag = ALGORITHM, field = Algorithm)]
    Algorithm(Algorithm),
    /// Size of the key , in bits
    #[key_param(tag = KEY_SIZE, field = Integer)]
    KeySize(i32),
    /// Block cipher mode(s) with which the key may be used
    #[serde(deserialize_with = "deserialize_primitive")]
    #[serde(serialize_with = "serialize_primitive")]
    #[key_param(tag = BLOCK_MODE, field = BlockMode)]
    BlockMode(BlockMode),
    /// Digest algorithms that may be used with the key to perform signing and verification
    #[serde(deserialize_with = "deserialize_primitive")]
    #[serde(serialize_with = "serialize_primitive")]
    #[key_param(tag = DIGEST, field = Digest)]
    Digest(Digest),
    /// Digest algorithms that can be used for MGF in RSA-OAEP.
    #[serde(deserialize_with = "deserialize_primitive")]
    #[serde(serialize_with = "serialize_primitive")]
    #[key_param(tag = RSA_OAEP_MGF_DIGEST, field = Digest)]
    RsaOaepMgfDigest(Digest),
    /// Padding modes that may be used with the key.  Relevant to RSA, AES and 3DES keys.
    #[serde(deserialize_with = "deserialize_primitive")]
    #[serde(serialize_with = "serialize_primitive")]
    #[key_param(tag = PADDING, field = PaddingMode)]
    PaddingMode(PaddingMode),
    /// Can the caller provide a nonce for nonce-requiring operations
    #[key_param(tag = CALLER_NONCE, field = BoolValue)]
    CallerNonce,
    /// Minimum length of MAC for HMAC keys and AES keys that support GCM mode
    #[key_param(tag = MIN_MAC_LENGTH, field = Integer)]
    MinMacLength(i32),
    /// The elliptic curve
    #[serde(deserialize_with = "deserialize_primitive")]
    #[serde(serialize_with = "serialize_primitive")]
    #[key_param(tag = EC_CURVE, field = EcCurve)]
    EcCurve(EcCurve),
    /// Value of the public exponent for an RSA key pair
    #[key_param(tag = RSA_PUBLIC_EXPONENT, field = LongInteger)]
    RSAPublicExponent(i64),
    /// An attestation certificate for the generated key should contain an application-scoped
    /// and time-bounded device-unique ID
    #[key_param(tag = INCLUDE_UNIQUE_ID, field = BoolValue)]
    IncludeUniqueID,
    //TODO: find out about this
    // /// Necessary system environment conditions for the generated key to be used
    // KeyBlobUsageRequirements(KeyBlobUsageRequirements),
    /// Only the boot loader can use the key
    #[key_param(tag = BOOTLOADER_ONLY, field = BoolValue)]
    BootLoaderOnly,
    /// When deleted, the key is guaranteed to be permanently deleted and unusable
    #[key_param(tag = ROLLBACK_RESISTANCE, field = BoolValue)]
    RollbackResistance,
    /// The Key shall only be used during the early boot stage
    #[key_param(tag = EARLY_BOOT_ONLY, field = BoolValue)]
    EarlyBootOnly,
    /// The date and time at which the key becomes active
    #[key_param(tag = ACTIVE_DATETIME, field = DateTime)]
    ActiveDateTime(i64),
    /// The date and time at which the key expires for signing and encryption
    #[key_param(tag = ORIGINATION_EXPIRE_DATETIME, field = DateTime)]
    OriginationExpireDateTime(i64),
    /// The date and time at which the key expires for verification and decryption
    #[key_param(tag = USAGE_EXPIRE_DATETIME, field = DateTime)]
    UsageExpireDateTime(i64),
    /// Minimum amount of time that elapses between allowed operations
    #[key_param(tag = MIN_SECONDS_BETWEEN_OPS, field = Integer)]
    MinSecondsBetweenOps(i32),
    /// Maximum number of times that a key may be used between system reboots
    #[key_param(tag = MAX_USES_PER_BOOT, field = Integer)]
    MaxUsesPerBoot(i32),
    /// The number of times that a limited use key can be used
    #[key_param(tag = USAGE_COUNT_LIMIT, field = Integer)]
    UsageCountLimit(i32),
    /// ID of the Android user that is permitted to use the key
    #[key_param(tag = USER_ID, field = Integer)]
    UserID(i32),
    /// A key may only be used under a particular secure user authentication state
    #[key_param(tag = USER_SECURE_ID, field = LongInteger)]
    UserSecureID(i64),
    /// No authentication is required to use this key
    #[key_param(tag = NO_AUTH_REQUIRED, field = BoolValue)]
    NoAuthRequired,
    /// The types of user authenticators that may be used to authorize this key
    #[serde(deserialize_with = "deserialize_primitive")]
    #[serde(serialize_with = "serialize_primitive")]
    #[key_param(tag = USER_AUTH_TYPE, field = HardwareAuthenticatorType)]
    HardwareAuthenticatorType(HardwareAuthenticatorType),
    /// The time in seconds for which the key is authorized for use, after user authentication
    #[key_param(tag = AUTH_TIMEOUT, field = Integer)]
    AuthTimeout(i32),
    /// The key's authentication timeout, if it has one, is automatically expired when the device is
    /// removed from the user's body. No longer implemented; this tag is no longer enforced.
    #[key_param(tag = ALLOW_WHILE_ON_BODY, field = BoolValue)]
    AllowWhileOnBody,
    /// The key must be unusable except when the user has provided proof of physical presence
    #[key_param(tag = TRUSTED_USER_PRESENCE_REQUIRED, field = BoolValue)]
    TrustedUserPresenceRequired,
    /// Applicable to keys with KeyPurpose SIGN, and specifies that this key must not be usable
    /// unless the user provides confirmation of the data to be signed
    #[key_param(tag = TRUSTED_CONFIRMATION_REQUIRED, field = BoolValue)]
    TrustedConfirmationRequired,
    /// The key may only be used when the device is unlocked
    #[key_param(tag = UNLOCKED_DEVICE_REQUIRED, field = BoolValue)]
    UnlockedDeviceRequired,
    /// When provided to generateKey or importKey, this tag specifies data
    /// that is necessary during all uses of the key
    #[key_param(tag = APPLICATION_ID, field = Blob)]
    ApplicationID(Vec<u8>),
    /// When provided to generateKey or importKey, this tag specifies data
    /// that is necessary during all uses of the key
    #[key_param(tag = APPLICATION_DATA, field = Blob)]
    ApplicationData(Vec<u8>),
    /// Specifies the date and time the key was created
    #[key_param(tag = CREATION_DATETIME, field = DateTime)]
    CreationDateTime(i64),
    /// Specifies where the key was created, if known
    #[serde(deserialize_with = "deserialize_primitive")]
    #[serde(serialize_with = "serialize_primitive")]
    #[key_param(tag = ORIGIN, field = Origin)]
    KeyOrigin(KeyOrigin),
    /// The key used by verified boot to validate the operating system booted
    #[key_param(tag = ROOT_OF_TRUST, field = Blob)]
    RootOfTrust(Vec<u8>),
    /// System OS version with which the key may be used
    #[key_param(tag = OS_VERSION, field = Integer)]
    OSVersion(i32),
    /// Specifies the system security patch level with which the key may be used
    #[key_param(tag = OS_PATCHLEVEL, field = Integer)]
    OSPatchLevel(i32),
    /// Specifies a unique, time-based identifier
    #[key_param(tag = UNIQUE_ID, field = Blob)]
    UniqueID(Vec<u8>),
    /// Used to deliver a "challenge" value to the attestKey() method
    #[key_param(tag = ATTESTATION_CHALLENGE, field = Blob)]
    AttestationChallenge(Vec<u8>),
    /// The set of applications which may use a key, used only with attestKey()
    #[key_param(tag = ATTESTATION_APPLICATION_ID, field = Blob)]
    AttestationApplicationID(Vec<u8>),
    /// Provides the device's brand name, to attestKey()
    #[key_param(tag = ATTESTATION_ID_BRAND, field = Blob)]
    AttestationIdBrand(Vec<u8>),
    /// Provides the device's device name, to attestKey()
    #[key_param(tag = ATTESTATION_ID_DEVICE, field = Blob)]
    AttestationIdDevice(Vec<u8>),
    /// Provides the device's product name, to attestKey()
    #[key_param(tag = ATTESTATION_ID_PRODUCT, field = Blob)]
    AttestationIdProduct(Vec<u8>),
    /// Provides the device's serial number, to attestKey()
    #[key_param(tag = ATTESTATION_ID_SERIAL, field = Blob)]
    AttestationIdSerial(Vec<u8>),
    /// Provides the primary IMEI for the device, to attestKey()
    #[key_param(tag = ATTESTATION_ID_IMEI, field = Blob)]
    AttestationIdIMEI(Vec<u8>),
    /// Provides a second IMEI for the device, to attestKey()
    #[key_param(tag = ATTESTATION_ID_SECOND_IMEI, field = Blob)]
    AttestationIdSecondIMEI(Vec<u8>),
    /// Provides the MEIDs for all radios on the device, to attestKey()
    #[key_param(tag = ATTESTATION_ID_MEID, field = Blob)]
    AttestationIdMEID(Vec<u8>),
    /// Provides the device's manufacturer name, to attestKey()
    #[key_param(tag = ATTESTATION_ID_MANUFACTURER, field = Blob)]
    AttestationIdManufacturer(Vec<u8>),
    /// Provides the device's model name, to attestKey()
    #[key_param(tag = ATTESTATION_ID_MODEL, field = Blob)]
    AttestationIdModel(Vec<u8>),
    /// Specifies the vendor image security patch level with which the key may be used
    #[key_param(tag = VENDOR_PATCHLEVEL, field = Integer)]
    VendorPatchLevel(i32),
    /// Specifies the boot image (kernel) security patch level with which the key may be used
    #[key_param(tag = BOOT_PATCHLEVEL, field = Integer)]
    BootPatchLevel(i32),
    /// Provides "associated data" for AES-GCM encryption or decryption
    #[key_param(tag = ASSOCIATED_DATA, field = Blob)]
    AssociatedData(Vec<u8>),
    /// Provides or returns a nonce or Initialization Vector (IV) for AES-GCM,
    /// AES-CBC, AES-CTR, or 3DES-CBC encryption or decryption
    #[key_param(tag = NONCE, field = Blob)]
    Nonce(Vec<u8>),
    /// Provides the requested length of a MAC or GCM authentication tag, in bits
    #[key_param(tag = MAC_LENGTH, field = Integer)]
    MacLength(i32),
    /// Specifies whether the device has been factory reset since the
    /// last unique ID rotation.  Used for key attestation
    #[key_param(tag = RESET_SINCE_ID_ROTATION, field = BoolValue)]
    ResetSinceIdRotation,
    /// Used to deliver a cryptographic token proving that the user
    /// confirmed a signing request
    #[key_param(tag = CONFIRMATION_TOKEN, field = Blob)]
    ConfirmationToken(Vec<u8>),
    /// Used to deliver the certificate serial number to the KeyMint instance
    /// certificate generation.
    #[key_param(tag = CERTIFICATE_SERIAL, field = Blob)]
    CertificateSerial(Vec<u8>),
    /// Used to deliver the certificate subject to the KeyMint instance
    /// certificate generation. This must be DER encoded X509 name.
    #[key_param(tag = CERTIFICATE_SUBJECT, field = Blob)]
    CertificateSubject(Vec<u8>),
    /// Used to deliver the not before date in milliseconds to KeyMint during key generation/import.
    #[key_param(tag = CERTIFICATE_NOT_BEFORE, field = DateTime)]
    CertificateNotBefore(i64),
    /// Used to deliver the not after date in milliseconds to KeyMint during key generation/import.
    #[key_param(tag = CERTIFICATE_NOT_AFTER, field = DateTime)]
    CertificateNotAfter(i64),
    /// Specifies a maximum boot level at which a key should function
    #[key_param(tag = MAX_BOOT_LEVEL, field = Integer)]
    MaxBootLevel(i32),
}
}

impl From<&KmKeyParameter> for KeyParameterValue {
    fn from(kp: &KmKeyParameter) -> Self {
        kp.clone().into()
    }
}

/// KeyParameter wraps the KeyParameterValue and the security level at which it is enforced.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct KeyParameter {
    value: KeyParameterValue,
    #[serde(deserialize_with = "deserialize_primitive")]
    #[serde(serialize_with = "serialize_primitive")]
    security_level: SecurityLevel,
}

impl KeyParameter {
    /// Create an instance of KeyParameter, given the value and the security level.
    pub fn new(value: KeyParameterValue, security_level: SecurityLevel) -> Self {
        KeyParameter {
            value,
            security_level,
        }
    }

    /// Construct a KeyParameter from the data from a rusqlite row.
    /// Note that following variants of KeyParameterValue should not be stored:
    /// IncludeUniqueID, ApplicationID, ApplicationData, RootOfTrust, UniqueID,
    /// Attestation*, AssociatedData, Nonce, MacLength, ResetSinceIdRotation, ConfirmationToken.
    /// This filtering is enforced at a higher level and here we support conversion for all the
    /// variants.
    pub fn new_from_sql(
        tag_val: Tag,
        data: &SqlField,
        security_level_val: SecurityLevel,
    ) -> Result<Self> {
        Ok(Self {
            value: KeyParameterValue::new_from_sql(tag_val, data)?,
            security_level: security_level_val,
        })
    }

    /// Get the KeyMint Tag of this this key parameter.
    pub fn get_tag(&self) -> Tag {
        self.value.get_tag()
    }

    /// Returns key parameter value.
    pub fn key_parameter_value(&self) -> &KeyParameterValue {
        &self.value
    }

    /// Returns the security level of this key parameter.
    pub fn security_level(&self) -> &SecurityLevel {
        &self.security_level
    }

    /// An authorization is a KeyParameter with an associated security level that is used
    /// to convey the key characteristics to keystore clients. This function consumes
    /// an internal KeyParameter representation to produce the Authorization wire type.
    pub fn into_authorization(self) -> Authorization {
        Authorization {
            securityLevel: self.security_level,
            keyParameter: self.value.into(),
        }
    }
}
