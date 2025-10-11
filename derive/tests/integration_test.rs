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

use kmr_derive::AsCborValue;
use kmr_wire::{cbor_type_error, AsCborValue, CborError};

#[derive(Clone, Debug, PartialEq, Eq, AsCborValue)]
struct NamedFields {
    i: i32,
    s: String,
}

#[test]
fn test_derive_named_struct_roundtrip() {
    let want = NamedFields {
        i: 42,
        s: "a string".to_string(),
    };
    let want_value = want.clone().to_cbor_value().unwrap();
    let got = NamedFields::from_cbor_value(want_value).unwrap();
    assert_eq!(want, got);
    assert_eq!(NamedFields::cddl_typename().unwrap(), "NamedFields");
    assert_eq!(
        NamedFields::cddl_schema().unwrap(),
        "[\n    i: int,\n    s: tstr,\n]"
    );
}

#[derive(Clone, Debug, PartialEq, Eq, AsCborValue)]
struct UnnamedFields(i32, String);

#[test]
fn test_derive_unnamed_struct_roundtrip() {
    let want = UnnamedFields(42, "a string".to_string());
    let want_value = want.clone().to_cbor_value().unwrap();
    let got = UnnamedFields::from_cbor_value(want_value).unwrap();
    assert_eq!(want, got);
    assert_eq!(UnnamedFields::cddl_typename().unwrap(), "UnnamedFields");
    assert_eq!(
        UnnamedFields::cddl_schema().unwrap(),
        "[\n    int,\n    tstr,\n]"
    );
}

#[derive(Clone, Debug, PartialEq, Eq, AsCborValue)]
enum NumericEnum {
    One = 1,
    Two = 2,
    Three = 3,
}

#[test]
fn test_derive_numeric_enum_roundtrip() {
    let want = NumericEnum::Two;
    let want_value = want.clone().to_cbor_value().unwrap();
    let got = NumericEnum::from_cbor_value(want_value).unwrap();
    assert_eq!(want, got);
    assert_eq!(NumericEnum::cddl_typename().unwrap(), "NumericEnum");
    assert_eq!(
        NumericEnum::cddl_schema().unwrap(),
        "&(\n    NumericEnum_One: 1,\n    NumericEnum_Two: 2,\n    NumericEnum_Three: 3,\n)"
    );
}
