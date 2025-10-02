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

use crate::cbor::value::Value;
use kmr_derive::AsCborValue;
use kmr_wire::{cbor_type_error, AsCborValue, CborError};

#[derive(Debug, Clone, PartialEq, Eq, AsCborValue)]
struct Timestamp {
    milliseconds: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, AsCborValue)]
struct NamedFields {
    challenge: i64,
    timestamp: Timestamp,
    mac: Vec<u8>,
}

#[test]
fn test_cbor_value_cddl() {
    assert_eq!(<NamedFields>::cddl_typename().unwrap(), "NamedFields");
    assert_eq!(
        <NamedFields>::cddl_schema().unwrap(),
        r#"[
    challenge: int,
    timestamp: Timestamp,
    mac: bstr,
]"#
    );
}

#[test]
fn test_cbor_value_roundtrip() {
    let obj = NamedFields {
        challenge: 42,
        timestamp: Timestamp { milliseconds: 10_000_000 },
        mac: vec![1, 2, 3, 4],
    };

    let obj_val = obj.clone().to_cbor_value().unwrap();
    let recovered_obj = <NamedFields>::from_cbor_value(obj_val).unwrap();
    assert_eq!(obj, recovered_obj);
}

#[test]
fn test_cbor_parse_fail() {
    let tests = vec![
        (Value::Map(vec![]), "expected arr"),
        (Value::Integer(0.into()), "expected arr"),
        (Value::Array(vec![]), "expected arr len 3"),
        (
            Value::Array(vec![
                Value::Integer(0.into()),
                Value::Integer(0.into()),
                Value::Integer(0.into()),
                Value::Integer(0.into()),
            ]),
            "expected arr len 3",
        ),
        (
            Value::Array(vec![
                Value::Integer(0.into()),
                Value::Array(vec![Value::Integer(0.into())]),
                Value::Integer(0.into()),
            ]),
            "expected bstr",
        ),
        (
            Value::Array(vec![
                Value::Integer(0.into()),
                Value::Array(vec![Value::Integer(0.into()), Value::Integer(0.into())]),
                Value::Bytes(vec![1, 2, 3]),
            ]),
            "expected arr len 1",
        ),
    ];
    for (val, wanterr) in tests {
        let result = <NamedFields>::from_cbor_value(val);
        expect_err(result, wanterr);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, AsCborValue)]
struct UnnamedFields(i64, Timestamp);

#[test]
fn test_unnamed_cbor_value_cddl() {
    assert_eq!(<UnnamedFields>::cddl_typename().unwrap(), "UnnamedFields");
    assert_eq!(
        <UnnamedFields>::cddl_schema().unwrap(),
        r#"[
    int,
    Timestamp,
]"#
    );
}

#[test]
fn test_unnamed_cbor_value_roundtrip() {
    let obj = UnnamedFields(42, Timestamp { milliseconds: 10_000_000 });

    let obj_val = obj.clone().to_cbor_value().unwrap();
    let recovered_obj = <UnnamedFields>::from_cbor_value(obj_val).unwrap();
    assert_eq!(obj, recovered_obj);
}

#[test]
fn test_unnamed_cbor_parse_fail() {
    let tests = vec![
        (Value::Map(vec![]), "expected arr"),
        (Value::Integer(0.into()), "expected arr"),
        (Value::Array(vec![]), "expected arr len 2"),
        (
            Value::Array(vec![
                Value::Integer(0.into()),
                Value::Integer(0.into()),
                Value::Integer(0.into()),
            ]),
            "expected arr len 2",
        ),
        (
            Value::Array(vec![
                Value::Bytes(vec![1, 2, 3]),
                Value::Array(vec![Value::Integer(0.into())]),
            ]),
            "expected i64",
        ),
        (
            Value::Array(vec![
                Value::Integer(0.into()),
                Value::Array(vec![Value::Integer(0.into()), Value::Integer(0.into())]),
            ]),
            "expected arr len 1",
        ),
    ];
    for (val, wanterr) in tests {
        let result = <UnnamedFields>::from_cbor_value(val);
        expect_err(result, wanterr);
    }
}

/// Check for an expected error.
#[cfg(test)]
pub fn expect_err<T, E: core::fmt::Debug>(result: Result<T, E>, err_msg: &str) {
    assert!(result.is_err(), "unexpected success; wanted error containing '{}'", err_msg);
    let err = result.err();
    assert!(
        format!("{:?}", err).contains(err_msg),
        "unexpected error {:?}, doesn't contain '{}'",
        err,
        err_msg
    );
}
