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

use super::*;
use crate::cbor::value::Value;

#[test]
fn test_read_to_value_ok() {
    let tests = vec![
        ("01", Value::Integer(1.into())),
        ("40", Value::Bytes(vec![])),
        ("60", Value::Text(String::new())),
    ];
    for (hexdata, want) in tests {
        let data = hex::decode(hexdata).unwrap();
        let got = read_to_value(&data).unwrap();
        assert_eq!(got, want, "failed for {}", hexdata);
    }
}

#[test]
fn test_read_to_value_fail() {
    let tests = vec![
        ("0101", CborError::ExtraneousData),
        ("43", CborError::DecodeFailed(cbor::de::Error::Io(EndOfFile))),
        ("8001", CborError::ExtraneousData),
    ];
    for (hexdata, want_err) in tests {
        let data = hex::decode(hexdata).unwrap();
        let got_err = read_to_value(&data).expect_err("decoding expected to fail");
        assert_eq!(format!("{:?}", got_err), format!("{:?}", want_err), "failed for {}", hexdata);
    }
}
