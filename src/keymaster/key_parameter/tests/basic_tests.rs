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

use super::*;

// Test basic functionality of KeyParameter.
#[test]
fn test_key_parameter() {
    let key_parameter = KeyParameter::new(
        KeyParameterValue::Algorithm(Algorithm::RSA),
        SecurityLevel::STRONGBOX,
    );

    assert_eq!(key_parameter.get_tag(), Tag::ALGORITHM);

    assert_eq!(
        *key_parameter.key_parameter_value(),
        KeyParameterValue::Algorithm(Algorithm::RSA)
    );

    assert_eq!(*key_parameter.security_level(), SecurityLevel::STRONGBOX);
}
