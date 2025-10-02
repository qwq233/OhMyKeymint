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

use std::collections::BTreeSet;

use super::*;

#[test]
fn test_auto_added_const() {
    let mut want = BTreeSet::new();
    for (tag, info) in INFO.iter() {
        if info.keymint_auto_adds.0 {
            want.insert(*tag);
        }
    }
    let got: BTreeSet<Tag> = AUTO_ADDED_CHARACTERISTICS.iter().cloned().collect();
    assert_eq!(want, got, "AUTO_ADDED_CHARACTERISTICS constant doesn't match INFO contents");
}

#[test]
fn test_keystore_enforced_const() {
    let mut want = BTreeSet::new();
    for (tag, info) in INFO.iter() {
        if info.characteristic == Characteristic::KeystoreEnforced {
            want.insert(*tag);
        }
    }
    let got: BTreeSet<Tag> = KEYSTORE_ENFORCED_CHARACTERISTICS.iter().cloned().collect();
    assert_eq!(want, got, "KEYSTORE_ENFORCED_CHARACTERISTICS constant doesn't match INFO contents");
}

#[test]
fn test_keymint_enforced_const() {
    let mut want = BTreeSet::new();
    for (tag, info) in INFO.iter() {
        if info.characteristic == Characteristic::KeyMintEnforced {
            want.insert(*tag);
        }
    }
    let got: BTreeSet<Tag> = KEYMINT_ENFORCED_CHARACTERISTICS.iter().cloned().collect();
    assert_eq!(want, got, "KEYMINT_ENFORCED_CHARACTERISTICS constant doesn't match INFO contents");
}

#[test]
fn test_tag_bit_index_unique() {
    let mut seen = std::collections::BTreeSet::new();
    for (tag, info) in INFO.iter() {
        assert!(
            !seen.contains(&info.bit_index),
            "Duplicate bit index {} for {:?}",
            info.bit_index,
            tag
        );
        seen.insert(info.bit_index);
        // Bitwise tag tracking currently assumes they will all fit in `u64`
        assert!(info.bit_index < 64);
    }
}

#[test]
fn test_tag_tracker() {
    let tests = vec![
        (true, vec![Tag::BlockMode, Tag::Padding]),
        (true, vec![Tag::BlockMode, Tag::Padding, Tag::BlockMode]),
        (true, vec![Tag::BlockMode, Tag::EcCurve]),
        (true, vec![Tag::BlockMode, Tag::EcCurve, Tag::BlockMode]),
        (false, vec![Tag::BlockMode, Tag::EcCurve, Tag::BlockMode, Tag::EcCurve]),
    ];
    for (valid, list) in tests {
        let mut tracker = DuplicateTagChecker::default();
        let (most, last) = list.split_at(list.len() - 1);
        for tag in most {
            tracker.add(*tag).unwrap();
        }
        let result = tracker.add(last[0]);
        if valid {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }
}
