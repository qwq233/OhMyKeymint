// Copyright 2025, The Android Open Source Project
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

//! This module tracks operations performed on IKeystoreSecurityLevel instances.

use crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel;
use std::collections::HashSet;
use std::sync::{LazyLock, Mutex};

/// Set of security levels of IKeystoreSecurityLevel instances for which an
/// operation was performed since the last call to `reset` (or since boot).
static OPERATION_PERFORMED: LazyLock<Mutex<HashSet<SecurityLevel>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// Indicate that a method was called on an IKeystoreSecurityLevel instance with
/// the given security level.
pub fn notify_operation_performed(sl: SecurityLevel) {
    OPERATION_PERFORMED.lock().unwrap().insert(sl);
}

/// Check if a method was called for an IKeystoreSecurityLevel instance with the
/// given security level since the last call to `reset` (or since boot).
pub fn was_operation_performed(sl: SecurityLevel) -> bool {
    OPERATION_PERFORMED.lock().unwrap().contains(&sl)
}

/// Reset the operations tracked for the given security level.
pub fn reset(sl: SecurityLevel) {
    OPERATION_PERFORMED.lock().unwrap().remove(&sl);
}
