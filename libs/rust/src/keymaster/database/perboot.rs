// Copyright 2021, The Android Open Source Project
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

//! This module implements a per-boot, shared, in-memory storage of auth tokens
//! for the main Keystore 2.0 database module.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::RwLock;

use crate::android::hardware::security::keymint::HardwareAuthToken::HardwareAuthToken;
use crate::android::hardware::security::keymint::HardwareAuthenticatorType::HardwareAuthenticatorType;
use crate::keymaster::db::AuthTokenEntry;

#[derive(PartialEq, PartialOrd, Ord, Eq, Hash)]
struct AuthTokenId {
    user_id: i64,
    auth_id: i64,
    authenticator_type: HardwareAuthenticatorType,
}

impl AuthTokenId {
    fn from_auth_token(tok: &HardwareAuthToken) -> Self {
        AuthTokenId {
            user_id: tok.userId,
            auth_id: tok.authenticatorId,
            authenticator_type: tok.authenticatorType,
        }
    }
}

//Implements Eq/Hash to only operate on the AuthTokenId portion
//of the AuthTokenEntry. This allows a HashSet to DTRT.
#[derive(Clone)]
struct AuthTokenEntryWrap(AuthTokenEntry);

impl std::hash::Hash for AuthTokenEntryWrap {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        AuthTokenId::from_auth_token(&self.0.auth_token).hash(state)
    }
}

impl PartialEq<AuthTokenEntryWrap> for AuthTokenEntryWrap {
    fn eq(&self, other: &AuthTokenEntryWrap) -> bool {
        AuthTokenId::from_auth_token(&self.0.auth_token)
            == AuthTokenId::from_auth_token(&other.0.auth_token)
    }
}

impl Eq for AuthTokenEntryWrap {}

/// Per-boot state structure. Currently only used to track auth tokens.
#[derive(Default)]
pub struct PerbootDB {
    // We can use a .unwrap() discipline on this lock, because only panicking
    // while holding a .write() lock will poison it. The only write usage is
    // an insert call which inserts a pre-constructed pair.
    auth_tokens: RwLock<HashSet<AuthTokenEntryWrap>>,
}

/// The global instance of the perboot DB. Located here rather than in globals
/// in order to restrict access to the database module.
pub static PERBOOT_DB: LazyLock<Arc<PerbootDB>> = LazyLock::new(|| Arc::new(PerbootDB::new()));

impl PerbootDB {
    /// Construct a new perboot database. Currently just uses default values.
    pub fn new() -> Self {
        Default::default()
    }
    /// Add a new auth token + timestamp to the database, replacing any which
    /// match all of user_id, auth_id, and auth_type.
    pub fn insert_auth_token_entry(&self, entry: AuthTokenEntry) {
        self.auth_tokens
            .write()
            .unwrap()
            .replace(AuthTokenEntryWrap(entry));
    }
    /// Locate an auth token entry which matches the predicate with the most
    /// recent update time.
    pub fn find_auth_token_entry<P: Fn(&AuthTokenEntry) -> bool>(
        &self,
        p: P,
    ) -> Option<AuthTokenEntry> {
        let reader = self.auth_tokens.read().unwrap();
        let mut matches: Vec<_> = reader.iter().filter(|x| p(&x.0)).collect();
        matches.sort_by_key(|x| x.0.time_received);
        matches.last().map(|x| x.0.clone())
    }
    /// Return how many auth tokens are currently tracked.
    pub fn auth_tokens_len(&self) -> usize {
        self.auth_tokens.read().unwrap().len()
    }
    #[cfg(test)]
    /// For testing, return all auth tokens currently tracked.
    pub fn get_all_auth_token_entries(&self) -> Vec<AuthTokenEntry> {
        self.auth_tokens
            .read()
            .unwrap()
            .iter()
            .cloned()
            .map(|x| x.0)
            .collect()
    }
}
