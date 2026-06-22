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

//! Implements the IKeystoreMetrics AIDL interface for the OMK RPC surface.

use crate::android::security::metrics::{
    AtomID::AtomID,
    IKeystoreMetrics::{BnKeystoreMetrics, IKeystoreMetrics},
    KeystoreAtom::KeystoreAtom,
};
use crate::err as ks_err;
use crate::keymaster::error::into_logged_binder;
use crate::keymaster::metrics_store::METRICS_STORE;
use crate::keymaster::permission::{check_keystore_permission, KeystorePerm};
use crate::watchdog as wd;
use anyhow::{Context, Result};
use rsbinder::status::Result as BinderResult;
use rsbinder::{BinderFeatures, Interface, Strong};

pub struct Metrics;

impl Metrics {
    pub fn new_native_binder() -> Result<Strong<dyn IKeystoreMetrics>> {
        let mut features = BinderFeatures::default();
        features.set_requesting_sid = true;
        Ok(BnKeystoreMetrics::new_binder_with_features(Self, features))
    }

    fn pull_metrics(&self, atom_id: AtomID) -> Result<Vec<KeystoreAtom>> {
        check_keystore_permission(KeystorePerm::PullMetrics, None).context(ks_err!())?;
        METRICS_STORE.get_atoms(atom_id)
    }
}

impl Interface for Metrics {}

#[allow(non_snake_case)]
impl IKeystoreMetrics for Metrics {
    fn pullMetrics(&self, atom_id: AtomID) -> BinderResult<Vec<KeystoreAtom>> {
        let _wp = wd::watch_millis_with("IKeystoreMetrics::pullMetrics", 500, atom_id);
        self.pull_metrics(atom_id).map_err(into_logged_binder)
    }
}
