/*
 * Copyright 2021, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.security.metrics;

import android.security.metrics.AtomID;

/**
 * Logs the atom id of the atoms associated with key creation/operation events, that have reached
 * the maximum storage limit allocated for different atom objects of that atom,
 * in keystore in-memory store.
 *
 * Size of the storage bucket for each atom is limited considering their expected cardinaltity.
 * This limit may exceed if the dimensions of the atoms take a large number of unexpected
 * combinations. This atom is used to track such cases.
 * @hide
 */
@RustDerive(Clone=true, Eq=true, PartialEq=true, Ord=true, PartialOrd=true, Hash=true)
parcelable Keystore2AtomWithOverflow {
    AtomID atom_id;
}