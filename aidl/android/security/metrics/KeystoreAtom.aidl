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

import android.security.metrics.KeystoreAtomPayload;

/**
 * Encapsulates a particular atom object of type KeystoreAtomPayload its count. Note that
 * the field: count is only relevant for the atom types that are stored in the
 * in-memory metrics store. E.g. count field is not relevant for the atom types such as StorageStats
 * that are not stored in the metrics store.
 * @hide
 */
@RustDerive(Clone=true, Eq=true, PartialEq=true, Ord=true, PartialOrd=true, Hash=true)
parcelable KeystoreAtom {
    KeystoreAtomPayload payload;
    int count;
}
