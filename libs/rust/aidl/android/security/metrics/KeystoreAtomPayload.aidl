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

import android.security.metrics.KeyCreationWithGeneralInfo;
import android.security.metrics.KeyCreationWithPurposeAndModesInfo;
import android.security.metrics.KeyCreationWithAuthInfo;
import android.security.metrics.KeyOperationWithGeneralInfo;
import android.security.metrics.KeyOperationWithPurposeAndModesInfo;
import android.security.metrics.StorageStats;
import android.security.metrics.Keystore2AtomWithOverflow;
import android.security.metrics.RkpErrorStats;
import android.security.metrics.CrashStats;

/** @hide */
@RustDerive(Clone=true, Eq=true, PartialEq=true, Ord=true, PartialOrd=true, Hash=true)
union KeystoreAtomPayload {
    StorageStats storageStats;
    KeyCreationWithGeneralInfo keyCreationWithGeneralInfo;
    KeyCreationWithAuthInfo keyCreationWithAuthInfo;
    KeyCreationWithPurposeAndModesInfo keyCreationWithPurposeAndModesInfo;
    Keystore2AtomWithOverflow keystore2AtomWithOverflow;
    KeyOperationWithPurposeAndModesInfo keyOperationWithPurposeAndModesInfo;
    KeyOperationWithGeneralInfo keyOperationWithGeneralInfo;
    RkpErrorStats rkpErrorStats;
    CrashStats crashStats;
}
