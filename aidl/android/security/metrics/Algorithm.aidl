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

/**
 * Algorithm enum as defined in stats/enums/system/security/keystore2/enums.proto.
 * @hide
 */
@Backing(type="int")
enum Algorithm {
    /** ALGORITHM is prepended because UNSPECIFIED exists in other enums as well. */
    ALGORITHM_UNSPECIFIED = 0,

    /** Asymmetric algorithms. */
    RSA = 1,

    /** 2 removed, do not reuse. */
    EC = 3,

    /** Block cipher algorithms. */
    AES = 32,
    TRIPLE_DES = 33,

    /** MAC algorithms. */
    HMAC = 128,
}