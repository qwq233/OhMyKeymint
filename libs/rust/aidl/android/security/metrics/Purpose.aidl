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
 * Purpose enum as defined in Keystore2KeyOperationWithPurposeAndModesInfo of
 * frameworks/proto_logging/stats/atoms.proto.
 * @hide
 */
@Backing(type="int")
enum Purpose {
    /** Unspecified takes 0. Other values are incremented by 1 compared to keymint spec. */
    KEY_PURPOSE_UNSPECIFIED = 0,

    /** Usable with RSA, 3DES and AES keys. */
    ENCRYPT = 1,

    /** Usable with RSA, 3DES and AES keys. */
    DECRYPT = 2,

    /** Usable with RSA, EC and HMAC keys. */
    SIGN = 3,

    /** Usable with RSA, EC and HMAC keys. */
    VERIFY = 4,

    /** 4 is reserved */

    /** Usable with RSA keys. */
    WRAP_KEY = 6,

    /** Key Agreement, usable with EC keys. */
    AGREE_KEY = 7,

    /**
     * Usable as an attestation signing key.  Keys with this purpose must not have any other
     * purpose.
     */
    ATTEST_KEY = 8,
}