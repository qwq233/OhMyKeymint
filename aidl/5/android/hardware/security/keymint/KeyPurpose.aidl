/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.hardware.security.keymint;

/**
 * Possible purposes of a key (or pair).
 * @hide
 */
@VintfStability
@Backing(type="int")
enum KeyPurpose {
    /* Usable with 3DES and AES keys. */
    ENCRYPT = 0,

    /* Usable with RSA, 3DES and AES keys. */
    DECRYPT = 1,

    /* Usable with RSA, EC and HMAC keys. */
    SIGN = 2,

    /* Usable with HMAC keys. */
    VERIFY = 3,

    /* 4 is reserved */

    /* Usable with wrapping keys. */
    WRAP_KEY = 5,

    /* Key Agreement, usable with EC keys. */
    AGREE_KEY = 6,

    /* Usable as an attestation signing key.  Keys with this purpose must not have any other
     * purpose; if they do, key generation/import must be rejected with
     * ErrorCode::INCOMPATIBLE_PURPOSE. (Rationale: If key also included KeyPurpose::SIGN, then
     * it could be used to sign arbitrary data, including any tbsCertificate, and so an
     * attestation produced by the key would have no security properties.)
     */
    ATTEST_KEY = 7,
}
