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
 * KeyOrigin enum as defined in Keystore2KeyCreationWithGeneralInfo of
 * frameworks/proto_logging/stats/atoms.proto.
 * @hide
 */
@Backing(type="int")
enum KeyOrigin {
    /** Unspecified takes 0. Other values are incremented by 1 compared to keymint spec. */
    ORIGIN_UNSPECIFIED = 0,

    /** Generated in KeyMint.  Should not exist outside the TEE. */
    GENERATED = 1,

    /** Derived inside KeyMint.  Likely exists off-device. */
    DERIVED = 2,

    /** Imported into KeyMint.  Existed as cleartext in Android. */
    IMPORTED = 3,

    /** Previously used for another purpose that is now obsolete. */
    RESERVED = 4,

    /** Securely imported into KeyMint. */
    SECURELY_IMPORTED = 5,
}