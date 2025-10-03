/*
 * Copyright 2020, The Android Open Source Project
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

package android.system.keystore2;

import android.hardware.security.keymint.SecurityLevel;
import android.system.keystore2.Authorization;
import android.system.keystore2.IKeystoreSecurityLevel;
import android.system.keystore2.KeyDescriptor;

/**
 * Metadata of a key entry including the key characteristics `authorizations`
 * security level `securityLevel` and a key id based key descriptor.
 * See KeyDescriptor.aidl for the benefits of key id based key descriptor usage.
 * @hide
 */
@VintfStability
parcelable KeyMetadata {
    /**
     * The KeyId based key descriptor. Using this key descriptor for subsequent
     * operations ensures that the private key material used in those operations
     * corresponds to the meta data in this structure. Alias based key descriptors
     * may point to a different key if the alias was rebound in the meantime.
     */
    KeyDescriptor key;
    /**
     * The security level that the key resides in.
     * TODO, we could also take this from the origin tag in authorizations.
     */
    SecurityLevel keySecurityLevel = SecurityLevel.SOFTWARE;
    /**
     * The authorizations describing the key, e.g., the algorithm, key size,
     * permissible purposes, digests and paddings, as well as usage restrictions,
     * e.g., whether or not user authorization is required.
     */
    Authorization[] authorizations;
    /**
     * The public certificate if the requested key is an asymmetric key.
     */
    @nullable byte[] certificate;
    /**
     * The certificate chain if the key has one, e.g., if the key was generated with
     * attestation or if the client installed one using `updateSubcomponent`.
     */
    @nullable byte[] certificateChain;
    /**
     * The time of the last modification in milliseconds since January 1st 1970.
     */
    long modificationTimeMs;
}