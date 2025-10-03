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

import android.system.keystore2.IKeystoreSecurityLevel;
import android.system.keystore2.KeyMetadata;

/**
 * This includes the metadata of the requested key and the security level interface
 * corresponding to the key's security level.
 * @hide
 */
@VintfStability
parcelable KeyEntryResponse {
    /**
     * The security level interface is served by the Keystore instance
     * that corresponds to the key's security level. It can be used to start
     * operations, generate, and import keys. This field is optional,
     * it is only populated by `IKeystoreService::getKeyEntry`.
     */
    @nullable IKeystoreSecurityLevel iSecurityLevel;
    /**
     * The KeyId based key descriptor. Using this key descriptor for subsequent
     * operations ensures that the private key material used in those operations
     * corresponds to the meta data in this structure. Alias based key descriptors
     * may point to a different key if the alias was rebound in the meantime.
     */
    KeyMetadata metadata;
}