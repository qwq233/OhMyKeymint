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

import android.hardware.security.keymint.KeyParameter;
import android.hardware.security.keymint.SecurityLevel;

/**
 * KeyCharacteristics defines the attributes of a key that are enforced by KeyMint, and the security
 * level (see SecurityLevel.aidl) of that enforcement.
 *
 * The `generateKey` `importKey` and `importWrappedKey` methods each return an array of
 * KeyCharacteristics, specifying the security levels of enforcement and the authorizations
 * enforced.  Note that enforcement at a given security level means that the semantics of the tag
 * and value are fully enforced.  See the definition of individual tags for specifications of what
 * must be enforced.
 * @hide
 */
@VintfStability
parcelable KeyCharacteristics {
    /**
     * The security level enforcing this collection of key properties.
     */
    SecurityLevel securityLevel = SecurityLevel.SOFTWARE;

    /**
     * `authorizations` is a list of key properties that are enforced at this security level.
     * A key can have different properties enforced by components of different security levels.
     * For example, some properties are provided by the operating system, which has a
     * different security level to the IKeyMintDevice.
     * See the `keyCharacteristics` field in `KeyCreationResult` for more details.
     */
    KeyParameter[] authorizations;
}
