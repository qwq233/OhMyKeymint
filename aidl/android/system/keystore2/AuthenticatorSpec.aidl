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

import android.hardware.security.keymint.HardwareAuthenticatorType;

/**
 * The authenticator spec is used by `IKeystoreSecurityLevel::importWrappedKey`
 * to specify the sid of each possible authenticator type, e.g., password or
 * biometric authenticator, that the imported key may be bound to.
 * @hide
 */
@VintfStability
parcelable AuthenticatorSpec {
    /**
     * The type of the authenticator in question.
     */
    HardwareAuthenticatorType authenticatorType = HardwareAuthenticatorType.NONE;
    /**
     * The secure user id by which the given authenticator knows the
     * user that a key should be bound to.
     */
    long authenticatorId;
}
