// Copyright 2021, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package android.security.authorization;

import android.hardware.security.keymint.HardwareAuthToken;
import android.hardware.security.secureclock.TimeStampToken;

/**
 * This parcelable is returned by `IKeystoreAuthorization::getAuthTokensForCredStore`.
 * @hide
 */
parcelable AuthorizationTokens {
    /**
     * HardwareAuthToken provided by an authenticator.
     */
    HardwareAuthToken authToken;
    /**
     * TimeStampToken provided by a SecureClock.
     */
    TimeStampToken timestampToken;
}