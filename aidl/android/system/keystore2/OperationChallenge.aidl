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

/**
 * An operation challenge is returned by `IKeystoreSecurityLevel::create` iff
 * the new operation requires user authorization. The challenge may be passed
 * to an authenticator, such as Gatekeeper or Fingerprint.
 * @hide
 */
@VintfStability
parcelable OperationChallenge {
    long challenge;
}