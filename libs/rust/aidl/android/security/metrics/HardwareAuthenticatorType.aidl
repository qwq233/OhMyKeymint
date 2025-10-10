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
 * HardwareAuthenticatorType enum as defined in Keystore2KeyCreationWithAuthInfo of
 * frameworks/proto_logging/stats/atoms.proto.
 * @hide
 */
@Backing(type="int")
enum HardwareAuthenticatorType {
    /** Unspecified takes 0. Other values are incremented by 1 compared to keymint spec. */
    AUTH_TYPE_UNSPECIFIED = 0,
    NONE = 1,
    PASSWORD = 2,
    FINGERPRINT = 3,
    ANY = 5,
}