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

/**
 * Used as exception codes by IKeystoreAuthorization.
 * @hide
 */
@Backing(type="int")
enum ResponseCode {
    /**
     * A matching auth token is not found.
     */
    NO_AUTH_TOKEN_FOUND = 1,
    /**
     * The matching auth token is expired.
     */
    AUTH_TOKEN_EXPIRED = 2,
    /**
     * Same as in keystore2/ResponseCode.aidl.
     * Any unexpected Error such as IO or communication errors.
     */
    SYSTEM_ERROR = 4,
    /**
     * Same as in keystore2/ResponseCode.aidl.
     * Indicates that the caller does not have the permissions for the attempted request.
     */
    PERMISSION_DENIED = 6,
    /**
     * Same as in keystore2/ResponseCode.aidl.
     * Indicates that the requested key does not exist.
     */
    KEY_NOT_FOUND = 7,
    /**
     * Same as in keystore2/ResponseCode.aidl.
     * Indicates that a value being processed is corrupted.
     */
    VALUE_CORRUPTED = 8,
    /**
     * Same as in keystore2/ResponseCode.aidl.
     * Indicates that an invalid argument was passed to an API call.
     */
    INVALID_ARGUMENT = 20,

 }