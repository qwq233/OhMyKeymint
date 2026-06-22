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
 * AIDL enum representing the
 * android.os.statsd.Keystore2KeyCreationWithAuthInfo.HardwareAuthenticatorType protocol buffer enum
 * defined in frameworks/proto_logging/stats/atoms.proto.
 *
 * This enum is a mirror of
 * hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/HardwareAuthenticatorType.aidl
 * except that:
 *   - The enum tag number for the ANY value is set to 5,
 *   - The enum tag numbers of all other values are incremented by 1, and
 *   - Two new values are added: AUTH_TYPE_UNSPECIFIED and NO_AUTH_TYPE.
 * The KeyMint AIDL enum is a bitmask, but since the enum tag numbers in this metrics-specific
 * mirror were shifted, this enum can't behave as a bitmask. As a result, we have to explicitly add
 * values to represent the bitwise OR of pairs of values that we expect to see in the wild.
 * @hide
 */
@Backing(type="int")
enum HardwareAuthenticatorType {
    // Sentinel value to represent undefined enum tag numbers (which would represent combinations of
    // values from the KeyMint enum that aren't explicitly represented here). We don't expect to see
    // this value in the metrics, but if we do it means that an unexpected (bitwise OR) combination
    // of KeyMint HardwareAuthenticatorType values is being used as the HardwareAuthenticatorType
    // key parameter.
    AUTH_TYPE_UNSPECIFIED = 0,
    // Corresponds to KeyMint's HardwareAuthenticatorType::NONE value (enum tag number 0).
    NONE = 1,
    // Corresponds to KeyMint's HardwareAuthenticatorType::PASSWORD value (enum tag number 1 << 0).
    PASSWORD = 2,
    // Corresponds to KeyMint's HardwareAuthenticatorType::FINGERPRINT value (enum tag number
    // 1 << 1).
    FINGERPRINT = 3,
    // Corresponds to the (bitwise OR) combination of KeyMint's HardwareAuthenticatorType::PASSWORD
    // and HardwareAuthenticatorType::FINGERPRINT values.
    PASSWORD_OR_FINGERPRINT = 4,
    // Corresponds to KeyMint's HardwareAuthenticatorType::ANY value (enum tag number 0xFFFFFFFF).
    ANY = 5,
    // No HardwareAuthenticatorType was specified in the key parameters.
    NO_AUTH_TYPE = 6,
}