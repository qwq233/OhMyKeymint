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

/**
 * Formats for key import and export.
 * @hide
 */
@VintfStability
@Backing(type="int")
enum KeyFormat {
    /** X.509 certificate format, for public key export. */
    X509 = 0,
    /** PKCS#8 format, asymmetric key pair import. */
    PKCS8 = 1,
    /**
     * Raw bytes, for symmetric key import, and for import of raw asymmetric keys for curve 25519.
     */
    RAW = 3,
}
