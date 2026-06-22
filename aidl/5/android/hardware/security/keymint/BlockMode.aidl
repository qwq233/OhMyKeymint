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
 * Symmetric block cipher modes provided by IKeyMintDevice implementations.
 * @hide
 */
@VintfStability
@Backing(type="int")
enum BlockMode {
    /*
     * Unauthenticated modes, usable only for encryption/decryption and not generally recommended
     * except for compatibility with existing other protocols.
     */
    ECB = 1,
    CBC = 2,
    CTR = 3,

    /*
     * Authenticated modes, usable for encryption/decryption and signing/verification.  Recommended
     * over unauthenticated modes for all purposes.
     */
    GCM = 32,
}
