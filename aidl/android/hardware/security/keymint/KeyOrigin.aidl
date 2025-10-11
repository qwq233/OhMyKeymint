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
 * The origin of a key (or pair), i.e. where it was generated.  Note that ORIGIN can be found in
 * either the hardware-enforced or software-enforced list for a key, indicating whether the key is
 * hardware or software-based.  Specifically, a key with GENERATED in the hardware-enforced list
 * must be guaranteed never to have existed outside the secure hardware.
 * @hide
 */
@VintfStability
@Backing(type="int")
enum KeyOrigin {
    /** Generated in keyMint.  Should not exist outside the TEE. */
    GENERATED = 0,

    /** Derived inside keyMint.  Likely exists off-device. */
    DERIVED = 1,

    /** Imported into keyMint.  Existed as cleartext in Android. */
    IMPORTED = 2,

    /** Previously used for another purpose that is now obsolete. */
    RESERVED = 3,

    /**
     * Securely imported into KeyMint.  Was created elsewhere, and passed securely through Android
     * to secure hardware.
     */
    SECURELY_IMPORTED = 4,
}
