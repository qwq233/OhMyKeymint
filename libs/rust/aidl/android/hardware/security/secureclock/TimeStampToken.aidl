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

package android.hardware.security.secureclock;

import android.hardware.security.secureclock.Timestamp;

/**
 * TimeStampToken instances are used for secure environments that requires secure time information.
 * @hide
 */
@VintfStability
@RustDerive(Clone=true, Eq=true, PartialEq=true, Ord=true, PartialOrd=true, Hash=true)
parcelable TimeStampToken {
    /**
     * The challenge that was provided as argument to ISecureClock.generateTimeStamp by the client.
     */
    long challenge;

    /**
     * The current time of the secure environment that generates the TimeStampToken.
     */
    Timestamp timestamp;

    /**
     * 32-byte HMAC-SHA256 of the above values, computed as:
     *
     *    HMAC(H,
     *         ISecureClock.TIME_STAMP_MAC_LABEL || challenge || timestamp || 1 )
     *
     * where:
     *
     *   ``ISecureClock.TIME_STAMP_MAC_LABEL'' is a string constant defined in ISecureClock.aidl.
     *
     *   ``H'' is the shared HMAC key (see computeSharedHmac() in ISharedSecret).
     *
     *   ``||'' represents concatenation
     *
     * The representation of challenge and timestamp is as 64-bit unsigned integers in big-endian
     * order.  1, above, is a 32-bit unsigned integer, also big-endian.
     */
    byte[] mac;
}
