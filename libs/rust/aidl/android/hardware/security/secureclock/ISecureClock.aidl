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
 * limitations under the License.
 */

package android.hardware.security.secureclock;
import android.hardware.security.secureclock.TimeStampToken;

/**
 * Secure Clock definition.
 *
 * An ISecureClock provides a keymint service to generate secure timestamp using a secure platform.
 * The secure time stamp contains time in milliseconds. This time stamp also contains a 256-bit MAC
 * which provides integrity protection. The MAC is generated using HMAC-SHA-256 and a shared
 * secret. The shared secret must be available to secure clock service by implementing
 * ISharedSecret aidl. Note: ISecureClock depends on the shared secret, without which the secure
 * time stamp token cannot be generated.
 *
 * The timer must be the same that is used for HardwareAuthTokens. The ISecureClock interface is
 * used to convey a fresh timestamp to those components that do not share a timer with the
 * authenticators.
 * @hide
 */
@VintfStability
interface ISecureClock {
    /**
     * String used as context in the HMAC computation signing the generated time stamp.
     * See TimeStampToken.mac for details.
     */
    const String TIME_STAMP_MAC_LABEL = "Auth Verification";

    /**
     * Generates an authenticated timestamp.
     *
     * @param A challenge value provided by the relying party. It will be included in the generated
     *        TimeStampToken to ensure freshness. The relying service must ensure that the
     *        challenge cannot be specified or predicted by an attacker.
     *
     * @return the TimeStampToken, see the definition for details.
     */
    TimeStampToken generateTimeStamp(in long challenge);
}
