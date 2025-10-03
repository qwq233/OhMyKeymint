/*
 * Copyright 2020 The Android Open Source Project
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

import android.hardware.security.keymint.HardwareAuthenticatorType;
import android.hardware.security.secureclock.Timestamp;

/**
 * HardwareAuthToken is used to prove successful user authentication, to unlock the use of a key.
 *
 * HardwareAuthTokens are produced by other secure environment applications, notably GateKeeper and
 * biometric authenticators, in response to successful user authentication events.  These tokens are
 * passed to begin(), update(), and finish() to prove that authentication occurred.  See those
 * methods for more details.  It is up to the caller to determine which of the generated auth tokens
 * is appropriate for a given key operation.
 * @hide
 */
@VintfStability
@RustDerive(Clone=true, Eq=true, PartialEq=true, Ord=true, PartialOrd=true, Hash=true)
parcelable HardwareAuthToken {
    /**
     * challenge is a value that's used to enable authentication tokens to authorize specific
     * events.  The primary use case for challenge is to authorize an IKeyMintDevice cryptographic
     * operation, for keys that require authentication per operation. See begin() for details.
     */
    long challenge;

    /**
     *  userId is the a "secure" user ID.  It is not related to any Android user ID or UID, but is
     *  created in the Gatekeeper application in the secure environment.
     */
    long userId;

    /**
     *  authenticatorId is the a "secure" user ID.  It is not related to any Android user ID or UID,
     *  but is created in an authentication application in the secure environment, such as the
     *  Fingerprint application.
     */
    long authenticatorId;

    /**
     * authenticatorType describes the type of authentication that took place, e.g. password or
     * fingerprint.
     */
    HardwareAuthenticatorType authenticatorType = HardwareAuthenticatorType.NONE;

    /**
     * timestamp indicates when the user authentication took place, in milliseconds since some
     * starting point (generally the most recent device boot) which all of the applications within
     * one secure environment must agree upon.  This timestamp is used to determine whether or not
     * the authentication occurred recently enough to unlock a key (see Tag::AUTH_TIMEOUT).
     */
    Timestamp timestamp;

    /**
     * MACs are computed with a backward-compatible method, used by Keymaster 3.0, Gatekeeper 1.0
     * and Fingerprint 1.0, as well as pre-treble HALs.
     *
     * The MAC is Constants::AUTH_TOKEN_MAC_LENGTH bytes in length and is computed as follows:
     *
     *     HMAC_SHA256(
     *         H, 0 || challenge || user_id || authenticator_id || authenticator_type || timestamp)
     *
     * where ``||'' represents concatenation, the leading zero is a single byte, and all integers
     * are represented as unsigned values, the full width of the type.  The challenge, userId and
     * authenticatorId values are in machine order, but authenticatorType and timestamp are in
     * network order (big-endian).  This odd construction is compatible with the hw_auth_token_t
     * structure.
     */
    byte[] mac;
}
