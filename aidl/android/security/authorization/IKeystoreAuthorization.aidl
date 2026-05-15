// Copyright 2020, The Android Open Source Project
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

import android.hardware.security.keymint.HardwareAuthToken;
import android.hardware.security.keymint.HardwareAuthenticatorType;
import android.security.authorization.AuthorizationTokens;

/**
 * IKeystoreAuthorization interface exposes the methods for other system components to
 * provide keystore with the information required to enforce authorizations on key usage.
 * @hide
 */
 @SensitiveData
interface IKeystoreAuthorization {
    /**
     * Allows the Android authenticators to hand over an auth token to Keystore.
     * Callers require 'AddAuth' permission.
     * ## Error conditions:
     * `ResponseCode::PERMISSION_DENIED` - if the callers do not have the 'AddAuth' permission.
     * `ResponseCode::SYSTEM_ERROR` - if failed to store the auth token in the database or if failed
     * to add the auth token to the operation, if it is a per-op auth token.
     *
     * @param authToken The auth token created by an authenticator, upon user authentication.
     */
    void addAuthToken(in HardwareAuthToken authToken);

    /**
     * Tells Keystore that the device is now unlocked for a user.  Requires the 'Unlock' permission.
     *
     * This method makes Keystore start allowing the use of the given user's keys that require an
     * unlocked device, following the device boot or an earlier call to onDeviceLocked() which
     * disabled the use of such keys.  In addition, once per boot, this method must be called with a
     * password before keys that require user authentication can be used.
     *
     * This method does two things to restore access to UnlockedDeviceRequired keys.  First, it sets
     * a flag that indicates the user is unlocked.  This is always done, and it makes Keystore's
     * logical enforcement of UnlockedDeviceRequired start passing.  Second, it recovers and caches
     * the user's UnlockedDeviceRequired super keys.  This succeeds only in the following cases:
     *
     *  - The (correct) password is provided, proving that the user has authenticated using LSKF or
     *    equivalent.  This is the most powerful type of unlock.  Keystore uses the password to
     *    decrypt the user's UnlockedDeviceRequired super keys from disk.  It also uses the password
     *    to decrypt the user's CredentialEncrypted super key from disk, if not already done.
     *
     *  - The user's UnlockedDeviceRequired super keys are cached in biometric-encrypted form, and a
     *    matching valid HardwareAuthToken has been added to Keystore.  I.e., class 3 biometric
     *    unlock is enabled and the user recently authenticated using a class 3 biometric.  The keys
     *    are cached in biometric-encrypted form if onDeviceLocked() was called with a nonempty list
     *    of unlockingSids, and onNonLskfUnlockMethodsExpired() was not called later.
     *
     *  - The user's UnlockedDeviceRequired super keys are already cached in plaintext.  This is the
     *    case if onDeviceLocked() was called with weakUnlockEnabled=true, and
     *    onWeakUnlockMethodsExpired() was not called later.  This case provides only
     *    Keystore-enforced logical security for UnlockedDeviceRequired.
     *
     * ## Error conditions:
     * `ResponseCode::PERMISSION_DENIED` - if the caller does not have the 'Unlock' permission.
     * `ResponseCode::VALUE_CORRUPTED` - if a super key can not be decrypted.
     * `ResponseCode::KEY_NOT_FOUND` - if a super key is not found.
     * `ResponseCode::SYSTEM_ERROR` - if another error occurred.
     *
     * @param userId The Android user ID of the user for which the device is now unlocked
     * @param password If available, a secret derived from the user's synthetic password
     */
    void onDeviceUnlocked(in int userId, in @nullable byte[] password);

    /**
     * Tells Keystore that the device is now locked for a user.  Requires the 'Lock' permission.
     *
     * This method makes Keystore stop allowing the use of the given user's keys that require an
     * unlocked device.  This is enforced logically, and when possible it's also enforced
     * cryptographically by wiping the UnlockedDeviceRequired super keys from memory.
     *
     * unlockingSids and weakUnlockEnabled specify the methods by which the device can become
     * unlocked for the user, in addition to LSKF-equivalent authentication.
     *
     * unlockingSids is the list of SIDs of class 3 (strong) biometrics that can unlock.  If
     * unlockingSids is non-empty, then this method saves a copy of the UnlockedDeviceRequired super
     * keys in memory encrypted by a new AES key that is imported into KeyMint and configured to be
     * usable only when user authentication has occurred using any of the SIDs.  This allows the
     * keys to be recovered if the device is unlocked using a class 3 biometric.
     *
     * weakUnlockEnabled is true if the unlock can happen using a method that does not have an
     * associated SID, such as a class 1 (convenience) biometric, class 2 (weak) biometric, or trust
     * agent.  These methods don't count as "authentication" from Keystore's perspective.  In this
     * case, Keystore keeps a copy of the UnlockedDeviceRequired super keys in memory in plaintext,
     * providing only logical security for UnlockedDeviceRequired.
     *
     * ## Error conditions:
     * `ResponseCode::PERMISSION_DENIED` - if the caller does not have the 'Lock' permission.
     *
     * @param userId The Android user ID of the user for which the device is now locked
     * @param unlockingSids SIDs of class 3 biometrics that can unlock the device for the user
     * @param weakUnlockEnabled Whether a weak unlock method can unlock the device for the user
     */
    void onDeviceLocked(in int userId, in long[] unlockingSids, in boolean weakUnlockEnabled);

    /**
    * Tells keystore about a user's credential-encrypted storage being locked.
    * Callers require 'Lock' permission
    *
    * ## Error conditions:
    * 'ResponseCode::PERMISSION_DENIED' - if the callers do not have the 'Lock' permission.
    *
    * @param userId - Android user id
    */
    void onUserStorageLocked(in int userId);

    /**
     * Tells Keystore that weak unlock methods can no longer unlock the device for the given user.
     * This is intended to be called after an earlier call to onDeviceLocked() with
     * weakUnlockEnabled=true.  It upgrades the security level of UnlockedDeviceRequired keys to
     * that which would have resulted from calling onDeviceLocked() with weakUnlockEnabled=false.
     *
     * ## Error conditions:
     * `ResponseCode::PERMISSION_DENIED` - if the caller does not have the 'Lock' permission.
     *
     * @param userId The Android user ID of the user for which weak unlock methods have expired
     */
    void onWeakUnlockMethodsExpired(in int userId);

    /**
     * Tells Keystore that non-LSKF-equivalent unlock methods can no longer unlock the device for
     * the given user.  This is intended to be called after an earlier call to onDeviceLocked() with
     * nonempty unlockingSids.  It upgrades the security level of UnlockedDeviceRequired keys to
     * that which would have resulted from calling onDeviceLocked() with unlockingSids=[] and
     * weakUnlockEnabled=false.
     *
     * ## Error conditions:
     * `ResponseCode::PERMISSION_DENIED` - if the caller does not have the 'Lock' permission.
     *
     * @param userId The Android user ID of the user for which non-LSKF unlock methods have expired
     */
    void onNonLskfUnlockMethodsExpired(in int userId);

    /**
     * Allows Credstore to retrieve a HardwareAuthToken and a TimestampToken.
     * Identity Credential Trusted App can run either in the TEE or in other secure Hardware.
     * So, credstore always need to retrieve a TimestampToken along with a HardwareAuthToken.
     *
     * The passed in |challenge| parameter must always be non-zero.
     *
     * The returned TimestampToken will always have its |challenge| field set to
     * the |challenge| parameter.
     *
     * This method looks through auth-tokens cached by keystore which match
     * the passed-in |secureUserId|.
     * The most recent matching auth token which has a |challenge| field which matches
     * the passed-in |challenge| parameter is returned.
     * In this case the |authTokenMaxAgeMillis| parameter is not used.
     *
     * Otherwise, the most recent matching auth token which is younger
     * than |authTokenMaxAgeMillis| is returned.
     *
     * This method is called by credstore (and only credstore).
     *
     * The caller requires 'get_auth_token' permission.
     *
     * ## Error conditions:
     * `ResponseCode::PERMISSION_DENIED` - if the caller does not have the 'get_auth_token'
     *                                     permission.
     * `ResponseCode::SYSTEM_ERROR` - if failed to obtain an authtoken from the database.
     * `ResponseCode::NO_AUTH_TOKEN_FOUND` - a matching auth token is not found.
     * `ResponseCode::INVALID_ARGUMENT` - if the passed-in |challenge| parameter is zero.
     */
    AuthorizationTokens getAuthTokensForCredStore(in long challenge, in long secureUserId,
     in long authTokenMaxAgeMillis);

    /**
     * Returns the last successful authentication time since boot for the given user with any of the
     * given authenticator types. This is determined by inspecting the cached auth tokens.
     *
     * ## Error conditions:
     * `ResponseCode::NO_AUTH_TOKEN_FOUND` - if there is no matching authentication token found
     */
    long getLastAuthTime(in long secureUserId, in HardwareAuthenticatorType[] authTypes);
}
