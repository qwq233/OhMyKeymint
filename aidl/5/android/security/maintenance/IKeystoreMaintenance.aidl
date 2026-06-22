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

package android.security.maintenance;

import android.system.keystore2.Domain;
import android.system.keystore2.KeyDescriptor;

/**
 * IKeystoreMaintenance interface exposes the methods for adding/removing users and changing the
 * user's password.
 * @hide
 */
 @SensitiveData
interface IKeystoreMaintenance {

    /**
     * Allows LockSettingsService to inform keystore about adding a new user.
     * Callers require 'ChangeUser' permission.
     *
     * ## Error conditions:
     * `ResponseCode::PERMISSION_DENIED` - if the callers do not have the 'ChangeUser' permission.
     * `ResponseCode::SYSTEM_ERROR` - if failed to delete the keys of an existing user with the same
     * user id.
     *
     * @param userId - Android user id
     */
    void onUserAdded(in int userId);

    /**
     * Allows LockSettingsService to tell Keystore to create a user's superencryption keys and store
     * them encrypted by the given secret.  Requires 'ChangeUser' permission.
     *
     * ## Error conditions:
     * `ResponseCode::PERMISSION_DENIED` - if caller does not have the 'ChangeUser' permission
     * `ResponseCode::SYSTEM_ERROR` - if failed to initialize the user's super keys
     *
     * @param userId - Android user id
     * @param password - a secret derived from the synthetic password of the user
     * @param allowExisting - if true, then the keys already existing is not considered an error
     */
    void initUserSuperKeys(in int userId, in byte[] password, in boolean allowExisting);

    /**
     * Allows LockSettingsService to inform keystore about removing a user.
     * Callers require 'ChangeUser' permission.
     *
     * ## Error conditions:
     * `ResponseCode::PERMISSION_DENIED` - if the callers do not have the 'ChangeUser' permission.
     * `ResponseCode::SYSTEM_ERROR` - if failed to delete the keys of the user being deleted.
     *
     * @param userId - Android user id
     */
    void onUserRemoved(in int userId);

    /**
     * Allows LockSettingsService to tell Keystore that a user's LSKF is being removed, ie the
     * user's lock screen is changing to Swipe or None.  Requires 'ChangePassword' permission.
     *
     * ## Error conditions:
     * `ResponseCode::PERMISSION_DENIED` - if caller does not have the 'ChangePassword' permission
     * `ResponseCode::SYSTEM_ERROR` - if failed to delete the user's auth-bound keys
     *
     * @param userId - Android user id
     */
    void onUserLskfRemoved(in int userId);

    /**
     * This function deletes all keys within a namespace. It mainly gets called when an app gets
     * removed and all resources of this app need to be cleaned up.
     *
     * @param domain - One of Domain.APP or Domain.SELINUX.
     * @param nspace - The UID of the app that is to be cleared if domain is Domain.APP or
     *                 the SEPolicy namespace if domain is Domain.SELINUX.
     */
    void clearNamespace(Domain domain, long nspace);

    /**
     * This function notifies the Keymint device of the specified securityLevel that
     * early boot has ended, so that they no longer allow early boot keys to be used.
     * ## Error conditions:
     * `ResponseCode::PERMISSION_DENIED` - if the caller does not have the 'EarlyBootEnded'
     *                                     permission.
     * A KeyMint ErrorCode may be returned indicating a backend diagnosed error.
     */
     void earlyBootEnded();

    /**
     * Migrate a key from one namespace to another. The caller must have use, grant, and delete
     * permissions on the source namespace and rebind permissions on the destination namespace.
     * The source may be specified by Domain::APP, Domain::SELINUX, or Domain::KEY_ID. The target
     * may be specified by Domain::APP or Domain::SELINUX.
     *
     * ## Error conditions:
     * `ResponseCode::PERMISSION_DENIED` - If the caller lacks any of the required permissions.
     * `ResponseCode::KEY_NOT_FOUND` - If the source did not exist.
     * `ResponseCode::INVALID_ARGUMENT` - If the target exists or if any of the above mentioned
     *                                    requirements for the domain parameter are not met.
     * `ResponseCode::SYSTEM_ERROR` - An unexpected system error occurred.
     */
    void migrateKeyNamespace(in KeyDescriptor source, in KeyDescriptor destination);

    /**
     * Deletes all keys in all hardware keystores.  Used when keystore is reset completely.  After
     * this function is called all keys with Tag::ROLLBACK_RESISTANCE in their hardware-enforced
     * authorization lists must be rendered permanently unusable.  Keys without
     * Tag::ROLLBACK_RESISTANCE may or may not be rendered unusable.
     */
    void deleteAllKeys();

    /**
     * Returns a list of App UIDs that have keys associated with the given SID, under the
     * given user ID.
     * When a given user's LSKF is removed or biometric authentication methods are changed
     * (addition of a fingerprint, for example), authentication-bound keys may be invalidated.
     * This method allows the platform to find out which apps would be affected (for a given user)
     * when a given user secure ID is removed.
     * Callers require the `android.permission.MANAGE_USERS` Android permission
     * (not SELinux policy).
     *
     * @param userId The affected user.
     * @param sid The user secure ID - identifier of the authentication method.
     *
     * @return A list of APP UIDs, in the form of (AID + userId*AID_USER_OFFSET), that have
     *         keys auth-bound to the given SID. These values can be passed into the
     *         PackageManager for resolution.
     */
    long[] getAppUidsAffectedBySid(in int userId, in long sid);
}
