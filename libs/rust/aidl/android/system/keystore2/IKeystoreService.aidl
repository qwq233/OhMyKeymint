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

package android.system.keystore2;

import android.hardware.security.keymint.SecurityLevel;
import android.hardware.security.keymint.Tag;
import android.system.keystore2.Domain;
import android.system.keystore2.IKeystoreSecurityLevel;
import android.system.keystore2.KeyDescriptor;
import android.system.keystore2.KeyEntryResponse;

/**
 * `IKeystoreService` is the primary interface to Keystore. It primarily provides
 * access to simple database bound requests. Request that require interactions
 * with a KeyMint backend are delegated to `IKeystoreSecurityLevel` which
 * may be acquired through this interface as well.
 *
 * ## Error conditions
 * Error conditions are reported as service specific error.
 * Positive codes correspond to `android.system.keystore2.ResponseCode`
 * and indicate error conditions diagnosed by the Keystore 2.0 service.
 * Negative codes correspond to `android.hardware.security.keymint.ErrorCode` and
 * indicate KeyMint back end errors. Refer to the KeyMint interface spec for
 * detail.
 * @hide
 */
@VintfStability
interface IKeystoreService {

    /**
     * Returns the security level specific interface.
     *
     * ## Error conditions
     * `ErrorCode::HARDWARE_TYPE_UNAVAILABLE` if the requested security level does not exist.
     */
    IKeystoreSecurityLevel getSecurityLevel(in SecurityLevel securityLevel);

    /**
     * Loads all relevant information about a key stored in the keystore database.
     * This includes the key metadata describing the key algorithm and usage
     * restrictions, and an optional certificate and certificate chain if
     * it is an asymmetric key.
     *
     * The metadata also includes an updated key id based KeyDescriptor (Domain::KEY_ID).
     * See KeyDescriptor.aidl for benefits of key id based key descriptor usage.
     *
     * The key maybe specified by any type of key descriptor (see KeyDescriptor.aidl)
     * except `Domain::BLOB`, in which case the key is not stored in the database.
     *
     * ## Error conditions
     * `ResponseCode::KEY_NOT_FOUND` if the key did not exist.
     * `ResponseCode::PERMISSION_DENIED` if the caller does not possess the `GET_INFO` permission
     *                 for the specified key.
     *
     * @param key Describes the key entry that is to be loaded.
     *
     * @param metadata Returns the key characteristics, security level of the key and
     *                      key id based key descriptor.
     *
     * @param publicCert The public certificate if the requested key is an asymmetric key.
     *
     * @param certificateChain The certificate chain if the key has one, e.g., if the
     *                      key was generated with attestation or if the client
     *                      installed one using `updateSubcomponent`.
     *
     * @return The `KeyEntryResponse includes the requested key's metadata and the security level
     *                      interface corresponding to the key's security level, which can be used
     *                      to start operations, generate, and import keys.
     */
    KeyEntryResponse getKeyEntry(in KeyDescriptor key);

    /**
     * Allows setting the public key or certificate chain of an asymmetric key.
     * Keystore 2.0 populates the subcomponents of asymmetric keys with a self signed certificate
     * or an attestation certificate, and an optional certificate chain. With this function these
     * fields can be updated with custom certificates.
     *
     * Callers require the `UPDATE` permission.
     *
     * If no key by the given name is found and only a the certificateChain argument is given,
     * A new entry is created by the given name. This is used by the Keystore SPI to create.
     * pure certificate entries. In this case the `REBIND` permission is checked.
     *
     * ## Error conditions
     * `ResponseCode::KEY_NOT_FOUND` if the key did not exist.
     * `ResponseCode::PERMISSION_DENIED` if the caller does not possess the `UPDATE` permission
     *                 for the specified key.
     *
     * @param key The key the subcomponents of which are to be updated.
     *
     * @param publicCert An optional new public key certificate for the given key.
     *
     * @param certificateChain An optional certificate chain for the given key.
     */
    void updateSubcomponent(in KeyDescriptor key, in @nullable byte[] publicCert,
                            in @nullable byte[] certificateChain);

    /**
     * List all entries accessible by the caller in the given `domain` and `nspace`.
     * If the number of entries accessible by the caller is greater than could fit in one Binder
     * transaction, a truncated list may be returned. Use `listEntriesBatched` in this case to
     * list all entries in batches.
     *
     * Callers must have the `GET_INFO` permission for the requested namespace to list all the
     * entries.
     *
     * ## Error conditions
     * `ResponseCode::INVALID_ARGUMENT` if `domain` is other than `Domain::APP` or `Domain::SELINUX`
     * `ResponseCode::PERMISSION_DENIED` if the caller does not have the permission `GET_INFO`
     *               For the requested namespace.
     *
     * @param domain If `Domain::APP` is passed, returns all keys associated with the caller's UID and
     *               the namespace parameter is ignored.
     *               If `Domain::SELINUX` is passed, returns all keys associated with the given
     *               namespace.
     *
     * @param nspace The SELinux keystore2_key namespace if `domain` is `Domain::SELINUX`,
     *               ignored otherwise.
     *
     * Note: `namespace` is a keyword in C++, the underscore disambiguates.
     *
     * @return List of KeyDescriptors.
     * @deprecated use listEntriesBatched instead.
     */
    KeyDescriptor[] listEntries(in Domain domain, in long nspace);

    /**
     * Deletes the designated key. This method can be used on keys with any domain except
     * Domain::BLOB, since keystore knows which security level any non Domain::BLOB key
     * belongs to. To delete Domain::BLOB keys, use IKeystoreSecurityLevel::deleteKey()
     * instead.
     *
     * ## Error conditions
     * `ResponseCode::KEY_NOT_FOUND` if the key designated by `key` did not exist.
     * `ResponseCode::PERMISSION_DENIED` if the caller does not have the permission `DELETE`
     *               for the designated key.
     *
     * @param key The key to be deleted.
     */
    void deleteKey(in KeyDescriptor key);

    /**
     * Grant takes a key descriptor `key`, the uid of a grantee `granteeUid` and a set of
     * permissions `accessVector`.
     * It creates a new key descriptor `grantKey` that can be used by the grantee designated by
     * its uid. Before the grantee can use the new grant, `grantKey` must be communicated to the
     * grantee using IPC.
     * Key usage by the grantee is restricted by `accessVector` which is a set of permissions of the
     * SELinux class "keystore2_key". A grant can never convey more privileges to a key than the
     * owner of that key has. To that end, this function must check if `accessVector` is a subset
     * of the granter's permission to their key. Additionally, the "grant" permission is checked.
     * If either of these checks fails `ResponseCode::PERMISSION_DENIED` is returned. If the grant
     * already exists, this call may update the access vector and return the same grant key
     * descriptor as when the grant was first created.
     *
     * ## Error conditions
     * `ResponseCode::KEY_NOT_FOUND` if the key designated by `key` did not exist.
     * `ResponseCode::PERMISSION_DENIED` if the caller does not have the permission `GRANT`
     *               for the designated key.
     *
     * @param key The key to be granted access to.
     *
     * @param granteeUid The UID of the grantee.
     *
     * @param accessVector A bitmap of `KeyPermission` values.
     *
     * @return A key descriptor that can be used by the grantee to perform operations
     *                  on the given key within the limits of the supplied access vector.
     */
    KeyDescriptor grant(in KeyDescriptor key, in int granteeUid, in int accessVector);

    /**
     * Removes a grant from the grant database. Because a key can be granted to multiple parties,
     * a grant is uniquely identified by target key and the grantee's UID.
     *
     * ## Error conditions
     * `ResponseCode::KEY_NOT_FOUND` if the key designated by `key` did not exist.
     * `ResponseCode::PERMISSION_DENIED` if the caller does not have the permission `grant`
     *               for the designated key.
     */
    void ungrant(in KeyDescriptor key, in int granteeUid);

    /**
     * Get the number of entries accessible to the caller in the given `domain` and `nspace`.
     *
     * Callers must have the `GET_INFO` permission for the requested namespace determine the number
     * of entries.
     *
     * ## Error conditions
     * `ResponseCode::INVALID_ARGUMENT` if `domain` is other than `Domain::APP` or `Domain::SELINUX`
     * `ResponseCode::PERMISSION_DENIED` if the caller does not have the permission `GET_INFO`
     *               For the requested namespace.
     *
     * @param domain If `Domain::APP` is passed, returns all keys associated with the caller's UID
     *               and the namespace parameter is ignored.
     *               If `Domain::SELINUX` is passed, returns all keys associated with the given
     *               namespace.
     *
     * @param nspace The SELinux keystore2_key namespace if `domain` is `Domain::SELINUX`,
     *               ignored otherwise.
     *
     * @return Number of entries.
     */
    int getNumberOfEntries(in Domain domain, in long nspace);

    /**
     * List all entries accessible by the caller in the given `domain` and
     * `nspace`, starting with the first entry greater than `startingPastAlias`.
     * If the number of entries accessible by the caller is greater than could fit in one Binder
     * transaction, a truncated list will be returned.
     *
     * See the `listEntries` variant above for calling permissions and documentation of the
     * `domain` and `nspace` parameters.
     *
     * Notes:
     * Consistency: The order of entries returned by this method is stable across calls.
     * If entries have been deleted or added to Keystore between calls to
     * this method, then some entries may be missing from the combined listing.
     *
     * Length of returned list: If Keystore estimates that the returned list would exceed
     * the Binder transaction size limit, it will return a smaller number of entries than
     * are available. Subsequent calls to this method need to be made with different
     * starting points.
     *
     * @param domain See `listEntries`
     *
     * @param nspace See `listEntries`
     *
     * @param startingPastAlias Only return aliases lexicographically bigger than this value.
     *
     * @return List of KeyDescriptors.
     */
    KeyDescriptor[] listEntriesBatched(in Domain domain, in long nspace,
            in @nullable String startingPastAlias);

    /**
     * Returns tag-specific info required to interpret a tag's attested value.
     * Attested values themselves are located in the attestation certificate.
     *
     * The semantics of the return value is specific to the input tag:
     *
     * o Tag::MODULE_HASH: returns the DER-encoded structure corresponding to the `Modules` schema
     *   described in the KeyMint HAL's KeyCreationResult.aidl. The SHA-256 hash of this encoded
     *   structure is what's included with the tag in attestations. To ensure the returned encoded
     *   structure is the one attested to, clients should verify its SHA-256 hash matches the one
     *   in the attestation. Note that the returned structure can vary between boots.
     *
     * ## Error conditions
     * `ResponseCode::INVALID_ARGUMENT` if `tag` is not specified in the list above.
     * `ResponseCode::INFO_NOT_AVAILABLE` if `IKeystoreService` does not have the requested info.
     */
    byte[] getSupplementaryAttestationInfo(in Tag tag);
}
