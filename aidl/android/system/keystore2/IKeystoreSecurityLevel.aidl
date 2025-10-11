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

import android.hardware.security.keymint.KeyParameter;
import android.system.keystore2.AuthenticatorSpec;
import android.system.keystore2.CreateOperationResponse;
import android.system.keystore2.EphemeralStorageKeyResponse;
import android.system.keystore2.IKeystoreOperation;
import android.system.keystore2.KeyDescriptor;
import android.system.keystore2.KeyMetadata;

/**
 * `IKeystoreSecurityLevel` is the per backend interface to Keystore. It provides
 * access to all requests that require KeyMint interaction, such as key import
 * and generation, as well as cryptographic operations.
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
@SensitiveData
interface IKeystoreSecurityLevel {

    /**
     * This flag disables cryptographic binding to the LSKF for auth bound keys.
     * It has no effect non auth bound keys. Such keys are not bound to the LSKF by
     * default.
     */
    const int KEY_FLAG_AUTH_BOUND_WITHOUT_CRYPTOGRAPHIC_LSKF_BINDING = 0x1;

    /**
     * This function creates a new key operation. Operations are the mechanism by which the
     * secret or private key material of a key can be used. There is a limited number
     * of operation slots. Implementations may prune an existing operation to make room
     * for a new one. The pruning strategy is implementation defined, but it must
     * account for forced operations (see parameter `forced` below).
     * Forced operations require the caller to possess the `REQ_FORCED_OP` permission.
     *
     * ## Pruning strategy recommendation
     * It is recommended to choose a strategy that rewards "good" behavior.
     * It is considered good behavior not to hog operations. Clients that use
     * few parallel operations shall have a better chance of starting and finishing
     * an operations than those that use many. Clients that use frequently update their
     * operations shall have a better chance to complete them successfully that those
     * that let their operations linger.
     *
     * ## Error conditions
     * `ResponseCode::BACKEND_BUSY` if the implementation was unable to find a free
     *            or free up an operation slot for the new operation.
     *
     * @param key Describes the key that is to be used for the operation.
     *
     * @param operationParameters Additional operation parameters that describe the nature
     *            of the requested operation.
     *
     * @param forced A forced operation has a very high pruning power. The implementation may
     *            select an operation to be pruned that would not have been pruned otherwise to
     *            free up an operation slot for the caller. Also, the resulting operation shall
     *            have a very high pruning resistance and cannot be pruned even by other forced
     *            operations.
     *
     * @return The operation interface which also acts as a handle to the pending
     *            operation and an optional operation challenge wrapped into the
     *            `CreateOperationResponse` parcelable. If the latter is present, user
     *            authorization is required for this operation.
     */
    CreateOperationResponse createOperation(in KeyDescriptor key,
                  in KeyParameter[] operationParameters, in boolean forced);

    /**
     * Generates a new key and associates it with the given descriptor.
     *
     * ## Error conditions
     * `ResponseCode::INVALID_ARGUMENT` if `key.domain` is set to any other value than
     *                   the ones described above.
     * A KeyMint ErrorCode may be returned indicating a backend diagnosed error.
     *
     * @param key The domain field of the key descriptor governs how the key will be stored.
     *            * App: The key is stored by the given alias string in the implicit UID namespace
     *                   of the caller.
     *            * SeLinux: The key is stored by the alias string in the namespace given by the
     *                       `nspace` field provided the caller has the appropriate access rights.
     *            * Blob: The key is returned as an opaque KeyMint blob in the KeyMetadata.key.blob
     *                    field of the return value.
     *                    The `alias` field is ignored. The caller must have the `MANAGE_BLOB`
     *                    permission for the targeted `keystore2_key` context given by
     *                    `nspace`. `nspace` is translated into the corresponding target context
     *                    `<target_context>` and `<target_context>:keystore2_key manage_blob` is
     *                    checked against the caller's context.
     *
     * @param attestationKey Optional key to be used for signing the attestation certificate.
     *
     * @param params Describes the characteristics of the to be generated key. See KeyMint HAL
     *                   for details.
     *
     * @param flags Additional flags that influence the key generation.
     *              See `KEY_FLAG_*` constants above for details.
     *
     * @param entropy This array of random bytes is mixed into the entropy source used for key
     *                   generation.
     *
     * @return KeyMetadata includes:
     *            * A key descriptor that can be used for subsequent key operations.
     *              If `Domain::BLOB` was requested, then the descriptor contains the
     *              generated key, and the caller must assure that the key is persistently
     *              stored accordingly; there is no way to recover the key if the blob is
     *              lost.
     *            * The generated public certificate if applicable. If `Domain::BLOB` was
     *              requested, there is no other copy of this certificate. It is the caller's
     *              responsibility to store it persistently if required.
     *            * The generated certificate chain if applicable. If `Domain::BLOB` was
     *              requested, there is no other copy of this certificate chain. It is the
     *              caller's responsibility to store it persistently if required.
     *            * The `IKeystoreSecurityLevel` field is always null in this context.
     */
    KeyMetadata generateKey(in KeyDescriptor key, in @nullable KeyDescriptor attestationKey,
                            in KeyParameter[] params, in int flags, in byte[] entropy);


    /**
     * Imports the given key. This API call works exactly like `generateKey`, only that the key is
     * provided by the caller rather than being generated by KeyMint. We only describe
     * the parameters where they deviate from the ones of `generateKey`.
     *
     * @param keyData The key to be imported. Expected encoding is PKCS#8 for asymmetric keys and
     *                raw key bits for symmetric keys.
     *
     * @return KeyMetadata see `generateKey`.
     */
    KeyMetadata importKey(in KeyDescriptor key, in @nullable KeyDescriptor attestationKey,
                          in KeyParameter[] params, in int flags, in byte[] keyData);

    /**
     * Allows importing keys wrapped with an RSA encryption key that is stored in AndroidKeystore.
     *
     * ## Error conditions
     * `ResponseCode::KEY_NOT_FOUND` if the specified wrapping key did not exist.
     *
     * @param key Governs how the imported key shall be stored. See `generateKey` for details.
     *
     * @param wrappingKey Indicates the key that shall be used for unwrapping the wrapped key
     *                    in a manner similar to starting a new operation with create.
     *
     * @param maskingKey Reserved for future use. Must be null for now.
     *
     * @param params These parameters describe the cryptographic operation that shall be performed
     *               using the wrapping key in order to unwrap the wrapped key.
     *
     * @param authenticators When generating or importing a key that is bound to a specific
     *                       authenticator, the authenticator ID is included in the key parameters.
     *                       Imported wrapped keys can also be authentication bound, however, the
     *                       key parameters were included in the wrapped key at a remote location
     *                       where the device's authenticator ID is not known. Therefore, the
     *                       caller has to provide all of the possible authenticator IDs so that
     *                       KeyMint can pick the right one based on the included key parameters.
     *
     * @return KeyMetadata see `generateKey`.
     */
    KeyMetadata importWrappedKey(in KeyDescriptor key, in KeyDescriptor wrappingKey,
                                 in @nullable byte[] maskingKey, in KeyParameter[] params,
                                 in AuthenticatorSpec[] authenticators);

    /**
     * Allows getting a per-boot wrapped ephemeral key from a wrapped storage key.
     *
     * ## Error conditions
     * `ResponseCode::PERMISSION_DENIED` if the caller does not have the
     * `ConvertStorageKeyToEphemeral` or the `ManageBlob` keystore2_key permissions
     * `ResponseCode::INVALID_ARGUMENT` if key.domain != Domain::BLOB or a key.blob isn't specified.
     *
     * A KeyMint ErrorCode may be returned indicating a backend diagnosed error.
     *
     * @param storageKey The KeyDescriptor with domain Domain::BLOB, and keyblob representing
     *                   the input wrapped storage key to convert
     *
     * @return byte[] representing the wrapped per-boot ephemeral key and an optional upgraded
     *                key blob.
     */
    EphemeralStorageKeyResponse convertStorageKeyToEphemeral(in KeyDescriptor storageKey);

    /**
     * Allows deleting a Domain::BLOB key from the backend underlying this IKeystoreSecurityLevel.
     * While there's another function "deleteKey()" in IKeystoreService, that function doesn't
     * handle Domain::BLOB keys because it doesn't have any information about which underlying
     * device to actually delete the key blob from.
     *
     * ## Error conditions
     * `ResponseCode::PERMISSION_DENIED` if the caller does not have the permission `DELETE`
     *               for the designated key, or the "MANAGE_BLOB" permission to manage
     *               Domain::BLOB keys.
     * `ResponseCode::INVALID_ARGUMENT` if key.domain != Domain::BLOB or key.blob isn't specified.
     *
     * A KeyMint ErrorCode may be returned indicating a backend diagnosed error.
     *
     * @param KeyDescriptor representing the key to delete.
     */
    void deleteKey(in KeyDescriptor key);
}
