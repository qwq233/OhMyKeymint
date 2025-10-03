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

import android.hardware.security.keymint.HardwareAuthToken;
import android.hardware.security.keymint.KeyParameter;
import android.hardware.security.secureclock.TimeStampToken;

/** @hide */
@VintfStability
@SensitiveData
interface IKeyMintOperation {
    /**
     * Provides additional authentication data (AAD) to a cryptographic operation begun with
     * begin(), provided in the input argument.  This method only applies to AEAD modes.  This
     * method may be called multiple times, supplying the AAD in chunks, but may not be called after
     * update() is called.  If updateAad() is called after update(), it must return
     * ErrorCode::INVALID_TAG.
     *
     * If the operation is in an invalid state (was aborted or had an error) update() must return
     * ErrorCode::INVALID_OPERATION_HANDLE.
     *
     * If this method returns an error code other than ErrorCode::OK, the operation is aborted and
     * the operation handle must be invalidated.  Any future use of this object must return
     * ErrorCode::INVALID_OPERATION_HANDLE.
     *
     * == Authorization Enforcement ==
     *
     * See the Authorization Enforcement section for the update() method.
     *
     *
     * For GCM encryption, the AEAD tag must be appended to the ciphertext by finish().  During
     * decryption, the last Tag::MAC_LENGTH bytes of the data provided to the last update call must
     * be the AEAD tag.  Since a given invocation of update cannot know if it's the last invocation,
     * it must process all but the tag length and buffer the possible tag data for processing during
     * finish().
     *
     * @param input Additional Authentication Data to be processed.
     *
     * @param authToken Authentication token, if provided.
     *
     * @param timeStampToken timestamp token, certifies the freshness of an auth token in case
     *        the security domain of this KeyMint instance has a different clock than the
     *        authenticator issuing the auth token.
     *
     * @return error Returns ErrorCode encountered in keymint as service specific errors. See the
     *         ErrorCode enum in ErrorCode.aidl.
     */
    void updateAad(in byte[] input, in @nullable HardwareAuthToken authToken,
            in @nullable TimeStampToken timeStampToken);

    /**
     * Provides data to, and possibly receives output from, an ongoing cryptographic operation begun
     * with begin().
     *
     * If operation is in an invalid state (was aborted or had an error) update() must return
     * ErrorCode::INVALID_OPERATION_HANDLE.
     *
     * Implementations may choose how much data to return as a result of the update.  This is
     * only relevant for encryption and decryption operations, because signing returns no data
     * until finish.  It is recommended to return data as early as possible, rather than buffer it.
     *
     * If this method returns an error code other than ErrorCode::OK, the operation is aborted and
     * the operation handle must be invalidated.  Any future use of the handle, with this method,
     * finish, or abort, must return ErrorCode::INVALID_OPERATION_HANDLE.
     *
     * == Authorization Enforcement ==
     *
     * Key authorization enforcement is performed primarily in IKeyMintDevice::begin().  There are
     * two exceptions to this:
     *
     *  1) Key with USER_SECURE_IDs but no AUTH_TIMEOUT
     *
     *  2) Key with USER_SECURE_IDs and AUTH_TIMEOUT, but the device does not support secure time.
     *
     * The first exception is the case where the key:
     *
     *   o Has one or more Tag::USER_SECURE_IDs, and
     *
     *   o Does not have a Tag::AUTH_TIMEOUT
     *
     * In this case, the key requires an authorization per operation, and update() / updateAad() /
     * finish() methods must receive a non-null and valid HardwareAuthToken.  For the auth token to
     * be valid, all of the following has to be true:
     *
     *   o The HMAC field must validate correctly.
     *
     *   o At least one of the Tag::USER_SECURE_ID values from the key must match at least one of
     *     the secure ID values in the token.
     *
     *   o The key must have a Tag::USER_AUTH_TYPE that matches the auth type in the token.
     *
     *   o The challenge field in the auth token must contain the challenge value contained in the
     *     BeginResult returned from IKeyMintDevice::begin().
     *
     *   If any of these conditions are not met, the method must return
     *   ErrorCode::KEY_USER_NOT_AUTHENTICATED.
     *
     * The caller must provide the auth token on every call to update(), updateAad() and finish().
     *
     *
     * The second exception is the case where the key:
     *
     *   o Has one or more Tag::USER_SECURE_IDs, and
     *
     *   o Has a Tag::AUTH_TIMEOUT value, but the device does not have a source of secure time (as
     *     indicated by the KeyMintHardwareInfo.timestampTokenRequired field).
     *
     * In this case, the key requires an per-operation authorization on the first call to update(),
     * updateAad() or finish() for the operation, using the provided timeStampToken as a source of
     * secure time.  For this timeStampToken to be valid, all of the following has to be true:
     *
     *   o The HMAC field must validate correctly.
     *
     *   o The challenge field in the timestamp token must contain the challenge value contained in
     *     the BeginResult returned from IKeyMintDevice::begin().
     *
     * The resulting secure time value is then used to authenticate the HardwareAuthToken. For the
     * auth token to be valid, all of the following has to be true:
     *
     *   o The HMAC field must validate correctly.
     *
     *   o At least one of the Tag::USER_SECURE_ID values from the key must match at least one of
     *     the secure ID values in the token.
     *
     *   o The key must have a Tag::USER_AUTH_TYPE that matches the auth type in the token.
     *
     *   o The timestamp in the auth token plus the value of the Tag::AUTH_TIMEOUT must be greater
     *     than the provided secure timestamp.

     *   If any of these conditions are not met, the method must return
     *   ErrorCode::KEY_USER_NOT_AUTHENTICATED.
     *
     *
     * -- RSA keys --
     *
     * For signing operations with Digest::NONE, this method must accept the entire block to be
     * signed in a single update.  It may not consume only a portion of the block in these cases.
     * However, the caller may choose to provide the data in multiple updates, and update() must
     * accept the data this way as well.  If the caller provides more data to sign than can be used
     * (length of data exceeds RSA key size), update() must return ErrorCode::INVALID_INPUT_LENGTH.
     *
     * -- ECDSA keys --
     *
     * For signing operations with Digest::NONE, this method must accept the entire block to be
     * signed in a single update.  This method may not consume only a portion of the block.
     * However, the caller may choose to provide the data in multiple updates and update() must
     * accept the data this way as well.  If the caller provides more data to sign than can be used,
     * the data is silently truncated.  (This differs from the handling of excess data provided in
     * similar RSA operations.  The reason for this is compatibility with legacy clients.)
     *
     * -- AES keys --
     *
     * For GCM encryption, the AEAD tag must be appended to the ciphertext by finish().  During
     * decryption, the last Tag::MAC_LENGTH bytes of the data provided to the last update call must
     * be the AEAD tag.  Since a given invocation of update cannot know if it's the last invocation,
     * it must process all but the tag length and buffer the possible tag data for processing during
     * finish().
     *
     * @param input Data to be processed.  update() must consume all input data.
     *
     * @param authToken Authentication token. Can be nullable if not provided.
     *
     * @param timeStampToken certifies the freshness of an auth token in case the security domain of
     *        this KeyMint instance has a different clock than the authenticator issuing the auth
     *        token.
     *
     * @return error Returns ErrorCode encountered in keymint as service specific errors. See the
     *         ErrorCode enum in ErrorCode.aidl.
     *
     * @return byte[] The output data, if any.
     */
    byte[] update(in byte[] input, in @nullable HardwareAuthToken authToken,
            in @nullable TimeStampToken timeStampToken);

    /**
     * Finalizes a cryptographic operation begun with begin() and invalidates the operation.
     *
     * This method is the last one called in an operation, so all processed data must be returned.
     *
     * Whether it completes successfully or returns an error, this method finalizes the operation.
     * Any future use of the operation, with finish(), update(), or abort(), must return
     * ErrorCode::INVALID_OPERATION_HANDLE.
     *
     * Signing operations return the signature as the output.
     *
     * == Authorization enforcement ==
     *
     * Key authorization enforcement is performed primarily in begin().  The exceptions are
     * authorization per operation keys and confirmation-required keys.
     *
     * Authorization per operation keys must be authorized as described for the update() method.
     *
     * Confirmation-required keys are keys that were generated with
     * Tag::TRUSTED_CONFIRMATION_REQUIRED.  For these keys, when doing a signing operation the
     * caller must pass a KeyParameter Tag::CONFIRMATION_TOKEN to finish().  Implementations must
     * check the confirmation token by computing the 32-byte HMAC-SHA256 over all of the
     * to-be-signed data, prefixed with the 18-byte UTF-8 encoded string "confirmation token". If
     * the computed value does not match the Tag::CONFIRMATION_TOKEN parameter, finish() must not
     * produce a signature and must return ErrorCode::NO_USER_CONFIRMATION.
     *
     * -- RSA keys --
     *
     * Some additional requirements, depending on the padding mode:
     *
     * o PaddingMode::NONE.  For unpadded signing and encryption operations, if the provided data is
     *   shorter than the key, the data must be zero-padded on the left before signing/encryption.
     *   If the data is the same length as the key, but numerically larger, finish() must return
     *   ErrorCode::INVALID_ARGUMENT.  For decryption operations, the data must be exactly as long
     *   as the key.  Otherwise, return ErrorCode::INVALID_INPUT_LENGTH.
     *
     * o PaddingMode::RSA_PSS.  For PSS-padded signature operations, the PSS salt length must match
     *   the size of the PSS digest selected.  The digest specified with Tag::DIGEST in params
     *   on begin() must be used as the PSS digest algorithm, MGF1 must be used as the mask
     *   generation function and the digest specified with Tag:DIGEST in params on begin() must also
     *   be used as the MGF1 digest algorithm.
     *
     * -- ECDSA keys --
     *
     * If the data provided for undigested signing is too long, truncate it.
     *
     * -- AES keys --
     *
     * Some additional conditions, depending on block mode:
     *
     * o BlockMode::ECB or BlockMode::CBC.  If padding is PaddingMode::NONE and the data length is
     *   not a multiple of the AES block size, finish() must return
     *   ErrorCode::INVALID_INPUT_LENGTH.  If padding is PaddingMode::PKCS7, pad the data per the
     *   PKCS#7 specification, including adding an additional padding block if the data is a
     *   multiple of the block length.  If padding is PaddingMode::PKCS7 and decryption does not
     *   result in valid padding, return ErrorCode::INVALID_ARGUMENT.
     *
     * o BlockMode::GCM.  During encryption, after processing all plaintext, compute the tag
     *   (Tag::MAC_LENGTH bytes) and append it to the returned ciphertext.  During decryption,
     *   process the last Tag::MAC_LENGTH bytes as the tag.  If tag verification fails, finish()
     *   must return ErrorCode::VERIFICATION_FAILED.
     *
     * @param input Data to be processed, per the parameters established in the call to begin().
     *        finish() must consume all provided data or return ErrorCode::INVALID_INPUT_LENGTH.
     *
     * @param signature The signature to be verified if the purpose specified in the begin() call
     *        was KeyPurpose::VERIFY.
     *
     * @param authToken Authentication token. Can be nullable if not provided.
     *
     * @param timestampToken certifies the freshness of an auth token in case the security domain of
     *        this KeyMint instance has a different clock than the authenticator issuing the auth
     *        token.
     *
     * @param confirmationToken is the confirmation token required by keys with
     *        Tag::TRUSTED_CONFIRMATION_REQUIRED.
     *
     * @return The output data, if any.
     */
    byte[] finish(in @nullable byte[] input, in @nullable byte[] signature,
            in @nullable HardwareAuthToken authToken,
            in @nullable TimeStampToken timestampToken,
            in @nullable byte[] confirmationToken);

    /**
     * Aborts a cryptographic operation begun with IKeyMintDevice::begin(), freeing all internal
     * resources.  If an operation was finalized, calling updateAad, update, finish, or abort yields
     * ErrorCode::INVALID_OPERATION_HANDLE. An operation is finalized if finish or abort was called
     * on it, or if updateAad or update returned an ErrorCode.
     *
     * @return error See the ErrorCode enum in ErrorCode.aidl.
     */
    void abort();
}
