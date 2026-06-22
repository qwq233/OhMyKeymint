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

/**
 * `IKeystoreOperation` represents a cryptographic operation with a Keystore key.
 *
 * The lifecycle of an operation begins with `KeystoreSecurityLevel.create`.
 * It ends with a call to `finish`, `abort`, or when the reference to the binder is
 * dropped.
 * During the lifecycle of an operation `update` may be called multiple times.
 * For AEAD operation `updateAad` may be called to add associated data, but
 * it must be called before the first call to `update`.
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
interface IKeystoreOperation {

    /**
     * `updateAad` advances an operation by adding additional authenticated data (AAD also AD for
     * associated data) to AEAD mode encryption or decryption operations. It cannot be called
     * after `update`, and doing so will yield `ErrorCode.INVALID_TAG`. This error code
     * is chosen for historic reasons, when AAD was passed as additional `KeyParameter`
     * with tag `ASSOCIATED_DATA`.
     *
     * ## Error conditions
     * * `ResponseCode::TOO_MUCH_DATA` if `aadInput` exceeds 32KiB.
     * * `ResponseCode::OPERATION_BUSY` if `updateAad` is called concurrently with any other
     *   `IKeystoreOperation` API call.
     * * `ErrorCode.INVALID_TAG` if `updateAad` was called after `update` on a given operation.
     *   TODO: this error code may change before stabilization/freezing of the API.
     * * `ErrorCode.INVALID_OPERATION_HANDLE` if the operation finalized for any reason.
     *
     * Note: Any error condition except `ResponseCode::OPERATION_BUSY` finalizes the
     *       operation such that subsequent API calls will yield `INVALID_OPERATION_HANDLE`.
     *
     * @param aadInput The AAD to be added to the operation.
     *
     */
    void updateAad(in byte[] aadInput);

    /**
     * Update advances an operation by adding more data to operation. Input data
     * may be to-be-encrypted or to-be-signed plain text, or to-be-decrypted
     * cipher text. During encryption operation this function returns the resulting
     * cipher text, and during decryption operations this function returns the
     * resulting plain text. Nothing it return during signing.
     *
     * ## Error conditions
     * * `ResponseCode::TOO_MUCH_DATA` if `input` exceeds 32KiB.
     * * `ResponseCode::OPERATION_BUSY` if `updateAad` is called concurrently with any other
     *   `IKeystoreOperation` API call.
     * * `ErrorCode.INVALID_OPERATION_HANDLE` if the operation finalized for any reason.
     *
     * Note: Any error condition except `ResponseCode::OPERATION_BUSY` finalizes the
     *       operation such that subsequent API calls will yield `INVALID_OPERATION_HANDLE`.
     *
     * @param input Input data.
     *
     * @return Optional output data.
     */
    @nullable byte[] update(in byte[] input);

    /**
     * Finalizes the operation. `finish` takes a final chunk of input data like `update`.
     * The output may be a signature during signing operations or plain text or cypher text
     * during encryption or decryption operations respectively.
     *
     * ## Error conditions
     * * `ResponseCode::TOO_MUCH_DATA` if `input` exceeds 32KiB.
     * * `ResponseCode::OPERATION_BUSY` if `updateAad` is called concurrently with any other
     *   `IKeystoreOperation` API call.
     * * `ErrorCode.INVALID_OPERATION_HANDLE` if the operation finalized for any reason.
     *
     * Note: `finish` finalizes the operation regardless of the outcome unless
     *       `ResponseCode::OPERATION_BUSY` was returned.
     *
     * @param input Finish takes one last chunk of data.
     *
     * @param signature An optional HMAC signature if the operation is an HMAC verification.
     *                TODO @swillden is this field used for anything else, if we don't do
     *                public key operations any more?
     *
     * @return A signature when finalizing a signing operation, or an AEAD message tag when
     *                performing an authenticated encryption, or the final chunk of cipher
     *                or plain text during encryption or decryption respectively.
     */
    @nullable byte[] finish(in @nullable byte[] input, in @nullable byte[] signature);

    /**
     * Aborts the operation.
     *
     * Note: `abort` finalizes the operation regardless of the outcome unless
     *       `ResponseCode::OPERATION_BUSY` was returned.
     */
    void abort();
}
