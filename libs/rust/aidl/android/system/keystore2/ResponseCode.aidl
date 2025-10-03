/*
 * Copyright 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.system.keystore2;

/** @hide */
@VintfStability
@Backing(type="int")
enum ResponseCode {
    /* 1 Reserved - formerly NO_ERROR */
    /**
     * TODO Determine exact semantic of Locked and Uninitialized.
     */
    LOCKED = 2,
    UNINITIALIZED = 3,
    /**
     * Any unexpected Error such as IO or communication errors.
     * Implementations should log details to logcat.
     */
    SYSTEM_ERROR = 4,
    /* 5 Reserved - formerly "protocol error" was never used */
    /**
     * Indicates that the caller does not have the permissions for the attempted request.
     */
    PERMISSION_DENIED = 6,
    /**
     * Indicates that the requested key does not exist.
     */
    KEY_NOT_FOUND = 7,
    /**
     * Indicates a data corruption in the Keystore 2.0 database.
     */
    VALUE_CORRUPTED = 8,
    /*
     * 9 Reserved - formerly "undefined action" was never used
     * 10 Reserved - formerly WrongPassword
     * 11 - 13 Reserved - formerly password retry count indicators: obsolete
     *
     * 14 Reserved - formerly SIGNATURE_INVALID: Keystore does not perform public key operations
     *               any more
     *
     *
     * 15 Reserved - Formerly OP_AUTH_NEEDED. This is now indicated by the optional
     *               `OperationChallenge` returned by `IKeystoreSecurityLevel::create`.
     *
     * 16 Reserved
     */
    KEY_PERMANENTLY_INVALIDATED = 17,
    /**
     * May be returned by `IKeystoreSecurityLevel.create` if all Keymint operation slots
     * are currently in use and none can be pruned.
     */
    BACKEND_BUSY = 18,
    /**
     * This is a logical error on the caller's side. They are trying to advance an
     * operation, e.g., by calling `update`, that is currently processing an `update`
     * or `finish` request.
     */
    OPERATION_BUSY = 19,
    /**
     * Indicates that an invalid argument was passed to an API call.
     */
    INVALID_ARGUMENT = 20,
    /**
     * Indicates that too much data was sent in a single transaction.
     * The binder kernel mechanism cannot really diagnose this condition unambiguously.
     * So in order to force benign clients into reasonable limits, we limit the maximum
     * amount of data that we except in a single transaction to 32KiB.
     */
    TOO_MUCH_DATA = 21,

    /**
     * Deprecated in API 34.
     * Previous to API 34, all failures to generate a key due to the exhaustion of the
     * remotely provisioned key pool were reflected as OUT_OF_KEYS. The client simply had
     * to retry. Starting with API 34, more detailed errors have been included so that
     * applications can take appropriate action.
     * @deprecated replaced by other OUT_OF_KEYS_* errors below
     */
    OUT_OF_KEYS = 22,

    /**
     * This device needs a software update as it may contain potentially vulnerable software.
     * This error is returned only on devices that rely solely on remotely-provisioned keys (see
     * <a href=
     * "https://android-developers.googleblog.com/2022/03/upgrading-android-attestation-remote.html"
     * >Remote Key Provisioning</a>).
     */
    OUT_OF_KEYS_REQUIRES_SYSTEM_UPGRADE = 23,

    /**
     * Indicates that the attestation key pool has been exhausted, and the remote key
     * provisioning server cannot currently be reached. Clients should wait for the
     * device to have connectivity, then retry.
     */
    OUT_OF_KEYS_PENDING_INTERNET_CONNECTIVITY = 24,

    /**
     * Indicates that the attestation key pool temporarily does not have any signed
     * attestation keys available. This can be thrown during attempts to generate a key.
     * This error indicates key generation may be retried with exponential back-off, as
     * future attempts to fetch attestation keys are expected to succeed.
     *
     * NOTE: This error is generally the last resort of the underlying provisioner. Future
     * OS updates should strongly consider adding new error codes if/when appropriate rather
     * than relying on this status code as a fallback.
     */
    OUT_OF_KEYS_TRANSIENT_ERROR = 25,

    /**
     * Indicates that this device will never be able to provision attestation keys using
     * the remote provisioning server. This may be due to multiple causes, such as the
     * device is not registered with the remote provisioning backend or the device has
     * been permanently revoked. Clients who receive this error should not attempt to
     * retry key creation.
     */
    OUT_OF_KEYS_PERMANENT_ERROR = 26,

    /**
     * Indicates that the device had an error when getting the attestation application
     * id. This is a temporary error that can be retried. This can happen if there is a
     * failure to make a binder call to the package manager from Keystore service.
     * The attestation can be retried as this can be seen as a warning.
     */
    GET_ATTESTATION_APPLICATION_ID_FAILED = 27,

    /**
     * Indicates that some information is not available.
     */
    INFO_NOT_AVAILABLE = 28,
}
