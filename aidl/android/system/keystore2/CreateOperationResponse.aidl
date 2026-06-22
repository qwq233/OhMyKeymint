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

import android.system.keystore2.IKeystoreOperation;
import android.system.keystore2.KeyParameters;
import android.system.keystore2.OperationChallenge;

/**
 * This parcelable is returned by `IKeystoreSecurityLevel::createOperation`.
 * @hide
 */
@VintfStability
parcelable CreateOperationResponse {
    /**
     * The binder representing the newly created operation.
     */
    IKeystoreOperation iOperation;
    /**
     * A challenge associated with the newly created operation. If this field is set.
     * it indicates that the operation has yet to be authorized by the user.
     */
    @nullable OperationChallenge operationChallenge;
    /**
     * Optional parameters returned from the KeyMint operation. This may contain a nonce
     * or an initialization vector IV for operations that use them.
     */
    @nullable KeyParameters parameters;
    /**
     * An optional opaque blob. If the key given to ISecurityLevel::CreateOperation
     * uses Domain::BLOB and was upgraded, then this field is present, and represents the
     * upgraded version of that key.
     */
    @nullable byte[] upgradedBlob;
}
