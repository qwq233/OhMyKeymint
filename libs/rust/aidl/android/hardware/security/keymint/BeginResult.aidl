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

import android.hardware.security.keymint.IKeyMintOperation;
import android.hardware.security.keymint.KeyParameter;

/**
 * This is all the results returned by the IKeyMintDevice begin() function.
 * @hide
 */
@VintfStability
parcelable BeginResult {
    /**
     * This is the challenge used to verify authorization of an operation.
     * See IKeyMintOperation.aidl entrypoints updateAad() and update().
     */
    long challenge;

    /**
     * begin() uses this field to return additional data from the operation
     * initialization, notably to return the IV or nonce from operations
     * that generate an IV or nonce.
     */
    KeyParameter[] params;
    IKeyMintOperation operation;
}
