/*
 * Copyright (C) 2021 The Android Open Source Project
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

import android.hardware.security.keymint.KeyParameter;

/**
 * Contains a key blob with Tag::ATTEST_KEY that can be used to sign an attestation certificate,
 * and the DER-encoded X.501 Subject Name that will be placed in the Issuer field of the attestation
 * certificate.
 * @hide
 */
@VintfStability
@RustDerive(Clone=true, Eq=true, PartialEq=true, Ord=true, PartialOrd=true, Hash=true)
parcelable AttestationKey {
    /**
     * Key blob containing a key pair with KeyPurpose::ATTEST_KEY
     */
    byte[] keyBlob;

    /**
     * Key parameters needed to use the key in keyBlob, notably Tag::APPLICATION_ID and
     * Tag::APPLICATION_DATA, if they were provided during generation of the key in keyBlob.
     */
    KeyParameter[] attestKeyParams;

    /**
     * The issuerSubjectName to use in the generated attestation.
     */
    byte[] issuerSubjectName;
}
