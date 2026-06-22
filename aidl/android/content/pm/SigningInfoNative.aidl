/*
** Copyright 2024, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

package android.content.pm;

import android.content.pm.SignatureNative;

/**
 * Information pertaining to the signing certificates used to sign a package.
 *
 * At present it's a small subset because it includes only items that have been required by
 * native code, but it uses the same structure and naming as the full SigningInfo in order to
 * ensure other elements can be cleanly added as necessary.
 *
 * See frameworks/base/core/java/android/content/pm/SigningInfo.java.
 */
parcelable SigningInfoNative {
    /**
     * APK content signers.  Includes the content of `SigningInfo#apkContentSigners()` if
     * `SigningInfo#hasMultipleSigners()` returns true, or the content of
     * `SigningInfo#getSigningCertificateHistory` otherwise.  Empty array if not set (i.e. not
     * nullable).
     */
    SignatureNative[] apkContentSigners;
}
