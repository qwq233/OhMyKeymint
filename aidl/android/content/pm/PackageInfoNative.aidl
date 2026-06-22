/*
**
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

import android.content.pm.SigningInfoNative;

/**
 * Overall information about the contents of a package.  This corresponds to a subset of the
 * information collected from AndroidManifest.xml
 *
 * At present it's a very small subset, because it includes only items that have been required
 * by native code, but it uses the same structure and naming as the full PackageInfo in order
 * to ensure other elements can be cleanly added as necessary.
 *
 * See frameworks/base/core/java/android/content/pm/PackageInfo.java.
 */
parcelable PackageInfoNative {
    String packageName;

    /**
     * Signing information read from the package file, potentially including past signing
     * certificates no longer used after signing certificate rotation.
     */
    @nullable SigningInfoNative signingInfo;

    /**
     * Full path to the base APK for this application.
     */
    @nullable String sourceDir;

    /**
     * Full paths to split APKs.
     * May be null if no splits are installed.
     */
    @nullable String[] splitSourceDirs;
}
