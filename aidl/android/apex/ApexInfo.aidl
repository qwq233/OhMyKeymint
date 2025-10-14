/*
 * Copyright (C) 2018 The Android Open Source Project
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

package android.apex;

parcelable ApexInfo {
    @utf8InCpp String moduleName;
    @utf8InCpp String modulePath;
    @utf8InCpp String preinstalledModulePath;
    long versionCode;
    @utf8InCpp String versionName;
    boolean isFactory;
    boolean isActive;

    // Populated only for getStagedApex() API
    boolean hasClassPathJars;

    // Will be set to true if during this boot a different APEX package of the APEX was
    // activated, than in the previous boot.
    // This can happen in the following situations:
    //  1. It was part of the staged session that was applied during this boot.
    //  2. A compressed system APEX was decompressed during this boot.
    //  3. apexd failed to activate an APEX on /data/apex/active (that was successfully
    //    activated during last boot) and needed to fallback to pre-installed counterpart.
    // Note: this field can only be set to true during boot, after boot is completed
    //  (sys.boot_completed = 1) value of this field will always be false.
    boolean activeApexChanged;

    /**
    * The partition that an APEX is pre-installed in or maps to.
    */
    enum Partition {
      SYSTEM,
      SYSTEM_EXT,
      PRODUCT,
      VENDOR,
      ODM
    }

    // For pre-installed APEX, this is the partition where it is pre-installed. For brand-new APEX, this is the partition where its credential is pre-installed.
    Partition partition;
}
