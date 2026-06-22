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

/**
 * Supported ML-DSA variants (see FIPS 204).
 * @hide
 */
@VintfStability
@Backing(type="int")
enum MlDsaVariant {
    // ML-DSA-44 is not supported.
    ML_DSA_65 = 1,
    ML_DSA_87 = 2,
}
