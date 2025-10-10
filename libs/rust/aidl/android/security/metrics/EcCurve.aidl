/*
 * Copyright 2021, The Android Open Source Project
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

package android.security.metrics;

/**
 * EcCurve enum as defined in Keystore2KeyCreationWithGeneralInfo of
 * frameworks/proto_logging/stats/atoms.proto.
 * @hide
 */
@Backing(type="int")
enum EcCurve {
    /** Unspecified takes 0. Other values are incremented by 1 compared to the keymint spec. */
    EC_CURVE_UNSPECIFIED = 0,
    P_224 = 1,
    P_256 = 2,
    P_384 = 3,
    P_521 = 4,
    CURVE_25519 = 5,
}