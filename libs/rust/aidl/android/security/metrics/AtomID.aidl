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
 * Atom IDs as defined in frameworks/proto_logging/stats/atoms.proto.
 * @hide
 */
@Backing(type="int")
enum AtomID {
    STORAGE_STATS = 10103,
    // reserved 10104
    KEY_CREATION_WITH_GENERAL_INFO = 10118,
    KEY_CREATION_WITH_AUTH_INFO = 10119,
    KEY_CREATION_WITH_PURPOSE_AND_MODES_INFO = 10120,
    KEYSTORE2_ATOM_WITH_OVERFLOW = 10121,
    KEY_OPERATION_WITH_PURPOSE_AND_MODES_INFO = 10122,
    KEY_OPERATION_WITH_GENERAL_INFO = 10123,
    RKP_ERROR_STATS = 10124,
    CRASH_STATS = 10125,
}
