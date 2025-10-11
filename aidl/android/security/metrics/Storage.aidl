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
 * Storage enum as defined in Keystore2StorageStats of frameworks/proto_logging/stats/atoms.proto.
 * @hide
 */
@Backing(type="int")
enum Storage {
    STORAGE_UNSPECIFIED = 0,
    KEY_ENTRY = 1,
    KEY_ENTRY_ID_INDEX = 2,
    KEY_ENTRY_DOMAIN_NAMESPACE_INDEX = 3,
    BLOB_ENTRY = 4,
    BLOB_ENTRY_KEY_ENTRY_ID_INDEX = 5,
    KEY_PARAMETER = 6,
    KEY_PARAMETER_KEY_ENTRY_ID_INDEX = 7,
    KEY_METADATA = 8,
    KEY_METADATA_KEY_ENTRY_ID_INDEX = 9,
    GRANT = 10,
    AUTH_TOKEN = 11,
    BLOB_METADATA = 12,
    BLOB_METADATA_BLOB_ENTRY_ID_INDEX =13,
    METADATA = 14,
    DATABASE = 15,
    LEGACY_STORAGE = 16,
}