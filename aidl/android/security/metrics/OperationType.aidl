/*
 * Copyright 2026, The Android Open Source Project
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
 * OperationType enum as defined in Keystore2OperationLatency of
 * frameworks/proto_logging/stats/atoms/keystore/keystore_extension_atoms.proto.
 * @hide
 */
@Backing(type="int")
enum OperationType {
    /** Unspecified operation. */
    UNSPECIFIED = 0,
    /** Key generation. */
    GENERATE_KEY = 1,
    /** Key import. */
    IMPORT_KEY = 2,
    /** Wrapped key import. */
    IMPORT_WRAPPED_KEY = 3,
    /** Operation creation (e.g. begin() call). */
    CREATE_OPERATION = 4,
    /**
     * All update() and finish() calls that are part of a single operation.
     * This represents the cumulative latency of all data processing for one operation.
     */
    ENTIRE_OPERATION = 5,
}
