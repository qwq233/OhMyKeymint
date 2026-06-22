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

import android.security.metrics.Algorithm;
import android.security.metrics.EcCurve;
import android.security.metrics.OperationType;
import android.security.metrics.SecurityLevel;

/**
 * Keystore2OperationLatency atom as defined in
 * frameworks/proto_logging/stats/atoms/keystore/keystore_extension_atoms.proto.
 * @hide
 */
@RustDerive(Clone=true, Eq=true, PartialEq=true, Ord=true, PartialOrd=true, Hash=true)
parcelable OperationLatency {
    /** The type of operation being performed. */
    OperationType operation_type;
    /** The algorithm used in the operation. */
    Algorithm algorithm;
    /** The size of the key in bits. Use -1 if not applicable. */
    int key_size;
    /** The elliptic curve used, if the algorithm is EC. Use UNSPECIFIED if not applicable. */
    EcCurve ec_curve;
    /** The security level (e.g. TEE, StrongBox) where the operation took place. */
    SecurityLevel security_level;
    /** Whether the operation was successful. */
    boolean is_success;
    /**
     * The rounded latency of the operation in milliseconds.
     * Latency is rounded to preserve useful precision while strictly limiting cardinality
     * to manage the system-wide metrics cache size limit.
     *
     * Rounding Logic:
     * - Values <= 10ms: rounded to nearest 5ms.
     * - Values 11ms - 100ms: rounded to nearest 10ms.
     * - Values > 100ms: rounded to approximately 5% of the current order of magnitude
     *   (targeting ~18 buckets per order of magnitude).
     */
    int latency_ms;
}
