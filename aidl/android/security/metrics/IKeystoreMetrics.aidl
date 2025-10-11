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

import android.security.metrics.KeystoreAtom;
import android.security.metrics.AtomID;

/**
 * IKeystoreMetrics interface exposes the method for system server to pull metrics from keystore.
 * @hide
 */
interface IKeystoreMetrics {
    /**
     * Allows the metrics routing proxy to pull the metrics from keystore.
     *
     * @return an array of KeystoreAtom objects with the atomID. There can be multiple atom objects
     * for the same atomID, encapsulating different combinations of values for the atom fields.
     * If there is no atom object found for the atomID in the metrics store, an empty array is
     * returned.
     *
     * Callers require 'PullMetrics' permission.
     *
     * @param atomID - ID of the atom to be pulled.
     *
     * Errors are reported as service specific errors.
     */
    KeystoreAtom[] pullMetrics(in AtomID atomID);
}