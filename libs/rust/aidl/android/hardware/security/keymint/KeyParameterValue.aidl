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

import android.hardware.security.keymint.Algorithm;
import android.hardware.security.keymint.BlockMode;
import android.hardware.security.keymint.Digest;
import android.hardware.security.keymint.EcCurve;
import android.hardware.security.keymint.HardwareAuthenticatorType;
import android.hardware.security.keymint.KeyOrigin;
import android.hardware.security.keymint.KeyPurpose;
import android.hardware.security.keymint.PaddingMode;
import android.hardware.security.keymint.SecurityLevel;

/** @hide */
@VintfStability
@RustDerive(Clone=true, Eq=true, PartialEq=true, Ord=true, PartialOrd=true, Hash=true)
union KeyParameterValue {
    /* Represents an invalid value type. */
    int invalid;

    /* Enum types */
    Algorithm algorithm;
    BlockMode blockMode;
    PaddingMode paddingMode;
    Digest digest;
    EcCurve ecCurve;
    KeyOrigin origin;
    KeyPurpose keyPurpose;
    HardwareAuthenticatorType hardwareAuthenticatorType;
    SecurityLevel securityLevel;

    /* Other types */
    boolean boolValue; // Always true, if present.
    int integer;
    long longInteger;
    long dateTime; // In milliseconds from epoch

    byte[] blob;
}
