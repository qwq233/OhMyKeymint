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
 * Device security levels.  These enum values are used in two ways:
 *
 * 1.  Returned from IKeyMintDevice::getHardwareInfo to identify the security level of the
 *     IKeyMintDevice.  This characterizes the sort of environment in which the KeyMint
 *     implementation runs, and therefore the security of its operations.
 *
 * 2.  Associated with individual KeyMint authorization Tags in KeyCharacteristics or in attestation
 *     certificates.  This specifies the security level of the weakest environment involved in
 *     enforcing that particular tag, i.e. the sort of security environment an attacker would have
 *     to subvert in order to break the enforcement of that tag.
 * @hide
 */
@VintfStability
@Backing(type="int")
enum SecurityLevel {
    /**
     * The SOFTWARE security level represents a KeyMint implementation that runs in an Android
     * process, or a tag enforced by such an implementation.  An attacker who can compromise that
     * process, or obtain root, or subvert the kernel on the device can defeat it.
     *
     * Note that the distinction between SOFTWARE and KEYSTORE is only relevant on-device.  For
     * attestation purposes, these categories are combined into the software-enforced authorization
     * list.
     */
    SOFTWARE = 0,

    /**
     * The TRUSTED_ENVIRONMENT security level represents a KeyMint implementation that runs in an
     * isolated execution environment that is securely isolated from the code running on the kernel
     * and above, and which satisfies the requirements specified in CDD 9.11.1 [C-1-2]. An attacker
     * who completely compromises Android, including the Linux kernel, does not have the ability to
     * subvert it.  An attacker who can find an exploit that gains them control of the trusted
     * environment, or who has access to the physical device and can mount a sophisticated hardware
     * attack, may be able to defeat it.
     */
    TRUSTED_ENVIRONMENT = 1,

    /**
     * The STRONGBOX security level represents a KeyMint implementation that runs in security
     * hardware that satisfies the requirements specified in CDD 9.11.2.  Roughly speaking, these
     * are discrete, security-focus computing environments that are hardened against physical and
     * side channel attack, and have had their security formally validated by a competent
     * penetration testing lab.
     */
    STRONGBOX = 2,

    /**
     * KeyMint implementations must never return the KEYSTORE security level from getHardwareInfo.
     * It is used to specify tags that are not enforced by the IKeyMintDevice, but are instead
     * to be enforced by Keystore.  An attacker who can subvert the keystore process or gain root or
     * subvert the kernel can prevent proper enforcement of these tags.
     *
     *
     * Note that the distinction between SOFTWARE and KEYSTORE is only relevant on-device.  When
     * KeyMint generates an attestation certificate, these categories are combined into the
     * software-enforced authorization list.
     */
    KEYSTORE = 100
}
