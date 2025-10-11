/*
 * Copyright 2020, The Android Open Source Project
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

package android.system.keystore2;

/**
 * KeyPermissions correspond to SELinux permission for the keystore2_key security class.
 * These values are used to specify the access vector for granted keys.
 * Key owners may grant a key to a another protection domain indicated by their uid.
 * Implementations must only allow granting permissions that the key owner possesses.
 * The grant permission cannot be granted.
 * Any granted permission applies only to the granted key.
 * @hide
 */
@VintfStability
@Backing(type="int")
enum KeyPermission {
    /**
     * Convenience variant indicating an empty access vector.
     */
    NONE = 0,
    /**
     * Allows deleting the key.
     */
    DELETE = 0x1,
    /**
     * Allows the usage of UNIQUE ID with the given key.
     */
    GEN_UNIQUE_ID = 0x2,
    /**
     * Allows reading metadata about the key including public key and certificate.
     */
    GET_INFO = 0x4,
    /**
     * Allows granting the key. Implementations must not allow this permission
     * to be granted though, so this is mentioned here just for completeness.
     */
    GRANT = 0x8,
    /**
     * Allows using a key by specifying the key blob in the key descriptor.
     * Implementations must not allow this permission to be granted.
     */
    MANAGE_BLOB = 0x10,
    /**
     * Allows rebinding an alias to a newly imported or generated key.
     * It makes no sense to grant this permission, because the API does not
     * permit generating keys by domains other than `App` or `SELinux`.
     * Implementations must not allow this permission to be granted.
     */
    REBIND = 0x20,
    /**
     * Allow requesting a forced operation with the given key.
     * Forced operations cannot be pruned and they have special pruning power
     * allowing them to evict any non forced operation to obtain a KeyMint
     * operation slot.
     */
    REQ_FORCED_OP = 0x40,
    /**
     * Allow updating the public certificate and certificate chain fields
     * of the given key.
     */
    UPDATE = 0x80,
    /**
     * Allow using the key for cryptographic operations within the limitations
     * of the key's usage restrictions.
     */
    USE = 0x100,
    /**
     * DO NOT USE. DOES NOTHING.
     * To generate a key with hardware identifiers for device ID attestation,
     * the caller must hold the READ_PRIVILEGED_PHONE_STATE Android permission.
     * Additionally, note that it makes no sense to grant this permission,
     * because attestation only works during key generation, and keys cannot be
     * created through a grant. Implementations must not allow this permission
     * to be granted.
     */
    USE_DEV_ID = 0x200,
    /**
     * Allows the creation of auth bound keys that are not cryptographically bound to the LSKF.
     * System components might need this if they required a logically authentication bound key
     * that is used for the derivation of the LSKF bound key material. This is essentially breaking
     * up a circular dependency.
     * This permission is checked during key generation and import if the
     * `KeyFlag.AUTH_BOUND_WITHOUT_CRYPTOGRAPHIC_LSKF_BINDING` was set. Because keys cannot
     * be generated or imported via grant, it does not make sense to grant this key.
     */
    USE_NO_LSKF_BINDING = 0x400,
    /**
     * Allows getting a per-boot wrapped ephemeral key from a long lived wrapped storage key.
     * This permission is checked on calls to IKeystoreSecurityLevel::convertStorageKeyToEphemeral()
     */
    CONVERT_STORAGE_KEY_TO_EPHEMERAL = 0x800,
 }
