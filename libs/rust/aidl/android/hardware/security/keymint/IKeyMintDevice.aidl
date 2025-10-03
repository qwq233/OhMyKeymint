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

import android.hardware.security.keymint.AttestationKey;
import android.hardware.security.keymint.BeginResult;
import android.hardware.security.keymint.HardwareAuthToken;
import android.hardware.security.keymint.IKeyMintOperation;
import android.hardware.security.keymint.KeyCharacteristics;
import android.hardware.security.keymint.KeyCreationResult;
import android.hardware.security.keymint.KeyFormat;
import android.hardware.security.keymint.KeyMintHardwareInfo;
import android.hardware.security.keymint.KeyParameter;
import android.hardware.security.keymint.KeyPurpose;
import android.hardware.security.keymint.SecurityLevel;
import android.hardware.security.secureclock.TimeStampToken;

/**
 * KeyMint device definition.
 *
 * == Features ==
 *
 * An IKeyMintDevice provides cryptographic services, including the following categories of
 * operations:
 *
 * o   Key generation
 * o   Import of asymmetric keys
 * o   Import of raw symmetric keys
 * o   Asymmetric decryption with appropriate padding modes
 * o   Asymmetric signing with digesting and appropriate padding modes
 * o   Symmetric encryption and decryption in appropriate modes, including an AEAD mode
 * o   Generation and verification of symmetric message authentication codes
 * o   Attestation to the presence and configuration of asymmetric keys.
 *
 * Protocol elements, such as purpose, mode and padding, as well as access control constraints, must
 * be specified by the caller when keys are generated or imported and must be permanently bound to
 * the key, ensuring that the key cannot be used in any other way.
 *
 * In addition to the list above, IKeyMintDevice implementations must provide one more service
 * which is not exposed as an API but used internally: Random number generation.  The random number
 * generator must be high-quality and must be used for generation of keys, initialization vectors,
 * random padding and other elements of secure protocols that require randomness.
 *
 * == Types of IKeyMintDevices ==
 *
 * All of the operations and storage of key material must occur in a secure environment.  Secure
 * environments may be either:
 *
 * 1.  Isolated execution environments, such as a separate virtual machine, hypervisor or
 *      purpose-built trusted execution environment like ARM TrustZone.  The isolated environment
 *      must provide complete separation from the Android kernel and user space (collectively called
 *      the "non-secure world", or NSW) so that nothing running in the NSW can observe or manipulate
 *      the results of any computation in the isolated environment.  Isolated execution environments
 *      are identified by the SecurityLevel TRUSTED_ENVIRONMENT.
 *
 * 2.  Completely separate, purpose-built and certified secure CPUs, called "StrongBox" devices.
 *      Examples of StrongBox devices are embedded Secure Elements (eSE) or on-SoC secure processing
 *      units (iSE).  StrongBox environments are identified by the SecurityLevel STRONGBOX.  To
 *      qualify as a StrongBox, a device must meet the requirements specified in CDD 9.11.2.
 *
 * == Necessary Primitives ==
 *
 * All IKeyMintDevice implementations must provide support for the following:
 *
 * o   RSA
 *
 *      - TRUSTED_ENVIRONMENT IKeyMintDevices must support 2048, 3072 and 4096-bit keys.
 *        STRONGBOX IKeyMintDevices must support 2048-bit keys.
 *      - Public exponent F4 (2^16+1)
 *      - Unpadded, RSASSA-PSS and RSASSA-PKCS1-v1_5 padding modes for RSA signing
 *      - TRUSTED_ENVIRONMENT IKeyMintDevices must support MD5, SHA1, SHA-2 224, SHA-2 256, SHA-2
 *        384 and SHA-2 512 digest modes for RSA signing.  STRONGBOX IKeyMintDevices must support
 *        SHA-2 256.
 *      - Unpadded, RSAES-OAEP and RSAES-PKCS1-v1_5 padding modes for RSA encryption.
 *
 * o   ECDSA and ECDH
 *
 *      - IKeyMintDevices must support elliptic curve signing (Purpose::SIGN, Purpose::ATTEST_KEY)
 *        and key agreement operations (Purpose::AGREE_KEY).
 *      - TRUSTED_ENVIRONMENT IKeyMintDevices must support NIST curves P-224, P-256, P-384 and
 *        P-521.  STRONGBOX IKeyMintDevices must support NIST curve P-256.
 *      - For signing, TRUSTED_ENVIRONMENT IKeyMintDevices must support SHA1, SHA-2 224, SHA-2 256,
 *        SHA-2 384 and SHA-2 512 digest modes.  STRONGBOX IKeyMintDevices must support SHA-2 256.
 *      - TRUSTED_ENVRIONMENT IKeyMintDevices must support curve 25519 for Purpose::SIGN (Ed25519,
 *        as specified in RFC 8032), Purpose::ATTEST_KEY (Ed25519) or for KeyPurpose::AGREE_KEY
 *        (X25519, as specified in RFC 7748).  However, a key must have exactly one of these
 *        purpose values; the same key cannot be used for multiple purposes. Signing operations
 *        (Purpose::SIGN) have a message size limit of 16 KiB; operations on messages longer than
 *        this limit must fail with ErrorCode::INVALID_INPUT_LENGTH.
 *        STRONGBOX IKeyMintDevices do not support curve 25519.
 *
 * o   AES
 *
 *      - TRUSTED_ENVIRONMENT IKeyMintDevices must support 128, 192 and 256-bit keys.
 *        STRONGBOX IKeyMintDevices must only support 128 and 256-bit keys.
 *      - CBC, CTR, ECB and GCM modes.  The GCM mode must not allow the use of tags smaller than 96
 *        bits or nonce lengths other than 96 bits.
 *      - CBC and ECB modes must support unpadded and PKCS7 padding modes.  With no padding CBC and
 *        ECB-mode operations must fail with ErrorCode::INVALID_INPUT_LENGTH if the input isn't a
 *        multiple of the AES block size.  With PKCS7 padding, GCM and CTR operations must fail with
 *        ErrorCode::INCOMPATIBLE_PADDING_MODE.
 *
 * o   3DES
 *
 *      - 168-bit keys.
 *      - CBC and ECB mode.
 *      - CBC and ECB modes must support unpadded and PKCS7 padding modes.  With no padding CBC and
 *        ECB-mode operations must fail with ErrorCode::INVALID_INPUT_LENGTH if the input isn't a
 *        multiple of the DES block size.
 *
 * o   HMAC
 *
 *      - Any key size that is between 64 and 512 bits (inclusive) and a multiple of 8 must be
 *        supported.  STRONGBOX IKeyMintDevices must not support keys larger than 512 bits.
 *      - TRUSTED_ENVIRONMENT IKeyMintDevices must support MD-5, SHA1, SHA-2-224, SHA-2-256,
 *        SHA-2-384 and SHA-2-512.  STRONGBOX IKeyMintDevices must support SHA-2-256.
 *
 * == Key Access Control ==
 *
 * Hardware-based keys that can never be extracted from the device don't provide much security if an
 * attacker can use them at will (though they're more secure than keys which can be
 * exfiltrated).  Therefore, IKeyMintDevice must enforce access controls.
 *
 * Access controls are defined as "authorization lists" of tag/value pairs.  Authorization tags are
 * 32-bit integers from the Tag enum, and the values are a variety of types, defined in the TagType
 * enum.  Some tags may be repeated to specify multiple values.  Whether a tag may be repeated is
 * specified in the documentation for the tag and in the TagType.  When a key is created or
 * imported, the caller specifies a `key_description` authorization list.  The IKeyMintDevice must
 * determine which tags it can and cannot enforce, and at what SecurityLevel, and return an array of
 * `KeyCharacteristics` structures that contains everything it will enforce, associated with the
 * appropriate security level, which is one of SOFTWARE, TRUSTED_ENVIRONMENT and STRONGBOX.
 * Typically, implementations will only return a single KeyCharacteristics structure, because
 * everything they enforce is enforced at the same security level.  There may be cases, however, for
 * which multiple security levels are relevant. One example is that of a StrongBox IKeyMintDevice
 * that relies on a TEE to enforce biometric user authentication.  In that case, the generate/import
 * methods must return two KeyCharacteristics structs, one with SecurityLevel::TRUSTED_ENVIRONMENT
 * and the biometric authentication-related tags, and another with SecurityLevel::STRONGBOX and
 * everything else.  The IKeyMintDevice must also add the following authorizations to the
 * appropriate list:
 *
 * o    Tag::OS_VERSION
 * o    Tag::OS_PATCHLEVEL
 * o    Tag::VENDOR_PATCHLEVEL
 * o    Tag::BOOT_PATCHLEVEL
 * o    Tag::ORIGIN
 *
 * The IKeyMintDevice must ignore unknown tags.
 *
 * The caller may provide the current date time in the keyParameter CREATION_DATETIME tag, but
 * this is optional and informational only.
 *
 * All authorization tags and their values enforced by an IKeyMintDevice must be cryptographically
 * bound to the private/secret key material such that any modification of the portion of the key
 * blob that contains the authorization list makes it impossible for the secure environment to
 * obtain the private/secret key material.  The recommended approach to meet this requirement is to
 * use the full set of authorization tags associated with a key as input to a secure key derivation
 * function used to derive a key (the KEK) that is used to encrypt the private/secret key material.
 * Note that it is NOT acceptable to use a static KEK to encrypt the private/secret key material
 * with an AEAD cipher mode, using the enforced authorization tags as AAD.  This is because
 * Tag::APPLICATION_DATA must not be included in the authorization tags stored in the key blob, but
 * must be provided by the caller for every use.  Assuming the Tag::APPLICATION_DATA value has
 * sufficient entropy, this provides a cryptographic guarantee that an attacker cannot use a key
 * without knowing the Tag::APPLICATION_DATA value, even if they compromise the IKeyMintDevice.
 *
 * IKeyMintDevice implementations must ignore any tags they cannot enforce and must not return them
 * in KeyCharacteristics.  For example, Tag::ORIGINATION_EXPIRE_DATETIME provides the date and time
 * after which a key may not be used to encrypt or sign new messages.  Unless the IKeyMintDevice has
 * access to a secure source of current date/time information, it is not possible for the
 * IKeyMintDevice to enforce this tag.  An IKeyMintDevice implementation will not rely on the
 * non-secure world's notion of time, because it could be controlled by an attacker. Similarly, it
 * cannot rely on GPSr time, even if it has exclusive control of the GPSr, because that might be
 * spoofed by attacker RF signals.
 *
 * Some tags must be enforced by the IKeyMintDevice.  See the detailed documentation on each Tag
 * in Tag.aidl.
 *
 * == Root of Trust Binding ==
 *
 * IKeyMintDevice keys must be bound to a root of trust, which is a bitstring that must be
 * provided to the secure environment (by an unspecified, implementation-defined mechanism) during
 * startup, preferably by the bootloader.  This bitstring must be cryptographically bound to every
 * key managed by the IKeyMintDevice.  As above, the recommended mechanism for this cryptographic
 * binding is to include the Root of Trust data in the input to the key derivation function used to
 * derive a key that is used to encrypt the private/secret key material.
 *
 * The root of trust consists of a bitstring that must be derived from the public key used by
 * Verified Boot to verify the signature on the boot image, from the lock state and from the
 * Verified Boot state of the device.  If the public key is changed to allow a different system
 * image to be used or if the lock state is changed, then all of the IKeyMintDevice-protected keys
 * created by the previous system state must be unusable, unless the previous state is restored.
 * The goal is to increase the value of the software-enforced key access controls by making it
 * impossible for an attacker-installed operating system to use IKeyMintDevice keys.
 *
 * == Version Binding ==
 *
 * All keys must also be bound to the operating system and patch level of the system image and the
 * patch levels of the vendor image and boot image.  This ensures that an attacker who discovers a
 * weakness in an old version of the software cannot roll a device back to the vulnerable version
 * and use keys created with the newer version.  In addition, when a key with a given version and
 * patch level is used on a device that has been upgraded to a newer version or patch level, the
 * key must be upgraded (See IKeyMintDevice::upgradeKey()) before it can be used, and the previous
 * version of the key must be invalidated.  In this way, as the device is upgraded, the keys will
 * "ratchet" forward along with the device, but any reversion of the device to a previous release
 * will cause the keys to be unusable.
 *
 * This version information must be associated with every key as a set of tag/value pairs in the
 * hardwareEnforced authorization list.  Tag::OS_VERSION, Tag::OS_PATCHLEVEL,
 * Tag::VENDOR_PATCHLEVEL, and Tag::BOOT_PATCHLEVEL must be cryptographically bound to every
 * IKeyMintDevice key, as described in the Key Access Control section above.
 * @hide
 */
@VintfStability
@SensitiveData
interface IKeyMintDevice {
    const int AUTH_TOKEN_MAC_LENGTH = 32;

    /**
     * @return info which contains information about the underlying IKeyMintDevice hardware, such
     *         as version number, security level, keyMint name and author name.
     */
    KeyMintHardwareInfo getHardwareInfo();

    /**
     * Adds entropy to the RNG used by KeyMint.  Entropy added through this method must not be the
     * only source of entropy used, and a secure mixing function must be used to mix the entropy
     * provided by this method with internally-generated entropy.  The mixing function must be
     * secure in the sense that if any one of the mixing function inputs is provided with any data
     * the attacker cannot predict (or control), then the output of the seeded CRNG is
     * indistinguishable from random.  Thus, if the entropy from any source is good, the output
     * must be good.
     *
     * @param data Bytes to be mixed into the CRNG seed.  The caller must not provide more than 2
     *        KiB of data per invocation.
     *
     * @return error ErrorCode::OK on success; ErrorCode::INVALID_INPUT_LENGTH if the caller
     *         provides more than 2 KiB of data.
     */
    void addRngEntropy(in byte[] data);

    /**
     * Generates a new cryptographic key, specifying associated parameters, which must be
     * cryptographically bound to the key.  IKeyMintDevice implementations must disallow any use
     * of a key in any way inconsistent with the authorizations specified at generation time.  With
     * respect to parameters that the secure environment cannot enforce, the secure environment's
     * obligation is limited to ensuring that the unenforceable parameters associated with the key
     * cannot be modified.  In addition, the characteristics returned by generateKey places
     * parameters correctly in the tee-enforced and strongbox-enforced lists.
     *
     * In addition to the parameters provided, generateKey must add the following to the returned
     * characteristics.
     *
     * o Tag::ORIGIN with the value KeyOrigin::GENERATED.
     *
     * o Tag::OS_VERSION, Tag::OS_PATCHLEVEL, Tag::VENDOR_PATCHLEVEL and Tag::BOOT_PATCHLEVEL with
     *   appropriate values.
     *
     * The parameters provided to generateKey depend on the type of key being generated.  This
     * section summarizes the necessary and optional tags for each type of key.  Tag::ALGORITHM is
     * always necessary, to specify the type.
     *
     * == RSA Keys ==
     *
     * The following parameters are required to generate an RSA key:
     *
     * o Tag::KEY_SIZE specifies the size of the public modulus, in bits.  If omitted, generateKey
     *   must return ErrorCode::UNSUPPORTED_KEY_SIZE.  Required values for TEE IKeyMintDevice
     *   implementations are 1024, 2048, 3072 and 4096.  StrongBox IKeyMintDevice implementations
     *   must support 2048.
     *
     * o Tag::RSA_PUBLIC_EXPONENT specifies the RSA public exponent value.  If omitted, generateKey
     *   must return ErrorCode::INVALID_ARGUMENT.  The values 3 and 65537 must be supported.  It is
     *   recommended to support all prime values up to 2^64.
     *
     * o Tag::CERTIFICATE_NOT_BEFORE and Tag::CERTIFICATE_NOT_AFTER specify the valid date range for
     *   the returned X.509 certificate holding the public key. If omitted, generateKey must return
     *   ErrorCode::MISSING_NOT_BEFORE or ErrorCode::MISSING_NOT_AFTER.
     *
     * The following parameters are not necessary to generate a usable RSA key, but generateKey must
     * not return an error if they are omitted:
     *
     * o Tag::PURPOSE specifies allowed purposes.  All KeyPurpose values (see KeyPurpose.aidl)
     *   except AGREE_KEY must be supported for RSA keys.
     *
     * o Tag::DIGEST specifies digest algorithms that may be used with the new key.  TEE
     *   IKeyMintDevice implementations must support all Digest values (see Digest.aidl) for RSA
     *   keys.  StrongBox IKeyMintDevice implementations must support SHA_2_256.
     *
     * o Tag::PADDING specifies the padding modes that may be used with the new
     *   key.  IKeyMintDevice implementations must support PaddingMode::NONE,
     *   PaddingMode::RSA_OAEP, PaddingMode::RSA_PSS, PaddingMode::RSA_PKCS1_1_5_ENCRYPT and
     *   PaddingMode::RSA_PKCS1_1_5_SIGN for RSA keys.
     *
     * == ECDSA/ECDH Keys ==
     *
     * Tag::EC_CURVE must be provided to generate an elliptic curve key.  If it is not provided,
     * generateKey must return ErrorCode::UNSUPPORTED_KEY_SIZE or ErrorCode::UNSUPPORTED_EC_CURVE.
     * TEE IKeyMintDevice implementations must support all required curves.  StrongBox
     * implementations must support P_256 and no other curves.
     *
     * Tag::CERTIFICATE_NOT_BEFORE and Tag::CERTIFICATE_NOT_AFTER must be provided to specify the
     * valid date range for the returned X.509 certificate holding the public key. If omitted,
     * generateKey must return ErrorCode::MISSING_NOT_BEFORE or ErrorCode::MISSING_NOT_AFTER.
     *
     * Keys with EC_CURVE of EcCurve::CURVE_25519 must have exactly one purpose in the set
     * {KeyPurpose::SIGN, KeyPurpose::ATTEST_KEY, KeyPurpose::AGREE_KEY}.  Key generation with more
     * than one purpose should be rejected with ErrorCode::INCOMPATIBLE_PURPOSE.
     * StrongBox implementation do not support CURVE_25519.
     *
     * Tag::DIGEST specifies digest algorithms that may be used with the new key when used for
     * signing.  TEE IKeyMintDevice implementations must support all Digest values (see Digest.aidl)
     * for ECDSA keys; Ed25519 keys only support Digest::NONE. StrongBox IKeyMintDevice
     * implementations must support SHA_2_256.
     *
     * == AES Keys ==
     *
     * Only Tag::KEY_SIZE is required to generate an AES key.  If omitted, generateKey must return
     * ErrorCode::UNSUPPORTED_KEY_SIZE.  128 and 256-bit key sizes must be supported.
     *
     * If Tag::BLOCK_MODE is specified with value BlockMode::GCM, then the caller must also provide
     * Tag::MIN_MAC_LENGTH.  If omitted, generateKey must return ErrorCode::MISSING_MIN_MAC_LENGTH.
     *
     * == 3DES Keys ==
     *
     * Only Tag::KEY_SIZE is required to generate an 3DES key, and its value must be 168.  If
     * omitted, generateKey must return ErrorCode::UNSUPPORTED_KEY_SIZE.
     *
     * == HMAC Keys ==
     *
     * Tag::KEY_SIZE must be provided to generate an HMAC key, and its value must be >= 64 and a
     * multiple of 8.  All devices must support key sizes up to 512 bits, but StrongBox devices must
     * not support key sizes larger than 512 bits.  If omitted or invalid, generateKey() must return
     * ErrorCode::UNSUPPORTED_KEY_SIZE.
     *
     * Tag::MIN_MAC_LENGTH must be provided, and must be a multiple of 8 in the range 64 to 512
     * bits (inclusive). If omitted, generateKey must return ErrorCode::MISSING_MIN_MAC_LENGTH; if
     * invalid, generateKey must return ErrorCode::UNSUPPORTED_MIN_MAC_LENGTH.
     *
     * @param keyParams Key generation parameters are defined as KeyMintDevice tag/value pairs,
     *        provided in params.  See above for detailed specifications of which tags are required
     *        for which types of keys.
     *
     * @param attestationKey, if provided, specifies the key that must be used to sign the
     *        attestation certificate.  If `keyParams` does not contain a Tag::ATTESTATION_CHALLENGE
     *        but `attestationKey` is non-null, the IKeyMintDevice must return
     *        ErrorCode::ATTESTATION_CHALLENGE_MISSING. If the provided AttestationKey does not
     *        contain a key blob containing an asymmetric key with KeyPurpose::ATTEST_KEY, the
     *        IKeyMintDevice must return ErrorCode::INCOMPATIBLE_PURPOSE.  If the provided
     *        AttestationKey has an empty issuer subject name, the IKeyMintDevice must return
     *        ErrorCode::INVALID_ARGUMENT.
     *
     *        If `attestationKey` is null and `keyParams` contains Tag::ATTESTATION_CHALLENGE but
     *        the KeyMint implementation does not have factory-provisioned attestation keys, it must
     *        return ErrorCode::ATTESTATION_KEYS_NOT_PROVISIONED.
     *
     * @return The result of key creation.  See KeyCreationResult.aidl.
     */
    KeyCreationResult generateKey(
            in KeyParameter[] keyParams, in @nullable AttestationKey attestationKey);

    /**
     * Imports key material into an IKeyMintDevice.  Key definition parameters and return values
     * are the same as for generateKey, with the following exceptions:
     *
     * o Tag::KEY_SIZE is not necessary in the input parameters.  If not provided, the
     *   IKeyMintDevice must deduce the value from the provided key material and add the tag and
     *   value to the key characteristics.  If Tag::KEY_SIZE is provided, the IKeyMintDevice must
     *   validate it against the key material.  In the event of a mismatch, importKey must return
     *   ErrorCode::IMPORT_PARAMETER_MISMATCH.
     *
     * o Tag::EC_CURVE is not necessary in the input parameters for import of EC keys. If not
     *   provided the IKeyMintDevice must deduce the value from the provided key material and add
     *   the tag and value to the key characteristics.  If Tag::EC_CURVE is provided, the
     *   IKeyMintDevice must validate it against the key material.  In the event of a mismatch,
     *   importKey must return ErrorCode::IMPORT_PARAMETER_MISMATCH.
     *
     * o Tag::RSA_PUBLIC_EXPONENT (for RSA keys only) is not necessary in the input parameters.  If
     *   not provided, the IKeyMintDevice must deduce the value from the provided key material and
     *   add the tag and value to the key characteristics.  If Tag::RSA_PUBLIC_EXPONENT is provided,
     *   the IKeyMintDevice must validate it against the key material.  In the event of a
     *   mismatch, importKey must return ErrorCode::IMPORT_PARAMETER_MISMATCH.
     *
     * o Tag::ORIGIN (returned in keyCharacteristics) must have the value KeyOrigin::IMPORTED.
     *
     * @param keyParams Key generation parameters are defined as KeyMintDevice tag/value pairs,
     *        provided in params.
     *
     * @param keyFormat The format of the key material to import.  See KeyFormat in keyformat.aidl.
     *
     * @param keyData The key material to import, in the format specified in keyFormat.
     *
     * @param attestationKey, if provided, specifies the key that must be used to sign the
     *        attestation certificate.  If `keyParams` does not contain a Tag::ATTESTATION_CHALLENGE
     *        but `attestationKey` is non-null, the IKeyMintDevice must return
     *        ErrorCode::INVALID_ARGUMENT.  If the provided AttestationKey does not contain a key
     *        blob containing an asymmetric key with KeyPurpose::ATTEST_KEY, the IKeyMintDevice must
     *        return ErrorCode::INCOMPATIBLE_PURPOSE.  If the provided AttestationKey has an empty
     *        issuer subject name, the IKeyMintDevice must return ErrorCode::INVALID_ARGUMENT.
     *
     *        If `attestationKey` is null and `keyParams` contains Tag::ATTESTATION_CHALLENGE but
     *        the KeyMint implementation does not have factory-provisioned attestation keys, it must
     *        return ErrorCode::ATTESTATION_KEYS_NOT_PROVISIONED.
     *
     * @return The result of key creation.  See KeyCreationResult.aidl.
     */
    KeyCreationResult importKey(in KeyParameter[] keyParams, in KeyFormat keyFormat,
            in byte[] keyData, in @nullable AttestationKey attestationKey);

    /**
     * Securely imports a key, or key pair, returning a key blob and a description of the imported
     * key.
     *
     * @param wrappedKeyData The wrapped key material to import, as ASN.1 DER-encoded data
     *        corresponding to the following schema.
     *
     *     KeyDescription ::= SEQUENCE(
     *         keyFormat INTEGER,                   # Values from KeyFormat enum.
     *         keyParams AuthorizationList,
     *     )
     *
     *     SecureKeyWrapper ::= SEQUENCE(
     *         version INTEGER,                     # Contains value 0
     *         encryptedTransportKey OCTET_STRING,
     *         initializationVector OCTET_STRING,
     *         keyDescription KeyDescription,
     *         encryptedKey OCTET_STRING,
     *         tag OCTET_STRING
     *     )
     *
     *     Where:
     *
     *     - keyFormat is an integer from the KeyFormat enum, defining the format of the plaintext
     *       key material.
     *     - keyParams is the characteristics of the key to be imported (as with generateKey or
     *       importKey).  If the secure import is successful, these characteristics must be
     *       associated with the key exactly as if the key material had been insecurely imported
     *       with the IKeyMintDevice::importKey.  See KeyCreationResult.aidl for documentation of
     *       the AuthorizationList schema.
     *     - encryptedTransportKey is a 256-bit AES key, XORed with a masking key and then encrypted
     *       with the wrapping key specified by wrappingKeyBlob.
     *     - keyDescription is a KeyDescription, above.
     *     - encryptedKey is the key material of the key to be imported, in format keyFormat, and
     *       encrypted with encryptedEphemeralKey in AES-GCM mode, with the DER-encoded
     *       representation of keyDescription provided as additional authenticated data.
     *     - tag is the tag produced by the AES-GCM encryption of encryptedKey.
     *
     * So, importWrappedKey does the following:
     *
     *     1. Get the private key material for wrappingKeyBlob, verifying that the wrapping key has
     *        purpose KEY_WRAP, padding mode RSA_OAEP, and digest SHA_2_256, returning the
     *        error INCOMPATIBLE_PURPOSE, INCOMPATIBLE_PADDING_MODE, or INCOMPATIBLE_DIGEST if any
     *        of those requirements fail.
     *     2. Extract the encryptedTransportKey field from the SecureKeyWrapper, and decrypt
     *        it with the wrapping key.
     *     3. XOR the result of step 2 with maskingKey.
     *     4. Use the result of step 3 as an AES-GCM key to decrypt encryptedKey, using the encoded
     *        value of keyDescription as the additional authenticated data.  Call the result
     *        "keyData" for the next step.
     *     5. Perform the equivalent of calling importKey(keyParams, keyFormat, keyData), except
     *        that the origin tag should be set to SECURELY_IMPORTED.
     *
     * @param wrappingKeyBlob The opaque key descriptor returned by generateKey() or importKey().
     *        This key must have been created with Purpose::WRAP_KEY.
     *
     * @param maskingKey The 32-byte value XOR'd with the transport key in the SecureWrappedKey
     *        structure.
     *
     * @param unwrappingParams must contain any parameters needed to perform the unwrapping
     *        operation.  For example, the padding mode for the RSA wrapping key must be specified
     *        in this argument.
     *
     * @param passwordSid specifies the password secure ID (SID) of the user that owns the key being
     *        installed.  If the authorization list in wrappedKeyData contains a
     *        Tag::USER_SECURE_ID with a value that has the HardwareAuthenticatorType::PASSWORD bit
     *        set, the constructed key must be bound to the SID value provided by this argument.  If
     *        the wrappedKeyData does not contain such a tag and value, this argument must be
     *        ignored.
     *
     * @param biometricSid specifies the biometric secure ID (SID) of the user that owns the key
     *        being installed.  If the authorization list in wrappedKeyData contains a
     *        Tag::USER_SECURE_ID with a value that has the HardwareAuthenticatorType::FINGERPRINT
     *        bit set, the constructed key must be bound to the SID value provided by this argument.
     *        If the wrappedKeyData does not contain such a tag and value, this argument must be
     *        ignored.
     *
     * @return The result of key creation.  See KeyCreationResult.aidl.
     */
    KeyCreationResult importWrappedKey(in byte[] wrappedKeyData, in byte[] wrappingKeyBlob,
            in byte[] maskingKey, in KeyParameter[] unwrappingParams, in long passwordSid,
            in long biometricSid);

    /**
     * Upgrades an old key blob.  Keys can become "old" in two ways: IKeyMintDevice can be
     * upgraded to a new version with an incompatible key blob format, or the system can be updated
     * to invalidate the OS version (OS_VERSION tag), system patch level (OS_PATCHLEVEL tag),
     * vendor patch level (VENDOR_PATCH_LEVEL tag), boot patch level (BOOT_PATCH_LEVEL tag) or
     * other, implementation-defined patch level (keyMint implementers are encouraged to extend
     * this HAL with a minor version extension to define validatable patch levels for other
     * images; tags must be defined in the implementer's namespace, starting at 10000).  In either
     * case, attempts to use an old key blob with begin() must result in IKeyMintDevice returning
     * ErrorCode::KEY_REQUIRES_UPGRADE.  The caller must use this method to upgrade the key blob.
     *
     * The upgradeKey method must examine each version or patch level associated with the key.  If
     * any one of them is higher than the corresponding current device value upgradeKey() must
     * return ErrorCode::INVALID_ARGUMENT.  There is one exception: it is always permissible to
     * "downgrade" from any OS_VERSION number to OS_VERSION 0.  For example, if the key has
     * OS_VERSION 080001, it is permisible to upgrade the key if the current system version is
     * 080100, because the new version is larger, or if the current system version is 0, because
     * upgrades to 0 are always allowed.  If the system version were 080000, however, keyMint must
     * return ErrorCode::INVALID_ARGUMENT because that value is smaller than 080001.  Values other
     * than OS_VERSION must never be downgraded.
     *
     * Note that Keymaster versions 2 and 3 required that the system and boot images have the same
     * patch level and OS version.  This requirement is relaxed for 4.0::IKeymasterDevice and
     * IKeyMintDevice, and the OS version in the boot image footer is no longer used.
     *
     * @param keyBlobToUpgrade The opaque descriptor returned by generateKey() or importKey().
     *
     * @param upgradeParams A parameter list containing any parameters needed to complete the
     *        upgrade, including Tag::APPLICATION_ID and Tag::APPLICATION_DATA.
     *
     * @return A new key blob that references the same key as keyBlobToUpgrade, but is in the new
     *         format, or has the new version data.
     */
    byte[] upgradeKey(in byte[] keyBlobToUpgrade, in KeyParameter[] upgradeParams);

    /**
     * Deletes the key, or key pair, associated with the key blob.  Calling this function on
     * a key with Tag::ROLLBACK_RESISTANCE in its hardware-enforced authorization list must
     * render the key permanently unusable.  Keys without Tag::ROLLBACK_RESISTANCE may or
     * may not be rendered unusable.
     *
     * @param keyBlob The opaque descriptor returned by generateKey() or importKey();
     *
     * @return error See the ErrorCode enum.
     */
    void deleteKey(in byte[] keyBlob);

    /**
     * Deletes all keys in the hardware keystore. Used when keystore is reset completely.
     *
     * For StrongBox KeyMint: After this function is called all keys created previously must be
     * rendered permanently unusable.
     *
     * For TEE KeyMint: After this function is called all keys with Tag::ROLLBACK_RESISTANCE in
     * their hardware-enforced authorization lists must be rendered permanently unusable.  Keys
     * without Tag::ROLLBACK_RESISTANCE may or may not be rendered unusable.
     */
    void deleteAllKeys();

    /**
     * Destroys knowledge of the device's ids.  This prevents all device id attestation in the
     * future.  The destruction must be permanent so that not even a factory reset will restore the
     * device ids.
     *
     * Device id attestation may be provided only if this method is fully implemented, allowing the
     * user to permanently disable device id attestation.  If this cannot be guaranteed, the device
     * must never attest any device ids.
     *
     * This is a NOP if device id attestation is not supported.
     */
    void destroyAttestationIds();

    /**
     * Begins a cryptographic operation using the specified key.  If all is well, begin() must
     * return ErrorCode::OK and create an IKeyMintOperation handle which will be used to perform
     * the cryptographic operation.
     *
     * It is critical that each successful call to begin() be paired with a subsequent call to
     * finish() or abort() on the resulting IKeyMintOperation, to allow the IKeyMintDevice
     * implementation to clean up any internal operation state.  The caller's failure to do this may
     * leak internal state space or other internal resources and may eventually cause begin() to
     * return ErrorCode::TOO_MANY_OPERATIONS when it runs out of space for operations.  Any result
     * other than ErrorCode::OK from begin() will not return an IKeyMintOperation (in which case
     * calling finish() or abort() is neither possible nor necessary). IKeyMintDevice
     * implementations must support 32 concurrent operations.
     *
     * If Tag::APPLICATION_ID or Tag::APPLICATION_DATA were specified during key generation or
     * import, calls to begin must include those tags with the originally-specified values in the
     * params argument to this method.  If not, begin() must return ErrorCode::INVALID_KEY_BLOB.
     *
     * == Authorization Enforcement ==
     *
     * The following key authorization parameters must be enforced by the IKeyMintDevice secure
     * environment if the tags were returned in the "hardwareEnforced" list in the
     * KeyCharacteristics.
     *
     * -- All Key Types --
     *
     * The tags in this section apply to all key types.  See below for additional key type-specific
     * tags.
     *
     * o Tag::PURPOSE: The purpose specified in the begin() call must match one of the purposes in
     *   the key authorizations.  If the specified purpose does not match, begin() must return
     *   ErrorCode::UNSUPPORTED_PURPOSE.
     *
     * o Tag::ACTIVE_DATETIME can only be enforced if a trusted UTC time source is available.  If
     *   the current date and time is prior to the tag value, begin() must return
     *   ErrorCode::KEY_NOT_YET_VALID.
     *
     * o Tag::ORIGINATION_EXPIRE_DATETIME can only be enforced if a trusted UTC time source is
     *   available.  If the current date and time is later than the tag value and the purpose is
     *   KeyPurpose::ENCRYPT or KeyPurpose::SIGN, begin() must return ErrorCode::KEY_EXPIRED.
     *
     * o Tag::USAGE_EXPIRE_DATETIME can only be enforced if a trusted UTC time source is
     *   available.  If the current date and time is later than the tag value and the purpose is
     *   KeyPurpose::DECRYPT or KeyPurpose::VERIFY, begin() must return ErrorCode::KEY_EXPIRED.
     *
     * o Tag::MAX_USES_PER_BOOT must be compared against a secure counter that tracks the uses of
     *   the key since boot time.  If the count of previous uses exceeds the tag value, begin() must
     *   return ErrorCode::KEY_MAX_OPS_EXCEEDED.
     *
     * o Tag::USER_SECURE_ID must be enforced by this method if and only if the key also has
     *   Tag::AUTH_TIMEOUT (if it does not have Tag::AUTH_TIMEOUT, the Tag::USER_SECURE_ID
     *   requirement must be enforced by updateAad(), update() and finish()).  If the key has both,
     *   then this method must receive a non-empty HardwareAuthToken in the authToken argument.  For
     *   the auth token to be valid, all of the following have to be true:
     *
     *   o The HMAC field must validate correctly.
     *
     *   o At least one of the Tag::USER_SECURE_ID values from the key must match at least one of
     *     the secure ID values in the token.
     *
     *   o The key must have a Tag::USER_AUTH_TYPE that matches the auth type in the token.
     *
     *   o If the device has a source of secure time, then the timestamp in the auth token plus the
     *     value of the Tag::AUTH_TIMEOUT must be greater than the current secure timestamp (which
     *     is a monotonic timer counting milliseconds since boot).
     *
     *   o If the device does not have a source of secure time, then the timestamp check should be
     *     performed on the first update(), updateAad() or finish() invocation for the operation,
     *     using the timeStampToken parameter provided on the invocation to indicate the current
     *     timestamp. It may optionally also be performed on subsequent update() / updateAad() /
     *     finish() invocations.
     *
     *   If any of these conditions are not met, begin() must return
     *   ErrorCode::KEY_USER_NOT_AUTHENTICATED.
     *
     * o Tag::CALLER_NONCE allows the caller to specify a nonce or initialization vector (IV).  If
     *   the key doesn't have this tag, but the caller provided Tag::NONCE to this method,
     *   ErrorCode::CALLER_NONCE_PROHIBITED must be returned.
     *
     * o Tag::BOOTLOADER_ONLY specifies that only the bootloader may use the key.  If this method is
     *   called with a bootloader-only key after the bootloader has finished executing, it must
     *   return ErrorCode::INVALID_KEY_BLOB.  The mechanism for notifying the IKeyMintDevice that
     *   the bootloader has finished executing is implementation-defined.
     *
     * -- RSA Keys --
     *
     * All RSA key operations must specify exactly one padding mode in params.  If unspecified or
     * specified more than once, the begin() must return ErrorCode::UNSUPPORTED_PADDING_MODE.
     *
     * RSA signing operations need a digest, as do RSA encryption and decryption operations with
     * OAEP padding mode.  For those cases, the caller must specify exactly one digest in params.
     * If unspecified or specified more than once, begin() must return
     * ErrorCode::UNSUPPORTED_DIGEST.
     *
     * Private key operations (KeyPurpose::DECRYPT and KeyPurpose::SIGN) need authorization of
     * digest and padding, which means that the key authorizations need to contain the specified
     * values.  If not, begin() must return ErrorCode::INCOMPATIBLE_DIGEST or
     * ErrorCode::INCOMPATIBLE_PADDING_MODE, as appropriate.
     *
     * With the exception of PaddingMode::NONE, all RSA padding modes are applicable only to certain
     * purposes.  Specifically, PaddingMode::RSA_PKCS1_1_5_SIGN and PaddingMode::RSA_PSS only
     * support signing, while PaddingMode::RSA_PKCS1_1_5_ENCRYPT and PaddingMode::RSA_OAEP only
     * support encryption and decryption.  begin() must return ErrorCode::UNSUPPORTED_PADDING_MODE
     * if the specified mode does not support the specified purpose.
     *
     * There are some important interactions between padding modes and digests:
     *
     * o PaddingMode::NONE indicates that a "raw" RSA operation is performed.  If signing,
     *   Digest::NONE is specified for the digest.  No digest is necessary for unpadded encryption
     *   or decryption.
     *
     * o PaddingMode::RSA_PKCS1_1_5_SIGN padding requires a digest.  The digest may be Digest::NONE,
     *   in which case the KeyMint implementation cannot build a proper PKCS#1 v1.5 signature
     *   structure, because it cannot add the DigestInfo structure.  Instead, the IKeyMintDevice
     *   must construct 0x00 || 0x01 || PS || 0x00 || M, where M is the provided message and PS is a
     *   random padding string at least eight bytes in length.  The size of the RSA key has to be at
     *   least 11 bytes larger than the message, otherwise finish() must return
     *   ErrorCode::INVALID_INPUT_LENGTH.
     *
     * o PaddingMode::RSA_PKCS1_1_1_5_ENCRYPT padding does not require a digest.
     *
     * o PaddingMode::RSA_PSS padding requires a digest, which must match one of the digest values
     *   in the key authorizations, and which may not be Digest::NONE.  begin() must return
     *   ErrorCode::INCOMPATIBLE_DIGEST if this is not the case.  In addition, the size of the RSA
     *   key must be at least (D + S + 9) bits, where D is the size of the digest (in bits) and
     *   S is the size of the salt (in bits).  The salt size S must equal D, so the RSA key must
     *   be at least (2*D + 9) bits. Otherwise begin() must return ErrorCode::INCOMPATIBLE_DIGEST.
     *
     * o PaddingMode::RSA_OAEP padding requires a digest, which must match one of the digest values
     *   in the key authorizations, and which may not be Digest::NONE.  begin() must return
     *   ErrorCode::INCOMPATIBLE_DIGEST if this is not the case.  RSA_OAEP padding also requires an
     *   MGF1 digest, specified with Tag::RSA_OAEP_MGF_DIGEST, which must match one of the MGF1
     *   padding values in the key authorizations and which may not be Digest::NONE.  begin() must
     *   return ErrorCode::INCOMPATIBLE_MGF_DIGEST if this is not the case. The OAEP mask generation
     *   function must be MGF1.
     *
     * -- EC Keys --
     *
     * Private key operations (KeyPurpose::SIGN) need authorization of digest, which means that the
     * key authorizations must contain the specified values.  If not, begin() must return
     * ErrorCode::INCOMPATIBLE_DIGEST.
     *
     * -- AES Keys --
     *
     * AES key operations must specify exactly one block mode (Tag::BLOCK_MODE) and one padding mode
     * (Tag::PADDING) in params.  If either value is unspecified or specified more than once,
     * begin() must return ErrorCode::UNSUPPORTED_BLOCK_MODE or
     * ErrorCode::UNSUPPORTED_PADDING_MODE.  The specified modes must be authorized by the key,
     * otherwise begin() must return ErrorCode::INCOMPATIBLE_BLOCK_MODE or
     * ErrorCode::INCOMPATIBLE_PADDING_MODE.
     *
     * If the block mode is BlockMode::GCM, params must specify Tag::MAC_LENGTH, and the specified
     * value must be a multiple of 8 that is not greater than 128 or less than the value of
     * Tag::MIN_MAC_LENGTH in the key authorizations.  For MAC lengths greater than 128 or
     * non-multiples of 8, begin() must return ErrorCode::UNSUPPORTED_MAC_LENGTH.  For values less
     * than the key's minimum length, begin() must return ErrorCode::INVALID_MAC_LENGTH.
     *
     * If the block mode is BlockMode::GCM or BlockMode::CTR, the specified padding mode must be
     * PaddingMode::NONE.  For BlockMode::ECB or BlockMode::CBC, the mode may be PaddingMode::NONE
     * or PaddingMode::PKCS7.  If the padding mode doesn't meet these conditions, begin() must
     * return ErrorCode::INCOMPATIBLE_PADDING_MODE.
     *
     * If the block mode is BlockMode::CBC, BlockMode::CTR, or BlockMode::GCM, an initialization
     * vector or nonce is required.  In most cases, callers shouldn't provide an IV or nonce and the
     * IKeyMintDevice implementation must generate a random IV or nonce and return it via Tag::NONCE
     * in outParams.  CBC and CTR IVs are 16 bytes.  GCM nonces are 12 bytes.  If the key
     * authorizations contain Tag::CALLER_NONCE, then the caller may provide an IV/nonce with
     * Tag::NONCE in params, which must be of the correct size (if not, return
     * ErrorCode::INVALID_NONCE).  If a nonce is provided when Tag::CALLER_NONCE is not authorized,
     * begin() must return ErrorCode::CALLER_NONCE_PROHIBITED.  If a nonce is not provided when
     * Tag::CALLER_NONCE is authorized, IKeyMintDevice must generate a random IV/nonce.
     *
     * -- 3DES Keys --
     *
     * 3DES key operations must specify exactly one block mode (Tag::BLOCK_MODE) and one padding
     * mode (Tag::PADDING) in params.  If either value is unspecified or specified more than once,
     * begin() must return ErrorCode::UNSUPPORTED_BLOCK_MODE or
     * ErrorCode::UNSUPPORTED_PADDING_MODE.  The specified modes must be authorized by the key,
     * otherwise begin() must return ErrorCode::INCOMPATIBLE_BLOCK_MODE or
     * ErrorCode::INCOMPATIBLE_PADDING_MODE.
     *
     * If the block mode is BlockMode::CBC, an initialization vector or nonce is required.  In most
     * cases, callers shouldn't provide an IV or nonce and the IKeyMintDevice implementation must
     * generate a random IV or nonce and return it via Tag::NONCE in outParams.  CBC IVs are 8
     * bytes.  If the key authorizations contain Tag::CALLER_NONCE, then the caller may provide an
     * IV/nonce with Tag::NONCE in params, which must be of the correct size (if not, return
     * ErrorCode::INVALID_NONCE).  If a nonce is provided when Tag::CALLER_NONCE is not authorized,
     * begin() must return ErrorCode::CALLER_NONCE_PROHIBITED.  If a nonce is not provided when
     * Tag::CALLER_NONCE is authorized, IKeyMintDevice must generate a random IV/nonce.
     *
     *
     * -- HMAC keys --
     *
     * HMAC key operations must specify Tag::MAC_LENGTH in params.  The specified value must be a
     * multiple of 8 that is not greater than the digest length or less than the value of
     * Tag::MIN_MAC_LENGTH in the key authorizations.  For MAC lengths greater than the digest
     * length or non-multiples of 8, begin() must return ErrorCode::UNSUPPORTED_MAC_LENGTH.  For
     * values less than the key's minimum length, begin() must return ErrorCode::INVALID_MAC_LENGTH.
     *
     * @param purpose The purpose of the operation, one of KeyPurpose::ENCRYPT, KeyPurpose::DECRYPT,
     *        KeyPurpose::SIGN, KeyPurpose::VERIFY, or KeyPurpose::AGREE_KEY.  Note that for AEAD
     *        modes, encryption and decryption imply signing and verification, respectively, but
     *        must be specified as KeyPurpose::ENCRYPT and KeyPurpose::DECRYPT.
     *
     * @param keyBlob The opaque key descriptor returned by generateKey() or importKey().  The key
     *        must have a purpose compatible with purpose and all of its usage requirements must be
     *        satisfied, or begin() must return an appropriate error code (see above).
     *
     * @param params Additional parameters for the operation.  If Tag::APPLICATION_ID or
     *        Tag::APPLICATION_DATA were provided during generation, they must be provided here, or
     *        the operation must fail with ErrorCode::INVALID_KEY_BLOB.  For operations that require
     *        a nonce or IV, on keys that were generated with Tag::CALLER_NONCE, params may
     *        contain a tag Tag::NONCE.  If Tag::NONCE is provided for a key without
     *        Tag:CALLER_NONCE, ErrorCode::CALLER_NONCE_PROHIBITED must be returned.
     *
     * @param authToken Authentication token.
     *
     * @return BeginResult as output, which contains the challenge, KeyParameters which haves
     *         additional data from the operation initialization, notably to return the IV or nonce
     *         from operations that generate an IV or nonce, and IKeyMintOperation object pointer
     *         which is used to perform updateAad(), update(), finish() or abort() operations.
     */
    BeginResult begin(in KeyPurpose purpose, in byte[] keyBlob, in KeyParameter[] params,
            in @nullable HardwareAuthToken authToken);

    /**
     * This method is deprecated and has never been used.  Implementations should return
     * ErrorCode::UNIMPLEMENTED.
     *
     * This method was originally intended to be used to notify KeyMint that the device is now
     * locked, and keys with the UNLOCKED_DEVICE_REQUIRED tag should no longer be usable until a
     * later valid HardwareAuthToken is presented.  However, Android has never called this method
     * and it cannot start doing so, because KeyMint's enforcement of UNLOCKED_DEVICE_REQUIRED did
     * not provide the correct semantics and therefore could never be enabled.  Specifically, the
     * following issues existed with the design of KeyMint's enforcement of
     * UNLOCKED_DEVICE_REQUIRED:
     *
     * o It assumed a global device lock state only.  Android actually has a separate lock state for
     *   each user.  See the javadoc for KeyguardManager#isDeviceLocked().
     * o It assumed that unlocking the device involves a successful user authentication that
     *   generates a HardwareAuthToken.  This is not necessarily the case, since Android supports
     *   weaker unlock methods including class 1 and 2 biometrics and trust agents.  These unlock
     *   methods do not generate a HardwareAuthToken or interact with KeyMint in any way.  Also,
     *   UNLOCKED_DEVICE_REQUIRED must work even for users who do not have a secure lock screen.
     * o It would have made UNLOCKED_DEVICE_REQUIRED incompatible with requiring user
     *   authentication in some cases.  These two key protections can each require a different
     *   HardwareAuthToken, but KeyMint only supports one HardwareAuthToken per operation.
     * o It would have provided no security benefit over Keystore's enforcement of
     *   UNLOCKED_DEVICE_REQUIRED.  This is because since Android 12, Keystore enforces
     *   UNLOCKED_DEVICE_REQUIRED not just logically, but it also cryptographically by
     *   superencrypting all such keys and wiping or re-encrypting the superencryption key when the
     *   device is locked (whenever possible).  KeyMint is still used to support biometric unlocks,
     *   but this mechanism does not use KeyMint's direct enforcement of UNLOCKED_DEVICE_REQUIRED.
     *
     * Therefore, this method is not useful, and there is no reason for it be called.
     * Implementations should return ErrorCode::UNIMPLEMENTED and should not include
     * UNLOCKED_DEVICE_REQUIRED in the list of hardware-enforced key parameters.
     *
     * @param passwordOnly N/A due to the deprecation
     * @param timestampToken N/A due to the deprecation
     * @deprecated Method has never been used due to design limitations
     */
    void deviceLocked(in boolean passwordOnly, in @nullable TimeStampToken timestampToken);

    /**
     * Called by client to notify the IKeyMintDevice that the device has left the early boot
     * state, and that keys with the EARLY_BOOT_ONLY tag may no longer be used.  All attempts to use
     * an EARLY_BOOT_ONLY key after this method is called must fail with Error::EARLY_BOOT_ENDED.
     */
    void earlyBootEnded();

    /**
     * Called by the client to get a wrapped per-boot ephemeral key from a wrapped storage key.
     * Clients will then use the returned per-boot ephemeral key in place of the wrapped storage
     * key. Whenever the hardware is presented with a per-boot ephemeral key for an operation, it
     * must use the storage key associated with that ephemeral key to perform the requested
     * operation.
     *
     * Implementations should return ErrorCode::UNIMPLEMENTED if they don't support wrapped storage
     * keys.
     *
     * Implementations should return ErrorCode::INVALID_ARGUMENT (as a ServiceSpecificException)
     * if the input key blob doesn't represent a valid long-lived wrapped storage key.
     *
     * @param storageKeyBlob is the wrapped storage key for which the client wants a per-boot
     *        ephemeral key
     *
     * @return a buffer containing the per-boot ephemeral keyblob that should henceforth be used in
     *         place of the input storageKeyBlob
     */
    byte[] convertStorageKeyToEphemeral(in byte[] storageKeyBlob);

    /**
     * Returns KeyMint-enforced parameters associated with the provided key. The returned tags are
     * a subset of KeyCharacteristics found in the KeyCreationResult returned by generateKey(),
     * importKey(), or importWrappedKey(). The returned value is a subset, as it does not include
     * any Keystore-enforced parameters.
     *
     * @param keyBlob The opaque descriptor returned by generateKey, importKey or importWrappedKey.
     *
     * @param appId An opaque byte string identifying the client.  This value must match the
     *        Tag::APPLICATION_ID data provided during key generation/import.  Without the correct
     *        value, it must be computationally infeasible for the secure hardware to obtain the
     *        key material.
     *
     * @param appData An opaque byte string provided by the application.  This value must match the
     *        Tag::APPLICATION_DATA data provided during key generation/import.  Without the
     *        correct value, it must be computationally infeasible for the secure hardware to
     *        obtain the key material.
     *
     * @return Characteristics of the generated key. See KeyCreationResult for details.
     */
    KeyCharacteristics[] getKeyCharacteristics(
            in byte[] keyBlob, in byte[] appId, in byte[] appData);

    /**
     * Returns a 16-byte random challenge nonce, used to prove freshness when exchanging root of
     * trust data.
     *
     * This method may only be implemented by StrongBox KeyMint.  TEE KeyMint implementations must
     * return ErrorCode::UNIMPLEMENTED.  StrongBox KeyMint implementations MAY return UNIMPLEMENTED,
     * to indicate that they have an alternative mechanism for getting the data.  If the StrongBox
     * implementation returns UNIMPLEMENTED, the client should not call `getRootofTrust()` or
     * `sendRootOfTrust()`.
     */
    byte[16] getRootOfTrustChallenge();

    /**
     * Returns the TEE KeyMint Root of Trust data.
     *
     * This method is required for TEE KeyMint.  StrongBox KeyMint implementations MUST return
     * ErrorCode::UNIMPLEMENTED.
     *
     * The returned data is an encoded COSE_Mac0 structure, denoted MacedRootOfTrust in the
     * following CDDL schema.  Note that K_mac is the shared HMAC key used for auth tokens, etc.:
     *
     *     MacedRootOfTrust = #6.17 [         ; COSE_Mac0 (tagged)
     *         protected: bstr .cbor {
     *             1 : 5,                     ; Algorithm : HMAC-256
     *         },
     *         unprotected : {},
     *         payload : bstr .cbor RootOfTrust,
     *         tag : bstr HMAC-256(K_mac, MAC_structure)
     *     ]
     *
     *     MAC_structure = [
     *         context : "MAC0",
     *         protected : bstr .cbor {
     *             1 : 5,                     ; Algorithm : HMAC-256
     *         },
     *         external_aad : bstr .size 16   ; Value of challenge argument
     *         payload : bstr .cbor RootOfTrust,
     *     ]
     *
     *     RootOfTrust = #6.40001 [           ; Tag 40001 indicates RoT v1.
     *         verifiedBootKey : bstr .size 32,
     *         deviceLocked : bool,
     *         verifiedBootState : &VerifiedBootState,
     *         verifiedBootHash : bstr .size 32,
     *         bootPatchLevel : int,          ; See Tag::BOOT_PATCHLEVEL
     *     ]
     *
     *     VerifiedBootState = (
     *         Verified : 0,
     *         SelfSigned : 1,
     *         Unverified : 2,
     *         Failed : 3
     *     )
     */
    byte[] getRootOfTrust(in byte[16] challenge);

    /**
     * Delivers the TEE KeyMint Root of Trust data to StrongBox KeyMint.  See `getRootOfTrust()`
     * above for specification of the data format and cryptographic security structure.
     *
     * The implementation must verify the MAC on the RootOfTrust data.  If it is valid, and if this
     * is the first time since reboot that StrongBox KeyMint has received this data, it must store
     * the RoT data for use in key attestation requests, then return ErrorCode::ERROR_OK.
     *
     * If the MAC on the Root of Trust data and challenge is incorrect, the implementation must
     * return ErrorCode::VERIFICATION_FAILED.
     *
     * If the RootOfTrust data has already been received since the last boot, the implementation
     * must validate the data and return ErrorCode::VERIFICATION_FAILED or ErrorCode::ERROR_OK
     * according to the result, but must not store the data for use in key attestation requests,
     * even if verification succeeds.  On success, the challenge is invalidated and a new challenge
     * must be requested before the RootOfTrust data may be sent again.
     *
     * This method is optional for StrongBox KeyMint, which MUST return ErrorCode::UNIMPLEMENTED if
     * not implemented.  TEE KeyMint implementations must return ErrorCode::UNIMPLEMENTED.
     */
    void sendRootOfTrust(in byte[] rootOfTrust);

    /**
     * Called by Android to deliver additional attestation information to the IKeyMintDevice.
     *
     * IKeyMintDevice must ignore KeyParameters with tags not included in the following list:
     *
     * o Tag::MODULE_HASH: holds a hash that must be included in attestations in the moduleHash
     *   field of the software enforced authorization list.
     *
     * @return error ErrorCode::MODULE_HASH_ALREADY_SET if this is not the first time
     *         setAdditionalAttestationInfo is called with Tag::MODULE_HASH, and the associated
     *         KeyParamValue of the current call doesn't match the KeyParamValue of the first call.
     */
    void setAdditionalAttestationInfo(in KeyParameter[] info);
}
