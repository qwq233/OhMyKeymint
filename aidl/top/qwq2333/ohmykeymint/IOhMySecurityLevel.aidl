package top.qwq2333.ohmykeymint;

import android.hardware.security.keymint.KeyParameter;
import android.system.keystore2.AuthenticatorSpec;
import android.system.keystore2.CreateOperationResponse;
import android.system.keystore2.EphemeralStorageKeyResponse;
import android.system.keystore2.IKeystoreOperation;
import android.system.keystore2.KeyDescriptor;
import android.system.keystore2.KeyMetadata;

import top.qwq2333.ohmykeymint.CallerInfo;

interface IOhMySecurityLevel {

    const int KEY_FLAG_AUTH_BOUND_WITHOUT_CRYPTOGRAPHIC_LSKF_BINDING = 0x1;

    CreateOperationResponse createOperation(in @nullable CallerInfo ctx, in KeyDescriptor key,
                  in KeyParameter[] operationParameters, in boolean forced);

    KeyMetadata generateKey(in @nullable CallerInfo ctx, in KeyDescriptor key, in @nullable KeyDescriptor attestationKey,
                            in KeyParameter[] params, in int flags, in byte[] entropy);

    KeyMetadata importKey(in @nullable CallerInfo ctx, in KeyDescriptor key, in @nullable KeyDescriptor attestationKey,
                          in KeyParameter[] params, in int flags, in byte[] keyData);

    KeyMetadata importWrappedKey(in @nullable CallerInfo ctx, in KeyDescriptor key, in KeyDescriptor wrappingKey,
                                 in @nullable byte[] maskingKey, in KeyParameter[] params,
                                 in AuthenticatorSpec[] authenticators);

    EphemeralStorageKeyResponse convertStorageKeyToEphemeral(in KeyDescriptor storageKey);

    void deleteKey(in KeyDescriptor key);
}
