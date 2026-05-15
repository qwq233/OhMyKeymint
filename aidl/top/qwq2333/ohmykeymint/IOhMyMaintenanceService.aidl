package top.qwq2333.ohmykeymint;

import android.system.keystore2.Domain;
import android.system.keystore2.KeyDescriptor;
import top.qwq2333.ohmykeymint.CallerInfo;

interface IOhMyMaintenanceService {
    void onUserAdded(in @nullable CallerInfo ctx, in int userId);
    void initUserSuperKeys(in @nullable CallerInfo ctx, in int userId, in byte[] password,
            in boolean allowExisting);
    void onUserRemoved(in @nullable CallerInfo ctx, in int userId);
    void onUserLskfRemoved(in @nullable CallerInfo ctx, in int userId);
    void clearNamespace(in @nullable CallerInfo ctx, in Domain domain, in long nspace);
    void earlyBootEnded(in @nullable CallerInfo ctx);
    void migrateKeyNamespace(in @nullable CallerInfo ctx, in KeyDescriptor source,
            in KeyDescriptor destination);
    void deleteAllKeys(in @nullable CallerInfo ctx);
    long[] getAppUidsAffectedBySid(in @nullable CallerInfo ctx, in int userId, in long sid);
}
