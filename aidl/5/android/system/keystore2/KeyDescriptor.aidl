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

package android.system.keystore2;

import android.system.keystore2.Domain;

/**
 * The key descriptor designates a key stored in keystore in different ways.
 * based on the given domain specifier.
 *
 * Domain::APP: The `nspace` field is ignored, and the caller's uid is used instead.
 *              The access tuple is `(App, caller_uid, alias)`.
 * Domain::SELINUX: The `nspace` field is used.
 *              The access tuple is `(SELinux, nspace, alias)`.
 * Domain::GRANT: The `nspace` field holds a grant id. The key_id is looked up
 *              in the grant database and the key is accessed by the key_id.
 * Domain::KEY_ID: The `nspace` field holds the `key_id` which can be used
 *              to access the key directly.
 *              While alias based key descriptors can yield different keys every time they are
 *              used because aliases can be rebound to newly generated or imported keys, the key
 *              id is unique for a given key. Using a key by its key id in subsequent Keystore
 *              calls guarantees that the private/secret key material used corresponds to the
 *              metadata previously loaded using `loadKeyEntry`. The key id does not protect
 *              against rebinding, but if the corresponding alias was rebound the key id ceases
 *              to be valid, thereby, indicating to the caller that the previously loaded
 *              metadata and public key material no longer corresponds to the key entry.
 *
 *              Note: Implementations must choose the key id as 64bit random number. So there is
 *              a minimal non-zero change of a collision with a previously existing key id.
 * Domain::BLOB: The `blob` field holds the key blob. It is not in the database.
 *
 * The key descriptor is used by various API calls. In any case, the implementation
 * must perform appropriate access control to assure that the caller has access
 * to the given key for the given request. In case of `Domain::BLOB` the implementation
 * must additionally check if the caller has `ManageBlob` permission. See KeyPermission.aidl.
 * @hide
 */
@VintfStability
@RustDerive(Clone=true, Eq=true, PartialEq=true, Ord=true, PartialOrd=true)
parcelable KeyDescriptor {
    Domain domain = Domain.APP;
    long nspace; /* namespace is a keyword in C++, so we had a to pick a different field name. */
    /**
     * A free form string denoting the key, chosen by the client.
     */
    @nullable String alias;
    /**
     * An opaque blob. This blob is represents a KeyMint key. It is encrypted
     * and cannot be interpreted by the client.
     */
    @nullable byte[] blob;
}
