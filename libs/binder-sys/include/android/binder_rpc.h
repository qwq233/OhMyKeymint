/*
 * Copyright (C) 2024 The Android Open Source Project
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

#pragma once

#include <android/binder_ibinder.h>
#include <sys/socket.h>

__BEGIN_DECLS

/**
 * @defgroup ABinderRpc Binder RPC
 *
 * This set of APIs makes it possible for a process to use the AServiceManager
 * APIs to get binder objects for services that are available over sockets
 * instead of the traditional kernel binder with the extra ServiceManager
 * process.
 *
 * These APIs are used to supply libbinder with enough information to create
 * and manage the socket connections underneath the ServiceManager APIs so the
 * clients do not need to know the service implementation details or what
 * transport they use for communication.
 *
 * @{
 */

/**
 * This represents an IAccessor implementation from libbinder that is
 * responsible for providing a pre-connected socket file descriptor for a
 * specific service. The service is an RpcServer and the pre-connected socket is
 * used to set up a client RpcSession underneath libbinder's IServiceManager APIs
 * to provide the client with the service's binder for remote communication.
 */
typedef struct ABinderRpc_Accessor ABinderRpc_Accessor;

/**
 * This represents an object that supplies ABinderRpc_Accessors to libbinder
 * when they are requested. They are requested any time a client is attempting
 * to get a service through IServiceManager APIs when the services aren't known by
 * servicemanager.
 */
typedef struct ABinderRpc_AccessorProvider ABinderRpc_AccessorProvider;

/**
 * This represents information necessary for libbinder to be able to connect to a
 * remote service.
 * It supports connecting to linux sockets and is created using sockaddr
 * types for sockets supported by libbinder like sockaddr_in, sockaddr_un,
 * sockaddr_vm.
 */
typedef struct ABinderRpc_ConnectionInfo ABinderRpc_ConnectionInfo;

/**
 * These APIs provide a way for clients of binder services to be able to get a
 * binder object of that service through the existing libbinder/libbinder_ndk
 * Service Manager APIs when that service is using RPC Binder over sockets
 * instead kernel binder.
 *
 * Some of these APIs are used on Android hosts when kernel binder is supported
 * and the usual servicemanager process is available. Some of these APIs are
 * only required when there is no kernel binder or extra servicemanager process
 * such as the case of microdroid or similar VMs.
 */

/**
 * This callback is responsible for returning ABinderRpc_Accessor objects for a given
 * service instance. These ABinderRpc_Accessor objects are implemented by
 * libbinder_ndk and backed by implementations of android::os::IAccessor in
 * libbinder.
 *
 * \param instance name of the service like
 *        `android.hardware.vibrator.IVibrator/default`. This string must remain
 *        valid and unchanged for the duration of this function call.
 * \param data the data that was associated with this instance when the callback
 *        was registered.
 * \return The ABinderRpc_Accessor associated with the service `instance`. This
 *        callback gives up ownership of the object once it returns it. The
 *        caller of this callback (libbinder_ndk) is responsible for deleting it
 *        with ABinderRpc_Accessor_delete.
 */
typedef ABinderRpc_Accessor* _Nullable (*ABinderRpc_AccessorProvider_getAccessorCallback)(
        const char* _Nonnull instance, void* _Nullable data);

/**
 * This callback is responsible deleting the `void* data` object that is passed
 * in to ABinderRpc_registerAccessorProvider for the ABinderRpc_AccessorProvider_getAccessorCallback
 * to use. That object is owned by the ABinderRpc_AccessorProvider and must remain valid for the
 * lifetime of the callback because it may be called and use the object.
 * This _delete callback is called after the ABinderRpc_AccessorProvider is remove and
 * is guaranteed never to be called again.
 *
 * \param data a pointer to data that the ABinderRpc_AccessorProvider_getAccessorCallback uses which
 * is to be deleted by this call.
 */
typedef void (*ABinderRpc_AccessorProviderUserData_deleteCallback)(void* _Nullable data);

/**
 * Inject an ABinderRpc_AccessorProvider_getAccessorCallback into the process for
 * the Service Manager APIs to use to retrieve ABinderRpc_Accessor objects associated
 * with different RPC Binder services.
 *
 * \param provider callback that returns ABinderRpc_Accessors for libbinder to set up
 *        RPC clients with.
 * \param instances array of instances that are supported by this provider. It
 *        will only be called if the client is looking for an instance that is
 *        in this list. These instances must be unique per-process. If an
 *        instance is being registered that was previously registered, this call
 *        will fail and the ABinderRpc_AccessorProviderUserData_deleteCallback
 *        will be called to clean up the data.
 *        This array of strings must remain valid and unchanged for the duration
 *        of this function call.
 * \param number of instances in the instances array.
 * \param data pointer that is passed to the ABinderRpc_AccessorProvider callback.
 *        IMPORTANT: The ABinderRpc_AccessorProvider now OWNS that object that data
 *        points to. It can be used as necessary in the callback. The data MUST
 *        remain valid for the lifetime of the provider callback.
 *        Do not attempt to give ownership of the same object to different
 *        providers through multiple calls to this function because the first
 *        one to be deleted will call the onDelete callback.
 * \param onDelete callback used to delete the objects that `data` points to.
 *        This is called after ABinderRpc_AccessorProvider is guaranteed to never be
 *        called again. Before this callback is called, `data` must remain
 *        valid.
 * \return nullptr on error if the data pointer is non-null and the onDelete
 *         callback is null or if an instance in the instances list was previously
 *         registered. In the error case of duplicate instances, if data was
 *         provided with a ABinderRpc_AccessorProviderUserData_deleteCallback,
 *         the callback will be called to delete the data.
 *         If nullptr is returned, ABinderRpc_AccessorProviderUserData_deleteCallback
 *         will be called on data immediately.
 *         Otherwise returns a pointer to the ABinderRpc_AccessorProvider that
 *         can be used to remove with ABinderRpc_unregisterAccessorProvider.
 */
ABinderRpc_AccessorProvider* _Nullable ABinderRpc_registerAccessorProvider(
        ABinderRpc_AccessorProvider_getAccessorCallback _Nonnull provider,
        const char* _Nullable const* const _Nonnull instances, size_t numInstances,
        void* _Nullable data, ABinderRpc_AccessorProviderUserData_deleteCallback _Nullable onDelete)
        __INTRODUCED_IN(36);

/**
 * Remove an ABinderRpc_AccessorProvider from libbinder. This will remove references
 *        from the ABinderRpc_AccessorProvider and will no longer call the
 *        ABinderRpc_AccessorProvider_getAccessorCallback.
 *
 * Note: The `data` object that was used when adding the accessor will be
 *       deleted by the ABinderRpc_AccessorProviderUserData_deleteCallback at some
 *       point after this call. Do not use the object and do not try to delete
 *       it through any other means.
 * Note: This will abort when used incorrectly if this provider was never
 *       registered or if it were already unregistered.
 *
 * \param provider to be removed and deleted
 *
 */
void ABinderRpc_unregisterAccessorProvider(ABinderRpc_AccessorProvider* _Nonnull provider)
        __INTRODUCED_IN(36);

/**
 * Callback which returns the RPC connection information for libbinder to use to
 * connect to a socket that a given service is listening on. This is needed to
 * create an ABinderRpc_Accessor so it can connect to these services.
 *
 * \param instance name of the service to connect to. This string must remain
 *        valid and unchanged for the duration of this function call.
 * \param data user data for this callback. The pointer is provided in
 *        ABinderRpc_Accessor_new.
 * \return ABinderRpc_ConnectionInfo with socket connection information for `instance`
 */
typedef ABinderRpc_ConnectionInfo* _Nullable (*ABinderRpc_ConnectionInfoProvider)(
        const char* _Nonnull instance, void* _Nullable data) __INTRODUCED_IN(36);
/**
 * This callback is responsible deleting the `void* data` object that is passed
 * in to ABinderRpc_Accessor_new for the ABinderRpc_ConnectionInfoProvider to use. That
 * object is owned by the ABinderRpc_Accessor and must remain valid for the
 * lifetime the Accessor because it may be used by the connection info provider
 * callback.
 * This _delete callback is called after the ABinderRpc_Accessor is removed and
 * is guaranteed never to be called again.
 *
 * \param data a pointer to data that the ABinderRpc_AccessorProvider uses which is to
 *        be deleted by this call.
 */
typedef void (*ABinderRpc_ConnectionInfoProviderUserData_delete)(void* _Nullable data);

/**
 * Create a new ABinderRpc_Accessor. This creates an IAccessor object in libbinder
 * that can use the info from the ABinderRpc_ConnectionInfoProvider to connect to a
 * socket that the service with `instance` name is listening to.
 *
 * \param instance name of the service that is listening on the socket. This
 *        string must remain valid and unchanged for the duration of this
 *        function call.
 * \param provider callback that can get the socket connection information for the
 *           instance. This connection information may be dynamic, so the
 *           provider will be called any time a new connection is required.
 * \param data pointer that is passed to the ABinderRpc_ConnectionInfoProvider callback.
 *        IMPORTANT: The ABinderRpc_ConnectionInfoProvider now OWNS that object that data
 *        points to. It can be used as necessary in the callback. The data MUST
 *        remain valid for the lifetime of the provider callback.
 *        Do not attempt to give ownership of the same object to different
 *        providers through multiple calls to this function because the first
 *        one to be deleted will call the onDelete callback.
 * \param onDelete callback used to delete the objects that `data` points to.
 *        This is called after ABinderRpc_ConnectionInfoProvider is guaranteed to never be
 *        called again. Before this callback is called, `data` must remain
 *        valid.
 * \return an ABinderRpc_Accessor instance. This is deleted by the caller once it is
 *         no longer needed.
 */
ABinderRpc_Accessor* _Nullable ABinderRpc_Accessor_new(
        const char* _Nonnull instance, ABinderRpc_ConnectionInfoProvider _Nonnull provider,
        void* _Nullable data, ABinderRpc_ConnectionInfoProviderUserData_delete _Nullable onDelete)
        __INTRODUCED_IN(36);

/**
 * Delete an ABinderRpc_Accessor
 *
 * \param accessor to delete
 */
void ABinderRpc_Accessor_delete(ABinderRpc_Accessor* _Nonnull accessor) __INTRODUCED_IN(36);

/**
 * Return the AIBinder associated with an ABinderRpc_Accessor. This can be used to
 * send the Accessor to another process or even register it with servicemanager.
 *
 * \param accessor to get the AIBinder for
 * \return binder of the supplied accessor with one strong ref count
 */
AIBinder* _Nullable ABinderRpc_Accessor_asBinder(ABinderRpc_Accessor* _Nonnull accessor)
        __INTRODUCED_IN(36);

/**
 * Return the ABinderRpc_Accessor associated with an AIBinder. The instance must match
 * the ABinderRpc_Accessor implementation.
 * This can be used when receiving an AIBinder from another process that the
 * other process obtained from ABinderRpc_Accessor_asBinder.
 *
 * \param instance name of the service that the Accessor is responsible for.
 *        This string must remain valid and unchanged for the duration of this
 *        function call.
 * \param accessorBinder proxy binder from another process's ABinderRpc_Accessor.
 *        This function preserves the refcount of this binder object and the
 *        caller still owns it.
 * \return ABinderRpc_Accessor representing the other processes ABinderRpc_Accessor
 *         implementation. The caller owns this ABinderRpc_Accessor instance and
 *         is responsible for deleting it with ABinderRpc_Accessor_delete or
 *         passing ownership of it elsewhere, like returning it through
 *         ABinderRpc_AccessorProvider_getAccessorCallback.
 *         nullptr on error when the accessorBinder is not a valid binder from
 *         an IAccessor implementation or the IAccessor implementation is not
 *         associated with the provided instance.
 */
ABinderRpc_Accessor* _Nullable ABinderRpc_Accessor_fromBinder(const char* _Nonnull instance,
                                                              AIBinder* _Nonnull accessorBinder)
        __INTRODUCED_IN(36);

/**
 * Wrap an ABinderRpc_Accessor proxy binder with a delegator binder.
 *
 * The IAccessorDelegator binder delegates all calls to the proxy binder.
 *
 * This is required only in very specific situations when the process that has
 * permissions to connect the to RPC service's socket and create the FD for it
 * is in a separate process from this process that wants to serve the Accessor
 * binder and the communication between these two processes is binder RPC. This
 * is needed because the binder passed over the binder RPC connection can not be
 * used as a kernel binder, and needs to be wrapped by a kernel binder that can
 * then be registered with service manager.
 *
 * \param instance name of the service associated with the Accessor
 * \param binder the AIBinder* from the ABinderRpc_Accessor from the
 *        ABinderRpc_Accessor_asBinder. The other process across the binder RPC
 *        connection will have called this and passed the AIBinder* across a
 *        binder interface to the process calling this function.
 * \param outDelegator the AIBinder* for the kernel binder that wraps the
 *        'binder' argument and delegates all calls to it. The caller now owns
 *        this object with one strong ref count and is responsible for removing
 *        that ref count with with AIBinder_decStrong when the caller wishes to
 *        drop the reference.
 * \return STATUS_OK on success.
 *         STATUS_UNEXPECTED_NULL if instance or binder arguments are null.
 *         STATUS_BAD_TYPE if the binder is not an IAccessor.
 *         STATUS_NAME_NOT_FOUND if the binder is an IAccessor, but not
 *         associated with the provided instance name.
 */
binder_status_t ABinderRpc_Accessor_delegateAccessor(const char* _Nonnull instance,
                                                     AIBinder* _Nonnull binder,
                                                     AIBinder* _Nullable* _Nonnull outDelegator)
        __INTRODUCED_IN(36);

/**
 * Create a new ABinderRpc_ConnectionInfo with sockaddr. This can be supported socket
 * types like sockaddr_vm (vsock) and sockaddr_un (Unix Domain Sockets).
 *
 * \param addr sockaddr pointer that can come from supported socket
 *        types like sockaddr_vm (vsock) and sockaddr_un (Unix Domain Sockets).
 * \param len length of the concrete sockaddr type being used. Like
 *        sizeof(sockaddr_vm) when sockaddr_vm is used.
 * \return the connection info based on the given sockaddr
 */
ABinderRpc_ConnectionInfo* _Nullable ABinderRpc_ConnectionInfo_new(const sockaddr* _Nonnull addr,
                                                                   socklen_t len)
        __INTRODUCED_IN(36);

/**
 * Delete an ABinderRpc_ConnectionInfo object that was created with
 * ABinderRpc_ConnectionInfo_new.
 *
 * \param info object to be deleted
 */
void ABinderRpc_ConnectionInfo_delete(ABinderRpc_ConnectionInfo* _Nonnull info) __INTRODUCED_IN(36);

/** @} */

__END_DECLS
