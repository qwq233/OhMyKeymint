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

#include <android/binder_ibinder.h>
#include <android/binder_parcel.h>
#include <android/binder_status.h>
#include <android/persistable_bundle.h>

/* Platform only */
#if defined(ANDROID_PLATFORM) || defined(__ANDROID_VENDOR__)
#include <android/binder_ibinder_platform.h>
#include <android/binder_manager.h>
#include <android/binder_parcel_platform.h>
#include <android/binder_process.h>
#include <android/binder_rpc.h>
#include <android/binder_shell.h>
#include <android/binder_stability.h>
#endif

namespace android {

namespace c_interface {

// Expose error codes from anonymous enum in binder_status.h
enum StatusCode {
    OK = STATUS_OK,
    UNKNOWN_ERROR = STATUS_UNKNOWN_ERROR,
    NO_MEMORY = STATUS_NO_MEMORY,
    INVALID_OPERATION = STATUS_INVALID_OPERATION,
    BAD_VALUE = STATUS_BAD_VALUE,
    BAD_TYPE = STATUS_BAD_TYPE,
    NAME_NOT_FOUND = STATUS_NAME_NOT_FOUND,
    PERMISSION_DENIED = STATUS_PERMISSION_DENIED,
    NO_INIT = STATUS_NO_INIT,
    ALREADY_EXISTS = STATUS_ALREADY_EXISTS,
    DEAD_OBJECT = STATUS_DEAD_OBJECT,
    FAILED_TRANSACTION = STATUS_FAILED_TRANSACTION,
    BAD_INDEX = STATUS_BAD_INDEX,
    NOT_ENOUGH_DATA = STATUS_NOT_ENOUGH_DATA,
    WOULD_BLOCK = STATUS_WOULD_BLOCK,
    TIMED_OUT = STATUS_TIMED_OUT,
    UNKNOWN_TRANSACTION = STATUS_UNKNOWN_TRANSACTION,
    FDS_NOT_ALLOWED = STATUS_FDS_NOT_ALLOWED,
    UNEXPECTED_NULL = STATUS_UNEXPECTED_NULL,
};

// Expose exception codes from anonymous enum in binder_status.h
enum ExceptionCode {
    NONE = EX_NONE,
    SECURITY = EX_SECURITY,
    BAD_PARCELABLE = EX_BAD_PARCELABLE,
    ILLEGAL_ARGUMENT = EX_ILLEGAL_ARGUMENT,
    NULL_POINTER = EX_NULL_POINTER,
    ILLEGAL_STATE = EX_ILLEGAL_STATE,
    NETWORK_MAIN_THREAD = EX_NETWORK_MAIN_THREAD,
    UNSUPPORTED_OPERATION = EX_UNSUPPORTED_OPERATION,
    SERVICE_SPECIFIC = EX_SERVICE_SPECIFIC,
    PARCELABLE = EX_PARCELABLE,

    /**
     * This is special, and indicates to native binder proxies that the
     * transaction has failed at a low level.
     */
    TRANSACTION_FAILED = EX_TRANSACTION_FAILED,
};

namespace consts {

enum {
    FIRST_CALL_TRANSACTION = FIRST_CALL_TRANSACTION,
    LAST_CALL_TRANSACTION = LAST_CALL_TRANSACTION,
};

enum {
    FLAG_ONEWAY = FLAG_ONEWAY,
#if defined(ANDROID_PLATFORM) || defined(__ANDROID_VENDOR__)
    FLAG_CLEAR_BUF = FLAG_CLEAR_BUF,
    FLAG_PRIVATE_LOCAL = FLAG_PRIVATE_LOCAL,
#endif
};

enum {
    APERSISTABLEBUNDLE_KEY_NOT_FOUND = APERSISTABLEBUNDLE_KEY_NOT_FOUND,
    APERSISTABLEBUNDLE_ALLOCATOR_FAILED = APERSISTABLEBUNDLE_ALLOCATOR_FAILED,
};

} // namespace consts

} // namespace c_interface

} // namespace android
