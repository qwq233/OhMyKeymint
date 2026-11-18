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

use crate::sys;

use libc::{pid_t, uid_t};

/// Static utility functions to manage Binder process state.
pub struct ProcessState;

impl ProcessState {
    /// Starts the Binder IPC thread pool.
    ///
    /// Starts 1 thread, plus allows the kernel to lazily start up to
    /// `num_threads` additional threads as specified by
    /// [`set_thread_pool_max_thread_count`](Self::set_thread_pool_max_thread_count).
    ///
    /// If this is called, it must be done before creating any Binder client or server.
    ///
    /// If neither this nor [`join_thread_pool`](Self::join_thread_pool) are
    /// called, then some things (such as callbacks and
    /// [`IBinder::link_to_death`](crate::IBinder::link_to_death)) will silently
    /// not work: the callbacks will be queued but never called as there is no
    /// thread to call them on.
    pub fn start_thread_pool() {
        // Safety: Safe FFI
        unsafe {
            sys::ABinderProcess_startThreadPool();
        }
    }

    /// Sets the maximum number of threads that can be started in the
    /// threadpool.
    ///
    /// By default, after [`start_thread_pool`](Self::start_thread_pool) is
    /// called, this is 15. If it is called additional times, the thread pool
    /// size can only be increased.
    pub fn set_thread_pool_max_thread_count(num_threads: u32) {
        // Safety: Safe FFI
        unsafe {
            sys::ABinderProcess_setThreadPoolMaxThreadCount(num_threads);
        }
    }

    /// Blocks on the Binder IPC thread pool by adding the current thread to the
    /// pool.
    ///
    /// Note that this adds the current thread in addition to those that are
    /// created by
    /// [`set_thread_pool_max_thread_count`](Self::set_thread_pool_max_thread_count)
    /// and [`start_thread_pool`](Self::start_thread_pool).
    pub fn join_thread_pool() {
        // Safety: Safe FFI
        unsafe {
            sys::ABinderProcess_joinThreadPool();
        }
    }
}

/// Static utility functions to manage Binder thread state.
pub struct ThreadState;

impl ThreadState {
    /// This returns the calling UID assuming that this thread is called from a
    /// thread that is processing a binder transaction (for instance, in the
    /// implementation of
    /// [`Remotable::on_transact`](crate::Remotable::on_transact)).
    ///
    /// This can be used with higher-level system services to determine the
    /// caller's identity and check permissions.
    ///
    /// Available since API level 29.
    ///
    /// \return calling uid or the current process's UID if this thread isn't
    /// processing a transaction.
    pub fn get_calling_uid() -> uid_t {
        // Safety: Safe FFI
        unsafe { sys::AIBinder_getCallingUid() }
    }

    /// This returns the calling PID assuming that this thread is called from a
    /// thread that is processing a binder transaction (for instance, in the
    /// implementation of
    /// [`Remotable::on_transact`](crate::Remotable::on_transact)).
    ///
    /// This can be used with higher-level system services to determine the
    /// caller's identity and check permissions. However, when doing this, one
    /// should be aware of possible TOCTOU problems when the calling process
    /// dies and is replaced with another process with elevated permissions and
    /// the same PID.
    ///
    /// Warning: do not use this as a security identifier! PID is unreliable
    /// as it may be re-used. This should mostly be used for debugging.
    ///
    /// oneway transactions do not receive PID. Even if you expect
    /// a transaction to be synchronous, a misbehaving client could send it
    /// as a synchronous call and result in a 0 PID here. Additionally, if
    /// there is a race and the calling process dies, the PID may still be
    /// 0 for a synchronous call.
    ///
    /// Available since API level 29.
    ///
    /// \return calling pid or the current process's PID if this thread isn't
    /// processing a transaction.
    pub fn get_calling_pid() -> pid_t {
        // Safety: Safe FFI
        unsafe { sys::AIBinder_getCallingPid() }
    }

    /// Determine whether the current thread is currently executing an incoming transaction.
    ///
    /// \return true if the current thread is currently executing an incoming transaction, and false
    /// otherwise.
    pub fn is_handling_transaction() -> bool {
        // Safety: Safe FFI
        unsafe { sys::AIBinder_isHandlingTransaction() }
    }

    /// This function makes the client's security context available to the
    /// service calling this function. This can be used for access control.
    /// It does not suffer from the TOCTOU issues of get_calling_pid.
    ///
    /// Implementations of `check_permission` should use the given CStr
    /// argument as context for selinux permission checks. If `None` is
    /// given, the implementation should fall back to using the PID
    /// instead.
    ///
    /// Note: `None` may be passed to the callback if the caller did not
    /// `set_requesting_sid` on the serviced binder, or if the underlying
    /// kernel is too old to support this feature.
    pub fn with_calling_sid<T, F>(check_permission: F) -> T
    where
        for<'a> F: FnOnce(Option<&'a core::ffi::CStr>) -> T,
    {
        // Safety: AIBinder_getCallingSid returns a c-string pointer
        // that is valid for a transaction. Also, the string returned
        // is thread local. By restricting the lifetime of the CStr
        // reference to the scope of the callback, we prevent it being
        // used beyond the guaranteed lifetime.
        check_permission(unsafe {
            let sid = sys::AIBinder_getCallingSid();
            // AIBinder_getCallingSid() returns a '\0' terminated string
            // or NULL.
            if sid.is_null() {
                None
            } else {
                Some(core::ffi::CStr::from_ptr(sid))
            }
        })
    }
}
