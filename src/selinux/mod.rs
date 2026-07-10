// Copyright 2020, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This crate provides some safe wrappers around the libselinux API. It is currently limited
//! to the API surface that Keystore 2.0 requires to perform permission checks against
//! the SEPolicy. Notably, it provides wrappers for:
//!  * getcon
//!  * selinux_check_access
//!  * selabel_lookup for the keystore2_key backend.
//!
//! And it provides an owning wrapper around context strings `Context`.

// TODO(b/290018030): Remove this and add proper safety comments.
#![allow(clippy::undocumented_unsafe_blocks)]

use anyhow::Context as AnyhowContext;
use anyhow::{anyhow, Result};
use std::ffi::{CStr, CString};
use std::fmt;
use std::io;
use std::marker::{Send, Sync};
pub use std::ops::Deref;
use std::os::raw::c_char;
use std::ptr;
use std::sync;

mod sys;

use self::sys as selinux;
pub use selinux::pid_t;
use selinux::SELABEL_CTX_ANDROID_KEYSTORE2_KEY;
use selinux::SELINUX_CB_LOG;

static SELINUX_LOG_INIT: sync::Once = sync::Once::new();

/// `selinux_check_access` is only thread safe if avc_init was called with lock callbacks.
/// However, avc_init is deprecated and not exported by androids version of libselinux.
/// `selinux_set_callbacks` does not allow setting lock callbacks. So the only option
/// that remains right now is to put a big lock around calls into libselinux.
/// TODO b/188079221 It should suffice to protect `selinux_check_access` but until we are
/// certain of that, we leave the extra locks in place
static LIB_SELINUX_LOCK: sync::Mutex<()> = sync::Mutex::new(());

fn redirect_selinux_logs_to_logcat() {
    // `selinux_set_callback` assigns the static lifetime function pointer
    // `selinux_log_callback` to a static lifetime variable.
    let cb = selinux::selinux_callback {
        func_log: Some(selinux::selinux_log_callback),
    };
    unsafe {
        selinux::selinux_set_callback(SELINUX_CB_LOG as i32, cb);
    }
}

// This function must be called before any entry point into lib selinux.
// Or leave a comment reasoning why calling this macro is not necessary
// for a given entry point.
fn init_logger_once() {
    SELINUX_LOG_INIT.call_once(redirect_selinux_logs_to_logcat)
}

/// Selinux Error code.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum Error {
    /// Indicates that an access check yielded no access.
    #[error("Permission Denied")]
    PermissionDenied,
    /// Indicates an unexpected system error. Nested string provides some details.
    #[error("Selinux SystemError: {0}")]
    SystemError(String),
}

impl Error {
    /// Constructs a `PermissionDenied` error.
    pub fn perm() -> Self {
        Error::PermissionDenied
    }
    fn sys<T: Into<String>>(s: T) -> Self {
        Error::SystemError(s.into())
    }
}

/// Context represents an SELinux context string. It can take ownership of a raw
/// s-string as allocated by `getcon` or `selabel_lookup`. In this case it uses
/// `freecon` to free the resources when dropped. In its second variant it stores
/// an `std::ffi::CString` that can be initialized from a Rust string slice.
#[derive(Debug)]
pub enum Context {
    /// Wraps a raw context c-string as returned by libselinux.
    Raw(*mut ::std::os::raw::c_char),
    /// Stores a context string as `std::ffi::CString`.
    CString(CString),
}

impl PartialEq for Context {
    fn eq(&self, other: &Self) -> bool {
        // We dereference both and thereby delegate the comparison
        // to `CStr`'s implementation of `PartialEq`.
        **self == **other
    }
}

impl Eq for Context {}

impl fmt::Display for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", (**self).to_str().unwrap_or("Invalid context"))
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        if let Self::Raw(p) = self {
            // No need to initialize the logger here, because
            // `freecon` cannot run unless `Backend::lookup` or `getcon`
            // has run.
            unsafe { selinux::freecon(*p) };
        }
    }
}

impl Deref for Context {
    type Target = CStr;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Raw(p) => unsafe { CStr::from_ptr(*p) },
            Self::CString(cstr) => cstr,
        }
    }
}

impl Context {
    /// Initializes the `Context::CString` variant from a Rust string slice.
    pub fn new(con: &str) -> Result<Self> {
        Ok(Self::CString(CString::new(con).with_context(|| {
            format!("Failed to create Context with \"{con}\"")
        })?))
    }
}

/// The backend trait provides a uniform interface to all libselinux context backends.
/// Currently, we only implement the KeystoreKeyBackend though.
pub trait Backend {
    /// Implementers use libselinux `selabel_lookup` to lookup the context for the given `key`.
    fn lookup(&self, key: &str) -> Result<Context>;
}

/// Keystore key backend takes onwnership of the SELinux context handle returned by
/// `selinux_android_keystore2_key_context_handle` and uses `selabel_close` to free
/// the handle when dropped.
/// It implements `Backend` to provide keystore_key label lookup functionality.
pub struct KeystoreKeyBackend {
    handle: *mut selinux::selabel_handle,
}

// SAFETY: KeystoreKeyBackend is Sync because selabel_lookup is thread safe.
unsafe impl Sync for KeystoreKeyBackend {}
// SAFETY: KeystoreKeyBackend is Send because selabel_lookup is thread safe.
unsafe impl Send for KeystoreKeyBackend {}

impl KeystoreKeyBackend {
    const BACKEND_TYPE: i32 = SELABEL_CTX_ANDROID_KEYSTORE2_KEY as i32;

    /// Creates a new instance representing an SELinux context handle as returned by
    /// `selinux_android_keystore2_key_context_handle`.
    pub fn new() -> Result<Self> {
        init_logger_once();
        let _lock = LIB_SELINUX_LOCK.lock().unwrap();

        let handle = unsafe { selinux::selinux_android_keystore2_key_context_handle() };
        if handle.is_null() {
            return Err(anyhow!(Error::sys("Failed to open KeystoreKeyBackend")));
        }
        Ok(KeystoreKeyBackend { handle })
    }
}

impl Drop for KeystoreKeyBackend {
    fn drop(&mut self) {
        // No need to initialize the logger here because it cannot be called unless
        // KeystoreKeyBackend::new has run.
        unsafe { selinux::selabel_close(self.handle) };
    }
}

// Because KeystoreKeyBackend is Sync and Send, member function must never call
// non thread safe libselinux functions. As of this writing no non thread safe
// functions exist that could be called on a label backend handle.
impl Backend for KeystoreKeyBackend {
    fn lookup(&self, key: &str) -> Result<Context> {
        let mut con: *mut c_char = ptr::null_mut();
        let c_key = CString::new(key).with_context(|| {
            format!("selabel_lookup: Failed to convert key \"{key}\" to CString.")
        })?;
        match unsafe {
            // No need to initialize the logger here because it cannot run unless
            // KeystoreKeyBackend::new has run.
            let _lock = LIB_SELINUX_LOCK.lock().unwrap();

            selinux::selabel_lookup(self.handle, &mut con, c_key.as_ptr(), Self::BACKEND_TYPE)
        } {
            0 => {
                if !con.is_null() {
                    Ok(Context::Raw(con))
                } else {
                    Err(anyhow!(Error::sys(format!(
                        "selabel_lookup returned a NULL context for key \"{key}\""
                    ))))
                }
            }
            _ => Err(anyhow!(io::Error::last_os_error()))
                .with_context(|| format!("selabel_lookup failed for key \"{key}\"")),
        }
    }
}

/// Safe wrapper around libselinux `getcon`. It initializes the `Context::Raw` variant of the
/// returned `Context`.
///
/// ## Return
///  * Ok(Context::Raw()) if successful.
///  * Err(Error::sys()) if getcon succeeded but returned a NULL pointer.
///  * Err(io::Error::last_os_error()) if getcon failed.
pub fn getcon() -> Result<Context> {
    init_logger_once();
    let _lock = LIB_SELINUX_LOCK.lock().unwrap();

    let mut con: *mut c_char = ptr::null_mut();
    match unsafe { selinux::getcon(&mut con) } {
        0 => {
            if !con.is_null() {
                Ok(Context::Raw(con))
            } else {
                Err(anyhow!(Error::sys("getcon returned a NULL context")))
            }
        }
        _ => Err(anyhow!(io::Error::last_os_error())).context("getcon failed"),
    }
}

/// Safe wrapper around selinux_check_access.
///
/// ## Return
///  * Ok(()) iff the requested access was granted.
///  * Err(anyhow!(Error::perm()))) if the permission was denied.
///  * Err(anyhow!(ioError::last_os_error())) if any other error occurred while performing
///    the access check.
pub fn check_access(source: &CStr, target: &CStr, tclass: &str, perm: &str) -> Result<()> {
    init_logger_once();

    let c_tclass = CString::new(tclass).with_context(|| {
        format!("check_access: Failed to convert tclass \"{tclass}\" to CString.")
    })?;
    let c_perm = CString::new(perm)
        .with_context(|| format!("check_access: Failed to convert perm \"{perm}\" to CString."))?;

    match unsafe {
        let _lock = LIB_SELINUX_LOCK.lock().unwrap();

        selinux::selinux_check_access(
            source.as_ptr(),
            target.as_ptr(),
            c_tclass.as_ptr(),
            c_perm.as_ptr(),
            ptr::null_mut(),
        )
    } {
        0 => Ok(()),
        _ => {
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::PermissionDenied => Err(anyhow!(Error::perm())),
                _ => Err(anyhow!(e)),
            }
            .with_context(|| {
                format!(
                    concat!(
                        "check_access: Failed with sctx: {:?} tctx: {:?}",
                        " with target class: \"{}\" perm: \"{}\""
                    ),
                    source, target, tclass, perm
                )
            })
        }
    }
}

/// Safe wrapper around setcon.
pub fn setcon(target: &CStr) -> std::io::Result<()> {
    // SAFETY: `setcon` takes a const char* and only performs read accesses on it
    // using strdup and strcmp. `setcon` does not retain a pointer to `target`
    // and `target` outlives the call to `setcon`.
    if unsafe { selinux::setcon(target.as_ptr()) } != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Represents an SEPolicy permission belonging to a specific class.
pub trait ClassPermission {
    /// The permission string of the given instance as specified in the class vector.
    fn name(&self) -> &'static str;
    /// The class of the permission.
    fn class_name(&self) -> &'static str;
}

/// This macro implements an enum with values mapped to SELinux permission names.
/// The example below implements `enum MyPermission with public visibility:
///  * From<i32> and Into<i32> are implemented. Where the implementation of From maps
///    any variant not specified to the default `None` with value `0`.
///  * `MyPermission` implements ClassPermission.
///  * An implicit default values `MyPermission::None` is created with a numeric representation
///    of `0` and a string representation of `"none"`.
///  * Specifying a value is optional. If the value is omitted it is set to the value of the
///    previous variant left shifted by 1.
///
/// ## Example
/// ```
/// implement_class!(
///     /// MyPermission documentation.
///     #[derive(Clone, Copy, Debug, Eq, PartialEq)]
///     #[selinux(class_name = my_class)]
///     pub enum MyPermission {
///         #[selinux(name = foo)]
///         Foo = 1,
///         #[selinux(name = bar)]
///         Bar = 2,
///         #[selinux(name = snafu)]
///         Snafu, // Implicit value: MyPermission::Bar << 1 -> 4
///     }
///     assert_eq!(MyPermission::Foo.name(), &"foo");
///     assert_eq!(MyPermission::Foo.class_name(), &"my_class");
///     assert_eq!(MyPermission::Snafu as i32, 4);
/// );
/// ```
macro_rules! implement_class {
    // First rule: Public interface.
    (
        $(#[$($enum_meta:tt)+])*
        $enum_vis:vis enum $enum_name:ident $body:tt
    ) => {
        implement_class! {
            @extract_class
            []
            [$(#[$($enum_meta)+])*]
            $enum_vis enum $enum_name $body
        }
    };

    // The next two rules extract the #[selinux(class_name = <name>)] meta field from
    // the types meta list.
    // This first rule finds the field and terminates the recursion through the meta fields.
    (
        @extract_class
        [$(#[$mout:meta])*]
        [
            #[selinux(class_name = $class_name:ident)]
            $(#[$($mtail:tt)+])*
        ]
        $enum_vis:vis enum $enum_name:ident {
            $(
                $(#[$($emeta:tt)+])*
                $vname:ident$( = $vval:expr)?
            ),* $(,)?
        }
    ) => {
        implement_class!{
            @extract_perm_name
            $class_name
            $(#[$mout])*
            $(#[$($mtail)+])*
            $enum_vis enum $enum_name {
                1;
                []
                [$(
                    [] [$(#[$($emeta)+])*]
                    $vname$( = $vval)?,
                )*]
            }
        }
    };

    // The second rule iterates through the type global meta fields.
    (
        @extract_class
        [$(#[$mout:meta])*]
        [
            #[$front:meta]
            $(#[$($mtail:tt)+])*
        ]
        $enum_vis:vis enum $enum_name:ident $body:tt
    ) => {
        implement_class!{
            @extract_class
            [
                $(#[$mout])*
                #[$front]
            ]
            [$(#[$($mtail)+])*]
            $enum_vis enum $enum_name $body
        }
    };

    // The next four rules implement two nested recursions. The outer iterates through
    // the enum variants and the inner iterates through the meta fields of each variant.
    // The first two rules find the #[selinux(name = <name>)] stanza, terminate the inner
    // recursion and descend a level in the outer recursion.
    // The first rule matches variants with explicit initializer $vval. And updates the next
    // value to ($vval << 1).
    (
        @extract_perm_name
        $class_name:ident
        $(#[$enum_meta:meta])*
        $enum_vis:vis enum $enum_name:ident {
            $next_val:expr;
            [$($out:tt)*]
            [
                [$(#[$mout:meta])*]
                [
                    #[selinux(name = $selinux_name:ident)]
                    $(#[$($mtail:tt)+])*
                ]
                $vname:ident = $vval:expr,
                $($tail:tt)*
            ]
        }
    ) => {
        implement_class!{
            @extract_perm_name
            $class_name
            $(#[$enum_meta])*
            $enum_vis enum $enum_name {
                ($vval << 1);
                [
                    $($out)*
                    $(#[$mout])*
                    $(#[$($mtail)+])*
                    $selinux_name $vname = $vval,
                ]
                [$($tail)*]
            }
        }
    };

    // The second rule differs form the previous in that there is no explicit initializer.
    // Instead $next_val is used as initializer and the next value is set to (&next_val << 1).
    (
        @extract_perm_name
        $class_name:ident
        $(#[$enum_meta:meta])*
        $enum_vis:vis enum $enum_name:ident {
            $next_val:expr;
            [$($out:tt)*]
            [
                [$(#[$mout:meta])*]
                [
                    #[selinux(name = $selinux_name:ident)]
                    $(#[$($mtail:tt)+])*
                ]
                $vname:ident,
                $($tail:tt)*
            ]
        }
    ) => {
        implement_class!{
            @extract_perm_name
            $class_name
            $(#[$enum_meta])*
            $enum_vis enum $enum_name {
                ($next_val << 1);
                [
                    $($out)*
                    $(#[$mout])*
                    $(#[$($mtail)+])*
                    $selinux_name $vname = $next_val,
                ]
                [$($tail)*]
            }
        }
    };

    // The third rule descends a step in the inner recursion.
    (
        @extract_perm_name
        $class_name:ident
        $(#[$enum_meta:meta])*
        $enum_vis:vis enum $enum_name:ident {
            $next_val:expr;
            [$($out:tt)*]
            [
                [$(#[$mout:meta])*]
                [
                    #[$front:meta]
                    $(#[$($mtail:tt)+])*
                ]
                $vname:ident$( = $vval:expr)?,
                $($tail:tt)*
            ]
        }
    ) => {
        implement_class!{
            @extract_perm_name
            $class_name
            $(#[$enum_meta])*
            $enum_vis enum $enum_name {
                $next_val;
                [$($out)*]
                [
                    [
                        $(#[$mout])*
                        #[$front]
                    ]
                    [$(#[$($mtail)+])*]
                    $vname$( = $vval)?,
                    $($tail)*
                ]
            }
        }
    };

    // The fourth rule terminates the outer recursion and transitions to the
    // implementation phase @spill.
    (
        @extract_perm_name
        $class_name:ident
        $(#[$enum_meta:meta])*
        $enum_vis:vis enum $enum_name:ident {
            $next_val:expr;
            [$($out:tt)*]
            []
        }
    ) => {
        implement_class!{
            @spill
            $class_name
            $(#[$enum_meta])*
            $enum_vis enum $enum_name {
                $($out)*
            }
        }
    };

    (
        @spill
        $class_name:ident
        $(#[$enum_meta:meta])*
        $enum_vis:vis enum $enum_name:ident {
            $(
                $(#[$emeta:meta])*
                $selinux_name:ident $vname:ident = $vval:expr,
            )*
        }
    ) => {
        $(#[$enum_meta])*
        $enum_vis enum $enum_name {
            /// The default variant of the enum.
            None = 0,
            $(
                $(#[$emeta])*
                $vname = $vval,
            )*
        }

        impl From<i32> for $enum_name {
            #[allow(non_upper_case_globals)]
            fn from (p: i32) -> Self {
                // Creating constants forces the compiler to evaluate the value expressions
                // so that they can be used in the match statement below.
                $(const $vname: i32 = $vval;)*
                match p {
                    0 => Self::None,
                    $($vname => Self::$vname,)*
                    _ => Self::None,
                }
            }
        }

        impl From<$enum_name> for i32 {
            fn from(p: $enum_name) -> i32 {
                p as i32
            }
        }

        impl ClassPermission for $enum_name {
            fn name(&self) -> &'static str {
                match self {
                    Self::None => &"none",
                    $(Self::$vname => stringify!($selinux_name),)*
                }
            }
            fn class_name(&self) -> &'static str {
                stringify!($class_name)
            }
        }
    };
}

pub(crate) use implement_class;

/// Calls `check_access` on the given class permission.
pub fn check_permission<T: ClassPermission>(source: &CStr, target: &CStr, perm: T) -> Result<()> {
    check_access(source, target, perm.class_name(), perm.name())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    /// The su_key namespace as defined in su.te and keystore_key_contexts of the
    /// SePolicy (system/sepolicy). Root frameworks can run in their own domains but still use the
    /// privileged root namespace for these tests.
    static SU_KEY_NAMESPACE: &str = "0";
    /// The shell_key namespace as defined in shell.te and keystore_key_contexts of the
    /// SePolicy (system/sepolicy).
    static SHELL_KEY_NAMESPACE: &str = "1";

    fn check_context() -> Result<(Context, &'static str, bool)> {
        let context = getcon()?;
        match context.to_str().unwrap() {
            "u:r:magisk:s0" | "u:r:ksu:s0" | "u:r:su:s0" => {
                Ok((context, SU_KEY_NAMESPACE, true))
            }
            "u:r:shell:s0" => Ok((context, SHELL_KEY_NAMESPACE, false)),
            c => Err(anyhow!(format!(
                "This test must be run as \"magisk\", \"ksu\", \"su\" or \"shell\". Current context: \"{}\"",
                c
            ))),
        }
    }

    #[test]
    fn test_getcon() -> Result<()> {
        check_context()?;
        Ok(())
    }

    #[test]
    fn test_label_lookup() -> Result<()> {
        let (_context, namespace, is_su) = check_context()?;
        let backend = KeystoreKeyBackend::new()?;
        let context = backend.lookup(namespace)?;
        if is_su {
            assert_eq!(context.to_str(), Ok("u:object_r:su_key:s0"));
        } else {
            assert_eq!(context.to_str(), Ok("u:object_r:shell_key:s0"));
        }
        Ok(())
    }

    #[test]
    fn context_from_string() -> Result<()> {
        let tctx = Context::new("u:object_r:keystore:s0").unwrap();
        let sctx = Context::new("u:r:system_server:s0").unwrap();
        check_access(&sctx, &tctx, "keystore2_key", "use")?;
        Ok(())
    }

    mod perm {
        use super::*;
        use anyhow::Result;

        /// check_key_perm(perm, privileged, priv_domain)
        /// `perm` is a permission of the keystore2_key class and `privileged` is a boolean
        /// indicating whether the permission is considered privileged.
        /// Privileged permissions are expected to be denied to `shell` users but granted
        /// to the given priv_domain.
        macro_rules! check_key_perm {
            // "use" is a keyword and cannot be used as an identifier, but we must keep
            // the permission string intact. So we map the identifier name on use_ while using
            // the permission string "use". In all other cases we can simply use the stringified
            // identifier as permission string.
            (use, $privileged:expr) => {
                check_key_perm!(use_, $privileged, "use");
            };
            ($perm:ident, $privileged:expr) => {
                check_key_perm!($perm, $privileged, stringify!($perm));
            };
            ($perm:ident, $privileged:expr, $p_str:expr) => {
                #[test]
                fn $perm() -> Result<()> {
                    let scontext = Context::new("u:r:shell:s0")?;
                    let backend = KeystoreKeyBackend::new()?;
                    let tcontext = backend.lookup(SHELL_KEY_NAMESPACE)?;

                    if $privileged {
                        assert_eq!(
                            Some(&Error::perm()),
                            check_access(
                                &scontext,
                                &tcontext,
                                "keystore2_key",
                                $p_str
                            )
                            .err()
                            .unwrap()
                            .root_cause()
                            .downcast_ref::<Error>()
                        );
                    } else {
                        assert!(check_access(
                            &scontext,
                            &tcontext,
                            "keystore2_key",
                            $p_str
                        )
                        .is_ok());
                    }
                    Ok(())
                }
            };
        }

        check_key_perm!(manage_blob, true);
        check_key_perm!(delete, false);
        check_key_perm!(use_dev_id, true);
        check_key_perm!(req_forced_op, true);
        check_key_perm!(gen_unique_id, true);
        check_key_perm!(grant, true);
        check_key_perm!(get_info, false);
        check_key_perm!(rebind, false);
        check_key_perm!(update, false);
        check_key_perm!(use, false);

        macro_rules! check_keystore_perm {
            ($perm:ident) => {
                #[test]
                fn $perm() -> Result<()> {
                    let ks_context = Context::new("u:object_r:keystore:s0")?;
                    let priv_context = Context::new("u:r:system_server:s0")?;
                    let unpriv_context = Context::new("u:r:shell:s0")?;
                    assert!(check_access(
                        &priv_context,
                        &ks_context,
                        "keystore2",
                        stringify!($perm)
                    )
                    .is_ok());
                    assert_eq!(
                        Some(&Error::perm()),
                        check_access(&unpriv_context, &ks_context, "keystore2", stringify!($perm))
                            .err()
                            .unwrap()
                            .root_cause()
                            .downcast_ref::<Error>()
                    );
                    Ok(())
                }
            };
        }

        check_keystore_perm!(add_auth);
        check_keystore_perm!(clear_ns);
        check_keystore_perm!(lock);
        check_keystore_perm!(reset);
        check_keystore_perm!(unlock);
    }
}
