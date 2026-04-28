use std::ffi::{CStr, CString};
use std::sync::OnceLock;

use anyhow::{anyhow, Context, Result};
use rsbinder::{hub, thread_state::CallingContext, Status};

use crate::android::hardware::security::keymint::{ErrorCode::ErrorCode, Tag::Tag};
use crate::android::system::keystore2::Domain::Domain;
use crate::android::system::keystore2::KeyDescriptor::KeyDescriptor;
use crate::android::system::keystore2::KeyPermission::KeyPermission;
use crate::android::system::keystore2::ResponseCode::ResponseCode;
use crate::keymaster::error::KsError;
use crate::top::qwq2333::ohmykeymint::CallerInfo::CallerInfo;

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
#[macro_export]
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
    };
}

implement_class!(
    /// KeyPerm provides a convenient abstraction from the SELinux class `keystore2_key`.
    /// At the same time it maps `KeyPermissions` from the Keystore 2.0 AIDL Grant interface to
    /// the SELinux permissions.
    #[repr(i32)]
    #[selinux(class_name = keystore2_key)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum KeyPerm {
        /// Checked when convert_storage_key_to_ephemeral is called.
        #[selinux(name = convert_storage_key_to_ephemeral)]
        ConvertStorageKeyToEphemeral = KeyPermission::CONVERT_STORAGE_KEY_TO_EPHEMERAL.0,
        /// Checked when the caller tries do delete a key.
        #[selinux(name = delete)]
        Delete = KeyPermission::DELETE.0,
        /// Checked when the caller tries to use a unique id.
        #[selinux(name = gen_unique_id)]
        GenUniqueId = KeyPermission::GEN_UNIQUE_ID.0,
        /// Checked when the caller tries to load a key.
        #[selinux(name = get_info)]
        GetInfo = KeyPermission::GET_INFO.0,
        /// Checked when the caller attempts to grant a key to another uid.
        /// Also used for gating key migration attempts.
        #[selinux(name = grant)]
        Grant = KeyPermission::GRANT.0,
        /// Checked when the caller attempts to use Domain::BLOB.
        #[selinux(name = manage_blob)]
        ManageBlob = KeyPermission::MANAGE_BLOB.0,
        /// Checked when the caller tries to create a key which implies rebinding
        /// an alias to the new key.
        #[selinux(name = rebind)]
        Rebind = KeyPermission::REBIND.0,
        /// Checked when the caller attempts to create a forced operation.
        #[selinux(name = req_forced_op)]
        ReqForcedOp = KeyPermission::REQ_FORCED_OP.0,
        /// Checked when the caller attempts to update public key artifacts.
        #[selinux(name = update)]
        Update = KeyPermission::UPDATE.0,
        /// Checked when the caller attempts to use a private or public key.
        #[selinux(name = use)]
        Use = KeyPermission::USE.0,
        /// Does nothing, and is not checked. For use of device identifiers,
        /// the caller must hold the READ_PRIVILEGED_PHONE_STATE Android
        /// permission.
        #[selinux(name = use_dev_id)]
        UseDevId = KeyPermission::USE_DEV_ID.0,
    }
);

/// Represents a set of `KeyPerm` permissions.
/// `IntoIterator` is implemented for this struct allowing the iteration through all the
/// permissions in the set.
/// It also implements a function `includes(self, other)` that checks if the permissions
/// in `other` are included in `self`.
///
/// KeyPermSet can be created with the macro `key_perm_set![]`.
///
/// ## Example
/// ```
/// let perms1 = key_perm_set![KeyPerm::Use, KeyPerm::ManageBlob, KeyPerm::Grant];
/// let perms2 = key_perm_set![KeyPerm::Use, KeyPerm::ManageBlob];
///
/// assert!(perms1.includes(perms2))
/// assert!(!perms2.includes(perms1))
///
/// let i = perms1.into_iter();
/// // iteration in ascending order of the permission's numeric representation.
/// assert_eq(Some(KeyPerm::ManageBlob), i.next());
/// assert_eq(Some(KeyPerm::Grant), i.next());
/// assert_eq(Some(KeyPerm::Use), i.next());
/// assert_eq(None, i.next());
/// ```
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct KeyPermSet(pub i32);

mod perm {
    use super::*;

    pub struct IntoIter {
        vec: KeyPermSet,
        pos: u8,
    }

    impl IntoIter {
        pub fn new(v: KeyPermSet) -> Self {
            Self { vec: v, pos: 0 }
        }
    }

    impl std::iter::Iterator for IntoIter {
        type Item = KeyPerm;

        fn next(&mut self) -> Option<Self::Item> {
            loop {
                if self.pos == 32 {
                    return None;
                }
                let p = self.vec.0 & (1 << self.pos);
                self.pos += 1;
                if p != 0 {
                    return Some(KeyPerm::from(p));
                }
            }
        }
    }
}

impl From<KeyPerm> for KeyPermSet {
    fn from(p: KeyPerm) -> Self {
        Self(p as i32)
    }
}

/// allow conversion from the AIDL wire type i32 to a permission set.
impl From<i32> for KeyPermSet {
    fn from(p: i32) -> Self {
        Self(p)
    }
}

impl From<KeyPermSet> for i32 {
    fn from(p: KeyPermSet) -> i32 {
        p.0
    }
}

impl KeyPermSet {
    /// Returns true iff this permission set has all of the permissions that are in `other`.
    pub fn includes<T: Into<KeyPermSet>>(&self, other: T) -> bool {
        let o: KeyPermSet = other.into();
        (self.0 & o.0) == o.0
    }
}

/// This macro can be used to create a `KeyPermSet` from a list of `KeyPerm` values.
///
/// ## Example
/// ```
/// let v = key_perm_set![Perm::delete(), Perm::manage_blob()];
/// ```
#[macro_export]
macro_rules! key_perm_set {
    () => { KeyPermSet(0) };
    ($head:expr $(, $tail:expr)* $(,)?) => {
        KeyPermSet($head as i32 $(| $tail as i32)*)
    };
}

impl IntoIterator for KeyPermSet {
    type Item = KeyPerm;
    type IntoIter = perm::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        Self::IntoIter::new(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeystorePerm {
    List,
}

impl KeystorePerm {
    pub const fn name(self) -> &'static str {
        match self {
            Self::List => "list",
        }
    }

    pub const fn class_name(self) -> &'static str {
        "keystore2"
    }
}

impl KeyPerm {
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ConvertStorageKeyToEphemeral => "convert_storage_key_to_ephemeral",
            Self::Delete => "delete",
            Self::GenUniqueId => "gen_unique_id",
            Self::GetInfo => "get_info",
            Self::Grant => "grant",
            Self::ManageBlob => "manage_blob",
            Self::Rebind => "rebind",
            Self::ReqForcedOp => "req_forced_op",
            Self::Update => "update",
            Self::Use => "use",
            Self::UseDevId => "use_dev_id",
        }
    }

    pub const fn class_name(self) -> &'static str {
        "keystore2_key"
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallerCtx {
    pub uid: u32,
    pub pid: i32,
    pub sid: Option<CString>,
}

impl CallerCtx {
    pub fn from_caller_info(ctx: Option<&CallerInfo>) -> Self {
        if let Some(ctx) = ctx {
            let sid = (!ctx.callingSid.is_empty())
                .then(|| CString::new(ctx.callingSid.clone()).ok())
                .flatten();
            return Self {
                uid: ctx.callingUid as u32,
                pid: ctx.callingPid as i32,
                sid,
            };
        }

        let calling = CallingContext::default();
        Self {
            uid: calling.uid as u32,
            pid: calling.pid as i32,
            sid: calling.sid,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedKeyPermission {
    pub descriptor: KeyDescriptor,
    pub access_vector: Option<KeyPermSet>,
}

const PERMISSION_MANAGER_SERVICE: &str = "permissionmgr";
const CHECK_UID_PERMISSION_TRANSACTION: u32 = rsbinder::FIRST_CALL_TRANSACTION + 30;
const DEFAULT_DEVICE_ID: i32 = 0;
const PERMISSION_GRANTED: i32 = 0;
const READ_PRIVILEGED_PHONE_STATE: &str = "android.permission.READ_PRIVILEGED_PHONE_STATE";
const REQUEST_UNIQUE_ID_ATTESTATION: &str = "android.permission.REQUEST_UNIQUE_ID_ATTESTATION";
const AOSP_KEYSTORE_CONTEXT: &str = "u:r:keystore:s0";

const KEYSTORE2_KEY_CONTEXT_FILES: &[&str] = &[
    "/system/etc/selinux/plat_keystore2_key_contexts",
    "/system_ext/etc/selinux/system_ext_keystore2_key_contexts",
    "/product/etc/selinux/product_keystore2_key_contexts",
    "/vendor/etc/selinux/vendor_keystore2_key_contexts",
    "/odm/etc/selinux/odm_keystore2_key_contexts",
];

fn parse_keystore2_key_contexts(contents: &str) -> Vec<(i64, CString)> {
    contents
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }

            let mut parts = line.split_whitespace();
            let namespace = parts.next()?.parse::<i64>().ok()?;
            let context = parts.next()?;
            if !context.starts_with("u:object_r:") {
                return None;
            }
            CString::new(context)
                .ok()
                .map(|context| (namespace, context))
        })
        .collect()
}

fn keystore2_key_contexts() -> Result<&'static Vec<(i64, CString)>> {
    static CONTEXTS: OnceLock<Result<Vec<(i64, CString)>, String>> = OnceLock::new();

    CONTEXTS
        .get_or_init(|| {
            let mut contexts = Vec::new();
            for path in KEYSTORE2_KEY_CONTEXT_FILES {
                match std::fs::read_to_string(path) {
                    Ok(contents) => contexts.extend(parse_keystore2_key_contexts(&contents)),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(format!("failed to read {path}: {error}"));
                    }
                }
            }

            if contexts.is_empty() {
                return Err("no keystore2 key context files were readable".to_string());
            }

            Ok(contexts)
        })
        .as_ref()
        .map_err(|error| anyhow!(error.clone()))
}

fn lookup_keystore2_key_context(namespace: i64) -> Result<CString> {
    keystore2_key_contexts()?
        .iter()
        .find(|(candidate, _)| *candidate == namespace)
        .map(|(_, context)| context.clone())
        .ok_or_else(|| anyhow!(KsError::perm()))
        .context(format!(
            "no keystore2 key context for namespace {namespace}"
        ))
}

#[cfg(target_os = "android")]
fn parse_selinux_context_bytes(bytes: Vec<u8>, label: &str) -> Result<CString> {
    let trimmed: Vec<u8> = bytes
        .into_iter()
        .take_while(|byte| *byte != 0 && *byte != b'\n' && *byte != b'\r')
        .collect();
    CString::new(trimmed).context(format!(
        "{label} SELinux context contained an interior NUL byte"
    ))
}

#[cfg(target_os = "android")]
fn current_selinux_context() -> Result<CString> {
    let bytes = std::fs::read("/proc/self/attr/current")
        .context("failed to read /proc/self/attr/current for SELinux context")?;
    parse_selinux_context_bytes(bytes, "current")
}

#[cfg(target_os = "android")]
fn lookup_process_selinux_context(process_name: &str) -> Result<Option<CString>> {
    for entry in std::fs::read_dir("/proc").context("failed to scan /proc for keystore2")? {
        let entry = entry.context("failed to inspect /proc entry")?;
        let file_name = entry.file_name();
        let Some(pid) = file_name
            .to_str()
            .filter(|name| name.bytes().all(|byte| byte.is_ascii_digit()))
        else {
            continue;
        };

        let cmdline = match std::fs::read(format!("/proc/{pid}/cmdline")) {
            Ok(bytes) => bytes,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                continue;
            }
            Err(error) => {
                return Err(error).context(format!(
                    "failed to read /proc/{pid}/cmdline while locating {process_name}"
                ));
            }
        };

        let Some(command) = cmdline
            .split(|byte| *byte == 0)
            .next()
            .filter(|command| !command.is_empty())
        else {
            continue;
        };

        let Ok(command) = std::str::from_utf8(command) else {
            continue;
        };
        let Some(basename) = std::path::Path::new(command)
            .file_name()
            .and_then(|name| name.to_str())
        else {
            continue;
        };
        if basename != process_name {
            continue;
        }

        let bytes = std::fs::read(format!("/proc/{pid}/attr/current")).with_context(|| {
            format!("failed to read /proc/{pid}/attr/current for {process_name}")
        })?;
        return parse_selinux_context_bytes(bytes, process_name).map(Some);
    }

    Ok(None)
}

#[cfg(target_os = "android")]
fn keystore_selinux_context() -> Result<CString> {
    static CONTEXT: OnceLock<Result<CString, String>> = OnceLock::new();

    CONTEXT
        .get_or_init(|| {
            (|| -> Result<CString> {
                let current = current_selinux_context()?;
                if current.to_bytes().starts_with(b"u:r:keystore:") {
                    return Ok(current);
                }

                if let Some(context) = lookup_process_selinux_context("keystore2")? {
                    return Ok(context);
                }

                Ok(CString::new(AOSP_KEYSTORE_CONTEXT).expect("static SELinux context is valid"))
            })()
            .map_err(|error| format!("{error:#}"))
        })
        .as_ref()
        .cloned()
        .map_err(|error| anyhow!(error.clone()))
}

#[cfg(not(target_os = "android"))]
fn current_selinux_context() -> Result<CString> {
    Ok(CString::new("u:r:keystore:s0").expect("static SELinux context is valid"))
}

#[cfg(not(target_os = "android"))]
fn keystore_selinux_context() -> Result<CString> {
    Ok(CString::new(AOSP_KEYSTORE_CONTEXT).expect("static SELinux context is valid"))
}

#[cfg(target_os = "android")]
fn check_selinux_permission_raw(
    source: &CStr,
    target: &CStr,
    class_name: &CStr,
    permission_name: &CStr,
) -> Result<()> {
    type SelinuxCheckAccessFn = unsafe extern "C" fn(
        *const libc::c_char,
        *const libc::c_char,
        *const libc::c_char,
        *const libc::c_char,
        *mut libc::c_void,
    ) -> libc::c_int;

    static CHECK_ACCESS: OnceLock<Result<SelinuxCheckAccessFn, String>> = OnceLock::new();
    let check_access = CHECK_ACCESS
        .get_or_init(|| unsafe {
            let library = CString::new("libselinux.so").expect("libselinux name is static");
            let symbol =
                CString::new("selinux_check_access").expect("selinux_check_access is static");
            let handle = libc::dlopen(library.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
            if handle.is_null() {
                return Err("dlopen(libselinux.so) failed".to_string());
            }
            let function = libc::dlsym(handle, symbol.as_ptr());
            if function.is_null() {
                return Err("dlsym(selinux_check_access) failed".to_string());
            }
            Ok(std::mem::transmute::<*mut libc::c_void, SelinuxCheckAccessFn>(function))
        })
        .as_ref()
        .map_err(|error| anyhow!(error.clone()))?;

    let rc = unsafe {
        check_access(
            source.as_ptr(),
            target.as_ptr(),
            class_name.as_ptr(),
            permission_name.as_ptr(),
            std::ptr::null_mut(),
        )
    };

    if rc == 0 {
        return Ok(());
    }

    let errno = std::io::Error::last_os_error();
    if matches!(errno.raw_os_error(), Some(libc::EACCES)) {
        return Err(KsError::perm()).context(format!(
            "SELinux denied {} {} {} -> {}",
            source.to_string_lossy(),
            class_name.to_string_lossy(),
            permission_name.to_string_lossy(),
            target.to_string_lossy()
        ));
    }

    Err(KsError::sys()).context(format!(
        "selinux_check_access failed for {} {} {} -> {}: {}",
        source.to_string_lossy(),
        class_name.to_string_lossy(),
        permission_name.to_string_lossy(),
        target.to_string_lossy(),
        errno
    ))
}

#[cfg(not(target_os = "android"))]
fn check_selinux_permission_raw(
    _source: &CStr,
    _target: &CStr,
    _class_name: &CStr,
    _permission_name: &CStr,
) -> Result<()> {
    Ok(())
}

fn check_selinux_permission(
    source: &CStr,
    target: &CStr,
    class_name: &str,
    permission_name: &str,
) -> Result<()> {
    let class_name = CString::new(class_name).expect("SELinux class names are static");
    let permission_name =
        CString::new(permission_name).expect("SELinux permission names are static");
    check_selinux_permission_raw(
        source,
        target,
        class_name.as_c_str(),
        permission_name.as_c_str(),
    )
}

#[cfg(target_os = "android")]
fn check_android_permission_for_uid(
    uid: u32,
    permission: &str,
    permission_denied: KsError,
) -> Result<()> {
    let binder = hub::get_service(PERMISSION_MANAGER_SERVICE)
        .ok_or_else(|| anyhow!(KsError::sys()))
        .context(format!("service {PERMISSION_MANAGER_SERVICE} unavailable"))?;
    let proxy = binder
        .as_proxy()
        .ok_or_else(|| anyhow!(KsError::sys()))
        .context("permissionmgr binder was unexpectedly local")?;
    let mut data = proxy
        .prepare_transact(true)
        .context("failed to prepare permissionmgr transaction")?;
    data.write(&(uid as i32))
        .context("failed to write permissionmgr uid argument")?;
    data.write(&permission.to_string())
        .context("failed to write permissionmgr permission argument")?;
    data.write(&DEFAULT_DEVICE_ID)
        .context("failed to write permissionmgr deviceId argument")?;

    let mut reply = proxy
        .submit_transact(CHECK_UID_PERMISSION_TRANSACTION, &data, 0)
        .context("permissionmgr transact failed")?
        .context("permissionmgr returned no reply")?;
    reply.set_data_position(0);

    let status: Status = reply
        .read()
        .context("failed to decode permissionmgr reply status")?;
    if !status.is_ok() {
        return Err(KsError::sys()).context(format!(
            "permissionmgr checkUidPermission returned non-ok status: {status}"
        ));
    }

    let result: i32 = reply
        .read()
        .context("failed to decode permissionmgr checkUidPermission result")?;
    if result == PERMISSION_GRANTED {
        Ok(())
    } else {
        Err(permission_denied).context(format!(
            "uid {uid} does not hold Android permission {permission}"
        ))
    }
}

#[cfg(not(target_os = "android"))]
fn check_android_permission_for_uid(
    _uid: u32,
    _permission: &str,
    _permission_denied: KsError,
) -> Result<()> {
    Ok(())
}

pub fn check_key_permission(
    permission: KeyPerm,
    key: &KeyDescriptor,
    access_vector: Option<&KeyPermSet>,
    caller: Option<&CallerInfo>,
) -> Result<()> {
    let caller = CallerCtx::from_caller_info(caller);

    if access_vector.is_some_and(|vector| vector.includes(permission)) {
        return Ok(());
    }

    let sid = caller
        .sid
        .as_ref()
        .ok_or_else(|| anyhow!(KsError::sys()))
        .context("caller SID unavailable for key permission check")?;

    let target = match key.domain {
        Domain::APP => {
            if caller.uid as i64 != key.nspace {
                return Err(KsError::perm()).context(format!(
                    "uid {} does not own app namespace {}",
                    caller.uid, key.nspace
                ));
            }
            keystore_selinux_context().context("failed to resolve keystore SELinux context")?
        }
        Domain::SELINUX => lookup_keystore2_key_context(key.nspace)?,
        Domain::GRANT => match access_vector {
            Some(_) => {
                return Err(KsError::perm())
                    .context(format!("{} was not granted", permission.name()));
            }
            None => {
                return Err(KsError::sys())
                    .context("cannot check Domain::GRANT without an access vector");
            }
        },
        Domain::KEY_ID => {
            return Err(KsError::sys()).context("cannot check permission for Domain::KEY_ID");
        }
        Domain::BLOB => {
            let target = lookup_keystore2_key_context(key.nspace)?;
            check_selinux_permission(
                sid.as_c_str(),
                target.as_c_str(),
                KeyPerm::ManageBlob.class_name(),
                KeyPerm::ManageBlob.name(),
            )?;
            target
        }
        _ => {
            return Err(KsError::Rc(ResponseCode::INVALID_ARGUMENT)).context(format!(
                "unsupported key domain {:?} for permission check",
                key.domain
            ));
        }
    };

    check_selinux_permission(
        sid.as_c_str(),
        target.as_c_str(),
        permission.class_name(),
        permission.name(),
    )
}

pub fn check_grant_permission(
    access_vector: KeyPermSet,
    key: &KeyDescriptor,
    caller: Option<&CallerInfo>,
) -> Result<()> {
    let caller = CallerCtx::from_caller_info(caller);
    let sid = caller
        .sid
        .as_ref()
        .ok_or_else(|| anyhow!(KsError::sys()))
        .context("caller SID unavailable for grant permission check")?;

    let target = match key.domain {
        Domain::APP => {
            if caller.uid as i64 != key.nspace {
                return Err(KsError::perm()).context(format!(
                    "uid {} does not own app namespace {}",
                    caller.uid, key.nspace
                ));
            }
            keystore_selinux_context().context("failed to resolve keystore SELinux context")?
        }
        Domain::SELINUX => lookup_keystore2_key_context(key.nspace)?,
        _ => {
            return Err(KsError::sys()).context(format!(
                "cannot grant permissions for domain {:?}",
                key.domain
            ));
        }
    };

    check_selinux_permission(
        sid.as_c_str(),
        target.as_c_str(),
        KeyPerm::Grant.class_name(),
        KeyPerm::Grant.name(),
    )?;

    if access_vector.includes(KeyPerm::Grant) {
        return Err(KsError::perm()).context("grant permission cannot itself be granted");
    }

    for permission in access_vector {
        check_selinux_permission(
            sid.as_c_str(),
            target.as_c_str(),
            permission.class_name(),
            permission.name(),
        )?;
    }
    Ok(())
}

pub fn check_keystore_permission(
    permission: KeystorePerm,
    caller: Option<&CallerInfo>,
) -> Result<()> {
    let caller = CallerCtx::from_caller_info(caller);
    let sid = caller
        .sid
        .as_ref()
        .ok_or_else(|| anyhow!(KsError::sys()))
        .context("caller SID unavailable for keystore permission check")?;
    let target = keystore_selinux_context()?;
    check_selinux_permission(
        sid.as_c_str(),
        target.as_c_str(),
        permission.class_name(),
        permission.name(),
    )
}

pub fn check_device_attestation_permissions(caller: Option<&CallerInfo>) -> Result<()> {
    let caller = CallerCtx::from_caller_info(caller);
    check_android_permission_for_uid(
        caller.uid,
        READ_PRIVILEGED_PHONE_STATE,
        KsError::Km(ErrorCode::CANNOT_ATTEST_IDS),
    )
}

pub fn check_unique_id_attestation_permissions(caller: Option<&CallerInfo>) -> Result<()> {
    let caller = CallerCtx::from_caller_info(caller);
    check_android_permission_for_uid(
        caller.uid,
        REQUEST_UNIQUE_ID_ATTESTATION,
        KsError::Km(ErrorCode::CANNOT_ATTEST_IDS),
    )
}

pub fn is_device_id_attestation_tag(tag: Tag) -> bool {
    matches!(
        tag,
        Tag::ATTESTATION_ID_IMEI
            | Tag::ATTESTATION_ID_MEID
            | Tag::ATTESTATION_ID_SERIAL
            | Tag::DEVICE_UNIQUE_ATTESTATION
            | Tag::ATTESTATION_ID_SECOND_IMEI
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app_key(namespace: i64) -> KeyDescriptor {
        KeyDescriptor {
            domain: Domain::APP,
            nspace: namespace,
            alias: Some("alias".to_string()),
            blob: None,
        }
    }

    #[test]
    fn parse_keystore2_key_contexts_skips_comments_and_extracts_pairs() {
        let parsed = parse_keystore2_key_contexts(
            "# comment\n25 ignored\n100 u:object_r:vold_key:s0\n\n120 u:object_r:resume_on_reboot_key:s0\n",
        );
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, 100);
        assert_eq!(parsed[0].1.to_string_lossy(), "u:object_r:vold_key:s0");
        assert_eq!(parsed[1].0, 120);
    }

    #[test]
    fn app_owner_has_permission_without_sid() {
        let caller = CallerInfo {
            callingUid: 10001,
            callingPid: 1234,
            callingSid: "u:r:untrusted_app:s0".to_string(),
        };
        check_key_permission(KeyPerm::Use, &app_key(10001), None, Some(&caller))
            .expect("owner should satisfy APP-domain ownership and SELinux permission checks");
    }

    #[test]
    fn grant_vector_allows_non_owner_app_access() {
        let caller = CallerInfo {
            callingUid: 20002,
            callingPid: 1234,
            callingSid: "u:r:untrusted_app:s0".to_string(),
        };
        check_key_permission(
            KeyPerm::Use,
            &app_key(10001),
            Some(&KeyPermSet::from(KeyPerm::Use)),
            Some(&caller),
        )
        .expect("grant vector should allow the requested permission");
    }

    #[test]
    fn missing_grant_denies_non_owner_app_access() {
        let caller = CallerInfo {
            callingUid: 20002,
            callingPid: 1234,
            callingSid: "u:r:untrusted_app:s0".to_string(),
        };
        let error = check_key_permission(KeyPerm::Use, &app_key(10001), None, Some(&caller))
            .expect_err("non-owner app key access should be denied without a grant");
        assert!(matches!(
            error.root_cause().downcast_ref::<KsError>(),
            Some(KsError::Rc(ResponseCode::PERMISSION_DENIED))
        ));
    }

    #[test]
    fn grant_permission_cannot_be_granted() {
        let caller = CallerInfo {
            callingUid: 10001,
            callingPid: 1234,
            callingSid: "u:r:untrusted_app:s0".to_string(),
        };
        let error = check_grant_permission(
            KeyPermSet::from(KeyPerm::Grant),
            &app_key(10001),
            Some(&caller),
        )
        .expect_err("grant permission itself must never be grantable");
        assert!(matches!(
            error.root_cause().downcast_ref::<KsError>(),
            Some(KsError::Rc(ResponseCode::PERMISSION_DENIED))
        ));
    }

    #[test]
    fn device_id_attestation_tags_match_aosp_surface() {
        assert!(is_device_id_attestation_tag(Tag::ATTESTATION_ID_SERIAL));
        assert!(is_device_id_attestation_tag(Tag::DEVICE_UNIQUE_ATTESTATION));
        assert!(is_device_id_attestation_tag(
            Tag::ATTESTATION_ID_SECOND_IMEI
        ));
        assert!(!is_device_id_attestation_tag(Tag::ATTESTATION_ID_BRAND));
        assert!(!is_device_id_attestation_tag(Tag::PURPOSE));
    }
}
