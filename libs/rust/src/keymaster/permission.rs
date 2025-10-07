use crate::android::system::keystore2::KeyPermission::KeyPermission;

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
