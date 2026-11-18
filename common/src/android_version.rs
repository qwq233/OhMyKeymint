use std::{
    cell::Cell,
    string::{String, ToString},
    sync::OnceLock,
};

static ANDROID_MAJOR_VERSION: OnceLock<Option<i32>> = OnceLock::new();

thread_local! {
    static FRAMEWORK_PARCEL_API: Cell<Option<i32>> = Cell::default();
}

pub fn with_framework_parcel<T>(api: i32, decode: impl FnOnce() -> T) -> T {
    struct Restore(Option<i32>);
    impl Drop for Restore {
        fn drop(&mut self) {
            FRAMEWORK_PARCEL_API.set(self.0);
        }
    }
    let _restore = Restore(FRAMEWORK_PARCEL_API.replace(Some(api)));
    decode()
}

pub fn framework_keymint_v5_union() -> bool {
    FRAMEWORK_PARCEL_API.get().is_none_or(|api| api >= 37)
}

pub fn android_major_version() -> Option<i32> {
    *ANDROID_MAJOR_VERSION.get_or_init(|| android_major_version_with(read_string_property))
}

pub fn android_major_version_with(read_property: impl Fn(&str) -> Option<String>) -> Option<i32> {
    read_property("ro.build.version.release_or_codename")
        .or_else(|| read_property("ro.build.version.release"))
        .and_then(|value| value.parse::<i32>().ok())
        .or_else(|| {
            read_property("ro.build.version.sdk").and_then(|sdk| sdk.parse::<i32>().ok()).map(
                |sdk| match sdk {
                    31 | 32 => 12,
                    33 => 13,
                    34 => 14,
                    35 => 15,
                    36 => 16,
                    value if value >= 37 => 17,
                    _ => panic!("unrecognized or unsupported SDK version: {}", sdk),
                },
            )
        })
}

fn read_string_property(name: &str) -> Option<String> {
    rsproperties::get::<String>(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}
