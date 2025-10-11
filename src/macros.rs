#[macro_export]
macro_rules! jni_methods {
    ($([$method:expr, $signature:expr, $fn:expr]),* $(,)?) => {
        vec![
            $(
                {
                    jni::NativeMethod {
                        name: jni::strings::JNIString::from($method),
                        sig: jni::strings::JNIString::from($signature),
                        fn_ptr: $fn as *mut _,
                    }
                }
            ),*
        ]
    };
}

/// Generates a message containing the current source file name and line number.
///
/// # Examples
///
/// ```
/// source_location_msg!("Key is expired.");
/// Result:
/// "src/lib.rs:7 Key is expired."
/// ```
#[macro_export]
macro_rules! err {
    { $($arg:tt)+ } => {
        format!("{}:{} {}", file!(), line!(), format_args!($($arg)+))
    };
    {} => {
        format!("{}:{}", file!(), line!())
    };
}
