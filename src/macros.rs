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

#[macro_export]
macro_rules! root_path {
    () => {
        "/data/misc/keystore/omk"
    };
    ($leaf:literal) => {
        concat!("/data/misc/keystore/omk/", $leaf)
    };
}
