#[macro_export]
#[cfg(target_os = "android")]
macro_rules! logd {
    ($tag:expr, $msg:expr) => {
        android_logger_lite::d($tag.to_string(), $msg.to_string())
    };
}

#[macro_export]
#[cfg(target_os = "android")]
macro_rules! logi {
    ($tag:expr, $msg:expr) => {
        android_logger_lite::i($tag.to_string(), $msg.to_string())
    };
}

#[macro_export]
#[cfg(target_os = "android")]
macro_rules! logw {
    ($tag:expr, $msg:expr) => {
        android_logger_lite::w($tag.to_string(), $msg.to_string())
    };
}

#[macro_export]
#[cfg(target_os = "android")]
macro_rules! loge {
    ($tag:expr, $msg:expr) => {
        android_logger_lite::e($tag.to_string(), $msg.to_string())
    };
}
