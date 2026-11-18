/// Unwrap a standard-library Mutex result, preserving poisoning failures.
#[macro_export]
macro_rules! panic_if_poisoned {
    ($poisonable:expr) => {
        $poisonable.unwrap()
    };
}
