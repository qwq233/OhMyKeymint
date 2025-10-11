//! Fuzzer for parsing ASN.1 key descriptions.
#![no_main]

use der::Decode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _result = kmr_ta::keys::SecureKeyWrapper::from_der(data);
});
