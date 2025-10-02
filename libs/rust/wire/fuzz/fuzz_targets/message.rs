// Copyright 2022, The Android Open Source Project
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

//! Fuzzer for request message parsing.

#![no_main]
use kmr_wire::AsCborValue;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // `data` allegedly holds a CBOR-serialized request message that has arrived from the HAL
    // service in userspace.  Do we trust it? I don't think so...
    let _ = kmr_wire::PerformOpReq::from_slice(data);
});
