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

//! Utility program to parse a legacy encrypted keyblob (but not decrypt it).

use kmr_common::keyblob::legacy::EncryptedKeyBlob;

fn main() {
    let mut hex = false;
    let args: Vec<String> = std::env::args().collect();
    for arg in &args[1..] {
        if arg == "--hex" {
            hex = !hex;
        } else {
            process(arg, hex);
        }
    }
}

fn process(filename: &str, hex: bool) {
    let _ = env_logger::builder().is_test(true).try_init();

    println!("File: {}", filename);
    let mut data: Vec<u8> = std::fs::read(filename).unwrap();
    if hex {
        let hexdata = std::str::from_utf8(&data).unwrap().trim();
        data = match hex::decode(hexdata) {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "{}: Failed to parse hex ({:?}): len={} {}",
                    filename,
                    e,
                    hexdata.len(),
                    hexdata
                );
                return;
            }
        };
    }
    let keyblob = match EncryptedKeyBlob::deserialize(&data) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("{}: Failed to parse: {:?}", filename, e);
            return;
        }
    };
    println!(
        "{}, KeyBlob  {{\n  format={:?}\n  nonce={},\n  ciphertext=...(len {}),\n  tag={},",
        filename,
        keyblob.format,
        hex::encode(&keyblob.nonce),
        keyblob.ciphertext.len(),
        hex::encode(&keyblob.tag)
    );
    if let Some(kdf_version) = keyblob.kdf_version {
        println!("  kdf_version={}", kdf_version);
    }
    if let Some(addl_info) = keyblob.addl_info {
        println!("  addl_info={}", addl_info);
    }
    println!("  hw_enforced={:?},\n  sw_enforced={:?},", keyblob.hw_enforced, keyblob.sw_enforced);
    if let Some(key_slot) = keyblob.key_slot {
        println!("  key_slot={}", key_slot);
    }
    println!("}}");

    // Also round-trip the keyblob to binary.
    let regenerated_data = keyblob.serialize().unwrap();
    assert_eq!(regenerated_data, data);
}
