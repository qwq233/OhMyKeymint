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

use super::*;
use crate::{
    binder,
    hal::keymint::{ErrorCode::ErrorCode, IKeyMintDevice::IKeyMintDevice},
    keymint::MAX_CBOR_OVERHEAD,
};
use kmr_wire::{
    keymint::{
        HardwareAuthToken, HardwareAuthenticatorType, NEXT_MESSAGE_SIGNAL_FALSE,
        NEXT_MESSAGE_SIGNAL_TRUE,
    },
    secureclock::{TimeStampToken, Timestamp},
    FinishRequest, PerformOpReq,
};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
struct TestChannel {
    req: Arc<Mutex<Vec<u8>>>,
    rsp: Vec<u8>,
}

impl TestChannel {
    fn new(rsp: &str) -> Self {
        Self { req: Arc::new(Mutex::new(vec![])), rsp: hex::decode(rsp).unwrap() }
    }
    fn req_data(&self) -> Vec<u8> {
        self.req.lock().unwrap().clone()
    }
}

impl SerializedChannel for TestChannel {
    const MAX_SIZE: usize = 4096;
    fn execute(&mut self, serialized_req: &[u8]) -> binder::Result<Vec<u8>> {
        *self.req.lock().unwrap() = serialized_req.to_vec();
        Ok(self.rsp.clone())
    }
}

#[test]
fn test_method_roundtrip() {
    let channel = TestChannel::new(concat!(
        "82", // 2-arr (PerformOpResponse)
        "00", // int   (PerformOpResponse.error_code == ErrorCode::Ok)
        "81", // 1-arr (PerformOpResponse.rsp)
        "82", // 2-arr (PerformOpResponse.rsp.0 : PerformOpRsp)
        "13", // 0x13 = KeyMintOperation::DEVICE_GENERATE_KEY
        "81", // 1-arr (GenerateKeyResponse)
        "83", // 3-arr (ret: KeyCreationResult)
        "41", "01", // 1-bstr (KeyCreationResult.keyBlob)
        "80", // 0-arr (KeyCreationResult.keyCharacteristics)
        "80", // 0-arr (KeyCreationResult.certificateChain)
    ));
    let imp = keymint::Device::new(Arc::new(Mutex::new(channel.clone())));

    let result = imp.generateKey(&[], None).unwrap();

    let want_req = concat!(
        "82", // 2-arr (PerformOpReq)
        "13", // 0x13 = DEVICE_GENERATE_KEY
        "82", // 1-arr (GenerateKeyRequest)
        "80", // 0-arr (* KeyParameter)
        "80", // 0-arr (? AttestationKey)
    );
    assert_eq!(channel.req_data(), hex::decode(want_req).unwrap());

    assert_eq!(result.keyBlob, vec![0x01]);
    assert!(result.keyCharacteristics.is_empty());
    assert!(result.certificateChain.is_empty());
}

#[test]
fn test_method_err_roundtrip() {
    let channel = TestChannel::new(concat!(
        "82", // 2-arr (PerformOpResponse)
        "21", // (PerformOpResponse.error_code = ErrorCode::UNSUPPORTED_PURPOSE)
        "80", // 0-arr (PerformOpResponse.rsp)
    ));
    let imp = keymint::Device::new(Arc::new(Mutex::new(channel.clone())));

    let result = imp.generateKey(&[], None);

    let want_req = concat!(
        "82", // 2-arr (PerformOpReq)
        "13", // 0x13 = DEVICE_GENERATE_KEY
        "82", // 1-arr (GenerateKeyRequest)
        "80", // 0-arr (* KeyParameter)
        "80", // 0-arr (? AttestationKey)
    );
    assert_eq!(channel.req_data(), hex::decode(want_req).unwrap());

    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.exception_code(), binder::ExceptionCode::SERVICE_SPECIFIC);
    assert_eq!(status.service_specific_error(), ErrorCode::UNSUPPORTED_PURPOSE.0);
}

#[test]
fn test_overhead_size() {
    let largest_op_req = PerformOpReq::OperationFinish(FinishRequest {
        op_handle: 0x7fffffff,
        input: Some(Vec::new()),
        signature: Some(vec![0; 132]),
        auth_token: Some(HardwareAuthToken {
            challenge: 0x7fffffff,
            user_id: 0x7fffffff,
            authenticator_id: 0x7fffffff,
            authenticator_type: HardwareAuthenticatorType::Password,
            timestamp: Timestamp { milliseconds: 0x7fffffff },
            mac: vec![0; 32],
        }),
        timestamp_token: Some(TimeStampToken {
            challenge: 0x7fffffff,
            timestamp: Timestamp { milliseconds: 0x7fffffff },
            mac: vec![0; 32],
        }),
        confirmation_token: Some(vec![0; 32]),
    });
    let data = largest_op_req.into_vec().unwrap();
    assert!(
        data.len() < MAX_CBOR_OVERHEAD,
        "expect largest serialized empty message (size {}) to be smaller than {}",
        data.len(),
        MAX_CBOR_OVERHEAD
    );
}

#[test]
fn test_extract_rsp_true_marker() {
    let msg_content = vec![0x82, 0x21, 0x80];
    // test true marker and message content
    let mut resp = vec![NEXT_MESSAGE_SIGNAL_TRUE];
    resp.extend_from_slice(&msg_content);
    assert_eq!(Ok((true, msg_content.as_slice())), extract_rsp(&resp));
}

#[test]
fn test_extract_rsp_false_marker() {
    let msg_content = vec![0x82, 0x21, 0x80];
    // test false signal and message content
    let mut resp = vec![NEXT_MESSAGE_SIGNAL_FALSE];
    resp.extend_from_slice(&msg_content);
    assert_eq!(Ok((false, msg_content.as_slice())), extract_rsp(&resp));
}

#[test]
fn test_extract_rsp_empty_input() {
    // test invalid (empty) input
    let resp3 = vec![];
    let result = extract_rsp(&resp3);
    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.exception_code(), binder::ExceptionCode::ILLEGAL_ARGUMENT);
}

#[test]
fn test_extract_rsp_single_byte_input() {
    // test invalid (single byte) input
    let resp4 = vec![NEXT_MESSAGE_SIGNAL_FALSE];
    let result = extract_rsp(&resp4);
    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.exception_code(), binder::ExceptionCode::ILLEGAL_ARGUMENT);
}
