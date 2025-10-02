use std::fmt::Debug;

use kmr_common::crypto::{self, des::Key, MonotonicClock};
use kmr_crypto_boring::{
    aes::BoringAes, aes_cmac::BoringAesCmac, des::BoringDes, ec::BoringEc, eq::BoringEq, hmac::BoringHmac, rng::BoringRng, rsa::BoringRsa, sha256::BoringSha256
};
use kmr_ta::{device::{CsrSigningAlgorithm, Implementation}, HardwareInfo, KeyMintTa, RpcInfo, RpcInfoV3};
use kmr_wire::{cbor::de, keymint::{AttestationKey, DateTime, KeyCharacteristics, KeyParam, KeyPurpose, SecurityLevel}, rpc::MINIMUM_SUPPORTED_KEYS_IN_CSR, sharedsecret::SharedSecretParameters, GenerateKeyRequest, GetHardwareInfoRequest, GetRootOfTrustRequest, GetSharedSecretParametersRequest, KeySizeInBits, PerformOpReq};
use log::{debug, error};
use kmr_wire::AsCborValue;

pub mod macros;
pub mod attest;
pub mod sdd;
pub mod clock;
pub mod proto;
pub mod soft;
pub mod rpc;
pub mod logging;

#[cfg(target_os = "android")]
const TAG: &str = "OhMyKeymint";

fn main(){
    debug!("Hello, OhMyKeymint!");
    logging::init_logger();
    #[cfg(target_os = "android")] logi!(TAG, "Application started");
    let security_level = SecurityLevel::TrustedEnvironment;
    let hw_info = HardwareInfo {
        version_number: 2,
        security_level,
        impl_name: "Qualcomm QTEE KeyMint 2",
        author_name: "Qualcomm Technologies",
        unique_id: "Qualcomm QTEE KeyMint 2",
    };

    let rpc_sign_algo = CsrSigningAlgorithm::EdDSA;
    let rpc_info_v3 = RpcInfoV3 {
        author_name: "Qualcomm Technologies",
        unique_id: "Qualcomm QTEE KeyMint 2",
        fused: false,
        supported_num_of_keys_in_csr: MINIMUM_SUPPORTED_KEYS_IN_CSR,
    };

    let mut rng = BoringRng;
    let sdd_mgr: Option<Box<dyn kmr_common::keyblob::SecureDeletionSecretManager>> =
        match sdd::HostSddManager::new(&mut rng) {
            Ok(v) => Some(Box::new(v)),
            Err(e) => {
                error!("Failed to initialize secure deletion data manager: {:?}", e);
                None
            }
        };
    let clock = clock::StdClock;
    let rsa = BoringRsa::default();
    let ec = BoringEc::default();
    let hkdf: Box<dyn kmr_common::crypto::Hkdf> = Box::new(BoringHmac);
    let imp = crypto::Implementation {
        rng: Box::new(rng),
        clock: Some(Box::new(clock)),
        compare: Box::new(BoringEq),
        aes: Box::new(BoringAes),
        des: Box::new(BoringDes),
        hmac: Box::new(BoringHmac),
        rsa: Box::new(rsa),
        ec: Box::new(ec),
        ckdf: Box::new(BoringAesCmac),
        hkdf,
        sha256: Box::new(BoringSha256),
    };

    let keys: Box<dyn kmr_ta::device::RetrieveKeyMaterial> = Box::new(soft::Keys);
    let rpc: Box<dyn kmr_ta::device::RetrieveRpcArtifacts> = Box::new(soft::RpcArtifacts::new(soft::Derive::default(), rpc_sign_algo));

    let dev = Implementation {
        keys,
        // Cuttlefish has `remote_provisioning.tee.rkp_only=1` so don't support batch signing
        // of keys.  This can be reinstated with:
        // ```
        // sign_info: Some(kmr_ta_nonsecure::attest::CertSignInfo::new()),
        // ```
        sign_info: Some(Box::new(attest::CertSignInfo::new())),
        // HAL populates attestation IDs from properties.
        attest_ids: None,
        sdd_mgr,
        // `BOOTLOADER_ONLY` keys not supported.
        bootloader: Box::new(kmr_ta::device::BootloaderDone),
        // `STORAGE_KEY` keys not supported.
        sk_wrapper: None,
        // `TRUSTED_USER_PRESENCE_REQUIRED` keys not supported
        tup: Box::new(kmr_ta::device::TrustedPresenceUnsupported),
        // No support for converting previous implementation's keyblobs.
        legacy_key: None,
        rpc,
    };

    let mut ta = KeyMintTa::new(hw_info, RpcInfo::V3(rpc_info_v3), imp, dev);

    let req =  PerformOpReq::DeviceGetHardwareInfo(GetHardwareInfoRequest{});
    let resp = ta.process_req(req);
    debug!("GetHardwareInfo response: {:?}", resp);

    let req = PerformOpReq::SetBootInfo(kmr_wire::SetBootInfoRequest {
            verified_boot_state: 0, // Verified
            verified_boot_hash: vec![0; 32],
            verified_boot_key: vec![0; 32],
            device_boot_locked: true,
            boot_patchlevel: 20250605,
    });
    let resp = ta.process_req(req);
    debug!("SetBootInfo response: {:?}", resp);

    let req = PerformOpReq::SetHalInfo(kmr_wire::SetHalInfoRequest {
        os_version: 35,
        os_patchlevel: 202506,
        vendor_patchlevel: 202506,
    });
    let resp = ta.process_req(req);
    debug!("SetHalInfo response: {:?}", resp);

    let req = PerformOpReq::SetHalVersion(kmr_wire::SetHalVersionRequest {
        aidl_version: 400,
    });
    let resp = ta.process_req(req);
    debug!("SetHalVersion response: {:?}", resp);

    let req = PerformOpReq::SetAttestationIds(kmr_wire::SetAttestationIdsRequest {
        ids: kmr_wire::AttestationIdInfo {
            brand: "generic".into(),
            device: "generic".into(),
            product: "generic".into(),
            serial: "0123456789ABCDEF".into(),
            manufacturer: "Generic".into(),
            model: "GenericModel".into(),
            imei: "350505563694821".into(),
            imei2: "350505563694822".into(),
            meid: "350505563694823".into(),
        }
    });
    let resp = ta.process_req(req);
    debug!("SetAttestationIds response: {:?}", resp);

    let req = PerformOpReq::DeviceEarlyBootEnded(kmr_wire::EarlyBootEndedRequest{});
    let resp = ta.process_req(req);
    debug!("DeviceEarlyBootEnded response: {:?}", resp);

    let clock = clock::StdClock;
    let current_time = clock.now().0;
    let keyblob = kmr_common::keyblob::EncryptedKeyBlobV1 {
        characteristics: vec![KeyCharacteristics {
            security_level: SecurityLevel::TrustedEnvironment,
            authorizations: vec![
                KeyParam::ApplicationId("com.example.app".as_bytes().to_vec()),
                KeyParam::AttestationApplicationId("com.example.app".as_bytes().to_vec()),
                KeyParam::Purpose(KeyPurpose::AttestKey),
                KeyParam::KeySize(KeySizeInBits(256)),
                KeyParam::Algorithm(kmr_wire::keymint::Algorithm::Ec),
                KeyParam::EcCurve(kmr_wire::keymint::EcCurve::P256),
                KeyParam::Digest(kmr_wire::keymint::Digest::Sha256),
                KeyParam::NoAuthRequired,
                KeyParam::CertificateNotBefore(DateTime{ms_since_epoch: clock.now().0 - 10000}), // -10 seconds
                KeyParam::CertificateNotAfter(DateTime{ms_since_epoch: clock.now().0 + 31536000000}), // +1 year
                KeyParam::CertificateSerial(b"1234567890".to_vec()),
                KeyParam::CertificateSubject(b"CN=Android Keystore Key".to_vec()),
                KeyParam::AttestationChallenge(b"Test Attestation Challenge".to_vec()),

            ],
        }],
        key_derivation_input: [0u8; 32],
        kek_context: vec![0; 32],
        encrypted_key_material: kmr_wire::coset::CoseEncrypt0::default(),
        secure_deletion_slot: None,
    };

    let req = PerformOpReq::DeviceGenerateKey(GenerateKeyRequest{
        key_params: vec![
                KeyParam::ApplicationId("com.example.app".as_bytes().to_vec()),
                KeyParam::AttestationApplicationId("com.example.app".as_bytes().to_vec()),
                KeyParam::Purpose(KeyPurpose::AttestKey),
                KeyParam::KeySize(KeySizeInBits(256)),
                KeyParam::Algorithm(kmr_wire::keymint::Algorithm::Ec),
                KeyParam::EcCurve(kmr_wire::keymint::EcCurve::P256),
                KeyParam::Digest(kmr_wire::keymint::Digest::Sha256),
                KeyParam::NoAuthRequired,
                KeyParam::CertificateNotBefore(DateTime{ms_since_epoch: current_time - 10000}), // -10 seconds
                KeyParam::CertificateNotAfter(DateTime{ms_since_epoch: current_time + 31536000000}), // +1 year
                KeyParam::CertificateSerial(b"1234567890".to_vec()),
                KeyParam::CertificateSubject(kmr_wire::keymint::DEFAULT_CERT_SUBJECT.to_vec()),
                KeyParam::AttestationChallenge(b"Test Attestation Challenge".to_vec()),

            ],
        attestation_key: None,
    });
    let resp = ta.process_req(req);
    match &resp.rsp {
        Some(rsp) => {
            if let kmr_wire::PerformOpRsp::DeviceGenerateKey(ref key_rsp) = rsp {
                std::fs::create_dir_all("./omk/output").unwrap();
                std::fs::write("./omk/output/cert.der", key_rsp.ret.certificate_chain[0].encoded_certificate.clone()).unwrap();
            } else {
                error!("Unexpected response: {:?}", resp);
            }
        },
        None => {
            error!("No response received");
        }
    }

}