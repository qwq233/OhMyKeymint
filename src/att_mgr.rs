use kmr_common::km_err;
use kmr_ta::device::RetrieveAttestationIds;
use kmr_wire::AttestationIdInfo;

use crate::config::config;

pub struct AttestationIdMgr;

impl RetrieveAttestationIds for AttestationIdMgr {
    fn get(&self) -> Result<AttestationIdInfo, kmr_common::Error> {
        let has_ids = |device: &crate::config::DeviceProperty| {
            device.override_telephony_properties
                || !device.imei.trim().is_empty()
                || !device.imei2.trim().is_empty()
                || !device.meid.trim().is_empty()
        };
        let mut guard = config()
            .read()
            .map_err(|_| km_err!(UnknownError, "config lock poisoned"))?;
        if !has_ids(&guard.device) {
            drop(guard);
            if let Err(error) = crate::plat::device_ids::resolve_runtime_device_ids() {
                log::warn!("failed to resolve attestation IDs from telephony: {error:#}");
            }
            guard = config()
                .read()
                .map_err(|_| km_err!(UnknownError, "config lock poisoned"))?;
        }

        if !has_ids(&guard.device) {
            return Err(km_err!(
                CannotAttestIds,
                "attestation ID info not available"
            ));
        }

        Ok(AttestationIdInfo {
            brand: guard.device.brand.clone().into_bytes(),
            device: guard.device.device.clone().into_bytes(),
            product: guard.device.product.clone().into_bytes(),
            serial: guard.device.serial.clone().into_bytes(),
            imei: guard.device.imei.clone().into_bytes(),
            imei2: guard.device.imei2.clone().into_bytes(),
            meid: guard.device.meid.clone().into_bytes(),
            manufacturer: guard.device.manufacturer.clone().into_bytes(),
            model: guard.device.model.clone().into_bytes(),
        })
    }

    fn destroy_all(&mut self) -> Result<(), kmr_common::Error> {
        // ignore this
        Ok(())
    }
}
