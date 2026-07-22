use std::sync::Mutex;

use kmr_common::km_err;
use kmr_ta::device::RetrieveAttestationIds;
use kmr_wire::AttestationIdInfo;

use crate::config::config;

pub struct AttestationIdMgr;

static ATTESTATION_IDS: Mutex<Option<AttestationIdInfo>> = Mutex::new(None);

impl RetrieveAttestationIds for AttestationIdMgr {
    fn get(&self) -> Result<AttestationIdInfo, kmr_common::Error> {
        self.get_ids()?
            .ok_or_else(|| km_err!(CannotAttestIds, "attestation ID info not available"))
    }

    fn get_ids(&self) -> Result<Option<AttestationIdInfo>, kmr_common::Error> {
        let mut cached = ATTESTATION_IDS
            .lock()
            .map_err(|_| km_err!(UnknownError, "attestation ID cache lock poisoned"))?;
        if let Some(ids) = cached.as_ref() {
            return Ok(Some(ids.clone()));
        }

        let needs_resolution = |device: &crate::config::DeviceProperty| {
            !device.override_telephony_properties
                && (device.imei.trim().is_empty()
                    || device.imei2.trim().is_empty()
                    || device.meid.trim().is_empty())
        };
        let guard = config()
            .read()
            .map_err(|_| km_err!(UnknownError, "config lock poisoned"))?;
        let device = if needs_resolution(&guard.device) {
            drop(guard);
            match crate::plat::device_ids::resolve_runtime_device_ids() {
                Ok(Some(device)) => device,
                Ok(None) => return Ok(None),
                Err(error) => {
                    log::warn!("failed to resolve runtime attestation IDs: {error:#}");
                    return Ok(None);
                }
            }
        } else {
            guard.device.clone()
        };

        let ids = AttestationIdInfo {
            brand: device.brand.into_bytes(),
            device: device.device.into_bytes(),
            product: device.product.into_bytes(),
            serial: device.serial.into_bytes(),
            imei: device.imei.into_bytes(),
            imei2: device.imei2.into_bytes(),
            meid: device.meid.into_bytes(),
            manufacturer: device.manufacturer.into_bytes(),
            model: device.model.into_bytes(),
        };
        *cached = Some(ids.clone());
        Ok(Some(ids))
    }

    fn destroy_all(&mut self) -> Result<(), kmr_common::Error> {
        // ignore this
        Ok(())
    }
}
