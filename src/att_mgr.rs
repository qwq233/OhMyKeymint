use kmr_common::km_err;
use kmr_ta::device::RetrieveAttestationIds;
use kmr_wire::AttestationIdInfo;

use crate::config::CONFIG;

pub struct AttestationIdMgr;

impl RetrieveAttestationIds for AttestationIdMgr {
    fn get(&self) -> Result<AttestationIdInfo, kmr_common::Error> {
        let info = {
            let config = CONFIG
                .read()
                .map_err(|_| km_err!(UnknownError, "config lock poisoned"))?;
            AttestationIdInfo {
                brand: config.device.brand.clone().into_bytes(),
                device: config.device.device.clone().into_bytes(),
                product: config.device.product.clone().into_bytes(),
                serial: config.device.serial.clone().into_bytes(),
                imei: config.device.imei.clone().into_bytes(),
                imei2: config.device.imei2.clone().into_bytes(),
                meid: config.device.meid.clone().into_bytes(),
                manufacturer: config.device.manufacturer.clone().into_bytes(),
                model: config.device.model.clone().into_bytes(),
            }
        };

        Ok(info)
    }

    fn destroy_all(&mut self) -> Result<(), kmr_common::Error> {
        // ignore this
        Ok(())
    }
}
