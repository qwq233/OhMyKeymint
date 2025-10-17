use std::cmp::Ordering;

use der::{
    asn1::{OctetString, SetOfVec},
    DerOrd, Encode, Sequence,
};

#[derive(Sequence, Debug)]
pub struct ApexModuleInfo {
    pub package_name: OctetString,
    pub version_code: u64,
}

impl DerOrd for ApexModuleInfo {
    // DER mandates "encodings of the component values of a set-of value shall appear in ascending
    // order". `der_cmp` serves as a proxy for determining that ordering (though why the `der` crate
    // requires this is unclear). Essentially, we just need to compare the `name` lengths, and then
    // if those are equal, the `name`s themselves. (No need to consider `version`s since there can't
    // be more than one `ModuleInfo` with the same `name` in the set-of `ModuleInfo`s.) We rely on
    // `OctetString`'s `der_cmp` to do the aforementioned comparison.
    fn der_cmp(&self, other: &Self) -> std::result::Result<Ordering, der::Error> {
        self.package_name.der_cmp(&other.package_name)
    }
}

pub fn encode_module_info(module_info: Vec<ApexModuleInfo>) -> Result<Vec<u8>, der::Error> {
    SetOfVec::<ApexModuleInfo>::from_iter(module_info.into_iter())?.to_der()
}
