use der::asn1::{OctetString, SetOfVec};

#[derive(der::Sequence, Debug)]
pub struct AttestationApplicationId {
    pub package_info_records: SetOfVec<PackageInfoRecord>,
    pub signature_digests: SetOfVec<OctetString>,
}

#[derive(der::Sequence, der::ValueOrd, Debug)]
pub struct PackageInfoRecord {
    pub package_name: OctetString,
    pub version: i64,
}
