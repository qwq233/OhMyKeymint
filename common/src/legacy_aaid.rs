use anyhow::Context;
use binder::binder_impl::{
    BorrowedParcel, DeserializeArray, IBinderInternal, Parcel, TransactionCode,
    UnstructuredParcelable, FLAG_CLEAR_BUF,
};
use binder::{SpIBinder, Status, StatusCode};

pub const AAID_MAX_VECTOR_LEN: i32 = 1024;
pub const PROVIDER_SERVICE: &str = "sec_key_att_app_id_provider";
pub const LEGACY_PROVIDER_DESCRIPTOR: &str =
    "android.security.keymaster.IKeyAttestationApplicationIdProvider";

pub fn should_use_aaid_provider() -> bool {
    should_use_legacy_aaid_provider(crate::android_version::android_major_version())
}

fn should_use_legacy_aaid_provider(android_major_version: Option<i32>) -> bool {
    matches!(android_major_version, Some(version) if version <= 14)
}

pub fn request_application_id(
    binder: &SpIBinder,
    code: TransactionCode,
    uid: u32,
) -> anyhow::Result<Parcel> {
    let mut data = binder
        .prepare_transact()
        .context("failed to prepare legacy getKeyAttestationApplicationId transaction")?;
    data.write(&(uid as i32))
        .context("failed to write legacy getKeyAttestationApplicationId uid")?;
    let reply = binder
        .submit_transact(code, data, FLAG_CLEAR_BUF)
        .context("legacy getKeyAttestationApplicationId transact failed")?;
    // SAFETY: Zero is within every valid Parcel.
    unsafe { reply.set_data_position(0)? };
    let status: Status =
        reply.read().context("failed to decode legacy getKeyAttestationApplicationId status")?;
    if !status.is_ok() {
        return Err(anyhow::Error::new(status));
    }
    Ok(reply)
}

// Android 13/14 Java parcelables have no structured-AIDL size prefix.
pub struct LegacyApplicationId {
    pub packages: Option<Vec<Option<LegacyPackageInfo>>>,
}

pub struct LegacyPackageInfo {
    pub name: Option<String>,
    pub version: i64,
    pub signatures: Option<Vec<Option<LegacySignature>>>,
}

pub struct LegacySignature(pub Vec<u8>);

impl UnstructuredParcelable for LegacyApplicationId {
    fn write_to_parcel(&self, parcel: &mut BorrowedParcel<'_>) -> Result<(), StatusCode> {
        parcel.write(&self.packages)
    }

    fn from_parcel(parcel: &BorrowedParcel<'_>) -> Result<Self, StatusCode> {
        Ok(Self { packages: read_typed_array(parcel)? })
    }
}

impl UnstructuredParcelable for LegacyPackageInfo {
    fn write_to_parcel(&self, parcel: &mut BorrowedParcel<'_>) -> Result<(), StatusCode> {
        parcel.write(&self.name)?;
        parcel.write(&self.version)?;
        parcel.write(&self.signatures)
    }

    fn from_parcel(parcel: &BorrowedParcel<'_>) -> Result<Self, StatusCode> {
        Ok(Self {
            name: parcel.read()?,
            version: parcel.read()?,
            signatures: read_typed_array(parcel)?,
        })
    }
}

impl UnstructuredParcelable for LegacySignature {
    fn write_to_parcel(&self, parcel: &mut BorrowedParcel<'_>) -> Result<(), StatusCode> {
        parcel.write(&self.0)
    }

    fn from_parcel(parcel: &BorrowedParcel<'_>) -> Result<Self, StatusCode> {
        parcel.read().map(Self)
    }
}

binder::impl_serialize_for_unstructured_parcelable!(LegacyApplicationId);
binder::impl_deserialize_for_unstructured_parcelable!(LegacyApplicationId);
binder::impl_serialize_for_unstructured_parcelable!(LegacyPackageInfo);
binder::impl_deserialize_for_unstructured_parcelable!(LegacyPackageInfo);
binder::impl_serialize_for_unstructured_parcelable!(LegacySignature);
binder::impl_deserialize_for_unstructured_parcelable!(LegacySignature);

fn read_typed_array<T: DeserializeArray>(
    parcel: &BorrowedParcel<'_>,
) -> Result<Option<Vec<T>>, StatusCode> {
    let position = parcel.get_data_position();
    let length: i32 = parcel.read()?;
    if !(-1..=AAID_MAX_VECTOR_LEN).contains(&length) {
        return Err(StatusCode::BAD_VALUE);
    }
    // SAFETY: Reading the length did not resize the Parcel, so its saved position is valid.
    unsafe {
        parcel.set_data_position(position)?;
    }
    parcel.read()
}
