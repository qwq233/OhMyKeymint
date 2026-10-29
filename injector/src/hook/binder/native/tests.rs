use super::*;

#[test]
fn native_request_offsets_admit_base_transactions_only() {
    assert_eq!(native_request_offsets(1, 0), Some([].as_slice()));
    assert_eq!(native_request_offsets(rsbinder::SHELL_COMMAND_TRANSACTION, 3), Some([].as_slice()));
    assert_eq!(
        native_request_offsets(rsbinder::DUMP_TRANSACTION, 1),
        Some(DUMP_OBJECT_OFFSETS.as_slice())
    );
    assert!(native_request_offsets(1, 1).is_none());
    assert!(native_request_offsets(rsbinder::DUMP_TRANSACTION, 2).is_none());
}

#[test]
fn legacy_aparcel_matches_android_12_13_aarch64_layout() {
    assert_eq!(size_of::<usize>(), 8);
    assert_eq!(std::mem::offset_of!(LegacyAParcel, binder), 0);
    assert_eq!(std::mem::offset_of!(LegacyAParcel, parcel), 8);
    assert_eq!(std::mem::offset_of!(LegacyAParcel, owns_parcel), 16);
    assert_eq!(size_of::<LegacyAParcel>(), 24);
}
