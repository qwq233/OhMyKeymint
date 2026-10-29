use super::*;

#[test]
fn request_interface_peek_uses_header_token_only() {
    let mut request = Parcel::new();
    request.write(&0i32).unwrap();
    request.write(&0i32).unwrap();
    request.write(&rsbinder::INTERFACE_HEADER).unwrap();
    request.write(&KEYSTORE_SERVICE_INTERFACE.to_string()).unwrap();
    request.write(&KEYSTORE_AUTHORIZATION_INTERFACE.to_string()).unwrap();

    let mut data = Vec::new();
    let mut cursor = 0;
    request.set_data_position(0);
    while cursor < request.data_size() {
        let chunk: [u8; 4] = (&mut request).try_into().unwrap();
        data.extend_from_slice(&chunk);
        cursor += 4;
    }
    data.truncate(request.data_size());
    let data = data.as_mut_ptr();
    let data_size = request.data_size();
    let bytes = unsafe { std::slice::from_raw_parts(data, data_size) };
    assert!(contains_utf16_token(bytes, KEYSTORE_AUTHORIZATION_INTERFACE));
    let interface = unsafe { peek_request_interface(data, data_size, std::ptr::null_mut(), 0) }
        .expect("request interface should parse");
    assert_eq!(interface, KEYSTORE_SERVICE_INTERFACE);
}
