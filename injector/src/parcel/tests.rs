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

#[test]
fn interface_tokens_preserve_utf16_identity_and_argument_cursor() {
    for token in crate::identify::KNOWN_KEYSTORE_INTERFACES.into_iter().chain(["\u{4f60}\u{1f600}"])
    {
        let units: Vec<u16> = token.encode_utf16().collect();
        let mut parcel = Parcel::new();
        parcel.write(&token.to_string()).unwrap();
        parcel.write(&0x1234_5678i32).unwrap();
        parcel.set_data_position(0);
        assert_eq!(read_interface_token(&mut parcel).unwrap(), token);
        assert_eq!(parcel.read::<i32>().unwrap(), 0x1234_5678);

        for surrogate in [0xd800, 0xdc00] {
            for position in [0, units.len() / 2, units.len()] {
                let mut malformed = units.clone();
                malformed.insert(position, surrogate);
                let mut parcel = Parcel::new();
                parcel.write(&(malformed.len() as i32)).unwrap();
                malformed.push(0);
                if malformed.len() % 2 != 0 {
                    malformed.push(0);
                }
                for pair in malformed.as_chunks::<2>().0 {
                    parcel.write(&(u32::from(pair[0]) | (u32::from(pair[1]) << 16))).unwrap();
                }
                parcel.set_data_position(0);
                assert!(read_interface_token(&mut parcel).is_err(), "unpaired unit in {token}");
            }
        }
    }
}
