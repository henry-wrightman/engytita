//! Unit and property tests for BLE advertisement encode/decode.

use proptest::prelude::*;

use crate::{
    decode_advertising_data, decode_service_data_ad, encode_advertising_data,
    encode_service_data_ad, fits_legacy_advertising_pdu, BleError, AD_TYPE_FLAGS,
    AD_TYPE_SERVICE_DATA_16, ENCODED_ADV_LEN, FLAGS_AD_LEN, LEGACY_ADV_DATA_MAX, SERVICE_UUID_16,
};

#[test]
fn protocol_version_matches_core() {
    assert_eq!(
        crate::ble_protocol_version(),
        engytita_core::PROTOCOL_VERSION
    );
}

#[test]
fn encoded_size_fits_legacy_pdu_with_room() {
    let eid = [0u8; 8];
    let adv = encode_advertising_data(&eid);
    assert_eq!(adv.len(), ENCODED_ADV_LEN);
    assert!(fits_legacy_advertising_pdu(&adv));
    // Compile-time budget is asserted in lib.rs; check remaining headroom here.
    assert_eq!(LEGACY_ADV_DATA_MAX - ENCODED_ADV_LEN, 16);
}

#[test]
fn encode_service_data_layout() {
    let eid = [1, 2, 3, 4, 5, 6, 7, 8];
    let ad = encode_service_data_ad(&eid);
    assert_eq!(ad[0], 11);
    assert_eq!(ad[1], AD_TYPE_SERVICE_DATA_16);
    assert_eq!(u16::from_le_bytes([ad[2], ad[3]]), SERVICE_UUID_16);
    assert_eq!(&ad[4..12], &eid);
}

#[test]
fn encode_advertising_data_layout() {
    let eid = [9, 8, 7, 6, 5, 4, 3, 2];
    let adv = encode_advertising_data(&eid);
    assert_eq!(adv[0], 2);
    assert_eq!(adv[1], AD_TYPE_FLAGS);
    assert_eq!(&adv[FLAGS_AD_LEN..], &encode_service_data_ad(&eid));
}

#[test]
fn round_trip_service_data() {
    let eid = [0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44];
    let enc = encode_service_data_ad(&eid);
    assert_eq!(decode_service_data_ad(&enc).unwrap(), eid);
}

#[test]
fn round_trip_advertising_data() {
    let eid = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
    let enc = encode_advertising_data(&eid);
    assert_eq!(decode_advertising_data(&enc).unwrap(), eid);
}

#[test]
fn decode_finds_eid_among_other_ad_structures() {
    let eid = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33];
    let mut buf = Vec::new();
    // Name AD: "x"
    buf.extend_from_slice(&[2, 0x09, b'x']);
    buf.extend_from_slice(&encode_service_data_ad(&eid));
    assert!(buf.len() <= LEGACY_ADV_DATA_MAX);
    assert_eq!(decode_advertising_data(&buf).unwrap(), eid);
}

#[test]
fn malformed_service_data_rejected_without_panic() {
    assert_eq!(decode_service_data_ad(&[]), Err(BleError::Truncated));
    assert_eq!(decode_service_data_ad(&[1, 2, 3]), Err(BleError::Truncated));
    let mut bad = encode_service_data_ad(&[0; 8]);
    bad[0] = 5; // wrong length
    assert_eq!(decode_service_data_ad(&bad), Err(BleError::BadLength));
    bad = encode_service_data_ad(&[0; 8]);
    bad[1] = 0x09; // wrong type
    assert_eq!(decode_service_data_ad(&bad), Err(BleError::BadType));
    bad = encode_service_data_ad(&[0; 8]);
    bad[2] ^= 0xff; // wrong uuid
    assert_eq!(decode_service_data_ad(&bad), Err(BleError::WrongUuid));
}

#[test]
fn malformed_advertising_data_rejected_without_panic() {
    assert_eq!(decode_advertising_data(&[]), Err(BleError::NotFound));
    assert_eq!(
        decode_advertising_data(&[0u8; LEGACY_ADV_DATA_MAX + 1]),
        Err(BleError::TooLong)
    );
    // Truncated AD structure
    assert_eq!(
        decode_advertising_data(&[5, 0x16, 0x71]),
        Err(BleError::Truncated)
    );
    // Zero length
    assert_eq!(decode_advertising_data(&[0]), Err(BleError::BadLength));
    // Valid flags only — no service data
    assert_eq!(
        decode_advertising_data(&[2, AD_TYPE_FLAGS, 0x06]),
        Err(BleError::NotFound)
    );
}

proptest! {
    #[test]
    fn prop_service_data_round_trip(eid in any::<[u8; 8]>()) {
        let enc = encode_service_data_ad(&eid);
        prop_assert!(fits_legacy_advertising_pdu(&enc));
        prop_assert_eq!(decode_service_data_ad(&enc).unwrap(), eid);
    }

    #[test]
    fn prop_advertising_data_round_trip(eid in any::<[u8; 8]>()) {
        let enc = encode_advertising_data(&eid);
        prop_assert_eq!(enc.len(), ENCODED_ADV_LEN);
        prop_assert!(fits_legacy_advertising_pdu(&enc));
        prop_assert_eq!(decode_advertising_data(&enc).unwrap(), eid);
    }

    #[test]
    fn prop_garbage_service_data_no_panic(data in prop::collection::vec(any::<u8>(), 0..64)) {
        let _ = decode_service_data_ad(&data);
    }

    #[test]
    fn prop_garbage_advertising_data_no_panic(data in prop::collection::vec(any::<u8>(), 0..64)) {
        let _ = decode_advertising_data(&data);
    }
}
