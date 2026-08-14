#![no_main]

use engytita_ble::{decode_advertising_data, decode_service_data_ad};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode_advertising_data(data);
    let _ = decode_service_data_ad(data);
});
