#![no_main]

use engytita_core::{Identity, Pairing};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let mut entropy = [0u8; 64];
    let n = data.len().min(64);
    entropy[..n].copy_from_slice(&data[..n]);
    let identity = Identity::from_entropy64(entropy);
    let eph = {
        let mut e = [0x42u8; 32];
        let m = data.len().min(32);
        e[..m].copy_from_slice(&data[..m]);
        e
    };
    let Ok((mut pairing, _)) = Pairing::responder(&identity, &eph) else {
        return;
    };
    // Chunk the remainder into successive read attempts (untrusted on-wire bytes).
    let mut offset = 0usize;
    while offset < data.len() {
        let end = (offset + 1 + (data[offset] as usize)).min(data.len());
        let _ = pairing.read(&data[offset..end]);
        offset = end;
    }
});
