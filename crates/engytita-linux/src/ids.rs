//! Shared GATT / service UUIDs — keep in lockstep with `ios/Demo` (`BleStack.swift`).

use uuid::Uuid;

/// Provisional Engytita 16-bit service `0xE671` in Bluetooth base UUID form.
pub fn service_uuid() -> Uuid {
    Uuid::parse_str("0000E671-0000-1000-8000-00805F9B34FB").expect("static uuid")
}

pub fn eid_uuid() -> Uuid {
    Uuid::parse_str("0000E672-0000-1000-8000-00805F9B34FB").expect("static uuid")
}

/// Central → peripheral pairing ciphertext.
pub fn pairing_write_uuid() -> Uuid {
    Uuid::parse_str("0000E673-0000-1000-8000-00805F9B34FB").expect("static uuid")
}

/// Peripheral → central pairing ciphertext (notify).
pub fn pairing_notify_uuid() -> Uuid {
    Uuid::parse_str("0000E674-0000-1000-8000-00805F9B34FB").expect("static uuid")
}
