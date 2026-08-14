//! BLE advertisement **bytes** for Engytita EIDs.
//!
//! # Scope
//!
//! This crate **encodes and decodes only**. It never transmits, scans, opens a
//! HCI socket, or depends on a radio stack (`bluer`, `btleplug`, CoreBluetooth,
//! Android `BluetoothLeAdvertiser`, etc. are all out of scope).
//!
//! **Transmission is the platform layer's job.**
//!
//! # Tracking resistance (critical)
//!
//! BLE random private address (**MAC**) rotation **MUST** be aligned to EID
//! rotation (each Engytita epoch, or more frequently). If the MAC stays stable
//! across EID changes, the MAC becomes a stable tracking identifier and the
//! entire unlinkability construction is defeated — regardless of IRK secrecy.
//! See `spec/engytita-v1.md` §8.1.
//!
//! # On-air layout (legacy advertising data)
//!
//! Encoded advertising data is 15 octets and therefore fits the 31-octet
//! legacy Advertising Data field with room for Flags and a 16-bit Service
//! Data UUID:
//!
//! ```text
//! Flags AD (3):          len=02  type=01  flags=06
//! Service Data AD (12):  len=0B  type=16  uuid=71E6(le)  eid[8]
//! Total = 15 ≤ 31
//! ```

#![forbid(unsafe_code)]

use engytita_core::PROTOCOL_VERSION;

/// Bluetooth Core Spec maximum length of legacy Advertising Data / Scan Response Data.
pub const LEGACY_ADV_DATA_MAX: usize = 31;

/// AD Type: Flags.
pub const AD_TYPE_FLAGS: u8 = 0x01;

/// AD Type: Service Data — 16-bit UUID.
pub const AD_TYPE_SERVICE_DATA_16: u8 = 0x16;

/// Provisional 16-bit service UUID for Engytita v1 beacons (`0xE671` LE on the wire).
///
/// Assigned for this protocol's Service Data AD structure. Platforms that need
/// a SIG-assigned UUID MUST treat this as provisional until one is registered.
pub const SERVICE_UUID_16: u16 = 0xE671;

/// LE General Discoverable + BR/EDR Not Supported (common for BLE-only beacons).
pub const DEFAULT_FLAGS: u8 = 0x06;

/// Length of the Flags AD structure (`len || type || flags`).
pub const FLAGS_AD_LEN: usize = 3;

/// Length of the Service Data AD structure carrying an 8-byte EID
/// (`len || type || uuid_le[2] || eid[8]`).
pub const SERVICE_DATA_AD_LEN: usize = 12;

/// Length of the full advertising data produced by [`encode_advertising_data`].
pub const ENCODED_ADV_LEN: usize = FLAGS_AD_LEN + SERVICE_DATA_AD_LEN;

const _: () = assert!(ENCODED_ADV_LEN <= LEGACY_ADV_DATA_MAX);
const _: () = assert!(SERVICE_DATA_AD_LEN <= LEGACY_ADV_DATA_MAX);

/// Errors from decode / validation (never panics on malformed input).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BleError {
    /// Buffer too short for the expected AD structure.
    Truncated,
    /// Length field inconsistent with remaining bytes or expected size.
    BadLength,
    /// AD type was not the expected value.
    BadType,
    /// 16-bit UUID did not match [`SERVICE_UUID_16`].
    WrongUuid,
    /// Advertising data exceeds the 31-byte legacy limit.
    TooLong,
    /// No Engytita Service Data AD found in the buffer.
    NotFound,
}

/// BLE helper crate tracks the same protocol version label as core.
pub fn ble_protocol_version() -> &'static str {
    PROTOCOL_VERSION
}

/// Encode an 8-byte EID as a Service Data (16-bit UUID) AD structure only.
///
/// Use this when the platform adds Flags (or other AD elements) itself.
///
/// # MAC rotation
///
/// The platform that transmits this payload **MUST** rotate the BLE random
/// private address in lockstep with EID / epoch rotation.
pub fn encode_service_data_ad(eid: &[u8; 8]) -> [u8; SERVICE_DATA_AD_LEN] {
    let uuid = SERVICE_UUID_16.to_le_bytes();
    let mut out = [0u8; SERVICE_DATA_AD_LEN];
    // Length = type(1) + uuid(2) + eid(8) = 11
    out[0] = 11;
    out[1] = AD_TYPE_SERVICE_DATA_16;
    out[2] = uuid[0];
    out[3] = uuid[1];
    out[4..12].copy_from_slice(eid);
    out
}

/// Decode a Service Data AD structure produced by [`encode_service_data_ad`].
///
/// Also accepts a buffer that is exactly the AD payload (length byte included).
/// Malformed input returns [`BleError`] and never panics.
pub fn decode_service_data_ad(data: &[u8]) -> Result<[u8; 8], BleError> {
    if data.len() < SERVICE_DATA_AD_LEN {
        return Err(BleError::Truncated);
    }
    if data[0] as usize != SERVICE_DATA_AD_LEN - 1 {
        return Err(BleError::BadLength);
    }
    if data[1] != AD_TYPE_SERVICE_DATA_16 {
        return Err(BleError::BadType);
    }
    let uuid = u16::from_le_bytes([data[2], data[3]]);
    if uuid != SERVICE_UUID_16 {
        return Err(BleError::WrongUuid);
    }
    let mut eid = [0u8; 8];
    eid.copy_from_slice(&data[4..12]);
    Ok(eid)
}

/// Encode Flags + Engytita Service Data into legacy advertising data (15 bytes).
///
/// Fits in [`LEGACY_ADV_DATA_MAX`] (31) with 16 bytes of headroom.
///
/// # MAC rotation
///
/// The platform that transmits this payload **MUST** rotate the BLE random
/// private address in lockstep with EID / epoch rotation. See crate-level docs.
pub fn encode_advertising_data(eid: &[u8; 8]) -> [u8; ENCODED_ADV_LEN] {
    let mut out = [0u8; ENCODED_ADV_LEN];
    out[0] = 2; // len: type + flags
    out[1] = AD_TYPE_FLAGS;
    out[2] = DEFAULT_FLAGS;
    out[FLAGS_AD_LEN..].copy_from_slice(&encode_service_data_ad(eid));
    debug_assert!(out.len() <= LEGACY_ADV_DATA_MAX);
    out
}

/// Walk legacy advertising data and extract the Engytita EID.
///
/// Ignores unknown AD structures. Returns [`BleError::NotFound`] if no matching
/// Service Data UUID is present. Never panics on malformed input.
pub fn decode_advertising_data(data: &[u8]) -> Result<[u8; 8], BleError> {
    if data.len() > LEGACY_ADV_DATA_MAX {
        return Err(BleError::TooLong);
    }
    let mut i = 0usize;
    while i < data.len() {
        let len = data[i] as usize;
        if len == 0 {
            return Err(BleError::BadLength);
        }
        // Structure occupies 1 + len bytes (length byte + len octets).
        let end = i
            .checked_add(1)
            .and_then(|x| x.checked_add(len))
            .ok_or(BleError::Truncated)?;
        if end > data.len() {
            return Err(BleError::Truncated);
        }
        let ad_type = data[i + 1];
        let ad_data = &data[i + 2..end];
        if ad_type == AD_TYPE_SERVICE_DATA_16 {
            if ad_data.len() != 2 + 8 {
                // Not our 8-byte EID payload; skip other service data.
                i = end;
                continue;
            }
            let uuid = u16::from_le_bytes([ad_data[0], ad_data[1]]);
            if uuid == SERVICE_UUID_16 {
                let mut eid = [0u8; 8];
                eid.copy_from_slice(&ad_data[2..10]);
                return Ok(eid);
            }
        }
        i = end;
    }
    Err(BleError::NotFound)
}

/// Returns `true` if `encoded` fits the legacy 31-byte Advertising Data limit.
pub fn fits_legacy_advertising_pdu(encoded: &[u8]) -> bool {
    encoded.len() <= LEGACY_ADV_DATA_MAX
}

#[cfg(test)]
mod tests;
