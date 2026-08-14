# engytita-ble

Encode and decode Engytita EIDs into BLE advertisement Service Data payloads.

**Bytes only.** No radio, no scanning, no advertising APIs — transmission is
the platform layer's job.

**MAC rotation MUST be aligned to EID rotation.** If the BLE address stays
stable across epochs, unlinkability is defeated.

## Layout

Legacy advertising data (15 bytes ≤ 31):

| AD | Contents |
|----|----------|
| Flags (3) | LE General Discoverable, BR/EDR Not Supported |
| Service Data 16-bit (12) | UUID `0xE671` + 8-byte EID |
