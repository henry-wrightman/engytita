# engytita-linux

Linux / BlueZ **reference host** for Engytita — aimed at Raspberry Pi, robots,
vehicles, and other `aarch64`/`arm` Linux boards.

This crate owns the **radio**. `engytita-core` and `engytita-ble` stay
sans-I/O / bytes-only.

## Requirements

- Linux with BlueZ (`bluetoothd`) and D-Bus
- Permission to use the adapter (often `bluetooth` group or root)
- Rust toolchain (native on Pi, or cross from a host)

## Commands

```bash
# Works on any OS (no radio) — creates ~/.config/engytita/identity.entropy
cargo run -p engytita-linux -- status

# Linux only:
cargo run -p engytita-linux -- responder
cargo run -p engytita-linux -- initiator
cargo run -p engytita-linux -- initiator --addr AA:BB:CC:DD:EE:FF
```

### Two-device test (two Pis, or Pi + phone later)

1. Device **B**: `engytita-linux responder`
2. Device **A**: `engytita-linux initiator` (or pass `--addr`)
3. Compare SAS verbally; type the six digits on each side
4. Expect “session keys derived” (key bytes are not printed)

## BLE layout

| Item | Value |
|------|--------|
| Service UUID | `0000E671-0000-1000-8000-00805F9B34FB` (`0xE671`) |
| EID characteristic | `…E672…` (8 bytes, read) |
| Pairing write | `…E673…` (central → peripheral) |
| Pairing notify | `…E674…` (peripheral → central) |

Responder also sets **LE service data** for `0xE671` to the 8-byte EID (Linux
can advertise this; iOS apps generally cannot). GATT UUIDs match
`ios/Demo` for future phone↔Pi pairing.

## Cross-compile (example)

```bash
rustup target add aarch64-unknown-linux-gnu
# with appropriate linker / sysroot for your board:
cargo build -p engytita-linux --release --target aarch64-unknown-linux-gnu
```

Runtime still needs BlueZ on the device.

## Not in scope

Audio, drones-specific flight stacks, UWB, or a system service packaging.
This is a reference CLI to prove Engytita on generic Linux ARM hardware.
