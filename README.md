# Engytita

[![CI](https://github.com/henry-wrightman/engytita/actions/workflows/ci.yml/badge.svg)](https://github.com/henry-wrightman/engytita/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-APACHE)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue.svg)](Cargo.toml)
[![security policy](https://img.shields.io/badge/security-policy-green.svg)](SECURITY.md)

Engytita is a protocol and reference library for mutually-consented,
privately-resolvable identity between physically nearby devices — **TLS for
physical proximity**. It does not carry application data and does not own a
radio: it establishes *who* the peer is, proves both sides consented, and
hands the caller session keys. Ranging, transport, and media are the
caller's responsibility.

**Status:** `v0.1` reference implementation — suitable for integration and
interop work, **not** a substitute for a third-party security audit. The core
is sans-I/O: hosts inject epoch and entropy; Engytita never opens sockets or
reads an OS clock/RNG.

## Crates

| Crate | Role |
|-------|------|
| [`engytita-core`](crates/engytita-core) | `no_std` protocol core — identity, resolution, pairing, consent |
| [`engytita-ffi`](crates/engytita-ffi) | UniFFI bindings (opaque handles; no raw long-term key export) |
| [`engytita-ble`](crates/engytita-ble) | BLE advertisement encode/decode (bytes only; no radio) |
| [`engytita-linux`](crates/engytita-linux) | Linux/BlueZ **reference host** (Pi, robots, vehicles) — owns the radio |

Generated Kotlin / Swift bindings (from UniFFI) live in
`android/library/generated/` and `ios/Engytita/Generated/`. Regenerate with
`./scripts/generate-bindings.sh`.

## Specification

Normative protocol text and interoperability vectors live in [`spec/`](spec/).
That directory is intended to become a standalone submodule once a second
implementer exists. `engytita-core` tests load `spec/vectors/v1.json` as the
known-answer contract.

## Security

Please report vulnerabilities privately — see [`SECURITY.md`](SECURITY.md).

## License

Dual-licensed under [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT).

## Platform support

| Capability | Android | iOS | Linux (BlueZ) |
|---|---|---|---|
| Identity, pairing, consent | Full | Full | Full (`engytita-linux`) |
| Beacon resolution | Full | Full | Full (LE service data + GATT) |
| Ranging keyed by Engytita | Full — `RangingParameters.sessionKeyInfo` accepts the derived STS key | **Not available** — Nearby Interaction manages ranging security internally; no seam to inject key material | Host's problem (not in this CLI) |
| Background operation | Foreground service; true background is a system-service milestone | Foreground only | Daemon / systemd (not packaged here) |

**iOS consequence:** ranging is an **untrusted input**. Engytita secures the
OOB channel and the transport, but distance and bearing measurements are
attested by Apple's stack, not by Engytita.

**Linux note:** `engytita-linux` can advertise the 8-byte EID in LE **service
data** (phones generally cannot from an app). GATT UUIDs match the iOS demo
for eventual phone↔board pairing. See [`crates/engytita-linux/README.md`](crates/engytita-linux/README.md).

Platform directories:

- Android: [`android/`](android/) — library + demo stubs; UniFFI Kotlin checked in
- iOS: [`ios/`](ios/) — UniFFI Swift + **reference sample** in [`ios/Demo/`](ios/Demo/)
- Linux: [`linux/`](linux/) → [`crates/engytita-linux`](crates/engytita-linux)

## Development

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build -p engytita-core --no-default-features --target thumbv7em-none-eabi
cargo deny check
cargo tarpaulin -p engytita-core -p engytita-ble -p engytita-ffi --features heapless
```

### iOS reference demo

Two physical devices (Xcode not run in CI):

```bash
./scripts/build-ios.sh
open ios/Demo/EngytitaDemo.xcodeproj
```

### Linux / Raspberry Pi host

Needs BlueZ + D-Bus (`libdbus-1-dev` / `pkg-config` to build on Linux).
Prefer building **on the board** (cross-compile needs a sysroot).

```bash
cargo run -p engytita-linux -- status
cargo run -p engytita-linux -- responder    # device B
cargo run -p engytita-linux -- initiator    # device A
```

Fuzz targets (BLE decode + pairing `read`) live under `fuzz/` — run with
[`cargo fuzz`](https://github.com/rust-fuzz/cargo-fuzz) after installing it.

**Out of scope here:** audio/media products, UWB session ownership, servers/accounts.
Android demo remains a stub.
