# Engytita

Engytita is a protocol and reference library for mutually-consented,
privately-resolvable identity between physically nearby devices — **TLS for
physical proximity**. It does not carry application data and does not own a
radio: it establishes *who* the peer is, proves both sides consented, and
hands the caller session keys. Ranging, transport, and media are the
caller's responsibility.

## Crates

| Crate | Role |
|-------|------|
| `engytita-core` | `no_std` protocol core — identity, resolution, pairing, consent |
| `engytita-ffi` | UniFFI bindings (opaque handles; no raw long-term key export) |
| `engytita-ble` | BLE advertisement encode/decode (bytes only; no radio) |

Generated Kotlin / Swift bindings (from UniFFI) live in
`android/library/generated/` and `ios/Engytita/Generated/`. Regenerate with
`./scripts/generate-bindings.sh`.

## Specification

Normative protocol text and interoperability vectors live in [`spec/`](spec/).
That directory is intended to become a standalone submodule once a second
implementer exists. `engytita-core` tests load `spec/vectors/v1.json` as the
known-answer contract.

## License

Dual-licensed under [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT).

## Platform support

| Capability | Android | iOS |
|---|---|---|
| Identity, pairing, consent | Full | Full |
| Beacon resolution | Full | Full |
| Ranging keyed by Engytita | Full — `RangingParameters.sessionKeyInfo` accepts the derived STS key | **Not available** — Nearby Interaction manages ranging security internally with its own discovery tokens; there is no seam to inject key material |
| Background operation | Foreground service; true background is a system-service milestone | Foreground only |

**iOS consequence:** ranging is an **untrusted input**. Engytita secures the
OOB channel and the transport, but distance and bearing measurements are
attested by Apple's stack, not by Engytita.

Platform directories:

- Android: [`android/`](android/) — library + demo stubs; UniFFI Kotlin checked in
- iOS: [`ios/`](ios/) — UniFFI Swift + **reference sample** in [`ios/Demo/`](ios/Demo/)
- Linux ARM (Pi / robots / vehicles): [`crates/engytita-linux`](crates/engytita-linux) — BlueZ CLI host

## Development

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build -p engytita-core --no-default-features --target thumbv7em-none-eabi
```

iOS reference demo (two physical devices; Xcode not run in CI):

```bash
./scripts/build-ios.sh
open ios/Demo/EngytitaDemo.xcodeproj
```

Linux / Raspberry Pi host:

```bash
cargo run -p engytita-linux -- status
# on a BlueZ machine:
cargo run -p engytita-linux -- responder
cargo run -p engytita-linux -- initiator
```

Fuzz targets (BLE decode + pairing `read`) live under `fuzz/` — run with
[`cargo fuzz`](https://github.com/rust-fuzz/cargo-fuzz) after installing it.

**Out of scope here:** audio/media products, UWB session ownership, servers/accounts.
Android demo remains a stub.
