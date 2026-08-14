# iOS scaffolding

Platform integration for Engytita on iOS. **Scaffold only** - this repository
does not ship an Xcode project, XCFramework, or CocoaPods/SPM package that
builds in CI.

## Layout

| Path | Role |
|------|------|
| [`Engytita/`](Engytita/) | Future Swift package / framework sources |
| [`Engytita/Generated/`](Engytita/Generated/) | Checked-in UniFFI Swift + C headers |
| [`Demo/`](Demo/) | Future sample app |

## Planned capabilities

- **Identity, pairing, consent:** full via `engytita-ffi`
- **Beacon resolution:** full (host supplies BLE scan bytes; decode with
  `engytita-ble` or equivalent platform parsing of the same AD layout)
- **BLE:** CoreBluetooth for advertising / scanning; MAC rotation **MUST**
  align with Engytita EID / epoch rotation (see `spec/engytita-v1.md` §8.1)

Regenerate Swift bindings:

```bash
./scripts/generate-bindings.sh
```

## Build instructions (when implemented)

Expected shape once the framework exists (not runnable from this repo yet):

1. Build `engytita-ffi` for Apple targets and package as a static/dynamic
   library or XCFramework.
2. Include `Engytita/Generated/` (`EngytitaFfi.swift`, `EngytitaFfiFFI.h`,
   module map) in the Swift package or Xcode target.
3. Host app performs sans-I/O pairing (ship bytes over your OOB channel),
   confirms SAS digits, then uses opaque peer handles for resolve / session
   APIs.

## Platform limitation - ranging

Ranging keyed by Engytita is **not available** on iOS. Nearby Interaction
manages ranging security internally with its own discovery tokens; there is
**no seam** to inject Engytita STS key material.

**Consequence:** on iOS, ranging is an **untrusted input**. Engytita secures
the OOB channel and the transport key handoff, but distance and bearing
measurements are attested by Apple's stack, not by Engytita. Do not treat NI
distance as Engytita-authenticated.

Background operation is **foreground only** for this scaffold's planned
scope.

## Platform matrix

See the root [`README.md`](../README.md#platform-support).
