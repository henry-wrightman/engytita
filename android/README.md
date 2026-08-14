# Android scaffolding

Platform integration for Engytita on Android. **Scaffold only** - this
repository does not ship an Android SDK, Gradle project, or NDK build. CI does
not compile Kotlin or link native libraries for device targets.

## Layout

| Path | Role |
|------|------|
| [`library/`](library/) | Future Android library module (UniFFI + BLE/UWB glue) |
| [`library/generated/`](library/generated/) | Checked-in UniFFI Kotlin bindings |
| [`demo/`](demo/) | Future sample app |

## Planned requirements

- **minSdk:** 34
- **BLE:** platform Bluetooth LE APIs for advertising / scanning Engytita
  service-data payloads produced by `engytita-ble` (encode/decode only lives
  in Rust; transmission is this layer's job)
- **UWB:** [`androidx.core.uwb`](https://developer.android.com/jetpack/androidx/releases/core-uwb)
- **Native:** `engytita-ffi` built as a shared library for the app ABI(s),
  loaded next to the generated Kotlin in `library/generated/`

Regenerate Kotlin bindings:

```bash
./scripts/generate-bindings.sh
```

## Build instructions (when implemented)

Expected shape once the library module exists (not runnable from this repo yet):

1. Build `engytita-ffi` for Android targets (`aarch64-linux-android`, etc.)
   with the NDK / `cargo-ndk`.
2. Package the `.so` into the Android library module alongside
   `library/generated/org/engytita/engytita_ffi.kt`.
3. Depend on `androidx.core.uwb` and declare BLE permissions / foreground
   service types as required by the demo or host app.
4. Wire Engytita session STS into UWB
   `RangingParameters.sessionKeyInfo` after an **Accepted** session.

## What Engytita fills

The UWB Jetpack / FiRa path leaves **out-of-band parameter exchange** to the
application: deciding *who* the peer is and supplying provisioned STS key
material. That OOB exchange is exactly what Engytita provides - identity,
mutual consent, and the 16-byte STS key handed to ranging. Engytita does not
own the radio or the ranging session itself.

## Platform matrix

See the root [`README.md`](../README.md#platform-support).
