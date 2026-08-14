# Android library module

**Not yet implemented - see roadmap.**

Future home for the Android library that:

- Links the `engytita-ffi` native shared library
- Exposes a small Kotlin API over the generated UniFFI bindings in
  [`generated/`](generated/)
- Owns BLE advertise/scan and UWB `RangingParameters` handoff

Do not expect Gradle or NDK builds from this repository's CI.
