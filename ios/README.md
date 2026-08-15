# iOS scaffolding

Platform integration for Engytita on iOS.

## Layout

| Path | Role |
|------|------|
| [`Engytita/Generated/`](Engytita/Generated/) | Checked-in UniFFI Swift + C headers |
| [`Demo/`](Demo/) | **Reference sample** (SwiftUI + CoreBluetooth) |

## Reference sample

See [`Demo/README.md`](Demo/README.md) for build and two-phone test steps.

```bash
./scripts/build-ios.sh
python3 scripts/generate-ios-xcodeproj.py   # if project missing
open ios/Demo/EngytitaDemo.xcodeproj
```

### Platform notes baked into the demo

- iOS apps cannot emit `engytita-ble` legacy AD bytes; the sample uses a GATT
  characteristic for the 8-byte EID under service UUID `0xE671`.
- Ranging keyed by Engytita is **not available**. Nearby Interaction distance
  is an **untrusted** input if you add it later.
- Foreground BLE only for this sample.

Regenerate UniFFI bindings:

```bash
./scripts/generate-bindings.sh
```

CI does **not** run Xcode builds.
