# Linux / embedded hosts

Generic (non-phone) Engytita hosts live as Rust binaries that call
`engytita-core` and speak BLE via the platform stack.

| Path | Role |
|------|------|
| [`../crates/engytita-linux`](../crates/engytita-linux) | BlueZ reference CLI (Pi, robots, vehicles) |

Phone demos: [`../ios/Demo`](../ios/Demo), [`../android/demo`](../android/demo).
