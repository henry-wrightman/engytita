# engytita-core

`no_std` protocol core for Engytita: mutually-consented, privately-resolvable
identity between physically nearby devices.

- Zero I/O (no radio, sockets, filesystem, or threads)
- Epoch is a caller-supplied `u64`
- Entropy is injected as byte slices by the caller
- Cryptographic primitives are composed from vetted crates only

## Surface

| Item | Role |
|------|------|
| `Identity` | Long-term X25519 static key + IRK (`rotate_own_irk`) |
| `PeerId` / `PeerRecord` | Opaque handle and stored peer material |
| Key schedule | `eid`, `peer_id`, `sts_key`, `transport_key`, `sas_digits` |
| `Resolver` / `HeaplessResolver` | Precomputed ±1-epoch EID lookup |
| `Pairing` (`std`) | Noise_XX sans-I/O + mandatory SAS + IRK exchange |
| `ConsentEngine` (`std`) | Availability, sessions, revoke (asymmetric) |

Pairing and consent require the `std` feature (via `snow`). Key schedule and
identity remain available on `no_std` targets.
