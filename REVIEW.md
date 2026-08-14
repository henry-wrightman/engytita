# Engytita Pre-Phase-6 Adversarial Review

**Scope:** Phases 0–5 (core, pairing, consent, spec/vectors, UniFFI, BLE codec)  
**Mode:** Originally report only; **F-01–F-07 (CRITICAL/HIGH) remediated 2026-08-13**  
**Date:** 2026-08-13  

---

## 1. Verdict

The key schedule matches the normative formulas (independently recomputed), SAS is enforced as a state-machine gate before IRK exchange, and the FFI layer does not export long-term secrets. **CRITICAL/HIGH items F-01–F-07 are addressed** (redacted `SessionKeys` Debug, CT linear resolve + collision-fail rebuild, sealed `Complete` + `take_peer_record`, `pub(crate)` secret accessors, digit-bound `confirm_sas`, `fuzz/` targets). Remaining open items are MEDIUM and below (expect-in-derive, clippy denies, heapless CI, nonce docs, etc.).

---

## 2. Findings table

| ID | Severity | Location | Summary | Status |
|----|----------|----------|---------|--------|
| F-01 | CRITICAL | `consent.rs` | `SessionKeys` derives `Debug` — prints STS/transport key bytes | **Fixed** (redacted Debug + Zeroize) |
| F-02 | HIGH | `resolver.rs` | Docs claim constant-time resolve; `HashMap` hit/miss is not CT | **Fixed** (linear CT scan) |
| F-03 | HIGH | `resolver.rs` | EID collision silently overwrites peer mapping | **Fixed** (`RebuildError::Collision`) |
| F-04 | HIGH | `pairing.rs`, `peer.rs` | `Complete(PeerRecord)` exposes IRK + pairwise root | **Fixed** (`Complete { peer_id }` + `take_peer_record`) |
| F-05 | HIGH | `identity.rs`, `peer.rs` | Public `irk()` / `peer_irk()` / `pairwise_root()` | **Fixed** (`pub(crate)`) |
| F-06 | HIGH | *(repo-wide)* | No fuzz targets for BLE decode or pairing message parse | **Fixed** (`fuzz/`) |
| F-07 | HIGH | `pairing.rs` | `confirm_sas()` does not bind to displayed digits | **Fixed** (digits arg + CT compare) |
| F-08 | MEDIUM | `derive.rs:28-29,97-98` | `expect()` in hot derivation path — aborts on `no_std` if ever wrong | Open |
| F-09 | MEDIUM | `engytita-core` lint config | Claimed `deny(clippy::unwrap_used, …)` not present; only `forbid(unsafe_code)` | Open |
| F-10 | MEDIUM | `spec/engytita-v1.md` §4/§8 | ±1 epoch window (~45 min validity) not called out as tracking-window trade-off | Open |
| F-11 | MEDIUM | `derive.rs` sts/transport docs | Nonce reuse: same keys, not prevented, not documented | Open |
| F-12 | MEDIUM | `identity.rs:31-37`, `pairing.rs:125-130` | All-zero / repeated entropy accepted with no check | Open |
| F-13 | MEDIUM | `pairing.rs:130` | Production path uses `fixed_ephemeral_key_for_testing_only` | Open |
| F-14 | MEDIUM | `.github/workflows/ci.yml` | `heapless` feature never built/tested in CI | Open |
| F-15 | MEDIUM | `tests.rs` phase2 revoke/rotate | Asymmetry (revoked peer still resolves *you*) not demonstrated by a test | Open |
| F-16 | MEDIUM | `ffi/.../lib.rs:210-217` | `resolve` rebuilds full table every call (O(peers) alloc+HMAC) | Open |
| F-17 | MEDIUM | vector provenance | Vectors were originally captured from this implementation (circular); values now independently match | Open |
| F-18 | LOW | `tests.rs` KATs | Vectors loaded via `include_str!` (compile-time embed), not runtime disk read | Open |
| F-19 | LOW | `Cargo.lock` / audit | Transitive `bincode`, `paste` unmaintained (via UniFFI) | Open |
| F-20 | LOW | public modules | Large public surface (`derive::*` labels, `PeerRecord::new`, consent helpers) beyond “six or seven” ops | Partially mitigated (`PeerRecord::new` crate-private) |
| F-21 | NIT | `snow` 0.9.6 | Newer 0.10.x exists on crates.io; no advisory found for 0.9.6 | Open |
| F-22 | NIT | BLE prop tests | Mostly round-trip identity; garbage “no panic” is useful but shallow | Open |

---

## 3. Detailed findings

### F-01 — CRITICAL — `SessionKeys: Debug` prints secrets

```54:58:crates/engytita-core/src/consent.rs
#[derive(Clone, Debug)]
pub struct SessionKeys {
    pub sts_key: [u8; 16],
    pub transport_key: [u8; 32],
}
```

**Problem:** Derived `Debug` formats raw key bytes. Logging `{:?}` (common in mobile/FFI glue) exfiltrates session keys to logs.

**Consequence:** Any debug logging of consent/FFI results dumps STS and transport keys.

**Direction:** Custom `Debug` that redacts; consider `Zeroize`/`ZeroizeOnDrop` on `SessionKeys` too. Same issue on FFI `SessionKeys` (`engytita-ffi/src/lib.rs:51-56`).

---

### F-02 — HIGH — Constant-time resolve claim is false

```15:30:crates/engytita-core/src/resolver.rs
/// 8-byte EID wrapper whose `Eq` is constant-time (no early-return on mismatch).
impl PartialEq for CtEid {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}
```

```68:70:crates/engytita-core/src/resolver.rs
    /// O(1) lookup. EID equality is constant-time ([`CtEid`]).
    pub fn resolve(&self, beacon: &[u8; 8]) -> Option<PeerId> {
        self.table.get(&CtEid(*beacon)).copied()
```

**Problem:** (1) `bool::from(Choice)` is an immediate branch after CT compare. (2) `HashMap::get` hashes the key and follows probe chains — timing depends on membership and bucket state. Module docs claim CT resolve.

**Consequence:** A local attacker measuring `resolve` timing can learn whether a beacon is in the contact set (and possibly more via hash collisions). This is weaker than “byte-by-byte early exit” but **not** constant-time w.r.t. membership.

**Direction:** Either document honestly (“average O(1), not CT”) or implement a linear CT scan over precomputed entries if membership privacy matters on-device.

---

### F-03 — HIGH — EID collision silent overwrite

```60:64:crates/engytita-core/src/resolver.rs
            for &e in &epochs {
                let beacon = eid(peer.peer_irk(), e);
                self.table.insert(CtEid(beacon), peer.peer_id());
            }
```

**Problem:** On duplicate EID, `insert` replaces the previous `PeerId` with no error. Deterministic last-wins; does not panic.

**Birthday bound:** For ~1000 peers × 3 epochs ≈ 3000 EIDs in a 2⁶⁴ space, collision probability ≈ `n²/2⁶⁵` ≈ 2.4×10⁻¹³ — negligible for realistic lists, but still undefined protocol behavior if it occurs (wrong peer identity on resolve).

**Direction:** Detect collision on insert; fail `rebuild` or keep a multi-map and refuse ambiguous resolve.

---

### F-04 — HIGH — `Complete(PeerRecord)` leaks long-term secrets

```51:52:crates/engytita-core/src/pairing.rs
    Complete(PeerRecord),
```

```67:72:crates/engytita-core/src/peer.rs
    pub fn peer_irk(&self) -> &[u8; 32] { &self.peer_irk }
    pub fn pairwise_root(&self) -> &[u8; 32] { &self.pairwise_root }
```

**Problem:** Successful pairing returns a struct whose public getters expose IRK and pairwise root. FFI remaps to `PeerId` only, but any direct `engytita-core` consumer gets secrets in the happy-path return type.

**Consequence:** Core API cannot claim “secrets never leave pairing except into a sealed store” — they are handed to the caller in plaintext struct form.

**Direction:** Return an opaque `PeerId` / sealed handle from pairing; keep `PeerRecord` crate-private or behind an explicit unsafe/audit-gated accessor.

---

### F-05 — HIGH — Public secret accessors on identity/peer

`Identity::irk()` (`identity.rs:50-51`) and `PeerRecord::{peer_irk,pairwise_root}` are public. Beacon generation needs *some* way to compute `eid`, but returning `&[u8;32]` IRK is the most footgun-shaped option.

**Direction:** Prefer `Identity::beacon_eid(epoch)` only (already exists); make raw IRK `pub(crate)` or feature-gated.

---

### F-06 — HIGH — No fuzz targets for untrusted input

Attacker-controlled bytes enter at:

1. `engytita-ble`: `decode_advertising_data` / `decode_service_data_ad`
2. `engytita-core` pairing: `Pairing::read` → snow decrypt/parse

Property tests cover random garbage “doesn’t panic” for BLE only. **No** `libFuzzer`/`cargo-fuzz` targets exist (confirmed by repo search).

**Direction:** Add fuzz targets before Phase 6 integrates these parsers with real radios/sockets.

---

### F-07 — HIGH — SAS confirmation is a honor-system API

```181:201:crates/engytita-core/src/pairing.rs
    pub fn confirm_sas(&mut self) -> PairingState {
        let data = match ... Stage::Confirm(data) ...
        // no digits parameter, no verification
```

**Problem:** State machine *does* require a `confirm_sas` call before IRK/`Complete` (traced: `Irk` only entered here; `Complete` only from `Irk`/`FinalIrkSend`). There is **no** path to `Complete` without that call. But nothing checks that the user compared digits — a compromised or careless host app can auto-confirm.

**Consequence:** MITM resistance is only as strong as the host UI. The protocol library cannot detect skip.

**Direction:** Accept user-entered digits and CT-compare to derived SAS before advancing; or document as a hard host requirement with a compliance test harness.

---

### F-08 — MEDIUM — `expect` in `no_std` derivation

```28:29:crates/engytita-core/src/derive.rs
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(irk).expect("HMAC-SHA256 accepts any key length");
```

```97:98:crates/engytita-core/src/derive.rs
    hk.expand(info, &mut okm)
        .expect("HKDF-SHA256 OKM length is within limit");
```

These are unlikely to fail for fixed key sizes, but on bare metal `expect` is abort. Review checklist asked for `deny(clippy::expect_used)` — not configured.

---

### F-09 — MEDIUM — Lint policy not enforced

`lib.rs` has `#![forbid(unsafe_code)]` only. **Not present:**  
`deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)`.

`PanicRng` deliberately panics (`pairing.rs:434-447`). Slice indexing in derive uses `[..8]` after fixed-size HMAC output — safe in practice but not lint-enforced.

---

### F-10 — MEDIUM — Skew window tracking trade-off undocumented in §8

Spec §4.3 defines `{epoch-1, epoch, epoch+1}`. §8 mentions skew absorption once but **does not** state that each EID is effectively valid ~45 minutes and that this widens the tracker’s correlation window.

Code uses saturating arithmetic (`resolver.rs:33-36`) — **no** underflow panic at `epoch==0` (verified). Near `u64::MAX`, `saturating_add(1)` clamps — window shrinks rather than wrapping. Good.

---

### F-11 — MEDIUM — Nonce reuse silent

`sts_key` / `transport_key` are pure functions of `(root, nonce)`. Reuse ⇒ identical keys. Not detectable, not prevented, not documented in API docs or spec security considerations.

**Consequence:** If a ranging/media stack treats these as unique per session, reuse is key reuse (severity depends on upper-layer AEAD nonce handling).

---

### F-12 — MEDIUM — Weak entropy accepted

`Identity::from_parts` / `from_entropy64` and pairing `ephemeral: &[u8;32]` accept all-zero and repeated patterns. No rejection. Clamped X25519 all-zero seeds are a known footgun class.

---

### F-13 — MEDIUM — Testing-only snow API in production

```128:130:crates/engytita-core/src/pairing.rs
        let builder = Builder::with_resolver(...)
            .fixed_ephemeral_key_for_testing_only(ephemeral);
```

Intent (inject entropy, avoid OsRng) is sound for the project rules; relying on a `doc(hidden)` testing API is a maintenance/compatibility risk if snow removes or changes it.

---

### F-14 — MEDIUM — `heapless` not in CI

CI `no-std` job: `cargo build -p engytita-core --no-default-features` — does **not** enable `heapless`. `HeaplessResolver` can bit-rot. Capacity failure returns `ResolverFull` (clean) when used — verified in API — but behavioural parity with `Resolver` is only lightly tested (`heapless_resolver_round_trip`, one peer).

---

### F-15 — MEDIUM — Revocation asymmetry not fully pinned by tests

`revoke_makes_beacons_unresolvable_*` shows **local** forgetfulness.  
`rotate_own_irk_stale_contacts_*` shows stale IRK fails after **your** rotation.

Missing: after Alice `revoke(Bob)`, assert Bob’s resolver (still holding Alice’s IRK) still resolves Alice’s beacon — the documented limitation.

---

### F-16 — MEDIUM — FFI resolve rebuilds every call

```210:217:crates/engytita-ffi/src/lib.rs
        let mut resolver = Resolver::new();
        resolver.rebuild(&eng.peer_records(), epoch);
        Ok(resolver.resolve(&arr).map(Into::into))
```

Every beacon costs full 3×N HMAC rebuild + alloc. Correct but hostile to embedded/battery if called per advertisement.

---

### F-17 — MEDIUM — Vector provenance was circular; values now OK

Chat history: vectors were produced by running this crate’s `gen_vectors` example and recording hex. That is generating the contract from the SUT.

**Independent recompute (Python HMAC-SHA256 / HKDF-Extract-Expand, empty salt → 32 zero bytes):** all `eid`, `peer_id`, `sts_key`, `transport_key`, `sas`, `pairwise_root` vectors in `spec/vectors/v1.json` **MATCH**. Work shown in Appendix B.

So: formulas are consistent with the spec; process risk remains if future vectors are regenerated from the same code without a second tool.

---

### F-18 — LOW — `include_str!` vs “read from disk at test time”

```46:49:crates/engytita-core/src/tests.rs
    const VECTORS_JSON: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../spec/vectors/v1.json"
```

Expected digests are **not** hardcoded as Rust literals; they live in JSON. Loading is compile-time embed, not `std::fs` at test runtime. Meets the spirit of “contract file”; fails a literal reading of “at test time.”

---

### F-19 — LOW — Supply chain warnings

`cargo audit`: no yanked/vulnerable crates; **warnings** RUSTSEC-2025-0141 (`bincode` unmaintained), RUSTSEC-2024-0436 (`paste` unmaintained) — transitive via UniFFI, not core crypto.

`cargo deny`: **not installed** in this environment — could not run.

---

### F-20 — LOW — Public surface larger than “six or seven calls”

Core re-exports all derive labels, `PeerRecord::new`, full consent engine, resolver internals, etc. FFI is closer to the intended small surface but still exposes `session_state`, dual pairing constructors, `take_initial_event`, etc.

---

### F-21 — NIT — snow version

Locked `snow 0.9.6`; crates.io also has 0.10.x. No advisory flagged for 0.9.6 by `cargo audit`.

---

### F-22 — NIT — BLE property tests shallow

Round-trip + “garbage doesn’t panic” — good baseline, not structured adversarial cases (nested length overflows beyond random, UUID confusion, truncated mid-structure sequences are partly covered by unit tests).

---

## Spec ↔ code extras (Part A list)

| Spec says | Code |
|-----------|------|
| HKDF no salt, ikm first | `Hkdf::new(None, ikm)` — **OK** (verified) |
| Labels exact ASCII | Match — **OK** |
| SAS mandatory | State gate — **OK**; honor-system confirm — F-07 |
| Asymmetric revocation | Documented in code+spec — **OK**; test gap — F-15 |
| BLE MAC rotation | Spec §8.1 + ble crate docs — **OK** |
| iOS ranging untrusted | Spec threat model + §7 — **OK** |
| `pairwise_root` from Split keys | Implemented + vectored — **OK** |
| Code beyond spec | `pairwise_root` JSON vectors (extra, fine); FFI `session_state`; BLE UUID `0xE671` provisional (documented) |
| Spec without code | Allowlist in core but not FFI; IRK update channel “authenticated update” mentioned, not implemented (out of scope) |

---

## Part B notes (checked)

- **Domain separation:** labels listed in `derive.rs`; none is a prefix of another (manual compare).
- **SAS bypass to Complete without `confirm_sas`:** none found (traced `Irk`/`FinalIrkSend`/`complete`).
- **Replay:** Noise AEAD should reject tampered/replayed handshake flights; no test resurrects a revoked peer via recorded IRK-only messages. Not fully experimentally verified beyond unit tamper test.
- **Hand-rolled crypto:** no curve/hash loops found; uses dalek/snow/RustCrypto.

---

## Part C notes

- `Identity`, `PeerRecord`: `Zeroize`+`ZeroizeOnDrop` present. `PeerId` is `Copy`+`Zeroize` — Copy defeats wipe of copies; PeerId is not key material.
- `from_entropy64` stack buffers not explicitly zeroized after use.
- `Pairing` Drop zeroizes `static_private`/`own_irk`; snow internal buffers **not verified**.
- `PeerRecord` Debug redacts secrets — **OK**. `SessionKeys` does not — F-01.
- No serde on core secret types — **OK**.

---

## 4. What I could not verify

1. **Line coverage** — `cargo-llvm-cov` / `tarpaulin` not installed; no numeric coverage.
2. **`cargo deny check`** — `cargo-deny` not installed.
3. **snow `dangerously_get_raw_split` after internal `split()`** — read snow source earlier: `split_raw` does not mutate `ck`, so second call should yield same k1/k2; did not write an assert that k1/k2 equal CipherState keys.
4. **Whether HashMap timing is exploitable remotely** — resolve is local; remote adversary needs a timing oracle on the device. Severity assumes local/side-channel relevant threat.
5. **Full transitive `std` leakage on `thumbv7em`** — CI build succeeds; did not run `nm`/`cargo readobj` for unexpected symbols.
6. **Replay resurrection** — reasoned from Noise properties; no dedicated replay-harness test.
7. **UniFFI generated Kotlin/Swift** — not audited line-by-line for accidental secret fields (Rust FFI layer checked; generated bindings assumed to mirror exported types only).
8. **Independent SAS vector** — recomputed with Python HKDF; did not use a third tool (e.g. OpenSSL CLI) as a second cross-check.

---

## 5. Coverage of this review

| Part | Depth |
|------|-------|
| A Spec conformance | Full on derivations + vector file loading; independent Python recompute of all vector types |
| B Crypto | Full SAS path trace; CT/HashMap; collision; nonce; epoch saturating; labels |
| C Secret hygiene | Full on derives/Debug/public getters; snow wipe incomplete |
| D no_std / robustness | Full on CI job + expect/lints; heapless sampled |
| E API/FFI | Full on secret boundary + consent gate; handle lifecycle sampled |
| F Tests | Full on tautology/fuzz/asymmetry gaps; coverage tool missing |
| G Supply chain | `cargo audit` run; `deny` missing; tree sampled for core |
| H Docs/spec | Full on §6.4/§7/§8.1/iOS; `missing_docs` deny absent |
| I Perf | Bench exists (~2ms historically); FFI rebuild noted |

**Human should re-check by hand:** F-02 threat relevance for your deployment, whether F-04/F-05 are acceptable for a Rust-only embedder vs FFI-only products, and regenerate vectors with a second independent tool before claiming multi-implementer interoperability.

---

## Appendix A — Tooling output

### `cargo fmt --all -- --check`

```
EXIT: 0 (clean)
```

### `cargo clippy --workspace --all-targets -- -D warnings`

```
Finished `dev` profile — EXIT: 0 (clean)
```

### `cargo test --workspace`

```
engytita-ble:  13 passed
engytita-core: 25 passed
engytita-ffi:   6 passed
EXIT: 0
```

### `cargo audit`

```
Scanning Cargo.lock for vulnerabilities (189 crate dependencies)

Crate:     bincode
Version:   1.3.3
Warning:   unmaintained
ID:        RUSTSEC-2025-0141

Crate:     paste
Version:   1.0.15
Warning:   unmaintained
ID:        RUSTSEC-2024-0436

warning: 2 allowed warnings found
EXIT: 0
```

### `cargo deny check`

```
cargo-deny not found
error: no such command: `deny`
(NOT RUN)
```

---

## Appendix B — Independent vector recompute (Python)

HKDF-Extract with empty/None salt uses 32 zero bytes; Expand per RFC 5869. HMAC-SHA256 for EID.

| Vector | Result |
|--------|--------|
| eid epoch 1234567 | `c451d591b83ebb31` MATCH |
| eid epoch 0 | `ff7bc96a4febd78c` MATCH |
| eid epoch 1 | `f595822be8192ab0` MATCH |
| peer_id | `54d1a24995e911cb93b871665be27ad0` MATCH |
| sts_key | `002cc4ae9332566889f52cc5ec2d31d6` MATCH |
| transport_key | `84e38cc3a63f4ac333abaa62753181f36a0357a8776fb67f2dd0347e4a4df5b5` MATCH |
| sas digits | `483984` → hex `040803090804` MATCH |
| pairwise_root | `bc263864a2bffe8bcb8905820a885e5d34c5cf070c7ce8bcd01298f90ed09a02` MATCH |
