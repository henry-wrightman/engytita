# Engytita Protocol Specification - Version 1

**Status:** Normative  
**Protocol label:** `v1`  
**Keywords:** The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document
are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

This document defines Engytita v1: mutually-consented, privately-resolvable
identity between physically nearby devices. A competent engineer MUST be able
to produce an interoperable implementation from this document alone, without
reading any reference source code.

Interoperability fixtures in `vectors/` are normative for the listed
derivations. Implementations MUST match those vectors byte-for-byte.

---

## 1. Scope and non-goals

### 1.1 Scope

Engytita defines:

1. Long-term device identity material (X25519 static key and Identity Resolving Key).
2. Domain-separated key schedule for ephemeral identifiers, peer handles, session keys, and short authentication strings.
3. Private resolution of rotating beacons to known peers.
4. A mutual pairing handshake with mandatory out-of-band SAS confirmation and IRK exchange.
5. Consent semantics for per-session authorization and revocation.

Engytita establishes *who* a peer is, proves both sides consented to a session,
and hands the caller session key material. It is deliberately analogous to TLS
for physical proximity: it authenticates and authorizes; it does not carry
application data.

### 1.2 Non-goals

Engytita does **not** define:

- Radio, BLE scanning/advertising, UWB ranging, or any I/O.
- Ranging setup, distance/bearing computation, or FiRa MAC/PHY procedures.
- Application transport, codecs, media, or spatial audio.
- Accounts, servers, cloud sync, or contact-book identifiers (phone numbers, emails, handles).
- A wall clock or CSPRNG inside the protocol logic - epoch and entropy are always caller-supplied.

Implementations of the core protocol logic MUST be fully deterministic given
identical inputs (keys, epochs, nonces, handshake bytes, entropy).

---

## 2. Threat model

### 2.1 Assets

- Long-term static X25519 secret and IRK.
- Pairwise root and derived STS/transport keys.
- The binding between a physical nearby device and a `PeerId` known to the user.
- User consent to engage in a session.

### 2.2 Adversaries

| Adversary | Capabilities | Goals Engytita resists |
|-----------|--------------|-------------------------|
| **Passive eavesdropper** | Observes BLE advertisements / handshake ciphertext on the wire | MUST NOT learn stable identifiers from EIDs alone; MUST NOT recover IRKs or pairwise roots from ciphertext |
| **Active MITM** | Relays or modifies pairing messages between two honest parties | MUST be detectable via mandatory SAS mismatch; MUST NOT complete pairing without both users confirming identical digits |
| **Tracker** | Collects beacons over time, possibly correlating with MAC addresses | MUST NOT link EIDs across epochs without the IRK; defeated if MAC rotation is not aligned (see §8) |
| **Revoked contact** | Previously paired; retains a copy of the victim's IRK until the victim rotates | After local `revoke`, MUST NOT resolve the revoked peer's beacons; the reverse direction is limited - see §6.4 |

### 2.3 Out of scope for this threat model

- Compromised device OS / malware with memory access.
- Physical coercion of SAS confirmation.
- Side-channel attacks on the host cryptographic library.
- On iOS, attestation of ranging measurements (see platform notes in the repository README): Engytita does not claim to authenticate Apple's distance/bearing outputs.

---

## 3. Identity and key schedule

All HKDF is **HKDF-SHA256** with **no salt** (`salt = empty`). All HMAC is
**HMAC-SHA256**. Labels are ASCII byte strings, versioned and domain-separated.
Concatenation is denoted `||`. Integers encoded for input are big-endian unless
stated otherwise.

### 3.1 Constants

| Name | Value |
|------|-------|
| `PROTOCOL_VERSION` | `v1` (informational label) |
| `EPOCH_SECONDS` | `900` (15 minutes) |

Epoch numbering is defined by the caller: `epoch = floor(unix_time_seconds / 900)`
is RECOMMENDED but not required. Implementations MUST treat `epoch` as an opaque
`u64` parameter.

### 3.2 Long-term identity

Each device holds:

- `static_secret`: 32-byte X25519 private key (clamping as specified by X25519).
- `static_public`: corresponding 32-byte X25519 public key.
- `irk`: 32-byte Identity Resolving Key (uniform random; caller-supplied entropy).

Implementations MUST zeroize `static_secret` and `irk` on destruction where the
platform allows.

### 3.3 Derivations (byte-exact)

```
eid(irk, epoch) =
    HMAC-SHA256(key = irk,
                data = "engytita/v1/eid" || be64(epoch))[0..8]

peer_id(static_public) =
    HKDF-SHA256(ikm = static_public,
                info = "engytita/v1/peerid",
                L = 16)

sts_key(root, nonce) =
    HKDF-SHA256(ikm = root,
                info = "engytita/v1/sts" || nonce,
                L = 16)

transport_key(root, nonce) =
    HKDF-SHA256(ikm = root,
                info = "engytita/v1/transport" || nonce,
                L = 32)

sas_digits(handshake_hash) =
    let okm = HKDF-SHA256(ikm = handshake_hash,
                          info = "engytita/v1/sas",
                          L = 4)
    let n = be32(okm) mod 1_000_000
    encode n as six decimal digits, each digit a byte in 0..=9 (MSB first)

pairwise_root(k1, k2) =
    HKDF-SHA256(ikm = k1 || k2,
                info = "engytita/v1/pairwise-root",
                L = 32)
```

Where:

- `nonce` is a caller-supplied 16-byte session nonce.
- `k1` and `k2` are the 32-byte keys from Noise `Split()` (see §5).
- `PeerId` is the 16-byte `peer_id(static_public)` value; it is an opaque handle,
  not a public key.

`sts_key` is 16 bytes to match provisioned-STS slots used by UWB stacks.
`transport_key` is 32 bytes for handoff to an application media/transport stack.

Normative known-answer tests for these functions (except where noted) appear in
`vectors/v1.json`.

---

## 4. Beacon format and rotation

### 4.1 Beacon payload

An Engytita beacon carries an **8-byte EID**:

```
beacon = eid(own_irk, epoch)
```

Encoding into a carrier (e.g. BLE Service Data) is specified by the platform
adapter (see `engytita-ble` for byte layout). The core protocol treats the
beacon as exactly 8 octets.

### 4.2 Rotation

EIDs MUST rotate when `epoch` changes. Implementations advertising beacons
MUST recompute `eid` for the current epoch.

### 4.3 Resolution window

A resolver that knows peer IRKs MUST precompute EIDs for each known peer over
the epoch window `{epoch - 1, epoch, epoch + 1}` (using saturating arithmetic
at the edges of the `u64` range). Resolution of a received 8-byte beacon MUST
map to at most one `PeerId` among stored contacts. If two distinct contacts
would share an EID in the window, rebuild MUST fail (implementations MUST NOT
silently overwrite).

Equality comparison of EID octets during resolve MUST be constant-time with
respect to the compared bytes (no early-exit on mismatch). Resolve MUST scan
all precomputed entries before returning a miss or hit result (no early exit
on the first match or miss mid-table). The final `Option`/`null` return may
still branch on whether any entry matched.

Resolution proves identity of a *known* peer only. It does **not** authorize a
session (see §6).

---

## 5. Pairing handshake and SAS

### 5.1 Pattern

Pairing MUST use:

```
Noise_XX_25519_ChaChaPoly_SHA256
```

as defined by the Noise Protocol Framework. Static keys are the devices'
long-term X25519 identities. Ephemeral keys MUST be supplied from caller
entropy (the protocol core MUST NOT read an OS CSPRNG).

Engytita MUST NOT hash, transmit, or otherwise process contact identifiers
(phone numbers, emails, social handles, etc.) in the handshake. PrivateDrop
(USENIX Security 2021) demonstrated that AirDrop-style identifier hashes fall
to trivial brute-force; Engytita authenticates cryptographic keys only.

### 5.2 Sans-I/O state machine

The handshake is a state machine. The implementation MUST expose states
equivalent to:

- `AwaitingMessage` - need inbound ciphertext
- `SendMessage(bytes)` - outbound ciphertext to transmit
- `ConfirmSas { digits }` - wait for out-of-band user confirmation of these digits
- `Complete { peer_id }` - success; sealed `PeerRecord` is taken via a dedicated API
- `Failed(error)` - terminal failure

The core MUST NOT open sockets, radios, or files.

### 5.3 Mandatory SAS

After the Noise XX handshake finishes, both parties MUST compute:

```
digits = sas_digits(handshake_hash)
```

where `handshake_hash` is the Noise handshake hash `h` at the end of the
handshake. Both users MUST compare the six digits out-of-band (e.g. verbally).
Pairing MUST NOT proceed to IRK exchange or `Complete` unless the local user
confirms a match by supplying the digits they entered/observed; the
implementation MUST constant-time compare those digits to the
handshake-derived SAS and MUST fail the session on mismatch.

Without SAS, XX is MITM-able and the construction is decorative. SAS is
**mandatory**, not optional.

### 5.4 IRK exchange and pairwise root

After SAS confirmation, both sides MUST exchange their 32-byte IRKs as
payloads inside the Noise **transport** channel (post-`Split()`).

Let `k1` and `k2` be the two 32-byte keys produced by Noise `Split()`. Both
parties MUST derive:

```
pairwise_root = pairwise_root(k1, k2)
```

using the same `k1`/`k2` ordering defined by Noise (identical on both sides).

A successful pairing yields a `PeerRecord`:

- `peer_id` = `peer_id(remote_static_public)`
- `peer_static_public` = remote static public key
- `peer_irk` = IRK received over the transport channel
- `pairwise_root` = as above

---

## 6. Consent and revocation semantics

### 6.1 Resolution is not authorization

A resolvable peer is **not** an authorized peer. Resolution only proves that a
beacon was produced by a known IRK. Every session MUST still require explicit
per-session acceptance under the local availability policy.

### 6.2 Availability

Local availability MUST be one of:

- `Off` - resolution MAY still run locally; session request and accept MUST be refused.
- `ContactsOnly` - any paired contact MAY request/accept subject to session state rules.
- `Allowlist(peers)` - only listed `PeerId`s MAY request/accept.

### 6.3 Session states

Per-peer session state MUST be drawn from:

`Idle`, `Requested`, `Accepted`, `Declined`, `Expired`, `Revoked`.

Illegal transitions MUST be rejected. Session STS/transport keys MUST be
derived only when state is `Accepted`:

```
sts_key(pairwise_root, nonce)
transport_key(pairwise_root, nonce)
```

### 6.4 Revocation (including asymmetric limitation)

`revoke(peer_id)` MUST immediately and irreversibly delete that peer's stored
IRK and pairwise root from the local contact book. Subsequent resolution of
that peer's beacons MUST fail. Session requests involving that peer MUST fail.

#### Limitation - revocation is asymmetric

**Revocation is asymmetric.** Deleting a peer's material from *your* device
stops *you* from resolving *them*. The revoked peer **retains a copy of your
IRK** and can continue to resolve *your* beacons until you rotate your own IRK
and redistribute the new IRK to every remaining contact.

Implementations MUST expose `rotate_own_irk(new_irk)`. After rotation, every
remaining contact MUST receive the new IRK (via fresh pairing or an
authenticated update over an existing secure channel) or they will stop
resolving you. This limitation MUST be documented in user-facing product copy
where revocation is offered.

---

## 7. Relationship to FiRa CSML

Engytita sits **above** FiRa ControLlee/Controller Session Management (CSML)
and related UWB ranging stacks. It does **not** redefine ranging setup,
slots, or MAC parameters.

Engytita supplies key material into the **provisioned-STS** slot: the 16-byte
`sts_key(pairwise_root, nonce)` is intended for APIs such as Android
`RangingParameters.sessionKeyInfo`. How the platform schedules ranging remains
the platform's responsibility.

On platforms with no seam to inject STS key material (notably iOS Nearby
Interaction), Engytita still secures pairing, consent, and transport key
handoff, but ranging measurements are an untrusted input attested by the
platform, not by Engytita.

---

## 8. Security considerations

### 8.1 BLE MAC rotation (critical)

If Engytita EIDs are carried in BLE advertisements, the platform **MUST**
rotate the BLE random private address on the same schedule as EID rotation
(each epoch boundary, or more frequently).

If the MAC address remains stable across EID rotations, the MAC becomes a
stable tracking identifier and **the entire unlinkability construction is
defeated**, regardless of IRK secrecy.

### 8.2 SAS is mandatory

Skipping SAS confirmation enables active MITM during pairing. Implementations
MUST NOT offer a "skip verification" path in production builds.

### 8.3 No contact-identifier hashing

Implementations MUST NOT incorporate phone numbers, emails, or similar
identifiers into handshake transcripts, beacons, or peer ids.

### 8.4 Entropy and epoch injection

Protocol logic MUST NOT read OS time or OS randomness. Callers MUST supply
fresh entropy for identity creation and Noise ephemerals, and a correct epoch
for beacons. Clock skew is absorbed only by the ±1 resolution window.

### 8.5 Session keys leave the core

STS and transport keys are handed to ranging/media stacks. Long-term secrets
(static key, IRK, pairwise root) MUST NOT be exported across FFI boundaries;
opaque handles are RECOMMENDED.

### 8.6 Asymmetric revocation

See §6.4. Product designs that imply "revoke = they can never find me again"
without IRK rotation are incorrect and unsafe.

---

## Appendix A. Test vectors

File: `vectors/v1.json`

All octet strings are lowercase hex. Implementations MUST pass these fixtures.
The Engytita reference library loads this file in its test suite rather than
hardcoding expected digests, so the file is the interoperability contract.
