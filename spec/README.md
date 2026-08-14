# Engytita specification

This directory holds the **normative** Engytita protocol documents and
interoperability test vectors.

It is intended to be extracted into a standalone repository and consumed as a
git submodule once a second independent implementer exists. Until then it
lives in-tree next to the reference Rust library. Treat `engytita-v1.md` and
`vectors/` as the contract; the Rust code is one implementation of that
contract.

| Path | Role |
|------|------|
| `engytita-v1.md` | Normative v1 protocol specification (RFC 2119) |
| `vectors/v1.json` | Deterministic, hex-encoded known-answer fixtures |

The reference `engytita-core` test suite **loads** `vectors/v1.json` rather
than hardcoding expected digests.
