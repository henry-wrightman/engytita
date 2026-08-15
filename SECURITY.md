# Security Policy

Engytita is a proximity-identity protocol library. Treat cryptographic and
consent bugs as security issues even when they do not involve remote code
execution.

## Supported versions

Security fixes are applied on the latest published release on the `main`
branch. Pre-1.0 (`0.x`) may include breaking changes alongside fixes.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security reports.**

1. Prefer **GitHub Private Vulnerability Reporting** for this repository  
   (Security → “Report a vulnerability”).
2. If that is unavailable, contact the repository maintainers via a private
   channel listed on their GitHub profiles and include a clear subject such as
   `SECURITY: engytita …`, plus impact and a minimal reproduction when possible.

We aim to acknowledge reports within **7 days** and to share a remediation
plan or status update within **30 days**. Please give us a reasonable window
to fix and disclose before posting publicly.

## Scope

In scope (non-exhaustive):

- Breaks in pairing, SAS, IRK secrecy, or session-key derivation
- Failures of beacon unlinkability / resolution privacy assumptions
- Consent bypasses (resolvable peer treated as authorized)
- Unsafe FFI boundary leaks of long-term key material
- Supply-chain issues in our published crates or release artifacts

Out of scope:

- Bugs that require physical possession of an unlocked device and are already
  inherent to the platform BLE/OS stack
- Issues solely in third-party ranging / media stacks that consume session keys
- Denial of service against local demos without a security boundary impact

## Safe harbor

We will not pursue legal action against good-faith research that follows this
policy, avoids privacy violations of third parties, and does not exploit a
vulnerability beyond what is needed to demonstrate it.
