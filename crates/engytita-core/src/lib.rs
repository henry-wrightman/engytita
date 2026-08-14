//! Engytita protocol core.
//!
//! `no_std`, zero I/O, fully deterministic. Epoch and entropy are always
//! supplied by the caller. Cryptographic primitives are composed from
//! vetted crates - never reimplemented here.
//!
//! This crate establishes *who* a nearby peer is and whether both sides
//! consented. It does not carry application data and does not own a radio.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod derive;
pub mod identity;
pub mod peer;

#[cfg(feature = "std")]
pub mod consent;
#[cfg(feature = "std")]
pub mod pairing;

#[cfg(any(feature = "std", feature = "heapless"))]
pub mod resolver;

pub use derive::{
    eid, pairwise_root_from_transport_keys, peer_id, sas_digits, sts_key, transport_key, LABEL_EID,
    LABEL_PAIRWISE_ROOT, LABEL_PEER_ID, LABEL_SAS, LABEL_STS, LABEL_TRANSPORT,
};
pub use identity::Identity;
pub use peer::{PeerId, PeerRecord};

#[cfg(feature = "std")]
pub use consent::{Availability, ConsentEngine, ConsentError, SessionKeys, SessionState};
#[cfg(feature = "std")]
pub use pairing::{Pairing, PairingError, PairingState};

#[cfg(feature = "heapless")]
pub use resolver::HeaplessResolver;
#[cfg(any(feature = "std", feature = "heapless"))]
pub use resolver::RebuildError;
#[cfg(feature = "std")]
pub use resolver::Resolver;

/// Protocol version label used in domain-separated derivations.
pub const PROTOCOL_VERSION: &str = "v1";

/// Epoch length in seconds (15 minutes).
pub const EPOCH_SECONDS: u64 = 900;

/// Crate is present and builds under `no_std`.
pub fn protocol_name() -> &'static str {
    "engytita"
}

#[cfg(test)]
mod tests;
