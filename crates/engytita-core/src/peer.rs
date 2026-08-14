//! Peer handles and stored peer records.

use crate::derive;
use x25519_dalek::PublicKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Opaque peer handle derived from a static public key — not the key itself.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize)]
pub struct PeerId(pub [u8; 16]);

impl PeerId {
    /// Derive a peer id from an X25519 public key encoding.
    pub fn from_static_public(static_public: &PublicKey) -> Self {
        Self(derive::peer_id(static_public.as_bytes()))
    }

    /// Raw 16-byte encoding.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Locally stored record for a paired peer.
///
/// Created by the pairing handshake (or crate-internal fixtures). Long-term
/// secrets (`peer_irk`, `pairwise_root`) are not part of the public API —
/// prefer consent/session APIs and the resolver rather than reading them out.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PeerRecord {
    peer_id: PeerId,
    #[zeroize(skip)]
    peer_static_public: PublicKey,
    peer_irk: [u8; 32],
    pairwise_root: [u8; 32],
}

impl core::fmt::Debug for PeerRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PeerRecord")
            .field("peer_id", &self.peer_id)
            .field("peer_static_public", &self.peer_static_public)
            .field("peer_irk", &"[redacted]")
            .field("pairwise_root", &"[redacted]")
            .finish()
    }
}

impl PeerRecord {
    /// Assemble a peer record from pairing outputs or trusted host storage.
    ///
    /// Prefer taking the sealed record from a completed pairing session. This
    /// constructor is for reconstituting a record the host already stored — it
    /// does not validate provenance.
    pub fn new(peer_static_public: PublicKey, peer_irk: [u8; 32], pairwise_root: [u8; 32]) -> Self {
        let peer_id = PeerId::from_static_public(&peer_static_public);
        Self {
            peer_id,
            peer_static_public,
            peer_irk,
            pairwise_root,
        }
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn peer_static_public(&self) -> &PublicKey {
        &self.peer_static_public
    }

    #[cfg(any(feature = "std", feature = "heapless"))]
    pub(crate) fn peer_irk(&self) -> &[u8; 32] {
        &self.peer_irk
    }

    #[cfg(feature = "std")]
    pub(crate) fn pairwise_root(&self) -> &[u8; 32] {
        &self.pairwise_root
    }
}
