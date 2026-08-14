//! Long-term device identity.

use crate::derive::{self, eid};
use crate::peer::PeerId;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Long-term identity for this device.
///
/// Constructed only from caller-injected entropy - this type never reads an
/// RNG or clock.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Identity {
    static_secret: StaticSecret,
    irk: [u8; 32],
}

impl Identity {
    /// Build an identity from caller-supplied key material.
    ///
    /// * `static_secret` - 32-byte X25519 seed (clamped by `x25519-dalek`)
    /// * `irk` - 32-byte Identity Resolving Key
    pub fn from_parts(static_secret: [u8; 32], irk: [u8; 32]) -> Self {
        Self {
            static_secret: StaticSecret::from(static_secret),
            irk,
        }
    }

    /// Split 64 bytes of entropy into static secret (first 32) and IRK (last 32).
    pub fn from_entropy64(entropy: [u8; 64]) -> Self {
        let mut static_secret = [0u8; 32];
        let mut irk = [0u8; 32];
        static_secret.copy_from_slice(&entropy[..32]);
        irk.copy_from_slice(&entropy[32..]);
        Self::from_parts(static_secret, irk)
    }

    /// X25519 public key corresponding to this identity's static secret.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.static_secret)
    }

    /// Opaque peer handle derived from this identity's static public key.
    pub fn peer_id(&self) -> PeerId {
        PeerId(derive::peer_id(self.public_key().as_bytes()))
    }

    /// Identity Resolving Key (secret). Used internally for pairing IRK exchange.
    ///
    /// Callers that only need a beacon MUST use [`Self::beacon_eid`] instead.
    #[cfg(feature = "std")]
    pub(crate) fn irk(&self) -> &[u8; 32] {
        &self.irk
    }

    /// Ephemeral identifier for `epoch`, suitable for a proximity beacon.
    pub fn beacon_eid(&self, epoch: u64) -> [u8; 8] {
        eid(&self.irk, epoch)
    }

    /// Replace this device's Identity Resolving Key.
    ///
    /// # Asymmetric revocation and redistribution
    ///
    /// Revoking a peer deletes *their* IRK from your store, but revocation is
    /// **asymmetric**: the revoked peer retains a copy of *your* IRK and can
    /// still resolve your beacons until you rotate. After `rotate_own_irk`,
    /// **every remaining contact must receive the new IRK** (fresh pairing or
    /// an authenticated IRK-update over an existing channel) or they will stop
    /// resolving you.
    pub fn rotate_own_irk(&mut self, new_irk: [u8; 32]) {
        self.irk = new_irk;
    }

    /// Access the static secret for handshake state machines.
    #[cfg(feature = "std")]
    pub(crate) fn static_secret(&self) -> &StaticSecret {
        &self.static_secret
    }
}
