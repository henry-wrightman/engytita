//! Consent and session authorization.
//!
//! Resolution proves *who* a peer is. It does **not** authorize a session.
//! Every session still requires explicit per-session acceptance under the
//! current [`Availability`] policy.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::derive::{sts_key, transport_key};
use crate::identity::Identity;
use crate::peer::{PeerId, PeerRecord};

/// Local willingness to engage in sessions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Availability {
    /// Resolution may still run locally, but no session may be requested or accepted.
    #[default]
    Off,
    /// Any paired contact may request / be accepted.
    ContactsOnly,
    /// Only the listed peer ids may request / be accepted.
    Allowlist(Vec<PeerId>),
}

/// Per-peer session lifecycle.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SessionState {
    #[default]
    Idle,
    Requested,
    Accepted,
    Declined,
    Expired,
    Revoked,
}

/// Illegal consent / session transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsentError {
    /// Peer is not in the local contact book (or was revoked).
    UnknownPeer,
    /// Current [`Availability`] forbids the operation.
    Unavailable,
    /// Peer is not on the allowlist.
    NotAllowlisted,
    /// Transition is not valid from the current [`SessionState`].
    IllegalTransition,
    /// Session is not in [`SessionState::Accepted`].
    NotAccepted,
}

/// STS + transport keys for an accepted session (handoff to ranging / media).
///
/// `Debug` redacts key material. Prefer zeroizing after handoff when possible.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    pub sts_key: [u8; 16],
    pub transport_key: [u8; 32],
}

impl core::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("sts_key", &"[redacted]")
            .field("transport_key", &"[redacted]")
            .finish()
    }
}

/// Contact book + availability + per-peer session state.
///
/// Owns the local [`Identity`] so IRK rotation stays consistent with consent.
pub struct ConsentEngine {
    identity: Identity,
    peers: BTreeMap<PeerId, PeerRecord>,
    sessions: BTreeMap<PeerId, SessionState>,
    availability: Availability,
}

impl ConsentEngine {
    pub fn new(identity: Identity) -> Self {
        Self {
            identity,
            peers: BTreeMap::new(),
            sessions: BTreeMap::new(),
            availability: Availability::Off,
        }
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn identity_mut(&mut self) -> &mut Identity {
        &mut self.identity
    }

    pub fn availability(&self) -> &Availability {
        &self.availability
    }

    pub fn set_availability(&mut self, availability: Availability) {
        self.availability = availability;
    }

    /// Insert or replace a paired peer (typically after [`crate::pairing::Pairing`] completes).
    pub fn insert_peer(&mut self, record: PeerRecord) {
        let id = record.peer_id();
        self.peers.insert(id, record);
        self.sessions.entry(id).or_insert(SessionState::Idle);
    }

    pub fn peer(&self, peer_id: &PeerId) -> Option<&PeerRecord> {
        self.peers.get(peer_id)
    }

    pub fn peers(&self) -> impl Iterator<Item = (&PeerId, &PeerRecord)> {
        self.peers.iter()
    }

    pub fn session_state(&self, peer_id: &PeerId) -> Option<SessionState> {
        self.sessions.get(peer_id).copied()
    }

    /// Snapshot of peer records for [`crate::Resolver::rebuild`].
    pub fn peer_records(&self) -> Vec<PeerRecord> {
        self.peers.values().cloned().collect()
    }

    fn sessions_allowed(&self, peer_id: &PeerId) -> Result<(), ConsentError> {
        match &self.availability {
            Availability::Off => Err(ConsentError::Unavailable),
            Availability::ContactsOnly => {
                if self.peers.contains_key(peer_id) {
                    Ok(())
                } else {
                    Err(ConsentError::UnknownPeer)
                }
            }
            Availability::Allowlist(list) => {
                if !self.peers.contains_key(peer_id) {
                    return Err(ConsentError::UnknownPeer);
                }
                if list.iter().any(|p| p == peer_id) {
                    Ok(())
                } else {
                    Err(ConsentError::NotAllowlisted)
                }
            }
        }
    }

    /// Local user requests a session with a resolvable/paired peer.
    ///
    /// A resolvable peer is not automatically authorized - availability and an
    /// explicit accept are still required.
    pub fn request_session(&mut self, peer_id: PeerId) -> Result<(), ConsentError> {
        self.sessions_allowed(&peer_id)?;
        let state = self
            .sessions
            .get_mut(&peer_id)
            .ok_or(ConsentError::UnknownPeer)?;
        match *state {
            SessionState::Idle | SessionState::Declined | SessionState::Expired => {
                *state = SessionState::Requested;
                Ok(())
            }
            _ => Err(ConsentError::IllegalTransition),
        }
    }

    /// Local user accepts a requested session.
    pub fn accept_session(&mut self, peer_id: PeerId) -> Result<(), ConsentError> {
        self.sessions_allowed(&peer_id)?;
        let state = self
            .sessions
            .get_mut(&peer_id)
            .ok_or(ConsentError::UnknownPeer)?;
        match *state {
            SessionState::Requested => {
                *state = SessionState::Accepted;
                Ok(())
            }
            _ => Err(ConsentError::IllegalTransition),
        }
    }

    /// Local user declines a requested session.
    pub fn decline_session(&mut self, peer_id: PeerId) -> Result<(), ConsentError> {
        // Declining is allowed even when Availability is Off (reject inbound).
        let state = self
            .sessions
            .get_mut(&peer_id)
            .ok_or(ConsentError::UnknownPeer)?;
        match *state {
            SessionState::Requested => {
                *state = SessionState::Declined;
                Ok(())
            }
            _ => Err(ConsentError::IllegalTransition),
        }
    }

    /// Mark an accepted/requested session expired.
    pub fn expire_session(&mut self, peer_id: PeerId) -> Result<(), ConsentError> {
        let state = self
            .sessions
            .get_mut(&peer_id)
            .ok_or(ConsentError::UnknownPeer)?;
        match *state {
            SessionState::Requested | SessionState::Accepted => {
                *state = SessionState::Expired;
                Ok(())
            }
            _ => Err(ConsentError::IllegalTransition),
        }
    }

    /// Delete the peer's IRK and pairwise root immediately and irreversibly.
    ///
    /// # Asymmetry (limitation)
    ///
    /// Revocation is **asymmetric**. This removes *their* material from *your*
    /// device, so you can no longer resolve their beacons or derive session
    /// keys. The revoked peer **retains a copy of your IRK** and can still
    /// resolve *your* beacons until you call
    /// [`Identity::rotate_own_irk`](crate::Identity::rotate_own_irk) and
    /// redistribute the new IRK to remaining contacts.
    pub fn revoke(&mut self, peer_id: PeerId) -> Result<(), ConsentError> {
        if self.peers.remove(&peer_id).is_none() {
            return Err(ConsentError::UnknownPeer);
        }
        self.sessions.insert(peer_id, SessionState::Revoked);
        if let Availability::Allowlist(list) = &mut self.availability {
            list.retain(|p| p != &peer_id);
        }
        Ok(())
    }

    /// Rotate the local IRK. See [`Identity::rotate_own_irk`] for redistribution
    /// consequences.
    pub fn rotate_own_irk(&mut self, new_irk: [u8; 32]) {
        self.identity.rotate_own_irk(new_irk);
    }

    /// Derive STS + transport keys for an **accepted** session.
    pub fn session_keys(
        &self,
        peer_id: &PeerId,
        nonce: &[u8; 16],
    ) -> Result<SessionKeys, ConsentError> {
        let state = self
            .sessions
            .get(peer_id)
            .copied()
            .ok_or(ConsentError::UnknownPeer)?;
        if state != SessionState::Accepted {
            return Err(ConsentError::NotAccepted);
        }
        let record = self.peers.get(peer_id).ok_or(ConsentError::UnknownPeer)?;
        Ok(SessionKeys {
            sts_key: sts_key(record.pairwise_root(), nonce),
            transport_key: transport_key(record.pairwise_root(), nonce),
        })
    }
}
