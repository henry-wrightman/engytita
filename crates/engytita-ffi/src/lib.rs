//! UniFFI surface for Engytita.
//!
//! # Boundary rules
//!
//! - Long-term secrets (static key, IRK, pairwise root) **never** cross this
//!   boundary — only opaque handles.
//! - The only key bytes returned to callers are session STS (16) and transport
//!   (32) keys, for handoff to ranging / media stacks.
//! - Pairing is sans-I/O: the host ships bytes returned in [`PairingEvent`].

use std::sync::{Arc, Mutex};

use engytita_core::{
    Availability, ConsentEngine, ConsentError, Identity, Pairing, PairingError, PairingState,
    PeerId as CorePeerId, PeerRecord, Resolver, SessionState,
};

uniffi::setup_scaffolding!();

/// Opaque peer handle (16 bytes). Not a public key and not a secret.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PeerId {
    pub bytes: Vec<u8>,
}

impl From<CorePeerId> for PeerId {
    fn from(value: CorePeerId) -> Self {
        Self {
            bytes: value.0.to_vec(),
        }
    }
}

impl TryFrom<&PeerId> for CorePeerId {
    type Error = EngytitaError;

    fn try_from(value: &PeerId) -> Result<Self, Self::Error> {
        let arr: [u8; 16] =
            value
                .bytes
                .as_slice()
                .try_into()
                .map_err(|_| EngytitaError::InvalidInput {
                    reason: "peer_id must be 16 bytes".into(),
                })?;
        Ok(CorePeerId(arr))
    }
}

/// Session keys for handoff — the only secret material exported by this crate.
///
/// `Debug` redacts key bytes; do not log the fields themselves.
#[derive(Clone, uniffi::Record)]
pub struct SessionKeys {
    /// 16-byte STS key for a ranging stack (e.g. UWB provisioned STS).
    pub sts_key: Vec<u8>,
    /// 32-byte transport key for a media / app stack.
    pub transport_key: Vec<u8>,
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("sts_key", &"[redacted]")
            .field("transport_key", &"[redacted]")
            .finish()
    }
}

/// Local willingness to engage in sessions.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum AvailabilityMode {
    /// Resolution still works; session request/accept are refused.
    Off,
    /// Any paired contact may request / accept.
    ContactsOnly,
}

/// Sans-I/O pairing step for the host to handle.
#[derive(Clone, Debug, uniffi::Enum)]
pub enum PairingEvent {
    AwaitingMessage,
    SendMessage {
        data: Vec<u8>,
    },
    /// Six decimal digits as a string (e.g. `"483984"`). Confirm out-of-band.
    ConfirmSas {
        digits: String,
    },
    /// Peer was stored in the engine; only the opaque id is returned.
    Complete {
        peer_id: PeerId,
    },
    Failed {
        message: String,
    },
}

/// Errors crossing the FFI boundary (no secret material in messages).
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum EngytitaError {
    #[error("invalid input: {reason}")]
    InvalidInput { reason: String },
    #[error("pairing error: {reason}")]
    Pairing { reason: String },
    #[error("consent error: {reason}")]
    Consent { reason: String },
}

impl From<ConsentError> for EngytitaError {
    fn from(value: ConsentError) -> Self {
        let reason = match value {
            ConsentError::UnknownPeer => "unknown peer",
            ConsentError::Unavailable => "availability off",
            ConsentError::NotAllowlisted => "not allowlisted",
            ConsentError::IllegalTransition => "illegal session transition",
            ConsentError::NotAccepted => "session not accepted",
        };
        Self::Consent {
            reason: reason.into(),
        }
    }
}

fn map_pairing_error(err: PairingError) -> EngytitaError {
    let reason = match err {
        PairingError::Init => "init",
        PairingError::Handshake => "handshake",
        PairingError::InvalidState => "invalid state",
        PairingError::SasRejected => "sas rejected",
        PairingError::SasMismatch => "sas mismatch",
        PairingError::BadRemoteKey => "bad remote key",
    };
    EngytitaError::Pairing {
        reason: reason.into(),
    }
}

fn require_len(data: &[u8], n: usize, what: &str) -> Result<(), EngytitaError> {
    if data.len() != n {
        return Err(EngytitaError::InvalidInput {
            reason: format!("{what} must be {n} bytes"),
        });
    }
    Ok(())
}

fn digits_to_string(digits: [u8; 6]) -> String {
    digits.iter().map(|d| char::from(b'0' + d)).collect()
}

fn parse_sas_digits(digits: &str) -> Result<[u8; 6], EngytitaError> {
    if digits.len() != 6 {
        return Err(EngytitaError::InvalidInput {
            reason: "sas digits must be exactly 6 decimal characters".into(),
        });
    }
    let mut out = [0u8; 6];
    for (i, c) in digits.chars().enumerate() {
        let Some(d) = c.to_digit(10) else {
            return Err(EngytitaError::InvalidInput {
                reason: "sas digits must be decimal 0-9".into(),
            });
        };
        out[i] = d as u8;
    }
    Ok(out)
}

/// Opaque Engytita engine: identity + contacts + consent + resolution.
///
/// Construct with caller-supplied entropy. No OS RNG is used inside.
#[derive(uniffi::Object)]
pub struct Engytita {
    inner: Mutex<ConsentEngine>,
}

#[uniffi::export]
impl Engytita {
    /// Create an engine from 64 bytes of entropy (32 static secret ‖ 32 IRK).
    #[uniffi::constructor]
    pub fn new(entropy: Vec<u8>) -> Result<Arc<Self>, EngytitaError> {
        require_len(&entropy, 64, "entropy")?;
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&entropy);
        let identity = Identity::from_entropy64(arr);
        let mut engine = ConsentEngine::new(identity);
        engine.set_availability(Availability::ContactsOnly);
        Ok(Arc::new(Self {
            inner: Mutex::new(engine),
        }))
    }

    /// This device's opaque peer id (derived from the static public key).
    pub fn peer_id(&self) -> PeerId {
        let eng = self.inner.lock().expect("engine lock");
        eng.identity().peer_id().into()
    }

    /// Set availability policy (`Off` or `ContactsOnly`).
    pub fn set_availability(&self, mode: AvailabilityMode) {
        let mut eng = self.inner.lock().expect("engine lock");
        eng.set_availability(match mode {
            AvailabilityMode::Off => Availability::Off,
            AvailabilityMode::ContactsOnly => Availability::ContactsOnly,
        });
    }

    /// Start Noise XX pairing as initiator. `ephemeral` is 32 bytes of caller entropy.
    pub fn start_pairing_initiator(
        self: Arc<Self>,
        ephemeral: Vec<u8>,
    ) -> Result<Arc<PairingSession>, EngytitaError> {
        require_len(&ephemeral, 32, "ephemeral")?;
        let mut eph = [0u8; 32];
        eph.copy_from_slice(&ephemeral);
        let eng = self.inner.lock().expect("engine lock");
        let (pairing, state) =
            Pairing::initiator(eng.identity(), &eph).map_err(map_pairing_error)?;
        drop(eng);
        Ok(Arc::new(PairingSession::new(self, pairing, state)))
    }

    /// Start Noise XX pairing as responder. `ephemeral` is 32 bytes of caller entropy.
    pub fn start_pairing_responder(
        self: Arc<Self>,
        ephemeral: Vec<u8>,
    ) -> Result<Arc<PairingSession>, EngytitaError> {
        require_len(&ephemeral, 32, "ephemeral")?;
        let mut eph = [0u8; 32];
        eph.copy_from_slice(&ephemeral);
        let eng = self.inner.lock().expect("engine lock");
        let (pairing, state) =
            Pairing::responder(eng.identity(), &eph).map_err(map_pairing_error)?;
        drop(eng);
        Ok(Arc::new(PairingSession::new(self, pairing, state)))
    }

    /// Resolve an 8-byte beacon EID at `epoch` to a known peer, if any.
    pub fn resolve(&self, beacon: Vec<u8>, epoch: u64) -> Result<Option<PeerId>, EngytitaError> {
        require_len(&beacon, 8, "beacon")?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&beacon);
        let eng = self.inner.lock().expect("engine lock");
        let mut resolver = Resolver::new();
        resolver
            .rebuild(&eng.peer_records(), epoch)
            .map_err(|_| EngytitaError::Consent {
                reason: "eid collision in contact book".into(),
            })?;
        Ok(resolver.resolve(&arr).map(Into::into))
    }

    /// Request a session with a paired peer.
    pub fn request_session(&self, peer_id: PeerId) -> Result<(), EngytitaError> {
        let id = CorePeerId::try_from(&peer_id)?;
        self.inner
            .lock()
            .expect("engine lock")
            .request_session(id)
            .map_err(Into::into)
    }

    /// Accept a requested session.
    pub fn accept_session(&self, peer_id: PeerId) -> Result<(), EngytitaError> {
        let id = CorePeerId::try_from(&peer_id)?;
        self.inner
            .lock()
            .expect("engine lock")
            .accept_session(id)
            .map_err(Into::into)
    }

    /// Decline a requested session.
    pub fn decline_session(&self, peer_id: PeerId) -> Result<(), EngytitaError> {
        let id = CorePeerId::try_from(&peer_id)?;
        self.inner
            .lock()
            .expect("engine lock")
            .decline_session(id)
            .map_err(Into::into)
    }

    /// Current session state name for a peer (`"idle"`, `"accepted"`, …), if known.
    pub fn session_state(&self, peer_id: PeerId) -> Result<Option<String>, EngytitaError> {
        let id = CorePeerId::try_from(&peer_id)?;
        Ok(self
            .inner
            .lock()
            .expect("engine lock")
            .session_state(&id)
            .map(|s| {
                match s {
                    SessionState::Idle => "idle",
                    SessionState::Requested => "requested",
                    SessionState::Accepted => "accepted",
                    SessionState::Declined => "declined",
                    SessionState::Expired => "expired",
                    SessionState::Revoked => "revoked",
                }
                .to_string()
            }))
    }

    /// Derive STS + transport keys for an **accepted** session.
    ///
    /// `nonce` must be 16 bytes. These are the only key bytes this API returns.
    pub fn session_keys(
        &self,
        peer_id: PeerId,
        nonce: Vec<u8>,
    ) -> Result<SessionKeys, EngytitaError> {
        require_len(&nonce, 16, "nonce")?;
        let id = CorePeerId::try_from(&peer_id)?;
        let mut n = [0u8; 16];
        n.copy_from_slice(&nonce);
        let keys = self
            .inner
            .lock()
            .expect("engine lock")
            .session_keys(&id, &n)?;
        Ok(SessionKeys {
            sts_key: keys.sts_key.to_vec(),
            transport_key: keys.transport_key.to_vec(),
        })
    }

    /// Revoke a peer (deletes their IRK and pairwise root locally).
    ///
    /// Revocation is asymmetric — see core docs / spec §6.4.
    pub fn revoke(&self, peer_id: PeerId) -> Result<(), EngytitaError> {
        let id = CorePeerId::try_from(&peer_id)?;
        self.inner
            .lock()
            .expect("engine lock")
            .revoke(id)
            .map_err(Into::into)
    }

    /// Rotate this device's IRK. `new_irk` must be 32 bytes.
    ///
    /// Remaining contacts must receive the new IRK or they will stop resolving you.
    pub fn rotate_irk(&self, new_irk: Vec<u8>) -> Result<(), EngytitaError> {
        require_len(&new_irk, 32, "new_irk")?;
        let mut irk = [0u8; 32];
        irk.copy_from_slice(&new_irk);
        self.inner.lock().expect("engine lock").rotate_own_irk(irk);
        Ok(())
    }
}

impl Engytita {
    fn insert_peer(&self, record: PeerRecord) {
        self.inner.lock().expect("engine lock").insert_peer(record);
    }
}

/// In-flight sans-I/O pairing session bound to an [`Engytita`] engine.
#[derive(uniffi::Object)]
pub struct PairingSession {
    engine: Arc<Engytita>,
    pairing: Mutex<Pairing>,
    /// Initial event produced at construction (initiator's first SendMessage, etc.).
    initial: Mutex<Option<PairingEvent>>,
}

impl PairingSession {
    fn new(engine: Arc<Engytita>, pairing: Pairing, state: PairingState) -> Self {
        let mut pairing = pairing;
        let initial = map_state(&engine, &mut pairing, state);
        Self {
            engine,
            pairing: Mutex::new(pairing),
            initial: Mutex::new(Some(initial)),
        }
    }
}

#[uniffi::export]
impl PairingSession {
    /// Return the event produced when the session was created (then clears it).
    ///
    /// Subsequent progress uses [`Self::read`], [`Self::poll`], [`Self::confirm_sas`].
    pub fn take_initial_event(&self) -> PairingEvent {
        self.initial
            .lock()
            .expect("initial lock")
            .take()
            .unwrap_or(PairingEvent::AwaitingMessage)
    }

    /// Feed an inbound ciphertext / handshake message.
    pub fn read(&self, message: Vec<u8>) -> PairingEvent {
        let mut pairing = self.pairing.lock().expect("pairing lock");
        let state = pairing.read(&message);
        map_state(&self.engine, &mut pairing, state)
    }

    /// Advance after transmitting a final handshake or IRK flight.
    pub fn poll(&self) -> PairingEvent {
        let mut pairing = self.pairing.lock().expect("pairing lock");
        let state = pairing.poll();
        map_state(&self.engine, &mut pairing, state)
    }

    /// Confirm SAS with the six digits the local user entered (e.g. `"483984"`).
    ///
    /// Begins encrypted IRK exchange on match; fails on mismatch.
    pub fn confirm_sas(&self, digits: String) -> Result<PairingEvent, EngytitaError> {
        let parsed = parse_sas_digits(&digits)?;
        let mut pairing = self.pairing.lock().expect("pairing lock");
        let state = pairing.confirm_sas(&parsed);
        Ok(map_state(&self.engine, &mut pairing, state))
    }

    /// Abort because SAS mismatched or the user cancelled.
    pub fn reject_sas(&self) -> PairingEvent {
        let mut pairing = self.pairing.lock().expect("pairing lock");
        let state = pairing.reject_sas();
        map_state(&self.engine, &mut pairing, state)
    }
}

fn map_state(engine: &Engytita, pairing: &mut Pairing, state: PairingState) -> PairingEvent {
    match state {
        PairingState::AwaitingMessage => PairingEvent::AwaitingMessage,
        PairingState::SendMessage(data) => PairingEvent::SendMessage { data },
        PairingState::ConfirmSas { digits } => PairingEvent::ConfirmSas {
            digits: digits_to_string(digits),
        },
        PairingState::Complete { peer_id } => {
            if let Some(record) = pairing.take_peer_record() {
                engine.insert_peer(record);
            }
            PairingEvent::Complete {
                peer_id: peer_id.into(),
            }
        }
        PairingState::Failed(err) => PairingEvent::Failed {
            message: match err {
                PairingError::Init => "init",
                PairingError::Handshake => "handshake",
                PairingError::InvalidState => "invalid state",
                PairingError::SasRejected => "sas rejected",
                PairingError::SasMismatch => "sas mismatch",
                PairingError::BadRemoteKey => "bad remote key",
            }
            .into(),
        },
    }
}

#[cfg(test)]
mod tests;
