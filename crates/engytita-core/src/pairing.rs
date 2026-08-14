//! Noise_XX pairing handshake (sans-I/O) with mandatory SAS and IRK exchange.
//!
//! Pattern: `Noise_XX_25519_ChaChaPoly_SHA256`.
//!
//! Engytita never hashes or transmits contact identifiers (phone numbers,
//! emails, etc.). PrivateDrop (USENIX Sec '21) showed identifier hashes fall
//! to trivial brute-force; this handshake authenticates static keys only.

use alloc::vec::Vec;

use rand_core::{CryptoRng, RngCore};
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::{Builder, HandshakeState, TransportState};
use subtle::ConstantTimeEq;
use x25519_dalek::PublicKey;
use zeroize::Zeroize;

use crate::derive::{pairwise_root_from_transport_keys, sas_digits};
use crate::identity::Identity;
use crate::peer::{PeerId, PeerRecord};

const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const MAX_MSG: usize = 512;

/// Errors from the pairing state machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PairingError {
    /// Snow builder / crypto init failed.
    Init,
    /// Message could not be read or written (decrypt, turn-taking, length).
    Handshake,
    /// Called when the machine is not waiting for that event.
    InvalidState,
    /// SAS was rejected by the caller.
    SasRejected,
    /// User-entered SAS digits did not match the handshake-derived digits.
    SasMismatch,
    /// Remote static key encoding was not 32 bytes.
    BadRemoteKey,
}

/// Public state observed by the caller after each drive step.
#[derive(Clone, Debug)]
pub enum PairingState {
    /// Waiting for the peer's next ciphertext.
    AwaitingMessage,
    /// Caller must transmit these bytes, then continue (see [`Pairing::poll`] after
    /// the initiator's final handshake flight).
    SendMessage(Vec<u8>),
    /// Out-of-band compare these six digits (`0..=9` each); then
    /// [`Pairing::confirm_sas`] with the digits the local user entered.
    ConfirmSas {
        digits: [u8; 6],
    },
    /// Pairing finished. Take the sealed peer record via [`Pairing::take_peer_record`].
    Complete {
        peer_id: PeerId,
    },
    Failed(PairingError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Initiator,
    Responder,
}

struct ConfirmData {
    transport: Box<TransportState>,
    pairwise_root: [u8; 32],
    remote_static: [u8; 32],
    digits: [u8; 6],
}

enum Stage {
    Handshake(Box<HandshakeState>),
    /// Initiator wrote the final XX message; after the caller transmits it, [`Pairing::poll`]
    /// advances to [`Stage::Confirm`].
    FinalFlight {
        data: ConfirmData,
    },
    Confirm(ConfirmData),
    Irk {
        transport: Box<TransportState>,
        pairwise_root: [u8; 32],
        remote_static: [u8; 32],
        peer_irk: Option<[u8; 32]>,
        sent_own: bool,
    },
    /// Outbound IRK was returned via [`PairingState::SendMessage`]; [`Pairing::poll`] completes.
    FinalIrkSend {
        pairwise_root: [u8; 32],
        remote_static: [u8; 32],
        peer_irk: [u8; 32],
    },
    /// Sealed peer record available via [`Pairing::take_peer_record`].
    Done(Option<PeerRecord>),
    Failed,
}

/// Sans-I/O pairing session.
///
/// The caller feeds inbound bytes and ships outbound bytes. Core never touches
/// a transport. Ephemeral X25519 material is **caller-injected** (no RNG here).
pub struct Pairing {
    role: Role,
    own_irk: [u8; 32],
    static_private: [u8; 32],
    stage: Stage,
}

impl Pairing {
    /// Start as Noise initiator. `ephemeral` is the X25519 ephemeral private key.
    pub fn initiator(
        identity: &Identity,
        ephemeral: &[u8; 32],
    ) -> Result<(Self, PairingState), PairingError> {
        let mut pairing = Self::new(Role::Initiator, identity, ephemeral)?;
        let state = pairing.write_handshake()?;
        Ok((pairing, state))
    }

    /// Start as Noise responder. `ephemeral` is the X25519 ephemeral private key.
    pub fn responder(
        identity: &Identity,
        ephemeral: &[u8; 32],
    ) -> Result<(Self, PairingState), PairingError> {
        let pairing = Self::new(Role::Responder, identity, ephemeral)?;
        Ok((pairing, PairingState::AwaitingMessage))
    }

    fn new(role: Role, identity: &Identity, ephemeral: &[u8; 32]) -> Result<Self, PairingError> {
        let static_private = identity.static_secret().to_bytes();
        let params = PATTERN.parse().map_err(|_| PairingError::Init)?;
        let builder = Builder::with_resolver(params, Box::new(SealedResolver::default()))
            .local_private_key(&static_private)
            .fixed_ephemeral_key_for_testing_only(ephemeral);
        let hs = match role {
            Role::Initiator => builder.build_initiator(),
            Role::Responder => builder.build_responder(),
        }
        .map_err(|_| PairingError::Init)?;

        Ok(Self {
            role,
            own_irk: *identity.irk(),
            static_private,
            stage: Stage::Handshake(Box::new(hs)),
        })
    }

    /// Advance after transmitting a final handshake or final IRK flight.
    pub fn poll(&mut self) -> PairingState {
        match core::mem::replace(&mut self.stage, Stage::Failed) {
            Stage::FinalFlight { data } => {
                let digits = data.digits;
                self.stage = Stage::Confirm(data);
                PairingState::ConfirmSas { digits }
            }
            Stage::FinalIrkSend {
                pairwise_root,
                remote_static,
                peer_irk,
            } => {
                let public = PublicKey::from(remote_static);
                let record = PeerRecord::new(public, peer_irk, pairwise_root);
                let peer_id = record.peer_id();
                self.stage = Stage::Done(Some(record));
                PairingState::Complete { peer_id }
            }
            other => {
                self.stage = other;
                self.fail(PairingError::InvalidState)
            }
        }
    }

    /// Feed an inbound message; returns the next public state.
    pub fn read(&mut self, message: &[u8]) -> PairingState {
        match &self.stage {
            Stage::Handshake(_) => self.read_handshake(message),
            Stage::Irk { .. } => self.read_irk(message),
            _ => self.fail(PairingError::InvalidState),
        }
    }

    /// Confirm SAS with the six digits the local user entered (`0..=9` each).
    ///
    /// Digits are compared in constant time to the handshake-derived SAS. On
    /// mismatch the session fails with [`PairingError::SasMismatch`]. On match,
    /// IRKs are exchanged inside the encrypted Noise channel.
    pub fn confirm_sas(&mut self, digits: &[u8; 6]) -> PairingState {
        let data = match core::mem::replace(&mut self.stage, Stage::Failed) {
            Stage::Confirm(data) => data,
            other => {
                self.stage = other;
                return self.fail(PairingError::InvalidState);
            }
        };

        if !bool::from(digits.ct_eq(&data.digits)) {
            return self.fail(PairingError::SasMismatch);
        }

        self.stage = Stage::Irk {
            transport: data.transport,
            pairwise_root: data.pairwise_root,
            remote_static: data.remote_static,
            peer_irk: None,
            sent_own: false,
        };

        match self.role {
            Role::Initiator => self.write_irk(),
            Role::Responder => PairingState::AwaitingMessage,
        }
    }

    /// Abort pairing because SAS did not match (or the user cancelled).
    pub fn reject_sas(&mut self) -> PairingState {
        match self.stage {
            Stage::Confirm(_) | Stage::FinalFlight { .. } => self.fail(PairingError::SasRejected),
            _ => self.fail(PairingError::InvalidState),
        }
    }

    /// Take the sealed [`PeerRecord`] after [`PairingState::Complete`].
    ///
    /// Returns `None` if pairing is not complete or the record was already taken.
    pub fn take_peer_record(&mut self) -> Option<PeerRecord> {
        match &mut self.stage {
            Stage::Done(slot) => slot.take(),
            _ => None,
        }
    }

    fn write_handshake(&mut self) -> Result<PairingState, PairingError> {
        let mut buf = [0u8; MAX_MSG];
        let (n, finished) = {
            let hs = match &mut self.stage {
                Stage::Handshake(hs) => hs,
                _ => return Err(PairingError::InvalidState),
            };
            let n = hs
                .write_message(&[], &mut buf)
                .map_err(|_| PairingError::Handshake)?;
            (n, hs.is_handshake_finished())
        };
        let msg = buf[..n].to_vec();
        if finished {
            let data = self.extract_confirm_data()?;
            self.stage = Stage::FinalFlight { data };
            Ok(PairingState::SendMessage(msg))
        } else {
            Ok(PairingState::SendMessage(msg))
        }
    }

    fn read_handshake(&mut self, message: &[u8]) -> PairingState {
        let finished = {
            let hs = match &mut self.stage {
                Stage::Handshake(hs) => hs,
                _ => return self.fail(PairingError::InvalidState),
            };
            let mut payload = [0u8; MAX_MSG];
            if hs.read_message(message, &mut payload).is_err() {
                return self.fail(PairingError::Handshake);
            }
            hs.is_handshake_finished()
        };

        if finished {
            match self.extract_confirm_data() {
                Ok(data) => {
                    let digits = data.digits;
                    self.stage = Stage::Confirm(data);
                    PairingState::ConfirmSas { digits }
                }
                Err(e) => self.fail(e),
            }
        } else {
            match self.write_handshake() {
                Ok(state) => state,
                Err(e) => self.fail(e),
            }
        }
    }

    fn extract_confirm_data(&mut self) -> Result<ConfirmData, PairingError> {
        let mut hs = match core::mem::replace(&mut self.stage, Stage::Failed) {
            Stage::Handshake(hs) => hs,
            other => {
                self.stage = other;
                return Err(PairingError::InvalidState);
            }
        };

        let (k1, k2) = hs.dangerously_get_raw_split();
        let pairwise_root = pairwise_root_from_transport_keys(&k1, &k2);
        let digits = sas_digits(hs.get_handshake_hash());
        let remote = hs.get_remote_static().ok_or(PairingError::BadRemoteKey)?;
        if remote.len() != 32 {
            return Err(PairingError::BadRemoteKey);
        }
        let mut remote_static = [0u8; 32];
        remote_static.copy_from_slice(remote);

        let transport = hs
            .into_transport_mode()
            .map_err(|_| PairingError::Handshake)?;

        Ok(ConfirmData {
            transport: Box::new(transport),
            pairwise_root,
            remote_static,
            digits,
        })
    }

    fn write_irk(&mut self) -> PairingState {
        let mut buf = [0u8; MAX_MSG];
        let (n, pairwise_root, remote_static, peer_irk) = {
            let Stage::Irk {
                transport,
                pairwise_root,
                remote_static,
                peer_irk,
                sent_own,
            } = &mut self.stage
            else {
                return self.fail(PairingError::InvalidState);
            };
            let n = match transport.write_message(&self.own_irk, &mut buf) {
                Ok(n) => n,
                Err(_) => return self.fail(PairingError::Handshake),
            };
            *sent_own = true;
            (n, *pairwise_root, *remote_static, *peer_irk)
        };
        let msg = buf[..n].to_vec();

        if let Some(peer_irk) = peer_irk {
            self.stage = Stage::FinalIrkSend {
                pairwise_root,
                remote_static,
                peer_irk,
            };
        }

        PairingState::SendMessage(msg)
    }

    fn read_irk(&mut self, message: &[u8]) -> PairingState {
        {
            let Stage::Irk {
                transport,
                peer_irk,
                ..
            } = &mut self.stage
            else {
                return self.fail(PairingError::InvalidState);
            };
            let mut payload = [0u8; 64];
            let n = match transport.read_message(message, &mut payload) {
                Ok(n) => n,
                Err(_) => return self.fail(PairingError::Handshake),
            };
            if n != 32 {
                return self.fail(PairingError::Handshake);
            }
            let mut irk = [0u8; 32];
            irk.copy_from_slice(&payload[..32]);
            *peer_irk = Some(irk);
        }

        let sent_own = match &self.stage {
            Stage::Irk { sent_own, .. } => *sent_own,
            _ => return self.fail(PairingError::InvalidState),
        };

        if !sent_own {
            self.write_irk()
        } else {
            self.complete()
        }
    }

    fn complete(&mut self) -> PairingState {
        let (pairwise_root, remote_static, peer_irk) =
            match core::mem::replace(&mut self.stage, Stage::Failed) {
                Stage::Irk {
                    pairwise_root,
                    remote_static,
                    peer_irk: Some(peer_irk),
                    sent_own: true,
                    ..
                } => (pairwise_root, remote_static, peer_irk),
                other => {
                    self.stage = other;
                    return self.fail(PairingError::InvalidState);
                }
            };

        let public = PublicKey::from(remote_static);
        let record = PeerRecord::new(public, peer_irk, pairwise_root);
        let peer_id = record.peer_id();
        self.stage = Stage::Done(Some(record));
        PairingState::Complete { peer_id }
    }

    fn fail(&mut self, err: PairingError) -> PairingState {
        self.stage = Stage::Failed;
        PairingState::Failed(err)
    }
}

impl Drop for Pairing {
    fn drop(&mut self) {
        self.static_private.zeroize();
        self.own_irk.zeroize();
    }
}

/// Resolver that never draws OS entropy. Ephemeral DH keys are supplied via
/// `fixed_ephemeral_key_for_testing_only`; this RNG exists only because snow
/// requires one at build time and must not be used for protocol secrets.
#[derive(Default)]
struct SealedResolver {
    inner: DefaultResolver,
}

impl CryptoResolver for SealedResolver {
    fn resolve_rng(&self) -> Option<Box<dyn snow::types::Random>> {
        Some(Box::new(PanicRng))
    }

    fn resolve_dh(&self, choice: &snow::params::DHChoice) -> Option<Box<dyn snow::types::Dh>> {
        self.inner.resolve_dh(choice)
    }

    fn resolve_hash(
        &self,
        choice: &snow::params::HashChoice,
    ) -> Option<Box<dyn snow::types::Hash>> {
        self.inner.resolve_hash(choice)
    }

    fn resolve_cipher(
        &self,
        choice: &snow::params::CipherChoice,
    ) -> Option<Box<dyn snow::types::Cipher>> {
        self.inner.resolve_cipher(choice)
    }
}

/// Panics if snow attempts to draw randomness (ephemeral must be caller-injected).
struct PanicRng;

impl RngCore for PanicRng {
    fn next_u32(&mut self) -> u32 {
        panic!("engytita-core: snow requested RNG; ephemeral must be caller-injected");
    }

    fn next_u64(&mut self) -> u64 {
        panic!("engytita-core: snow requested RNG; ephemeral must be caller-injected");
    }

    fn fill_bytes(&mut self, _dest: &mut [u8]) {
        panic!("engytita-core: snow requested RNG; ephemeral must be caller-injected");
    }

    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand_core::Error> {
        panic!("engytita-core: snow requested RNG; ephemeral must be caller-injected");
    }
}

impl CryptoRng for PanicRng {}
impl snow::types::Random for PanicRng {}
