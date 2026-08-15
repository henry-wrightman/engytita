//! Drive sans-I/O pairing with stdout SAS prompt.

use anyhow::{bail, Context, Result};
use engytita_core::{ConsentEngine, Pairing, PairingError, PairingState, PeerId, SessionKeys};
use tokio::io::{AsyncBufReadExt, BufReader};

pub struct PairingDrive {
    pub pairing: Pairing,
}

impl PairingDrive {
    pub fn start_initiator(engine: &ConsentEngine, eph: &[u8; 32]) -> Result<(Self, PairingState)> {
        let (pairing, state) = Pairing::initiator(engine.identity(), eph)
            .map_err(|e| anyhow::anyhow!("pairing init: {e:?}"))?;
        Ok((Self { pairing }, state))
    }

    pub fn start_responder(engine: &ConsentEngine, eph: &[u8; 32]) -> Result<(Self, PairingState)> {
        let (pairing, state) = Pairing::responder(engine.identity(), eph)
            .map_err(|e| anyhow::anyhow!("pairing init: {e:?}"))?;
        Ok((Self { pairing }, state))
    }

    pub fn apply_inbound(&mut self, msg: &[u8]) -> PairingState {
        self.pairing.read(msg)
    }

    pub fn poll_after_send(&mut self) -> Option<PairingState> {
        let s = self.pairing.poll();
        match &s {
            PairingState::Failed(PairingError::InvalidState) => None,
            _ => Some(s),
        }
    }
}

pub async fn prompt_sas_and_confirm(
    drive: &mut PairingDrive,
    displayed: &[u8; 6],
) -> Result<PairingState> {
    let shown: String = displayed.iter().map(|d| char::from(b'0' + d)).collect();
    eprintln!("SAS digits (compare out-of-band): {shown}");
    eprint!("Type the 6 digits you confirmed: ");
    let mut line = String::new();
    let mut stdin = BufReader::new(tokio::io::stdin());
    stdin.read_line(&mut line).await?;
    let digits: String = line
        .chars()
        .filter(|c| c.is_ascii_digit())
        .take(6)
        .collect();
    if digits.len() != 6 {
        bail!("need exactly 6 digits");
    }
    let mut arr = [0u8; 6];
    for (i, c) in digits.chars().enumerate() {
        arr[i] = c.to_digit(10).unwrap() as u8;
    }
    Ok(drive.pairing.confirm_sas(&arr))
}

pub fn finish_complete(
    engine: &mut ConsentEngine,
    drive: &mut PairingDrive,
    peer_id: PeerId,
) -> Result<SessionKeys> {
    let record = drive
        .pairing
        .take_peer_record()
        .context("missing peer record after Complete")?;
    assert_eq!(record.peer_id(), peer_id);
    engine.insert_peer(record);
    engine
        .request_session(peer_id)
        .map_err(|e| anyhow::anyhow!("request_session: {e:?}"))?;
    engine
        .accept_session(peer_id)
        .map_err(|e| anyhow::anyhow!("accept_session: {e:?}"))?;
    let nonce = crate::store::random_bytes::<16>();
    let keys = engine
        .session_keys(&peer_id, &nonce)
        .map_err(|e| anyhow::anyhow!("session_keys: {e:?}"))?;
    Ok(keys)
}

pub fn log_keys_ok(keys: &SessionKeys) {
    eprintln!(
        "session keys derived (sts={} transport={} bytes) — not printed",
        keys.sts_key.len(),
        keys.transport_key.len()
    );
}
