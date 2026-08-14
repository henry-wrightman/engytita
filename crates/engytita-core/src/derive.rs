//! Domain-separated key schedule (HKDF-SHA256 / HMAC-SHA256).
//!
//! All labels are versioned. Epoch and entropy are caller-supplied; this
//! module never reads a clock or RNG.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Domain-separation label for ephemeral identifiers.
pub const LABEL_EID: &[u8] = b"engytita/v1/eid";
/// Domain-separation label for opaque peer handles.
pub const LABEL_PEER_ID: &[u8] = b"engytita/v1/peerid";
/// Domain-separation label for FiRa/UWB STS key material (16 bytes).
pub const LABEL_STS: &[u8] = b"engytita/v1/sts";
/// Domain-separation label for transport session keys (32 bytes).
pub const LABEL_TRANSPORT: &[u8] = b"engytita/v1/transport";
/// Domain-separation label for short authentication strings.
pub const LABEL_SAS: &[u8] = b"engytita/v1/sas";
/// Domain-separation label for pairwise root from Noise transport keys.
pub const LABEL_PAIRWISE_ROOT: &[u8] = b"engytita/v1/pairwise-root";

/// `eid(irk, epoch) = HMAC-SHA256(irk, "engytita/v1/eid" || be64(epoch))[0..8]`
pub fn eid(irk: &[u8; 32], epoch: u64) -> [u8; 8] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(irk).expect("HMAC-SHA256 accepts any key length");
    mac.update(LABEL_EID);
    mac.update(&epoch.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

/// `peer_id(static_pub) = HKDF-SHA256(ikm = static_pub, info = "engytita/v1/peerid")[0..16]`
pub fn peer_id(static_public: &[u8; 32]) -> [u8; 16] {
    hkdf_expand(static_public, LABEL_PEER_ID)
}

/// `sts_key(root, nonce) = HKDF-SHA256(ikm = root, info = "engytita/v1/sts" || nonce)[0..16]`
///
/// `nonce` is a caller-supplied 16-byte session nonce. The 16-byte STS key
/// matches what UWB stacks expect for provisioned STS.
pub fn sts_key(root: &[u8; 32], nonce: &[u8; 16]) -> [u8; 16] {
    let mut info = [0u8; LABEL_STS.len() + 16];
    info[..LABEL_STS.len()].copy_from_slice(LABEL_STS);
    info[LABEL_STS.len()..].copy_from_slice(nonce);
    let out: [u8; 16] = hkdf_expand(root, &info);
    info.zeroize();
    out
}

/// `transport_key(root, nonce) = HKDF-SHA256(ikm = root, info = "engytita/v1/transport" || nonce)[0..32]`
pub fn transport_key(root: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    let mut info = [0u8; LABEL_TRANSPORT.len() + 16];
    info[..LABEL_TRANSPORT.len()].copy_from_slice(LABEL_TRANSPORT);
    info[LABEL_TRANSPORT.len()..].copy_from_slice(nonce);
    let out: [u8; 32] = hkdf_expand(root, &info);
    info.zeroize();
    out
}

/// Derive six SAS digits from a Noise handshake hash.
///
/// `HKDF(handshake_hash, info = "engytita/v1/sas")`, first 4 bytes as big-endian
/// `u32`, then `mod 1_000_000`. Each output byte is a decimal digit `0..=9`.
///
/// SAS is **mandatory**: without out-of-band confirmation the XX handshake is
/// MITM-able.
pub fn sas_digits(handshake_hash: &[u8]) -> [u8; 6] {
    let okm: [u8; 4] = hkdf_expand(handshake_hash, LABEL_SAS);
    let n = u32::from_be_bytes(okm) % 1_000_000;
    let mut digits = [0u8; 6];
    let mut rest = n;
    for i in (0..6).rev() {
        digits[i] = (rest % 10) as u8;
        rest /= 10;
    }
    digits
}

/// Fold Noise `Split()` transport keys into the long-term pairwise root.
pub fn pairwise_root_from_transport_keys(k1: &[u8; 32], k2: &[u8; 32]) -> [u8; 32] {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(k1);
    ikm[32..].copy_from_slice(k2);
    let out: [u8; 32] = hkdf_expand(&ikm, LABEL_PAIRWISE_ROOT);
    ikm.zeroize();
    out
}

fn hkdf_expand<const N: usize>(ikm: &[u8], info: &[u8]) -> [u8; N] {
    let hk = hkdf::Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; N];
    hk.expand(info, &mut okm)
        .expect("HKDF-SHA256 OKM length is within limit");
    okm
}
