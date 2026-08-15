//! Unit tests for identity, key schedule, and resolution.

use std::collections::HashSet;
use std::time::Instant;

use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::derive::{eid, peer_id, sts_key, transport_key};
use crate::{Identity, PeerId, PeerRecord, Resolver, EPOCH_SECONDS};

fn parse_hex<const N: usize>(s: &str) -> [u8; N] {
    let bytes = hex::decode(s).expect("valid hex");
    assert_eq!(bytes.len(), N, "hex length for {s}");
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    out
}

fn fixture_peer(seed: u8, irk_seed: u8, root_seed: u8) -> PeerRecord {
    let mut sk_bytes = [seed; 32];
    sk_bytes[0] = seed;
    sk_bytes[31] = seed.wrapping_add(1);
    let sk = StaticSecret::from(sk_bytes);
    let pk = PublicKey::from(&sk);
    let mut irk = [irk_seed; 32];
    irk[0] ^= 0x5a;
    let mut root = [root_seed; 32];
    root[15] ^= 0xa5;
    PeerRecord::new(pk, irk, root)
}

#[test]
fn protocol_constants() {
    assert_eq!(crate::protocol_name(), "engytita");
    assert_eq!(EPOCH_SECONDS, 900);
    assert_eq!(crate::PROTOCOL_VERSION, "v1");
}

#[test]
fn peer_id_as_bytes_round_trip() {
    let peer = fixture_peer(3, 30, 31);
    let id = peer.peer_id();
    assert_eq!(id.as_bytes(), &id.0);
}

#[test]
fn rebuild_skips_duplicate_eid_same_peer() {
    let peer = fixture_peer(6, 60, 61);
    let mut resolver = Resolver::new();
    resolver
        .rebuild(&[peer.clone(), peer.clone()], 7)
        .expect("same peer twice is not a collision");
    assert!(!resolver.is_empty());
    assert_eq!(resolver.len(), 3);
}

/// Known-answer tests loaded from the normative `spec/vectors/v1.json` contract.
mod kats {
    use super::*;
    use crate::derive::{pairwise_root_from_transport_keys, sas_digits};
    use serde::Deserialize;

    const VECTORS_JSON: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../spec/vectors/v1.json"
    ));

    #[derive(Debug, Deserialize)]
    struct Vectors {
        eid: Vec<EidVec>,
        peer_id: Vec<PeerIdVec>,
        sts_key: Vec<StsVec>,
        transport_key: Vec<TransportVec>,
        sas: Vec<SasVec>,
        pairwise_root: Vec<PairwiseVec>,
    }

    #[derive(Debug, Deserialize)]
    struct EidVec {
        irk: String,
        epoch: u64,
        expected: String,
    }

    #[derive(Debug, Deserialize)]
    struct PeerIdVec {
        static_public: String,
        expected: String,
    }

    #[derive(Debug, Deserialize)]
    struct StsVec {
        root: String,
        nonce: String,
        expected: String,
    }

    #[derive(Debug, Deserialize)]
    struct TransportVec {
        root: String,
        nonce: String,
        expected: String,
    }

    #[derive(Debug, Deserialize)]
    struct SasVec {
        handshake_hash: String,
        expected: String,
    }

    #[derive(Debug, Deserialize)]
    struct PairwiseVec {
        k1: String,
        k2: String,
        expected: String,
    }

    fn load() -> Vectors {
        serde_json::from_str(VECTORS_JSON).expect("parse spec/vectors/v1.json")
    }

    #[test]
    fn eid_vectors_from_spec() {
        for v in load().eid {
            let irk = parse_hex::<32>(&v.irk);
            assert_eq!(
                hex::encode(eid(&irk, v.epoch)),
                v.expected,
                "eid epoch {}",
                v.epoch
            );
        }
    }

    #[test]
    fn peer_id_vectors_from_spec() {
        for v in load().peer_id {
            let pk = parse_hex::<32>(&v.static_public);
            assert_eq!(hex::encode(peer_id(&pk)), v.expected);
        }
    }

    #[test]
    fn sts_key_vectors_from_spec() {
        for v in load().sts_key {
            let root = parse_hex::<32>(&v.root);
            let nonce = parse_hex::<16>(&v.nonce);
            assert_eq!(hex::encode(sts_key(&root, &nonce)), v.expected);
        }
    }

    #[test]
    fn transport_key_vectors_from_spec() {
        for v in load().transport_key {
            let root = parse_hex::<32>(&v.root);
            let nonce = parse_hex::<16>(&v.nonce);
            assert_eq!(hex::encode(transport_key(&root, &nonce)), v.expected);
        }
    }

    #[test]
    fn sas_vectors_from_spec() {
        for v in load().sas {
            let hash = hex::decode(&v.handshake_hash).unwrap();
            let digits = sas_digits(&hash);
            assert_eq!(hex::encode(digits), v.expected);
            assert!(digits.iter().all(|d| *d <= 9));
        }
    }

    #[test]
    fn pairwise_root_vectors_from_spec() {
        for v in load().pairwise_root {
            let k1 = parse_hex::<32>(&v.k1);
            let k2 = parse_hex::<32>(&v.k2);
            assert_eq!(
                hex::encode(pairwise_root_from_transport_keys(&k1, &k2)),
                v.expected
            );
        }
    }
}

#[test]
fn eid_rotates_across_adjacent_epochs() {
    let irk = parse_hex::<32>("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let e0 = eid(&irk, 100);
    let e1 = eid(&irk, 101);
    let e2 = eid(&irk, 102);
    assert_ne!(e0, e1);
    assert_ne!(e1, e2);
    assert_ne!(e0, e2);
}

#[test]
fn identity_from_entropy_is_deterministic() {
    let mut entropy = [0u8; 64];
    entropy[..32].copy_from_slice(&[0x11; 32]);
    entropy[32..].copy_from_slice(&[0x22; 32]);
    let a = Identity::from_entropy64(entropy);
    let b = Identity::from_entropy64(entropy);
    assert_eq!(a.public_key().as_bytes(), b.public_key().as_bytes());
    assert_eq!(a.peer_id(), b.peer_id());
    assert_eq!(a.irk(), b.irk());
    assert_eq!(a.beacon_eid(42), b.beacon_eid(42));
    assert_eq!(a.peer_id(), PeerId::from_static_public(&a.public_key()));
}

#[test]
fn resolve_hits_known_peers_and_misses_unknown() {
    let alice = fixture_peer(1, 10, 20);
    let bob = fixture_peer(2, 11, 21);
    let carol_unknown = fixture_peer(3, 12, 22);

    let epoch = 5000u64;
    let mut resolver = Resolver::new();
    resolver
        .rebuild(&[alice.clone(), bob.clone()], epoch)
        .expect("rebuild");

    let alice_eid = eid(alice.peer_irk(), epoch);
    let bob_eid = eid(bob.peer_irk(), epoch);
    let unknown_eid = eid(carol_unknown.peer_irk(), epoch);

    assert_eq!(resolver.resolve(&alice_eid), Some(alice.peer_id()));
    assert_eq!(resolver.resolve(&bob_eid), Some(bob.peer_id()));
    assert_eq!(resolver.resolve(&unknown_eid), None);
}

#[test]
fn resolve_hits_full_epoch_window() {
    let peer = fixture_peer(9, 90, 91);
    let epoch = 10_000u64;
    let mut resolver = Resolver::new();
    resolver
        .rebuild(std::slice::from_ref(&peer), epoch)
        .expect("rebuild");

    for e in [epoch - 1, epoch, epoch + 1] {
        let beacon = eid(peer.peer_irk(), e);
        assert_eq!(
            resolver.resolve(&beacon),
            Some(peer.peer_id()),
            "epoch {e} should resolve"
        );
    }

    let outside = eid(peer.peer_irk(), epoch + 2);
    assert_eq!(resolver.resolve(&outside), None);
}

#[test]
fn forgetting_peer_makes_beacons_unresolvable() {
    let keep = fixture_peer(1, 1, 1);
    let forget = fixture_peer(2, 2, 2);
    let epoch = 777u64;

    let mut resolver = Resolver::new();
    resolver
        .rebuild(&[keep.clone(), forget.clone()], epoch)
        .expect("rebuild");
    let forget_eid = eid(forget.peer_irk(), epoch);
    assert_eq!(resolver.resolve(&forget_eid), Some(forget.peer_id()));

    resolver
        .rebuild(std::slice::from_ref(&keep), epoch)
        .expect("rebuild");
    assert_eq!(resolver.resolve(&forget_eid), None);
    assert_eq!(
        resolver.resolve(&eid(keep.peer_irk(), epoch)),
        Some(keep.peer_id())
    );
}

#[test]
fn unlinkability_1000_epochs_no_repeats_or_structure() {
    let irk = parse_hex::<32>("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    let mut seen = HashSet::with_capacity(1000);
    let mut as_u64 = Vec::with_capacity(1000);

    for epoch in 0..1000u64 {
        let e = eid(&irk, epoch);
        assert!(seen.insert(e), "EID repeated at epoch {epoch}");
        as_u64.push(u64::from_be_bytes(e));
    }

    // No trivial arithmetic progression across the whole series.
    let deltas: Vec<i128> = as_u64
        .windows(2)
        .map(|w| w[1] as i128 - w[0] as i128)
        .collect();
    let first_delta = deltas[0];
    assert!(
        deltas.iter().any(|d| *d != first_delta),
        "EIDs look like an arithmetic sequence"
    );

    // Adjacent EIDs should not be nearly identical (Hamming distance check).
    for window in as_u64.windows(2) {
        let xor = window[0] ^ window[1];
        assert!(
            xor.count_ones() >= 8,
            "adjacent EIDs too similar (hamming {})",
            xor.count_ones()
        );
    }
}

#[test]
fn eid_equality_is_constant_time_helper() {
    let a = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let b = [1u8, 2, 3, 4, 5, 6, 7, 9];
    let c = a;
    assert!(!bool::from(a.ct_eq(&b)));
    assert!(bool::from(a.ct_eq(&c)));
}

#[test]
fn rebuild_1000_peers_fast() {
    let peers: Vec<PeerRecord> = (0..1000u32)
        .map(|i| {
            let mut sk = [0u8; 32];
            sk[..4].copy_from_slice(&i.to_le_bytes());
            let secret = StaticSecret::from(sk);
            let public = PublicKey::from(&secret);
            let mut irk = [0u8; 32];
            irk[..4].copy_from_slice(&i.to_be_bytes());
            let root = [0x5au8; 32];
            PeerRecord::new(public, irk, root)
        })
        .collect();

    let mut resolver = Resolver::new();
    // Warm-up
    resolver.rebuild(&peers, 1_000_000).expect("rebuild");

    let start = Instant::now();
    resolver.rebuild(&peers, 1_000_001).expect("rebuild");
    let elapsed = start.elapsed();
    assert_eq!(resolver.len(), 3000);

    // Criterion (`benches/resolver.rs`) is the authoritative latency check.
    // Debug builds are slower; enforce the <10ms budget only in release.
    if !cfg!(debug_assertions) {
        assert!(
            elapsed.as_millis() < 10,
            "rebuild took {elapsed:?}, expected well under 10ms in release"
        );
    }
}

#[cfg(feature = "heapless")]
#[test]
fn heapless_resolver_round_trip() {
    use crate::{HeaplessResolver, RebuildError};

    let peer = fixture_peer(4, 40, 41);
    let epoch = 42u64;
    let mut resolver = HeaplessResolver::<16>::new();
    assert!(resolver.is_empty());
    resolver
        .rebuild(std::slice::from_ref(&peer), epoch)
        .expect("capacity");
    assert_eq!(resolver.len(), 3);
    let beacon = eid(peer.peer_irk(), epoch);
    assert_eq!(resolver.resolve(&beacon), Some(peer.peer_id()));

    let collider = fixture_peer(5, 40, 42); // same IRK seed as peer
    let mut r2 = HeaplessResolver::<16>::default();
    assert_eq!(
        r2.rebuild(&[peer.clone(), collider], epoch),
        Err(RebuildError::Collision)
    );
    assert!(r2.is_empty());

    let mut tiny = HeaplessResolver::<2>::new();
    assert_eq!(
        tiny.rebuild(std::slice::from_ref(&peer), epoch),
        Err(RebuildError::Full)
    );

    let mut dup = HeaplessResolver::<16>::new();
    dup.rebuild(&[peer.clone(), peer.clone()], epoch)
        .expect("duplicate same peer");
    assert_eq!(dup.len(), 3);
}

#[test]
fn rebuild_fails_on_eid_collision() {
    use crate::RebuildError;

    let alice = fixture_peer(1, 10, 20);
    // Same IRK as alice → same EIDs, different peer id.
    let collider = fixture_peer(2, 10, 21);
    let mut resolver = Resolver::new();
    assert_eq!(
        resolver.rebuild(&[alice, collider], 5000),
        Err(RebuildError::Collision)
    );
    assert!(resolver.is_empty());
}

mod phase2 {
    use super::*;
    use crate::{
        Availability, ConsentEngine, ConsentError, Pairing, PairingError, PairingState,
        SessionKeys, SessionState,
    };

    fn identity(seed: u8) -> Identity {
        let mut entropy = [seed; 64];
        entropy[0] ^= 0x3c;
        entropy[32] ^= 0xc3;
        entropy[63] = seed.wrapping_add(7);
        Identity::from_entropy64(entropy)
    }

    /// Drive two in-memory identities through Noise XX + SAS + IRK exchange.
    fn pair_identities(
        alice: &Identity,
        bob: &Identity,
        eph_a: [u8; 32],
        eph_b: [u8; 32],
    ) -> (PeerRecord, PeerRecord, [u8; 6]) {
        let (mut a, s) = Pairing::initiator(alice, &eph_a).expect("initiator");
        let (mut b, _) = Pairing::responder(bob, &eph_b).expect("responder");

        let PairingState::SendMessage(m1) = s else {
            panic!("expected m1");
        };
        let PairingState::SendMessage(m2) = b.read(&m1) else {
            panic!("expected m2");
        };
        let PairingState::SendMessage(m3) = a.read(&m2) else {
            panic!("expected m3");
        };
        let PairingState::ConfirmSas { digits: da } = a.poll() else {
            panic!("alice SAS");
        };
        let PairingState::ConfirmSas { digits: db } = b.read(&m3) else {
            panic!("bob SAS");
        };
        assert_eq!(da, db, "SAS digits must match");

        let PairingState::SendMessage(irk_a) = a.confirm_sas(&da) else {
            panic!("alice IRK send");
        };
        assert!(matches!(b.confirm_sas(&db), PairingState::AwaitingMessage));

        let PairingState::SendMessage(irk_b) = b.read(&irk_a) else {
            panic!("bob IRK send");
        };
        let PairingState::Complete { .. } = b.poll() else {
            panic!("bob complete");
        };
        let PairingState::Complete { .. } = a.read(&irk_b) else {
            panic!("alice complete");
        };
        let bob_view_of_alice = b.take_peer_record().expect("bob record");
        let alice_view_of_bob = a.take_peer_record().expect("alice record");
        assert!(a.take_peer_record().is_none(), "second take is empty");

        (alice_view_of_bob, bob_view_of_alice, da)
    }

    #[test]
    fn full_pairing_matching_root_and_sas() {
        let alice = identity(1);
        let bob = identity(2);
        let (a_rec, b_rec, digits) = pair_identities(&alice, &bob, [0xA1; 32], [0xB2; 32]);

        assert_eq!(a_rec.pairwise_root(), b_rec.pairwise_root());
        assert_eq!(a_rec.peer_id(), bob.peer_id());
        assert_eq!(b_rec.peer_id(), alice.peer_id());
        assert_eq!(a_rec.peer_irk(), bob.irk());
        assert_eq!(b_rec.peer_irk(), alice.irk());
        assert!(digits.iter().all(|d| *d <= 9));
    }

    #[test]
    fn tampered_handshake_bytes_fail() {
        let alice = identity(3);
        let bob = identity(4);
        let (mut a, s) = Pairing::initiator(&alice, &[0x11; 32]).unwrap();
        let (mut b, _) = Pairing::responder(&bob, &[0x22; 32]).unwrap();
        let PairingState::SendMessage(m1) = s else {
            panic!();
        };
        let PairingState::SendMessage(mut m2) = b.read(&m1) else {
            panic!();
        };
        // Message 2 is AEAD-protected; flipping a ciphertext byte must fail.
        let last = m2.len() - 1;
        m2[last] ^= 0xff;
        assert!(matches!(
            a.read(&m2),
            PairingState::Failed(PairingError::Handshake)
        ));
    }

    #[test]
    fn mitm_split_sessions_produce_different_sas() {
        let alice = identity(5);
        let bob = identity(6);
        let mallory = identity(7);

        let (_ar, _ma, sas_am) = pair_identities(&alice, &mallory, [0x51; 32], [0x52; 32]);
        let (_br, _mb, sas_bm) = pair_identities(&bob, &mallory, [0x61; 32], [0x62; 32]);
        assert_ne!(
            sas_am, sas_bm,
            "MITM split sessions must not share SAS digits"
        );
    }

    #[test]
    fn illegal_session_transitions_rejected() {
        let alice = identity(8);
        let bob = identity(9);
        let (rec, _, _) = pair_identities(&alice, &bob, [0x81; 32], [0x82; 32]);
        let peer = rec.peer_id();

        let mut engine = ConsentEngine::new(alice);
        engine.insert_peer(rec);
        engine.set_availability(Availability::ContactsOnly);

        assert_eq!(
            engine.accept_session(peer),
            Err(ConsentError::IllegalTransition)
        );
        assert_eq!(
            engine.decline_session(peer),
            Err(ConsentError::IllegalTransition)
        );

        engine.request_session(peer).unwrap();
        assert_eq!(
            engine.request_session(peer),
            Err(ConsentError::IllegalTransition)
        );
        engine.decline_session(peer).unwrap();
        assert_eq!(engine.session_state(&peer), Some(SessionState::Declined));

        engine.request_session(peer).unwrap();
        engine.accept_session(peer).unwrap();
        assert_eq!(engine.session_state(&peer), Some(SessionState::Accepted));
        assert_eq!(
            engine.accept_session(peer),
            Err(ConsentError::IllegalTransition)
        );
    }

    #[test]
    fn availability_off_blocks_request_and_accept_resolution_still_ok() {
        let alice = identity(10);
        let bob = identity(11);
        let (rec, _, _) = pair_identities(&alice, &bob, [0xA0; 32], [0xA1; 32]);
        let peer = rec.peer_id();
        let bob_irk = *rec.peer_irk();

        let mut engine = ConsentEngine::new(alice);
        engine.insert_peer(rec);
        engine.set_availability(Availability::Off);

        assert_eq!(engine.request_session(peer), Err(ConsentError::Unavailable));

        let mut resolver = Resolver::new();
        resolver
            .rebuild(&engine.peer_records(), 100)
            .expect("rebuild");
        assert_eq!(
            resolver.resolve(&eid(&bob_irk, 100)),
            Some(peer),
            "resolution still works while Availability::Off"
        );
    }

    #[test]
    fn resolvable_is_not_authorized_without_accept() {
        let alice = identity(12);
        let bob = identity(13);
        let (rec, _, _) = pair_identities(&alice, &bob, [0xC0; 32], [0xC1; 32]);
        let peer = rec.peer_id();

        let mut engine = ConsentEngine::new(alice);
        engine.insert_peer(rec);
        engine.set_availability(Availability::ContactsOnly);
        engine.request_session(peer).unwrap();

        let nonce = [9u8; 16];
        assert_eq!(
            engine.session_keys(&peer, &nonce).err(),
            Some(ConsentError::NotAccepted)
        );
        engine.accept_session(peer).unwrap();
        assert!(engine.session_keys(&peer, &nonce).is_ok());
    }

    #[test]
    fn revoke_makes_beacons_unresolvable_and_blocks_sessions() {
        let alice = identity(14);
        let bob = identity(15);
        let (rec, _, _) = pair_identities(&alice, &bob, [0xD0; 32], [0xD1; 32]);
        let peer = rec.peer_id();
        let bob_irk = *rec.peer_irk();

        let mut engine = ConsentEngine::new(alice);
        engine.insert_peer(rec);
        engine.set_availability(Availability::ContactsOnly);
        engine.request_session(peer).unwrap();
        engine.accept_session(peer).unwrap();

        engine.revoke(peer).unwrap();
        assert_eq!(engine.session_state(&peer), Some(SessionState::Revoked));
        assert!(engine.peer(&peer).is_none());

        let mut resolver = Resolver::new();
        resolver
            .rebuild(&engine.peer_records(), 200)
            .expect("rebuild");
        assert_eq!(resolver.resolve(&eid(&bob_irk, 200)), None);

        assert_eq!(engine.request_session(peer), Err(ConsentError::UnknownPeer));
    }

    #[test]
    fn rotate_own_irk_stale_contacts_fail_updated_succeed() {
        let mut alice = identity(16);
        let bob = identity(17);
        let (bob_rec_for_alice, alice_rec_for_bob, _) =
            pair_identities(&alice, &bob, [0xE0; 32], [0xE1; 32]);

        // Bob's view of Alice (has alice's IRK).
        let mut bob_engine = ConsentEngine::new(bob);
        bob_engine.insert_peer(alice_rec_for_bob);
        let alice_id = alice.peer_id();
        let old_eid = alice.beacon_eid(300);

        let mut resolver = Resolver::new();
        resolver
            .rebuild(&bob_engine.peer_records(), 300)
            .expect("rebuild");
        assert_eq!(resolver.resolve(&old_eid), Some(alice_id));

        // Alice rotates; bob still has stale IRK.
        let new_irk = [0x5eu8; 32];
        alice.rotate_own_irk(new_irk);
        let new_eid = alice.beacon_eid(300);
        assert_ne!(old_eid, new_eid);

        resolver
            .rebuild(&bob_engine.peer_records(), 300)
            .expect("rebuild");
        assert_eq!(
            resolver.resolve(&new_eid),
            None,
            "stale contact must fail to resolve after rotate"
        );
        assert_eq!(resolver.resolve(&old_eid), Some(alice_id));

        // Updated contact: bob replaces alice's record with new IRK.
        let updated = PeerRecord::new(
            alice.public_key(),
            new_irk,
            *bob_rec_for_alice.pairwise_root(),
        );
        bob_engine.insert_peer(updated);
        resolver
            .rebuild(&bob_engine.peer_records(), 300)
            .expect("rebuild");
        assert_eq!(resolver.resolve(&new_eid), Some(alice_id));
    }

    #[test]
    fn confirm_sas_rejects_wrong_digits() {
        let alice = identity(30);
        let bob = identity(31);
        let (mut a, s) = Pairing::initiator(&alice, &[0x30; 32]).unwrap();
        let (mut b, _) = Pairing::responder(&bob, &[0x31; 32]).unwrap();
        let PairingState::SendMessage(m1) = s else {
            panic!();
        };
        let PairingState::SendMessage(m2) = b.read(&m1) else {
            panic!();
        };
        let PairingState::SendMessage(m3) = a.read(&m2) else {
            panic!();
        };
        let PairingState::ConfirmSas { digits } = a.poll() else {
            panic!();
        };
        let _ = b.read(&m3);
        let mut wrong = digits;
        wrong[0] = (wrong[0] + 1) % 10;
        assert!(matches!(
            a.confirm_sas(&wrong),
            PairingState::Failed(PairingError::SasMismatch)
        ));
    }

    #[test]
    fn reject_sas_aborts() {
        let alice = identity(18);
        let bob = identity(19);
        let (mut a, s) = Pairing::initiator(&alice, &[0x18; 32]).unwrap();
        let (mut b, _) = Pairing::responder(&bob, &[0x19; 32]).unwrap();
        let PairingState::SendMessage(m1) = s else {
            panic!();
        };
        let PairingState::SendMessage(m2) = b.read(&m1) else {
            panic!();
        };
        let PairingState::SendMessage(m3) = a.read(&m2) else {
            panic!();
        };
        let _ = a.poll();
        let _ = b.read(&m3);
        assert!(matches!(
            a.reject_sas(),
            PairingState::Failed(PairingError::SasRejected)
        ));
    }

    #[test]
    fn allowlist_enforced() {
        let alice = identity(20);
        let bob = identity(21);
        let (rec, _, _) = pair_identities(&alice, &bob, [0x20; 32], [0x21; 32]);
        let peer = rec.peer_id();

        let mut engine = ConsentEngine::new(alice);
        engine.insert_peer(rec);
        engine.set_availability(Availability::Allowlist(vec![]));
        assert_eq!(
            engine.request_session(peer),
            Err(ConsentError::NotAllowlisted)
        );
        engine.set_availability(Availability::Allowlist(vec![peer]));
        engine.request_session(peer).unwrap();
    }

    #[test]
    fn expire_session_paths_and_session_keys_debug() {
        let alice = identity(40);
        let bob = identity(41);
        let (rec, _, _) = pair_identities(&alice, &bob, [0x40; 32], [0x41; 32]);
        let peer = rec.peer_id();

        let mut engine = ConsentEngine::new(alice);
        assert_eq!(*engine.availability(), Availability::Off);
        engine.insert_peer(rec);
        engine.set_availability(Availability::ContactsOnly);
        assert!(engine.peers().any(|(id, _)| *id == peer));
        let _ = engine.identity_mut().peer_id();

        engine.request_session(peer).unwrap();
        engine.expire_session(peer).unwrap();
        assert_eq!(engine.session_state(&peer), Some(SessionState::Expired));
        assert_eq!(
            engine.expire_session(peer),
            Err(ConsentError::IllegalTransition)
        );

        engine.request_session(peer).unwrap();
        engine.accept_session(peer).unwrap();
        engine.expire_session(peer).unwrap();
        assert_eq!(engine.session_state(&peer), Some(SessionState::Expired));

        let unknown = identity(42).peer_id();
        assert_eq!(engine.revoke(unknown), Err(ConsentError::UnknownPeer));
        assert_eq!(
            engine.expire_session(unknown),
            Err(ConsentError::UnknownPeer)
        );

        engine.set_availability(Availability::Allowlist(vec![peer]));
        engine.request_session(peer).unwrap();
        engine.revoke(peer).unwrap();
        assert!(engine.peer(&peer).is_none());
        // Allowlist entry for the revoked peer is cleaned up.
        if let Availability::Allowlist(list) = engine.availability() {
            assert!(!list.contains(&peer));
        }

        let keys = SessionKeys {
            sts_key: [1u8; 16],
            transport_key: [2u8; 32],
        };
        let dbg = format!("{keys:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("01, 01"));
    }

    #[test]
    fn allowlist_unknown_peer_and_pairing_invalid_ops() {
        let alice = identity(43);
        let bob = identity(44);
        let (rec, _, _) = pair_identities(&alice, &bob, [0x43; 32], [0x44; 32]);
        let peer = rec.peer_id();
        let stranger = identity(45).peer_id();

        let mut engine = ConsentEngine::new(alice);
        engine.insert_peer(rec);
        engine.set_availability(Availability::Allowlist(vec![peer]));
        assert_eq!(
            engine.request_session(stranger),
            Err(ConsentError::UnknownPeer)
        );

        let (mut a, _m1) = Pairing::initiator(&identity(46), &[0x46; 32]).unwrap();
        assert!(matches!(
            a.poll(),
            PairingState::Failed(PairingError::InvalidState)
        ));
        assert!(matches!(
            a.read(&[0u8; 8]),
            PairingState::Failed(PairingError::InvalidState)
        ));

        let (mut b, _) = Pairing::responder(&identity(47), &[0x47; 32]).unwrap();
        assert!(matches!(
            b.confirm_sas(&[0; 6]),
            PairingState::Failed(PairingError::InvalidState)
        ));
        assert!(matches!(
            b.reject_sas(),
            PairingState::Failed(PairingError::InvalidState)
        ));
    }

    #[test]
    fn peer_record_debug_and_resolver_empty() {
        let peer = super::fixture_peer(7, 8, 9);
        let _ = peer.peer_static_public();
        let dbg = format!("{peer:?}");
        assert!(dbg.contains("redacted"));
        assert!(dbg.contains("peer_id"));

        let mut resolver = Resolver::new();
        assert!(resolver.is_empty());
        resolver.rebuild(&[], 1).unwrap();
        assert!(resolver.is_empty());
    }

    #[test]
    fn take_peer_record_before_complete_is_none() {
        let (mut a, _) = Pairing::initiator(&identity(60), &[0x60; 32]).unwrap();
        assert!(a.take_peer_record().is_none());
    }

    #[test]
    fn irk_garbage_after_sas_fails_handshake() {
        let alice = identity(61);
        let bob = identity(62);
        let (mut a, m1) = Pairing::initiator(&alice, &[0x61; 32]).unwrap();
        let (mut b, _) = Pairing::responder(&bob, &[0x62; 32]).unwrap();

        let PairingState::SendMessage(m1) = m1 else {
            panic!("m1");
        };
        let PairingState::SendMessage(m2) = b.read(&m1) else {
            panic!("m2");
        };
        let PairingState::SendMessage(m3) = a.read(&m2) else {
            panic!("m3");
        };
        let PairingState::ConfirmSas { digits: da } = a.poll() else {
            panic!("sas a");
        };
        let PairingState::ConfirmSas { digits: db } = b.read(&m3) else {
            panic!("sas b");
        };
        assert_eq!(da, db);

        let PairingState::SendMessage(_) = a.confirm_sas(&da) else {
            panic!("alice irk");
        };
        assert!(matches!(
            b.confirm_sas(&db),
            PairingState::AwaitingMessage
        ));
        assert!(matches!(
            b.read(&[0u8; 16]),
            PairingState::Failed(PairingError::Handshake)
        ));
    }

    #[test]
    fn revoke_asymmetry_revoked_peer_still_resolves_you() {
        // Alice revokes Bob; Bob still holds Alice's IRK and resolves her beacon.
        let alice = identity(50);
        let bob = identity(51);
        let (alice_view_of_bob, bob_view_of_alice, _) =
            pair_identities(&alice, &bob, [0x50; 32], [0x51; 32]);

        let mut alice_engine = ConsentEngine::new(alice);
        alice_engine.insert_peer(alice_view_of_bob);
        let bob_id = bob.peer_id();
        alice_engine.set_availability(Availability::ContactsOnly);
        alice_engine.revoke(bob_id).unwrap();

        let mut bob_engine = ConsentEngine::new(bob);
        bob_engine.insert_peer(bob_view_of_alice);
        let alice_id = alice_engine.identity().peer_id();
        let eid = alice_engine.identity().beacon_eid(900);
        let mut resolver = Resolver::new();
        resolver
            .rebuild(&bob_engine.peer_records(), 900)
            .unwrap();
        assert_eq!(
            resolver.resolve(&eid),
            Some(alice_id),
            "revoked peer retains IRK and can still resolve you"
        );
    }
}
