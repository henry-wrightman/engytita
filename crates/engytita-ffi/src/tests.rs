//! Round-trip tests through the FFI layer (opaque handles only).

use std::sync::Arc;

use crate::{AvailabilityMode, Engytita, PairingEvent};

fn entropy(seed: u8) -> Vec<u8> {
    let mut e = vec![seed; 64];
    e[0] ^= 0x3c;
    e[32] ^= 0xc3;
    e[63] = seed.wrapping_add(7);
    e
}

fn drive_pair(alice: Arc<Engytita>, bob: Arc<Engytita>) -> (crate::PeerId, crate::PeerId) {
    let a_sess = alice
        .clone()
        .start_pairing_initiator(vec![0xa1; 32])
        .expect("initiator");
    let b_sess = bob
        .clone()
        .start_pairing_responder(vec![0xb2; 32])
        .expect("responder");

    let PairingEvent::SendMessage { data: m1 } = a_sess.take_initial_event() else {
        panic!("m1");
    };
    let _ = b_sess.take_initial_event(); // AwaitingMessage

    let PairingEvent::SendMessage { data: m2 } = b_sess.read(m1) else {
        panic!("m2");
    };
    let PairingEvent::SendMessage { data: m3 } = a_sess.read(m2) else {
        panic!("m3");
    };
    let PairingEvent::ConfirmSas { digits: da } = a_sess.poll() else {
        panic!("alice sas");
    };
    let PairingEvent::ConfirmSas { digits: db } = b_sess.read(m3) else {
        panic!("bob sas");
    };
    assert_eq!(da, db);
    assert_eq!(da.len(), 6);

    let PairingEvent::SendMessage { data: irk_a } =
        a_sess.confirm_sas(da.clone()).expect("confirm")
    else {
        panic!("alice irk");
    };
    assert!(matches!(
        b_sess.confirm_sas(db).expect("confirm"),
        PairingEvent::AwaitingMessage
    ));
    let PairingEvent::SendMessage { data: irk_b } = b_sess.read(irk_a) else {
        panic!("bob irk");
    };
    let PairingEvent::Complete {
        peer_id: bob_sees_alice,
    } = b_sess.poll()
    else {
        panic!("bob complete");
    };
    let PairingEvent::Complete {
        peer_id: alice_sees_bob,
    } = a_sess.read(irk_b)
    else {
        panic!("alice complete");
    };

    assert_eq!(alice_sees_bob.bytes, bob.peer_id().bytes);
    assert_eq!(bob_sees_alice.bytes, alice.peer_id().bytes);
    (alice_sees_bob, bob_sees_alice)
}

#[test]
fn ffi_protocol_surface_round_trip() {
    let alice = Engytita::new(entropy(1)).unwrap();
    let bob = Engytita::new(entropy(2)).unwrap();

    assert_ne!(alice.peer_id().bytes, bob.peer_id().bytes);

    let (bob_id, _alice_id) = drive_pair(alice.clone(), bob.clone());

    // Resolve bob's beacon from alice's engine.
    // We don't have bob's IRK at FFI - resolution uses stored peer record from pairing.
    // Produce bob's beacon via core would need IRK; instead verify session path.

    alice.request_session(bob_id.clone()).expect("request");
    assert_eq!(
        alice.session_state(bob_id.clone()).unwrap().as_deref(),
        Some("requested")
    );
    alice.accept_session(bob_id.clone()).expect("accept");

    let keys = alice
        .session_keys(bob_id.clone(), vec![9u8; 16])
        .expect("keys");
    assert_eq!(keys.sts_key.len(), 16);
    assert_eq!(keys.transport_key.len(), 32);

    // Keys must match on both sides for same nonce after bob also accepts.
    bob.request_session(alice.peer_id()).unwrap();
    bob.accept_session(alice.peer_id()).unwrap();
    let keys_b = bob.session_keys(alice.peer_id(), vec![9u8; 16]).unwrap();
    assert_eq!(keys.sts_key, keys_b.sts_key);
    assert_eq!(keys.transport_key, keys_b.transport_key);

    alice.revoke(bob_id.clone()).unwrap();
    assert!(alice.request_session(bob_id).is_err());
}

#[test]
fn ffi_resolve_after_pairing() {
    use engytita_core::Identity;

    let alice = Engytita::new(entropy(3)).unwrap();
    let bob = Engytita::new(entropy(4)).unwrap();
    let (bob_id, _) = drive_pair(alice.clone(), bob.clone());

    // Reconstruct bob's beacon from the same entropy used for bob's engine.
    let bob_ident = Identity::from_entropy64({
        let e = entropy(4);
        let mut a = [0u8; 64];
        a.copy_from_slice(&e);
        a
    });
    let epoch = 42u64;
    let beacon = bob_ident.beacon_eid(epoch).to_vec();
    let resolved = alice.resolve(beacon, epoch).unwrap();
    assert_eq!(resolved.map(|p| p.bytes), Some(bob_id.bytes));
}

#[test]
fn ffi_beacon_eid_is_eight_bytes() {
    let eng = Engytita::new(entropy(10)).unwrap();
    let eid = eng.beacon_eid(1);
    assert_eq!(eid.len(), 8);
    assert_ne!(eid, eng.beacon_eid(2));
}

#[test]
fn ffi_availability_off_blocks_session() {
    let alice = Engytita::new(entropy(5)).unwrap();
    let bob = Engytita::new(entropy(6)).unwrap();
    let (bob_id, _) = drive_pair(alice.clone(), bob);

    alice.set_availability(AvailabilityMode::Off);
    assert!(alice.request_session(bob_id).is_err());
}

#[test]
fn ffi_rotate_irk_accepts_32_bytes() {
    let eng = Engytita::new(entropy(7)).unwrap();
    eng.rotate_irk(vec![0x5e; 32]).unwrap();
    assert!(eng.rotate_irk(vec![1, 2, 3]).is_err());
}

#[test]
fn ffi_rejects_bad_entropy_length() {
    assert!(Engytita::new(vec![0u8; 32]).is_err());
}

#[test]
fn ffi_decline_session() {
    let alice = Engytita::new(entropy(8)).unwrap();
    let bob = Engytita::new(entropy(9)).unwrap();
    let (bob_id, _) = drive_pair(alice.clone(), bob);
    alice.request_session(bob_id.clone()).unwrap();
    alice.decline_session(bob_id.clone()).unwrap();
    assert_eq!(
        alice.session_state(bob_id).unwrap().as_deref(),
        Some("declined")
    );
}

#[test]
fn ffi_beacon_adv_encode_decode_and_epoch() {
    assert_eq!(crate::epoch_seconds(), engytita_core::EPOCH_SECONDS);

    let eng = Engytita::new(entropy(11)).unwrap();
    let eid = eng.beacon_eid(42);
    let adv = crate::encode_beacon_advertising_data(eid.clone()).unwrap();
    assert_eq!(
        crate::decode_beacon_advertising_data(adv).unwrap(),
        Some(eid)
    );
    assert!(crate::encode_beacon_advertising_data(vec![1, 2, 3]).is_err());
    assert_eq!(
        crate::decode_beacon_advertising_data(vec![0, 1, 2]).unwrap(),
        None
    );
}

#[test]
fn ffi_session_keys_accept_revoke_and_debug() {
    let alice = Engytita::new(entropy(12)).unwrap();
    let bob = Engytita::new(entropy(13)).unwrap();
    let (bob_id, _) = drive_pair(alice.clone(), bob);

    alice.request_session(bob_id.clone()).unwrap();
    alice.accept_session(bob_id.clone()).unwrap();
    assert_eq!(
        alice.session_state(bob_id.clone()).unwrap().as_deref(),
        Some("accepted")
    );

    let keys = alice.session_keys(bob_id.clone(), vec![0xab; 16]).unwrap();
    assert_eq!(keys.sts_key.len(), 16);
    assert_eq!(keys.transport_key.len(), 32);
    let dbg = format!("{keys:?}");
    assert!(dbg.contains("redacted"));

    assert!(alice.session_keys(bob_id.clone(), vec![1, 2, 3]).is_err());
    assert!(alice
        .request_session(crate::PeerId {
            bytes: vec![0u8; 15]
        })
        .is_err());

    alice.revoke(bob_id.clone()).unwrap();
    assert_eq!(
        alice.session_state(bob_id).unwrap().as_deref(),
        Some("revoked")
    );
}

#[test]
fn ffi_pairing_sas_parse_errors_and_reject() {
    let alice = Engytita::new(entropy(14)).unwrap();
    let bob = Engytita::new(entropy(15)).unwrap();

    // Parse errors never touch pairing state.
    let a_sess = alice
        .clone()
        .start_pairing_initiator(vec![0xa1; 32])
        .unwrap();
    let b_sess = bob.clone().start_pairing_responder(vec![0xb2; 32]).unwrap();

    let PairingEvent::SendMessage { data: m1 } = a_sess.take_initial_event() else {
        panic!("m1");
    };
    let _ = b_sess.take_initial_event();
    let PairingEvent::SendMessage { data: m2 } = b_sess.read(m1) else {
        panic!("m2");
    };
    let PairingEvent::SendMessage { data: m3 } = a_sess.read(m2) else {
        panic!("m3");
    };
    let PairingEvent::ConfirmSas { digits: da } = a_sess.poll() else {
        panic!("sas");
    };
    let _ = b_sess.read(m3);

    assert!(a_sess.confirm_sas("12345".into()).is_err());
    assert!(a_sess.confirm_sas("12ab56".into()).is_err());
    let PairingEvent::Failed { message } = a_sess.confirm_sas("000000".into()).unwrap() else {
        panic!("expected sas mismatch");
    };
    assert!(message.contains("mismatch"));
    let _ = da;

    // Reject on a fresh ConfirmSas session.
    let a2 = alice
        .clone()
        .start_pairing_initiator(vec![0xa3; 32])
        .unwrap();
    let b2 = bob.clone().start_pairing_responder(vec![0xb4; 32]).unwrap();
    let PairingEvent::SendMessage { data: m1 } = a2.take_initial_event() else {
        panic!("m1");
    };
    let _ = b2.take_initial_event();
    let PairingEvent::SendMessage { data: m2 } = b2.read(m1) else {
        panic!("m2");
    };
    let PairingEvent::SendMessage { data: m3 } = a2.read(m2) else {
        panic!("m3");
    };
    assert!(matches!(a2.poll(), PairingEvent::ConfirmSas { .. }));
    let _ = b2.read(m3);
    assert!(matches!(
        a2.reject_sas(),
        PairingEvent::Failed { message } if message.contains("rejected")
    ));
}

#[test]
fn ffi_error_mapping_and_session_state_labels() {
    use crate::{map_pairing_error, EngytitaError};
    use engytita_core::{ConsentError, PairingError};

    for (err, needle) in [
        (ConsentError::UnknownPeer, "unknown"),
        (ConsentError::Unavailable, "availability"),
        (ConsentError::NotAllowlisted, "allowlist"),
        (ConsentError::IllegalTransition, "illegal"),
        (ConsentError::NotAccepted, "not accepted"),
    ] {
        let mapped = EngytitaError::from(err);
        assert!(mapped.to_string().contains(needle), "{mapped}");
    }

    for err in [
        PairingError::Init,
        PairingError::Handshake,
        PairingError::InvalidState,
        PairingError::SasRejected,
        PairingError::SasMismatch,
        PairingError::BadRemoteKey,
    ] {
        let mapped = map_pairing_error(err);
        assert!(matches!(mapped, EngytitaError::Pairing { .. }));
    }

    let alice = Engytita::new(entropy(16)).unwrap();
    let bob = Engytita::new(entropy(17)).unwrap();
    let (bob_id, _) = drive_pair(alice.clone(), bob);

    assert_eq!(
        alice.session_state(bob_id.clone()).unwrap().as_deref(),
        Some("idle")
    );

    alice.set_availability(AvailabilityMode::ContactsOnly);
    alice.request_session(bob_id.clone()).unwrap();
    assert_eq!(
        alice.session_state(bob_id.clone()).unwrap().as_deref(),
        Some("requested")
    );
    // Illegal transition: request while already requested.
    assert!(alice.request_session(bob_id.clone()).is_err());
    // NotAccepted: keys before accept.
    assert!(alice.session_keys(bob_id.clone(), vec![0; 16]).is_err());

    alice.accept_session(bob_id.clone()).unwrap();
    alice.expire_session_for_test(bob_id.clone()).unwrap();
    assert_eq!(
        alice.session_state(bob_id).unwrap().as_deref(),
        Some("expired")
    );
}

#[test]
fn ffi_resolve_rebuild_collision_maps_error() {
    use engytita_core::{Identity, PeerRecord};

    let eng = Engytita::new(entropy(18)).unwrap();
    let id_a = Identity::from_entropy64({
        let mut e = [0x1au8; 64];
        e[0] = 1;
        e
    });
    let id_b = Identity::from_entropy64({
        let mut e = [0x1bu8; 64];
        e[0] = 2;
        e
    });
    let irk = [0x33u8; 32];
    let root = [0x44u8; 32];
    eng.insert_peer(PeerRecord::new(id_a.public_key(), irk, root));
    eng.insert_peer(PeerRecord::new(id_b.public_key(), irk, root));
    let err = eng.resolve(vec![0u8; 8], 1).unwrap_err();
    assert!(
        err.to_string().contains("collision"),
        "unexpected err: {err}"
    );
}
