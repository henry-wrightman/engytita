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
