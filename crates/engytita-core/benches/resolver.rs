//! Criterion bench: 1000 peers × 3 epochs rebuild.

use criterion::{criterion_group, criterion_main, Criterion};
use engytita_core::{PeerRecord, Resolver};
use x25519_dalek::{PublicKey, StaticSecret};

fn peer_at(i: u32) -> PeerRecord {
    let mut sk = [0u8; 32];
    sk[..4].copy_from_slice(&i.to_le_bytes());
    sk[4] = 0x42;
    let secret = StaticSecret::from(sk);
    let public = PublicKey::from(&secret);
    let mut irk = [0u8; 32];
    irk[..4].copy_from_slice(&i.to_be_bytes());
    irk[31] = 0x7e;
    let mut root = [0u8; 32];
    root[0] = 0xa5;
    root[1..5].copy_from_slice(&i.to_le_bytes());
    PeerRecord::new(public, irk, root)
}

fn rebuild_1000(c: &mut Criterion) {
    let peers: Vec<PeerRecord> = (0..1000).map(peer_at).collect();
    let mut resolver = Resolver::new();
    c.bench_function("resolver_rebuild_1000_peers_x3_epochs", |b| {
        b.iter(|| {
            resolver.rebuild(&peers, 1_000_000).expect("rebuild");
        });
    });
}

criterion_group!(benches, rebuild_1000);
criterion_main!(benches);
