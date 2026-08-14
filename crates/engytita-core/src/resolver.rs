//! Precomputed EID resolution table.
//!
//! `rebuild` expands each known peer across `{epoch-1, epoch, epoch+1}` so
//! modest clock skew still resolves. `resolve` scans every precomputed entry
//! with constant-time EID equality (no early exit on mismatch or miss mid-scan).
//! Distinct peers that collide on an EID in the window cause `rebuild` to fail.

use crate::derive::eid;
use crate::peer::{PeerId, PeerRecord};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

#[cfg(feature = "std")]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::collections::HashMap;

/// Failure while rebuilding a resolution table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RebuildError {
    /// Two distinct peers produced the same EID in the epoch window.
    Collision,
    /// Heapless capacity exhausted while inserting precomputed EIDs.
    #[cfg(feature = "heapless")]
    Full,
}

/// Deprecated name; prefer matching on [`RebuildError`].
#[cfg(feature = "heapless")]
#[deprecated(note = "use RebuildError")]
pub type ResolverFull = RebuildError;

#[derive(Clone, Copy, Debug)]
struct ResolveEntry {
    eid: [u8; 8],
    peer_id: PeerId,
}

fn epoch_window(epoch: u64) -> [u64; 3] {
    let prev = epoch.saturating_sub(1);
    let next = epoch.saturating_add(1);
    [prev, epoch, next]
}

fn ct_select_peer_id(current: &PeerId, candidate: &PeerId, cond: Choice) -> PeerId {
    let mut out = [0u8; 16];
    for (o, (cur, cand)) in out.iter_mut().zip(current.0.iter().zip(candidate.0.iter())) {
        *o = u8::conditional_select(cur, cand, cond);
    }
    PeerId(out)
}

fn resolve_entries(entries: &[ResolveEntry], beacon: &[u8; 8]) -> Option<PeerId> {
    let mut found = Choice::from(0);
    let mut out = PeerId([0u8; 16]);
    for entry in entries {
        let eq = beacon.ct_eq(&entry.eid);
        out = ct_select_peer_id(&out, &entry.peer_id, eq);
        found |= eq;
    }
    // Branch only after scanning every entry (membership privacy vs early miss).
    if bool::from(found) {
        Some(out)
    } else {
        None
    }
}

/// Host resolution table (`std` builds).
#[cfg(feature = "std")]
#[derive(Clone, Debug, Default)]
pub struct Resolver {
    entries: Vec<ResolveEntry>,
}

#[cfg(feature = "std")]
impl Resolver {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Precompute EIDs for `peers` over `{epoch-1, epoch, epoch+1}`.
    ///
    /// Returns [`RebuildError::Collision`] if two distinct peers share an EID in
    /// the window (refuses ambiguous resolve rather than last-write-wins).
    pub fn rebuild(&mut self, peers: &[PeerRecord], epoch: u64) -> Result<(), RebuildError> {
        self.entries.clear();
        let epochs = epoch_window(epoch);
        let cap = peers.len().saturating_mul(3);
        self.entries.reserve(cap);

        // HashMap is used only during rebuild for O(1) collision detection.
        // Resolve never consults it - see [`Self::resolve`].
        let mut seen: HashMap<[u8; 8], PeerId> = HashMap::with_capacity(cap);
        for peer in peers {
            for &e in &epochs {
                let beacon = eid(peer.peer_irk(), e);
                match seen.get(&beacon) {
                    Some(existing) if *existing != peer.peer_id() => {
                        self.entries.clear();
                        return Err(RebuildError::Collision);
                    }
                    Some(_) => {}
                    None => {
                        seen.insert(beacon, peer.peer_id());
                        self.entries.push(ResolveEntry {
                            eid: beacon,
                            peer_id: peer.peer_id(),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Linear scan over all precomputed entries with constant-time EID compares.
    ///
    /// Does not early-exit on a miss or mid-table hit. The final `Option` still
    /// branches on whether any entry matched.
    pub fn resolve(&self, beacon: &[u8; 8]) -> Option<PeerId> {
        resolve_entries(&self.entries, beacon)
    }

    /// Number of precomputed EID entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Embedded resolution table backed by [`heapless::Vec`].
///
/// `N` must be large enough for at most `peers.len() * 3` entries (epoch window).
#[cfg(feature = "heapless")]
#[derive(Clone, Debug)]
pub struct HeaplessResolver<const N: usize> {
    entries: heapless::Vec<ResolveEntry, N>,
}

#[cfg(feature = "heapless")]
impl<const N: usize> Default for HeaplessResolver<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "heapless")]
impl<const N: usize> HeaplessResolver<N> {
    pub fn new() -> Self {
        Self {
            entries: heapless::Vec::new(),
        }
    }

    /// Precompute EIDs for `peers` over `{epoch-1, epoch, epoch+1}`.
    pub fn rebuild(&mut self, peers: &[PeerRecord], epoch: u64) -> Result<(), RebuildError> {
        self.entries.clear();
        let epochs = epoch_window(epoch);
        for peer in peers {
            for &e in &epochs {
                let beacon = eid(peer.peer_irk(), e);
                let mut collision = false;
                let mut duplicate = false;
                for entry in self.entries.iter() {
                    if entry.eid == beacon {
                        if entry.peer_id != peer.peer_id() {
                            collision = true;
                        } else {
                            duplicate = true;
                        }
                        break;
                    }
                }
                if collision {
                    self.entries.clear();
                    return Err(RebuildError::Collision);
                }
                if duplicate {
                    continue;
                }
                self.entries
                    .push(ResolveEntry {
                        eid: beacon,
                        peer_id: peer.peer_id(),
                    })
                    .map_err(|_| RebuildError::Full)?;
            }
        }
        Ok(())
    }

    /// Linear scan over all precomputed entries with constant-time EID compares.
    pub fn resolve(&self, beacon: &[u8; 8]) -> Option<PeerId> {
        resolve_entries(&self.entries, beacon)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
