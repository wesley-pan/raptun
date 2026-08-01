//! Live per-tunnel accounting for the server's `--monitor` TUI.
//!
//! The server keeps one [`TunnelRegistry`] for the whole process. Every FEC
//! tunnel, on spawn, publishes an [`Arc<TunnelStats>`] into it and holds a
//! [`RegistryGuard`] that removes the entry when the tunnel task ends on any
//! path (clean finish, error, or abort). The monitor UI snapshots the registry
//! on a timer and renders it.
//!
//! Design constraints that shape this module:
//!
//! * **Hot path is lock-free.** The tunnel data loops only ever call
//!   `fetch_add`/`store` on the atomics inside an already-cloned
//!   `Arc<TunnelStats>` — they never touch the registry map. Registration,
//!   unregistration, and snapshotting are all cold (tunnel spawn/teardown, and
//!   a ~1 Hz UI tick), so a plain `std::sync::RwLock<HashMap>` is more than
//!   fast enough and avoids pulling a concurrent-map dependency into core.
//! * **Optional and zero-cost when off.** The whole feature threads through the
//!   run loop as `Option<Arc<TunnelRegistry>>`; when the server is not in
//!   monitor mode it is `None` and no `TunnelStats` are ever allocated, so the
//!   data path is byte-for-byte what it was before.
//! * **No lifetime extension.** `TunnelStats` holds a [`Weak`] to the QUIC
//!   connection so the UI can sample live RTT/cwnd, but a lingering registry
//!   entry can never keep a closed connection alive.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock, Weak};
use std::time::Instant;

/// Identifies one tunnel process-wide: the QUIC connection's stable id paired
/// with the tunnel's stream id. `stable_id` stays constant across connection
/// migration, so a tunnel keeps its identity even if the client's address
/// changes mid-session.
pub type TunnelId = (usize, u64);

/// Live counters for a single FEC tunnel, shared between the tunnel's data
/// loops (which write) and the monitor UI (which reads).
///
/// All counters are cumulative and monotonic; the UI derives rates by diffing
/// consecutive snapshots. Writes use [`Ordering::Relaxed`] — these are
/// statistics, not synchronization, so the cheapest ordering is correct.
#[derive(Debug)]
pub struct TunnelStats {
    /// The client's source address (connection-level; every tunnel on the same
    /// QUIC connection shares it). Used to group tunnels by peer in the UI.
    pub remote: SocketAddr,
    /// This tunnel's stream id.
    pub stream_id: u64,
    /// When the tunnel task started, for the "age" column.
    pub started_at: Instant,
    /// Weak handle to the owning QUIC connection so the UI can sample live
    /// RTT/cwnd/loss. Weak so a stale registry entry never keeps a dead
    /// connection alive; `upgrade()` returning `None` means the connection is
    /// gone and the row can be dropped.
    conn: Weak<quinn::Connection>,
    /// The block geometry `K`, so the UI can estimate source symbols as
    /// `total_blocks * k` without a separate hot-path counter.
    k: u32,
    /// Application bytes read from the local socket (client -> target).
    pub bytes_up: AtomicU64,
    /// Application bytes written to the local socket (target -> client).
    pub bytes_down: AtomicU64,
    /// Blocks emitted upstream so far; `* k` estimates source symbols sent.
    pub total_blocks: AtomicU64,
    /// Repair symbols emitted (initial per-block repair plus NACK top-ups).
    pub repair_symbols: AtomicU64,
    /// Peer's delivered-block high-water, mirrored from the flow-control credit
    /// / ack signals. Lets the UI show `delivered/total` and flag laggards.
    pub delivered_blocks: AtomicU64,
}

impl TunnelStats {
    /// Create a stats block for a freshly-spawned tunnel. `conn` is downgraded
    /// to a [`Weak`] so the stats never extend the connection's lifetime.
    pub fn new(remote: SocketAddr, stream_id: u64, conn: &Arc<quinn::Connection>, k: u32) -> Self {
        Self {
            remote,
            stream_id,
            started_at: Instant::now(),
            conn: Arc::downgrade(conn),
            k: k.max(1),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            total_blocks: AtomicU64::new(0),
            repair_symbols: AtomicU64::new(0),
            delivered_blocks: AtomicU64::new(0),
        }
    }

    /// The block geometry `K`.
    pub fn k(&self) -> u32 {
        self.k
    }

    /// Estimated source symbols sent so far (`total_blocks * k`). This is an
    /// estimate: the final block may be padded, so the true source-symbol count
    /// is slightly lower, but for a live-monitoring readout the difference is
    /// immaterial and it costs no extra hot-path counter.
    pub fn source_symbols_est(&self) -> u64 {
        self.total_blocks.load(Ordering::Relaxed) * self.k as u64
    }

    /// Try to resolve the owning connection, e.g. to read live RTT/cwnd.
    /// `None` once the connection has been dropped.
    pub fn connection(&self) -> Option<Arc<quinn::Connection>> {
        self.conn.upgrade()
    }

    // --- Hot-path accessors: cheap Relaxed accumulation, never touch the map.

    pub fn add_bytes_up(&self, n: u64) {
        self.bytes_up.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_bytes_down(&self, n: u64) {
        self.bytes_down.fetch_add(n, Ordering::Relaxed);
    }

    /// One block was emitted upstream, contributing `repair` repair symbols.
    pub fn record_block(&self, repair: u32) {
        self.total_blocks.fetch_add(1, Ordering::Relaxed);
        self.repair_symbols
            .fetch_add(repair as u64, Ordering::Relaxed);
    }

    /// Additional repair symbols minted for a NACK top-up (no new block).
    pub fn add_repair(&self, repair: u32) {
        self.repair_symbols
            .fetch_add(repair as u64, Ordering::Relaxed);
    }

    /// Advance the delivered-block high-water. Monotonic: a stale/lower credit
    /// never rewinds it.
    pub fn set_delivered(&self, delivered: u64) {
        self.delivered_blocks
            .fetch_max(delivered, Ordering::Relaxed);
    }
}

/// Process-wide registry of live tunnels, keyed by [`TunnelId`].
///
/// Cloneable-by-`Arc` on the outside; internally a single `RwLock<HashMap>`.
/// Only cold operations take the lock (register on spawn, unregister on
/// teardown, snapshot on the UI tick), so contention is a non-issue.
#[derive(Debug, Default)]
pub struct TunnelRegistry {
    inner: RwLock<HashMap<TunnelId, Arc<TunnelStats>>>,
}

impl TunnelRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Publish a tunnel's stats and hand back a guard that unregisters it on
    /// drop. The guard holds an `Arc<Self>`, so the registry outlives every
    /// tunnel it tracks.
    pub fn register(self: &Arc<Self>, id: TunnelId, stats: Arc<TunnelStats>) -> RegistryGuard {
        self.write_lock().insert(id, stats);
        RegistryGuard {
            registry: Arc::clone(self),
            id,
        }
    }

    /// A point-in-time copy of every live tunnel's stats handle, for the UI to
    /// read without holding the lock while it renders.
    pub fn snapshot(&self) -> Vec<Arc<TunnelStats>> {
        self.read_lock().values().cloned().collect()
    }

    /// Number of live tunnels.
    pub fn len(&self) -> usize {
        self.read_lock().len()
    }

    /// Whether any tunnels are live.
    pub fn is_empty(&self) -> bool {
        self.read_lock().is_empty()
    }

    fn remove(&self, id: &TunnelId) {
        self.write_lock().remove(id);
    }

    // Recover from a poisoned lock instead of panicking the registry. A
    // poisoning is rare (a panic in a writer while holding the lock), but
    // the registry is a UI observation point — killing the server over a
    // stale read/write is strictly worse than logging and continuing with
    // an empty or partially-empty map. The data inside is independent
    // (TunnelStats atomics + IDs), so `into_inner()` on a poisoned lock
    // is safe: we get the same HashMap back.
    fn read_lock(&self) -> std::sync::RwLockReadGuard<'_, HashMap<TunnelId, Arc<TunnelStats>>> {
        match self.inner.read() {
            Ok(g) => g,
            Err(poisoned) => {
                tracing::warn!("TunnelRegistry read lock poisoned; recovering");
                poisoned.into_inner()
            }
        }
    }
    fn write_lock(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<TunnelId, Arc<TunnelStats>>> {
        match self.inner.write() {
            Ok(g) => g,
            Err(poisoned) => {
                tracing::warn!("TunnelRegistry write lock poisoned; recovering");
                poisoned.into_inner()
            }
        }
    }
}

/// Removes a tunnel's registry entry when the tunnel task ends, on any path.
/// Mirrors the `ActiveGuard` pattern used for the active-tunnel counter: RAII
/// cleanup means an early `?` return or a panic still deregisters the tunnel.
pub struct RegistryGuard {
    registry: Arc<TunnelRegistry>,
    id: TunnelId,
}

impl Drop for RegistryGuard {
    fn drop(&mut self) {
        self.registry.remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// LOW-1 smoke: a freshly-created registry is empty. The end-to-end
    /// register() path requires a quinn::Connection, covered in
    /// `tests/critical_dos.rs`; here we just guard the structural
    /// invariant (initial state is consistent).
    #[test]
    fn fresh_registry_is_empty() {
        let reg = TunnelRegistry::new();
        assert_eq!(reg.len(), 0);
        assert!(reg.is_empty());
        assert_eq!(reg.snapshot().len(), 0);
    }

    /// LOW-1 regression: a poisoned registry lock is recovered, not
    /// panicked. We test the recovery shape directly: poison a lock by
    /// panicking while holding a write, then read via the same
    /// `read_lock` / `write_lock` pattern the registry uses and confirm
    /// `into_inner()` returns the inner data.
    #[test]
    fn poisoned_lock_is_recovered() {
        use std::sync::{Arc, RwLock};

        let lock: Arc<RwLock<u32>> = Arc::new(RwLock::new(0));
        {
            let lock_for_panic = Arc::clone(&lock);
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let mut g = lock_for_panic.write().unwrap();
                *g = 1;
                panic!("poison the lock");
            }));
        }
        // The lock is now poisoned. `read()` returns Err; `into_inner()`
        // on the PoisonError yields the inner guard — the same pattern
        // used in `TunnelRegistry::read_lock` / `write_lock`.
        let res = lock.read();
        match res {
            Ok(_) => panic!("expected poison"),
            Err(poisoned) => {
                let g = poisoned.into_inner();
                assert_eq!(*g, 1, "into_inner() yields the value written before panic");
            }
        }
    }
}
