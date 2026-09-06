//! The datagram + RaptorQ FEC data pump (Phase 2).
//!
//! This is the second of Raptun's two data paths. Where [`crate::run`]'s
//! baseline tunnels a TCP connection over a *reliable* QUIC bi-stream, this
//! module tunnels it over *unreliable* QUIC datagrams protected by RaptorQ
//! forward error correction — the path that recovers loss without waiting a
//! round-trip for a retransmit.
//!
//! # Mapping
//!
//! One tunnelled TCP connection ↔ one `stream_id`. The sender chunks the TCP
//! byte stream into fixed-size *blocks*, RaptorQ-encodes each into source +
//! repair symbols, and sends every symbol as one datagram. The receiver routes
//! datagrams by `(stream_id, block_id)` to a per-block [`BlockManager`], and —
//! because TCP is an ordered byte stream — delivers decoded blocks to the local
//! socket strictly in block order via a small reorder buffer.
//!
//! # What is proven here
//!
//! [`FecSender`] and [`FecReceiver`] are pure, socket-free state machines so the
//! encode → loss → decode → in-order-deliver flow is unit-testable, and the
//! loopback integration test drives them over real QUIC datagrams with induced
//! loss. NACK-driven repair and the degraded fallback are decided by the
//! [`BlockManager`] (see `raptun-fec`); this module surfaces those decisions.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::mpsc;

use raptun_proto::BlockId;

/// A framed message on a FEC tunnel's reliable signaling bi-stream.
///
/// The datagram path carries bulk data unreliably; this reliable side-channel
/// carries the small, must-not-be-lost control messages that back the FEC
/// fallback: how many blocks the stream contains, per-block NACKs that ask the
/// sender to mint fresh repair symbols when proactive FEC did not suffice, and —
/// as the ultimate bounded fallback — a request/response pair that ships a
/// stranded block's bytes reliably so the stream can never deadlock.
///
/// Wire format: 1-byte tag + fields, all big-endian. `ReliableData` is length-
/// prefixed; the fixed variants are self-delimiting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelSignal {
    /// Sender → receiver: this stream comprises exactly `total` blocks. Sent
    /// once, when the upstream reaches EOF, so the receiver knows when it has
    /// delivered everything despite datagram loss.
    BlockCount { total: u64 },
    /// Sender → receiver: the sender has emitted `blocks` blocks so far (a
    /// running high-water mark, *not* a terminal count). Sent on the reliable
    /// stream after a send burst so the receiver learns that a block exists even
    /// when every one of its datagrams was lost and no later block follows — the
    /// interactive request/response case where the stream would otherwise strand
    /// forever with no progress signal to trip the loss detector.
    HighWater { blocks: u64 },
    /// Receiver → sender: block `block` is stalled; the receiver has `have`
    /// symbols and still needs `need` more. The sender responds by minting
    /// `need` fresh repair symbols (idempotent: repeated NACKs request fewer).
    Nack {
        block: BlockId,
        have: u32,
        need: u32,
    },
    /// Receiver → sender: FEC has given up on `block` (budget exhausted or the
    /// link is congestion-limited, where adding repair would hurt). Please send
    /// its bytes over this reliable channel instead. This is the convergence
    /// lower bound: it always terminates the block.
    ReliableRequest { block: BlockId },
    /// Sender → receiver: the reliable copy of `block`'s original payload bytes.
    /// Injected directly into the receiver's reorder buffer, bypassing RaptorQ.
    ReliableData { block: BlockId, bytes: Vec<u8> },
    /// Receiver → sender: `delivered` is the number of blocks handed to the
    /// local TCP so far (the receiver's cumulative delivery high-water). The
    /// sender uses it as a flow-control credit — it may keep at most a bounded
    /// number of blocks in flight beyond what the peer has delivered, so it
    /// cannot outrun the link and self-inflict congestion loss. Modelled on
    /// smux's `cmdUPD` (consumed/window) credit, but block-denominated.
    Credit { delivered: u64 },
    /// Receiver -> sender: block `block` has been decoded successfully, so its
    /// symbols are no longer needed. The sender may release the retained
    /// encoder/payload for this block immediately. Unlike `Credit` (which
    /// advances only with in-order delivery), `BlockAck` fires per-block on
    /// decode, so a block that decoded out of order still frees its sender
    /// state without waiting for the delivery floor to reach it. This is the
    /// "decoded -> ack -> release" signal that keeps sender memory bounded by
    /// in-flight blocks rather than by the byte retention window.
    BlockAck { block: BlockId },
}

impl TunnelSignal {
    const TAG_BLOCK_COUNT: u8 = 1;
    const TAG_NACK: u8 = 2;
    const TAG_RELIABLE_REQUEST: u8 = 3;
    const TAG_RELIABLE_DATA: u8 = 4;
    const TAG_HIGH_WATER: u8 = 5;
    const TAG_CREDIT: u8 = 6;
    const TAG_BLOCKACK: u8 = 7;

    /// Upper bound on a `ReliableData` payload we will accept, to cap the
    /// allocation a peer can force. One block is at most `K * symbol_size`;
    /// 1 MiB is far above any realistic geometry.
    const MAX_RELIABLE_DATA: usize = 1024 * 1024;

    /// Encode into a fresh buffer.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        match self {
            TunnelSignal::BlockCount { total } => {
                b.push(Self::TAG_BLOCK_COUNT);
                b.extend_from_slice(&total.to_be_bytes());
            }
            TunnelSignal::HighWater { blocks } => {
                b.push(Self::TAG_HIGH_WATER);
                b.extend_from_slice(&blocks.to_be_bytes());
            }
            TunnelSignal::Nack { block, have, need } => {
                b.push(Self::TAG_NACK);
                b.extend_from_slice(&block.to_be_bytes());
                b.extend_from_slice(&have.to_be_bytes());
                b.extend_from_slice(&need.to_be_bytes());
            }
            TunnelSignal::ReliableRequest { block } => {
                b.push(Self::TAG_RELIABLE_REQUEST);
                b.extend_from_slice(&block.to_be_bytes());
            }
            TunnelSignal::ReliableData { block, bytes } => {
                b.push(Self::TAG_RELIABLE_DATA);
                b.extend_from_slice(&block.to_be_bytes());
                b.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                b.extend_from_slice(bytes);
            }
            TunnelSignal::Credit { delivered } => {
                b.push(Self::TAG_CREDIT);
                b.extend_from_slice(&delivered.to_be_bytes());
            }
            TunnelSignal::BlockAck { block } => {
                b.push(Self::TAG_BLOCKACK);
                b.extend_from_slice(&block.to_be_bytes());
            }
        }
        b
    }

    /// Try to decode one message from the front of `buf`.
    ///
    /// Return values:
    /// - `Some(Ok((sig, n)))` — decoded a signal, consume `n` bytes.
    /// - `Some(Err(n))` — `n` bytes were unknown/garbage and have been
    ///   consumed so the caller can advance past them. Used to recover from
    ///   a version skew, malicious peer, or framing corruption.
    /// - `None` — the buffer holds a *valid* tag whose payload is incomplete;
    ///   caller must read more bytes before retrying.
    pub fn decode(buf: &[u8]) -> Option<Result<(TunnelSignal, usize), usize>> {
        let tag = *buf.first()?;
        match tag {
            Self::TAG_BLOCK_COUNT => {
                if buf.len() < 1 + 8 {
                    return None;
                }
                let total = u64::from_be_bytes(buf[1..9].try_into().unwrap());
                Some(Ok((TunnelSignal::BlockCount { total }, 9)))
            }
            Self::TAG_HIGH_WATER => {
                if buf.len() < 1 + 8 {
                    return None;
                }
                let blocks = u64::from_be_bytes(buf[1..9].try_into().unwrap());
                Some(Ok((TunnelSignal::HighWater { blocks }, 9)))
            }
            Self::TAG_NACK => {
                if buf.len() < 1 + 8 + 4 + 4 {
                    return None;
                }
                let block = u64::from_be_bytes(buf[1..9].try_into().unwrap());
                let have = u32::from_be_bytes(buf[9..13].try_into().unwrap());
                let need = u32::from_be_bytes(buf[13..17].try_into().unwrap());
                Some(Ok((TunnelSignal::Nack { block, have, need }, 17)))
            }
            Self::TAG_RELIABLE_REQUEST => {
                if buf.len() < 1 + 8 {
                    return None;
                }
                let block = u64::from_be_bytes(buf[1..9].try_into().unwrap());
                Some(Ok((TunnelSignal::ReliableRequest { block }, 9)))
            }
            Self::TAG_RELIABLE_DATA => {
                if buf.len() < 1 + 8 + 4 {
                    return None;
                }
                let block = u64::from_be_bytes(buf[1..9].try_into().unwrap());
                let len = u32::from_be_bytes(buf[9..13].try_into().unwrap()) as usize;
                if len > Self::MAX_RELIABLE_DATA {
                    // Malformed/hostile length: the length field itself is
                    // the problem, not a block to ship. Drop just the tag
                    // byte and resync — the old behaviour synthesised a
                    // ReliableRequest for the embedded block_id, which both
                    // hid the framing error from the operator and prompted a
                    // real reliable retransmit for a block the peer may never
                    // have intended to ship (its length was bogus, after all).
                    return Some(Err(1));
                }
                let end = 13 + len;
                if buf.len() < end {
                    return None; // need the whole payload
                }
                let bytes = buf[13..end].to_vec();
                Some(Ok((TunnelSignal::ReliableData { block, bytes }, end)))
            }
            Self::TAG_CREDIT => {
                if buf.len() < 1 + 8 {
                    return None;
                }
                let delivered = u64::from_be_bytes(buf[1..9].try_into().unwrap());
                Some(Ok((TunnelSignal::Credit { delivered }, 9)))
            }
            Self::TAG_BLOCKACK => {
                if buf.len() < 1 + 8 {
                    return None;
                }
                let block = u64::from_be_bytes(buf[1..9].try_into().unwrap());
                Some(Ok((TunnelSignal::BlockAck { block }, 9)))
            }
            // Unknown tag: drop one byte and resync. Previously this synthesised
            // a BlockCount { total: u64::MAX } which permanently hung the
            // downstream task (highest_delivered() could never reach u64::MAX).
            _ => Some(Err(1)),
        }
    }
}

use raptun_fec::codec::{actual_k_for, max_payload, RaptorQBlockDecoderImpl, RaptorQBlockEncoder};
use raptun_fec::encoder::BlockEncoder;
use raptun_fec::BlockManager;
use raptun_proto::datagram::SymbolHeader;
use raptun_proto::StreamId;

/// One demultiplexed inbound symbol: its block, actual source-block size,
/// encoding-symbol id, and payload.
pub type InboundSymbol = (BlockId, u32, u32, Bytes);

/// Connection-level datagram demultiplexer.
///
/// QUIC datagrams are per-connection, but Raptun multiplexes many tunnelled
/// connections over one QUIC connection, so inbound symbols must be routed by
/// `stream_id` to the right tunnel's [`FecReceiver`]. The hub owns the single
/// datagram read loop and forwards each symbol to the registered channel for
/// its stream.
///
/// Because a tunnel's first data symbols can race ahead of its route being
/// registered (the receiving end must first read the stream id off the
/// signaling stream), the hub briefly **buffers** symbols for not-yet-known
/// streams and replays them on registration. This closes the startup race
/// without relying on FEC repair to paper over the initial burst.
#[derive(Clone)]
pub struct DatagramHub {
    inner: Arc<Mutex<HubInner>>,
}

/// Cap on buffered symbols per unregistered stream, to bound memory if a peer
/// sends datagrams for a stream that is never opened.
const MAX_PENDING_PER_STREAM: usize = 256;

/// Cap on the number of *distinct* stream_ids that can have pending datagrams
/// buffered at once. Each pending stream holds up to MAX_PENDING_PER_STREAM
/// symbols, so without this cap an attacker spraying random stream_ids (the
/// 64-bit id space is too large to enumerate) can balloon the hub's memory
/// up to MAX_PENDING_PER_STREAM * 2^64 in the limit. 1024 streams * 256
/// symbols * ~1100 B = ~288 MB worst case — bounded and well above the
/// realistic maximum number of in-flight tunnels per connection.
pub const MAX_PENDING_STREAMS: usize = 1024;

/// Per-route channel capacity (symbols buffered for a single registered
/// stream before its consumer drains them). Bounds the per-stream backlog
/// when the downstream task is slow or stalled: a full channel means
/// `dispatch` drops new symbols instead of growing memory without bound
/// (M1). Generous by design — one head-of-queue block plus a few in-flight
/// repairs is well under 100 symbols for the default K=16; 1024 covers a
/// very large K with a much-slowed receiver.
pub const ROUTE_CAPACITY: usize = 8192;

struct HubInner {
    routes: HashMap<StreamId, mpsc::Sender<InboundSymbol>>,
    /// Symbols that arrived before their stream was registered.
    pending: HashMap<StreamId, Vec<InboundSymbol>>,
}

impl Default for DatagramHub {
    fn default() -> Self {
        Self::new()
    }
}

impl DatagramHub {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HubInner {
                routes: HashMap::new(),
                pending: HashMap::new(),
            })),
        }
    }

    /// Register interest in a tunnel's `stream_id`. Returns a [`HubGuard`]
    /// that owns the receive channel and, on drop, removes the route from the
    /// hub. Holding the guard for the lifetime of the tunnel guarantees the
    /// route is removed even if the tunnel task panics or unwinds through a
    /// `?` early-return — important because the hub's `routes` map is shared
    /// across the whole connection, and a leak here would silently drop
    /// inbound symbols for the rest of the connection's life.
    ///
    /// The per-route channel is bounded ([`ROUTE_CAPACITY`]) so a stalled
    /// downstream task cannot accumulate an unbounded backlog of symbols in
    /// memory (M1). When full, `dispatch` drops the new symbol and logs a
    /// rate-limited warn so a wedged receiver is operator-visible.
    ///
    /// Any symbols buffered before registration are replayed immediately, in
    /// arrival order. Replay uses `try_send`: the startup burst is well
    /// under the cap, and we cannot `blocking_send` here (this is called
    /// from a runtime thread, where blocking the executor is a panic).
    pub fn register(&self, stream_id: StreamId) -> HubGuard {
        let (tx, rx) = mpsc::channel(ROUTE_CAPACITY);
        let mut inner = self.inner.lock().unwrap();
        if let Some(buffered) = inner.pending.remove(&stream_id) {
            for sym in buffered {
                if let Err(mpsc::error::TrySendError::Full(returned)) = tx.try_send(sym) {
                    // Should be impossible: startup burst << ROUTE_CAPACITY
                    // and no consumer is yet attached. If it ever happens
                    // (e.g. a future change inflates the burst), drop the
                    // excess rather than block the executor.
                    tracing::warn!(
                        stream_id,
                        cap = ROUTE_CAPACITY,
                        "dropping replay symbol: channel full at register time"
                    );
                    let _ = returned;
                }
            }
        }
        inner.routes.insert(stream_id, tx);
        HubGuard {
            hub: self.clone(),
            stream_id,
            rx: Some(rx),
        }
    }

    /// Stop routing a tunnel's symbols (tunnel closed). Equivalent to
    /// dropping the [`HubGuard`] returned by `register`; the public method
    /// remains for callers that need to tear down a route without holding
    /// the guard (e.g. tests).
    pub fn unregister(&self, stream_id: StreamId) {
        let mut inner = self.inner.lock().unwrap();
        inner.routes.remove(&stream_id);
        inner.pending.remove(&stream_id);
    }

    /// True if `stream_id` currently has an active registered route. Used by
    /// the server side to reject duplicate `stream_id`s announced on the
    /// control stream — a peer that re-uses an id would otherwise overwrite
    /// the prior route, leaving the older tunnel's receiver silent (M3).
    pub fn has_route(&self, stream_id: StreamId) -> bool {
        self.inner.lock().unwrap().routes.contains_key(&stream_id)
    }

    /// Number of *distinct* stream_ids currently buffered but not yet routed.
    /// Public so integration tests can assert the cap end-to-end and ops
    /// tooling can inspect hub state.
    pub fn pending_len(&self) -> usize {
        self.inner.lock().unwrap().pending.len()
    }

    /// Route one received datagram for a **registered** stream.
    ///
    /// Returns `Some((sender, symbol))` if the stream is registered, with the
    /// hub lock already released. The caller must `.send(symbol).await` on the
    /// returned sender: awaiting outside the lock is what prevents the
    /// deadlock that `try_send` inside `dispatch` was working around. When the
    /// channel is full the caller parks here until the downstream task drains
    /// one slot — that backpressure propagates to Quinn's receive window so the
    /// remote sender naturally slows down instead of having symbols dropped.
    ///
    /// Returns `None` for unregistered streams. The caller should then call
    /// [`Self::dispatch`] to buffer the symbol in the pending map.
    pub fn dispatch_route(
        &self,
        datagram: &[u8],
    ) -> Option<(mpsc::Sender<InboundSymbol>, InboundSymbol)> {
        let Ok((hdr, payload)) = SymbolHeader::parse(datagram) else {
            return None;
        };
        let sym = (hdr.block_id, hdr.actual_k as u32, hdr.esi, Bytes::copy_from_slice(payload));
        let inner = self.inner.lock().unwrap();
        if let Some(tx) = inner.routes.get(&hdr.stream_id) {
            // Clone is cheap (Arc refcount bump). Drop the lock before the
            // caller awaits so other tunnels' dispatches are not blocked.
            let tx = tx.clone();
            drop(inner);
            Some((tx, sym))
        } else {
            None
        }
    }

    /// Buffer a datagram for a **not-yet-registered** stream.
    ///
    /// Symbols for registered streams must go through [`Self::dispatch_route`]
    /// so the send can be awaited outside the mutex. This method handles only
    /// the pending-buffer path for streams whose route has not been registered
    /// yet; calling it for a registered stream is a no-op (the symbol is
    /// silently dropped).
    pub fn dispatch(&self, datagram: &[u8]) {
        let Ok((hdr, payload)) = SymbolHeader::parse(datagram) else {
            return;
        };
        let sym = (hdr.block_id, hdr.actual_k as u32, hdr.esi, Bytes::copy_from_slice(payload));
        let mut inner = self.inner.lock().unwrap();
        // Registered streams are handled by dispatch_route; skip them here.
        if inner.routes.contains_key(&hdr.stream_id) {
            return;
        }
        // Unknown stream — buffer only if both we don't already have a slot
        // for it AND we're under the distinct-stream cap. The cap matters
        // because an attacker can spray random 8-byte stream_ids and the
        // 64-bit space is too large to enumerate, so without it the pending
        // map grows without bound.
        if !inner.pending.contains_key(&hdr.stream_id) {
            if inner.pending.len() >= MAX_PENDING_STREAMS {
                tracing::warn!(
                    stream_id = hdr.stream_id,
                    pending_streams = inner.pending.len(),
                    "datagram for unregistered stream dropped: pending stream cap reached"
                );
                return;
            }
            inner.pending.insert(hdr.stream_id, Vec::new());
        }
        let buf = inner
            .pending
            .get_mut(&hdr.stream_id)
            .expect("just inserted");
        if buf.len() < MAX_PENDING_PER_STREAM {
            buf.push(sym);
        }
        // else: per-stream cap hit, drop silently — the legitimate start-of-
        // tunnel burst is well under this, so a cap-hit is by definition
        // pathological.
    }
}

/// RAII guard for a registered hub route. Holds the inbound symbol channel
/// and, on drop, removes the route from the hub. Mirrors `RegistryGuard` in
/// `raptun_core::monitor` — the contract is the same: even a panic or early
/// `?` return in the tunnel task must remove the route, otherwise inbound
/// symbols silently get dropped (no route to forward to) and the connection
/// slowly degrades without any operator signal.
pub struct HubGuard {
    hub: DatagramHub,
    stream_id: StreamId,
    rx: Option<mpsc::Receiver<InboundSymbol>>,
}

impl HubGuard {
    /// Take the underlying receive channel. After this call, dropping the
    /// guard no longer removes the route — useful when the channel needs to
    /// outlive the guard (it does not, in the current code, but the API
    /// allows the pattern).
    pub fn take_rx(&mut self) -> mpsc::Receiver<InboundSymbol> {
        self.rx.take().expect("rx already taken")
    }
}

impl std::ops::Deref for HubGuard {
    type Target = mpsc::Receiver<InboundSymbol>;
    fn deref(&self) -> &Self::Target {
        self.rx.as_ref().expect("rx already taken")
    }
}

impl std::ops::DerefMut for HubGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.rx.as_mut().expect("rx already taken")
    }
}

impl Drop for HubGuard {
    fn drop(&mut self) {
        self.hub.unregister(self.stream_id);
    }
}

/// Sender half of the FEC pump for one tunnelled connection.
///
/// Chunks application bytes into blocks and produces framed symbol datagrams.
/// Tracks how many repair symbols each block has originated so a later NACK can
/// continue the ESI sequence with fresh symbols.
pub struct FecSender {
    stream_id: StreamId,
    symbol_size: u16,
    k: u32,
    next_block: BlockId,
    /// Repair symbols already emitted per still-live block (for NACK top-ups).
    repair_sent: HashMap<BlockId, u32>,
    /// Source-block size (actual K) each block was encoded with.
    block_k: HashMap<BlockId, u32>,
    /// Retained encoders per block, so additional repair can be minted on NACK.
    encoders: HashMap<BlockId, RaptorQBlockEncoder>,
    /// Retained original payload bytes per block, so a stranded block can be
    /// shipped reliably as the convergence lower-bound fallback.
    payloads: HashMap<BlockId, Vec<u8>>,
    /// Lowest block id still retained; the low-water edge of the retention
    /// window, advanced as old blocks are evicted so eviction stays O(evicted).
    oldest_retained: BlockId,
    /// When each retained block was first emitted. Used by proactive repair
    /// spurts to identify blocks that have not been acknowledged after one RTT.
    block_sent_at: HashMap<BlockId, Instant>,
    /// How many proactive top-ups have been issued per retained block. Capped
    /// so proactive spurts do not infinite-loop before the NACK path takes over.
    proactive_counts: HashMap<BlockId, u32>,
    /// Number of blocks the peer has acked (decoded). Monotonically non-
    /// decreasing: each `BlockAck` increments via `retire_block`. When this
    /// reaches `next_block`, every block this sender has ever produced has
    /// been decoded, and the post-EOF `up` task can tear the tunnel down
    /// without waiting the full 120 s stall timeout (which would otherwise
    /// fire on every short-lived single-block tunnel — see the 2026-08-16
    /// live test: 973 `tunnel stalled (post-EOF)` warns in 80 min, all
    /// `total_blocks=1 delivered=1 stalled_s=120`).
    acked_blocks: u64,
}

/// Upper bound on the *bytes* of source data a sender retains for possible NACK
/// top-ups and reliable retransmits, per tunnel. A block older than this behind
/// the send frontier has, in every convergent case, already been delivered or
/// reliably retransmitted; retaining it further only grows memory.
///
/// This is a *byte* budget, not a block count, so per-tunnel memory is flat and
/// independent of the block geometry K. The previous fixed 1024-block window
/// meant ~2·K·symbol_size·1024 bytes per tunnel (~38 MB at the default
/// geometry, since each block is retained as both an encoder and a raw payload
/// copy), so a few hundred concurrent large transfers exhausted RAM. Bounding
/// by bytes keeps the worst case predictable regardless of concurrency.
const SENDER_RETAIN_BYTES: u64 = 32 * 1024 * 1024;

/// Maximum number of proactive repair spurts a single block may receive. After
/// this cap the sender stops主动补喷 for that block and lets the receiver's
/// NACK / ReliableRequest path take over. This bounds bandwidth and avoids
/// outrunning a genuinely stalled receiver.
const PROACTIVE_TOPUP_CAP: u32 = 3;

impl FecSender {
    pub fn new(stream_id: StreamId, symbol_size: u16, k: u32) -> Self {
        Self {
            stream_id,
            symbol_size,
            k: k.max(1),
            next_block: 0,
            repair_sent: HashMap::new(),
            block_k: HashMap::new(),
            encoders: HashMap::new(),
            payloads: HashMap::new(),
            oldest_retained: 0,
            block_sent_at: HashMap::new(),
            proactive_counts: HashMap::new(),
            acked_blocks: 0,
        }
    }

    /// How many recent blocks to retain, derived from the byte budget and this
    /// tunnel's block size. At least 1 so a just-sent block can always be
    /// NACK-topped-up or reliably retransmitted. Each retained block costs
    /// roughly two source copies (the encoder's padded block plus the raw
    /// payload), hence the `2 *` in the denominator.
    fn retain_blocks(&self) -> u64 {
        let per_block = 2 * self.block_payload().max(1) as u64;
        (SENDER_RETAIN_BYTES / per_block).max(1)
    }

    /// Application payload capacity of one block at this geometry.
    pub fn block_payload(&self) -> usize {
        max_payload(self.symbol_size, self.k)
    }

    /// Encode `data` into as many full blocks as it fills, returning the framed
    /// symbol datagrams to send. `repair_count` repair symbols are added per
    /// block (chosen by the adaptive strategy from live telemetry).
    ///
    /// Any trailing bytes that don't fill a whole block are returned to the
    /// caller as `leftover` to be prepended next time — the caller owns the
    /// pending buffer so back-pressure stays visible.
    pub fn encode_blocks(&mut self, data: &[u8], repair_count: u32) -> Vec<Bytes> {
        let cap = self.block_payload();
        let mut out = Vec::new();
        for chunk in data.chunks(cap) {
            out.extend(self.encode_one_block(chunk, repair_count));
        }
        out
    }

    /// Encode a single (possibly short, e.g. final) block.
    pub fn encode_one_block(&mut self, payload: &[u8], repair_count: u32) -> Vec<Bytes> {
        let block_id = self.next_block;
        self.next_block += 1;

        // Use only as many source symbols as the payload actually needs. This
        // prevents a 100-byte message from being padded to a full K-symbol block
        // and flooding the link with ~K datagrams.
        let actual_k = actual_k_for(payload.len(), self.symbol_size, self.k);
        let encoder = RaptorQBlockEncoder::new(payload, self.symbol_size, actual_k);
        let symbols = encoder.emit(self.stream_id, block_id, repair_count);
        self.repair_sent.insert(block_id, repair_count);
        self.block_k.insert(block_id, actual_k);
        self.encoders.insert(block_id, encoder);
        // Retain the raw payload for a possible reliable-retransmit fallback.
        self.payloads.insert(block_id, payload.to_vec());
        // Record when this block was first sent. Proactive top-ups use this to
        // identify blocks that have not been acknowledged after one RTT.
        self.block_sent_at.insert(block_id, Instant::now());

        // Bound memory on long-lived connections: retire blocks that have fallen
        // more than SENDER_RETAIN_BLOCKS behind the send frontier. Without this,
        // encoders + payloads grow without limit for the life of the tunnel.
        self.evict_old_blocks();

        symbols.into_iter().map(|s| s.datagram.freeze()).collect()
    }

    /// Drop retained state for blocks older than the retention window. Cheap:
    /// only runs when the frontier advances past the window edge.
    fn evict_old_blocks(&mut self) {
        let retain = self.retain_blocks();
        if self.next_block <= retain {
            return;
        }
        let cutoff = self.next_block - retain;
        // Retiring by exact id keeps this O(evicted) rather than scanning the
        // whole map; the frontier advances by a handful of blocks per burst.
        for block_id in self.oldest_retained..cutoff {
            self.encoders.remove(&block_id);
            self.repair_sent.remove(&block_id);
            self.block_k.remove(&block_id);
            self.payloads.remove(&block_id);
            self.block_sent_at.remove(&block_id);
            self.proactive_counts.remove(&block_id);
        }
        self.oldest_retained = self.oldest_retained.max(cutoff);
    }

    /// Mint `extra` additional repair symbols for `block_id` in response to a
    /// NACK, continuing the ESI sequence so every symbol is fresh.
    pub fn additional_repair(&mut self, block_id: BlockId, extra: u32) -> Vec<Bytes> {
        let Some(encoder) = self.encoders.get(&block_id) else {
            return Vec::new(); // block already retired
        };
        let already = *self.repair_sent.get(&block_id).unwrap_or(&0);
        let symbols = encoder.emit_additional_repair(self.stream_id, block_id, already, extra);
        self.repair_sent.insert(block_id, already + extra);
        symbols.into_iter().map(|s| s.datagram.freeze()).collect()
    }

    /// The retained raw payload bytes for `block_id`, to serve a
    /// `ReliableRequest`. `None` if the block was already retired.
    pub fn reliable_payload(&self, block_id: BlockId) -> Option<Vec<u8>> {
        self.payloads.get(&block_id).cloned()
    }

    /// Release the retained encoder for a block once the receiver confirms it
    /// decoded (via an ack) or it ages out. Bounds memory on long connections.
    pub fn retire_block(&mut self, block_id: BlockId) {
        self.encoders.remove(&block_id);
        self.repair_sent.remove(&block_id);
        self.block_k.remove(&block_id);
        self.payloads.remove(&block_id);
        self.block_sent_at.remove(&block_id);
        self.proactive_counts.remove(&block_id);
        self.acked_blocks = self.acked_blocks.saturating_add(1);
    }

    /// Number of blocks the peer has acked (decoded). When this reaches
    /// `next_block` the post-EOF `up` task can break out of its stall guard
    /// immediately instead of waiting `TUNNEL_MAX_STALL`. See
    /// `acked_blocks` field docs for the live-test context.
    pub fn acked_blocks(&self) -> u64 {
        self.acked_blocks
    }

    /// Return blocks that should receive a proactive repair spurt.
    ///
    /// A block is eligible if it has been retained, has not been acknowledged,
    /// was first sent more than `rtt` ago, and the link is not congestion-
    /// limited. For each eligible block this reserves repair budget and bumps
    /// the per-block proactive counter, returning the `(block_id, extra_symbols)`
    /// pairs the caller should emit via [`Self::additional_repair`].
    pub fn proactive_topups(
        &mut self,
        now: Instant,
        rtt: Duration,
        budget: &raptun_fec::RepairBudget,
        link: &raptun_fec::LinkState,
    ) -> Vec<(BlockId, u32)> {
        use raptun_fec::link::LossRegime;

        // Only top up when the link actually shows random loss. In the
        // Quiescent regime (negligible loss) extra repair is pure waste and
        // can fill the send buffer, stalling large transfers on clean links.
        // In Congestion, adding redundancy deepens the collapse.
        if !matches!(link.regime(), LossRegime::Random) {
            return Vec::new();
        }

        let mut out = Vec::new();

        for (&block_id, &sent_at) in &self.block_sent_at {
            // The encoder must still be retained (BlockAck retires it).
            if !self.encoders.contains_key(&block_id) {
                continue;
            }
            if now.duration_since(sent_at) <= rtt {
                continue;
            }
            let count = *self.proactive_counts.get(&block_id).unwrap_or(&0);
            if count >= PROACTIVE_TOPUP_CAP {
                continue;
            }
            // Conservative extra amount: enough to push a block toward decode but
            // not so large that a single spurt can exhaust the repair budget.
            // Scale by the block's actual K, not the negotiated maximum.
            let actual_k = self.block_k.get(&block_id).copied().unwrap_or(self.k);
            let desired = (actual_k / 4).max(1);
            if !budget.try_reserve(desired) {
                continue;
            }
            *self.proactive_counts.entry(block_id).or_insert(0) = count + 1;
            out.push((block_id, desired));
        }
        out
    }
}

/// Receiver half of the FEC pump for one tunnelled connection.
///
/// Routes symbols to per-block managers and delivers decoded blocks to the
/// application in strict block order.
pub struct FecReceiver {
    symbol_size: u16,
    k: u32,
    /// Active per-block reassembly state machines.
    managers: HashMap<BlockId, BlockManager>,
    /// Decoded-but-not-yet-delivered blocks, awaiting earlier blocks.
    ready: HashMap<BlockId, Vec<u8>>,
    /// The next block id to deliver to the application (ensures TCP order).
    next_deliver: BlockId,
    /// Highest block id for which any symbol has arrived. Used as the
    /// sequence-progress oracle: a block is "genuinely behind" (not merely
    /// reordered) when a strictly higher block has already been seen. This is
    /// what lets the *head* block — which blocks delivery and can never advance
    /// the delivery floor past itself — still be recognized as stalled.
    highest_seen: BlockId,
    /// Total block count the sender announced (via `BlockCount`), once known.
    /// Lets the receiver detect blocks that were *entirely* lost — no symbol
    /// ever arrived, so they have no manager — and request them reliably.
    total_blocks: Option<u64>,
    /// Sender high-water mark from `HighWater`: the number of blocks the sender
    /// has emitted so far (running, not terminal). Blocks `[0, high_water)`
    /// provably exist even if no symbol for them ever arrived and no later block
    /// followed, so this bounds the entirely-lost scan on idle streams.
    high_water: u64,
    /// Blocks for which a reliable retransmit has already been requested, so the
    /// control tick does not re-request them every cycle while the reliable data
    /// is in flight.
    reliable_requested: std::collections::HashSet<BlockId>,
    /// Blocks decoded since the last `drain_acks` - queued for a `BlockAck`
    /// signal to the sender so it can release their retained state. A block is
    /// pushed the moment it decodes (enters `ready`), not when it is delivered
    /// in order, so an out-of-order decode still frees sender memory promptly.
    pending_acks: Vec<BlockId>,
}

impl FecReceiver {
    pub fn new(symbol_size: u16, k: u32) -> Self {
        Self {
            symbol_size,
            k: k.max(1),
            managers: HashMap::new(),
            ready: HashMap::new(),
            next_deliver: 0,
            highest_seen: 0,
            total_blocks: None,
            high_water: 0,
            reliable_requested: std::collections::HashSet::new(),
            pending_acks: Vec::new(),
        }
    }

    /// Record the total block count announced by the sender. Enables detection
    /// of entirely-lost blocks in [`FecReceiver::tick`].
    pub fn set_total_blocks(&mut self, total: u64) {
        self.total_blocks = Some(total);
    }

    /// Record the sender's running high-water mark (from `HighWater`). Monotonic:
    /// only ever advances. Lets the entirely-lost scan reach a block whose every
    /// datagram was lost and which no later block follows.
    pub fn set_high_water(&mut self, blocks: u64) {
        self.high_water = self.high_water.max(blocks);
    }

    /// Feed one received symbol (already split from its datagram header).
    ///
    /// Returns any application bytes that became deliverable as a result —
    /// possibly zero (block not yet complete), possibly several blocks' worth
    /// (this symbol completed a block that unblocked a run of buffered ones).
    ///
    /// `budget` is the shared repair budget so the block manager can release any
    /// reservation held for an outstanding NACK when this symbol makes progress.
    pub fn on_symbol(
        &mut self,
        block_id: BlockId,
        actual_k: u32,
        esi: u32,
        payload: &[u8],
        now: std::time::Instant,
        budget: &raptun_fec::RepairBudget,
    ) -> Vec<u8> {
        // Blocks already delivered are ignored (late duplicates).
        if block_id < self.next_deliver {
            return Vec::new();
        }
        self.highest_seen = self.highest_seen.max(block_id);

        let symbol_size = self.symbol_size;
        // The block was encoded with actual_k source symbols (≤ negotiated K).
        // Use that, not the negotiated maximum, to size the decoder.
        let k = actual_k.max(1).min(self.k);
        let mgr = self.managers.entry(block_id).or_insert_with(|| {
            let codec = Box::new(RaptorQBlockDecoderImpl::new(symbol_size, k));
            BlockManager::new(block_id, k, codec)
        });

        if let raptun_fec::DecoderAction::Deliver { bytes } =
            mgr.on_symbol(now, esi, payload, budget)
        {
            self.managers.remove(&block_id);
            self.ready.insert(block_id, bytes);
            // Queue a BlockAck: the block decoded, so the sender can release
            // its encoder/payload for this block now (not when it is delivered
            // in order).
            self.pending_acks.push(block_id);
        }

        self.drain_ready()
    }

    /// Deliver as many contiguous decoded blocks as are ready, starting at
    /// `next_deliver`, concatenated into one buffer.
    fn drain_ready(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(bytes) = self.ready.remove(&self.next_deliver) {
            out.extend_from_slice(&bytes);
            self.next_deliver += 1;
        }
        out
    }

    /// Access a block's manager for the control-tick arbitration (NACK /
    /// degrade decisions) driven by [`run_fec_tunnel`]'s downstream tick.
    pub fn manager_mut(&mut self, block_id: BlockId) -> Option<&mut BlockManager> {
        self.managers.get_mut(&block_id)
    }

    /// The highest block id we have delivered, for the decoder's sequence
    /// oracle (`later_blocks_progressing`).
    pub fn highest_delivered(&self) -> BlockId {
        self.next_deliver
    }

    /// Take the blocks decoded since the last call, to be acknowledged to the
    /// sender via [`TunnelSignal::BlockAck`]. Each decoded block appears once;
    /// the caller drains and sends after each `on_symbol` / `on_reliable_block`
    /// burst and/or on the control tick.
    pub fn drain_acks(&mut self) -> Vec<BlockId> {
        std::mem::take(&mut self.pending_acks)
    }

    /// Iterate the block ids with live (undecoded) managers, for control-tick
    /// arbitration.
    pub fn live_blocks(&self) -> Vec<BlockId> {
        self.managers.keys().copied().collect()
    }

    /// Run the convergence arbitration over every live block.
    ///
    /// This is the Phase-3 control tick: for each undecoded block, ask its
    /// [`BlockManager`] what to do given the current link state and repair
    /// budget. The manager encapsulates the whole convergence policy — the
    /// three-condition stall test (jitter/reorder tolerant), the
    /// congestion-vs-random arbitration, the in-flight repair budget brake, and
    /// the degraded fallback. Here we merely collect the resulting actions so
    /// the caller can put them on the wire.
    ///
    /// Returns the [`TunnelSignal`]s to send: `Nack`s for blocks that should get
    /// more repair, and `ReliableRequest`s for blocks the manager has given up
    /// on (budget exhausted / congestion), which the sender answers by shipping
    /// the block's bytes over the reliable channel. Once a block is requested
    /// reliably it is left in place; the arriving [`TunnelSignal::ReliableData`]
    /// (via [`FecReceiver::on_reliable_block`]) completes it. To avoid spamming
    /// duplicate requests each tick, requested blocks are remembered.
    pub fn tick(
        &mut self,
        link: &raptun_fec::LinkState,
        budget: &raptun_fec::RepairBudget,
        now: std::time::Instant,
    ) -> Vec<TunnelSignal> {
        use raptun_fec::decoder::TickCtx;
        use raptun_fec::DecoderAction;

        let highest = self.highest_seen;
        let mut out = Vec::new();
        // Snapshot ids so we can mutate the map while iterating.
        let ids: Vec<BlockId> = self.managers.keys().copied().collect();
        for block_id in ids {
            // A block is "genuinely behind" (not merely reordered) if a strictly
            // higher block has already been seen. This correctly flags the head
            // block, which blocks delivery and thus can never see the delivery
            // floor advance past itself.
            let later_progressing = highest > block_id;
            let action = {
                let Some(mgr) = self.managers.get_mut(&block_id) else {
                    continue;
                };
                let ctx = TickCtx {
                    now,
                    link,
                    budget,
                    later_blocks_progressing: later_progressing,
                };
                mgr.tick(&ctx)
            };
            match action {
                DecoderAction::SendNack { have, need } => {
                    out.push(TunnelSignal::Nack {
                        block: block_id,
                        have,
                        need,
                    });
                }
                DecoderAction::RequestReliableRetransmit => {
                    // Degraded: FEC gave up (budget exhausted or congestion,
                    // where more repair would hurt). Fall back to a reliable
                    // copy of the block's bytes — the convergence lower bound.
                    // Request at most once; further ticks stay quiet until the
                    // reliable data lands and completes the block.
                    if self.reliable_requested.insert(block_id) {
                        tracing::debug!(block_id, "block degraded -> reliable retransmit");
                        out.push(TunnelSignal::ReliableRequest { block: block_id });
                    }
                }
                DecoderAction::Deliver { .. } | DecoderAction::Idle => {}
            }
        }

        // Detect *entirely lost* blocks: ids below a known upper bound that have
        // no manager (no symbol ever arrived), are not already buffered ready,
        // and have not yet been requested. These are invisible to the per-block
        // arbitration above (no manager exists), yet they hole the stream, so we
        // must request them reliably too. The upper bound is whatever we can
        // prove exists: `highest_seen` is the id of the highest block for which a
        // symbol arrived (so `highest_seen + 1` blocks exist by observation),
        // `high_water` is the sender's announced running block count, and — once
        // the stream ends — `total_blocks`. Using the reliable `high_water` here
        // is what lets an entirely-lost block be recovered even when no later
        // block ever arrives to advance `highest_seen`.
        let upper = {
            let by_seen = if self.managers.is_empty() && self.highest_seen == 0 {
                // No symbol has ever arrived; nothing observed to exist.
                0
            } else {
                self.highest_seen + 1
            };
            let by_high_water = self.high_water;
            let by_total = self.total_blocks.unwrap_or(0);
            by_seen.max(by_high_water).max(by_total)
        };
        for block_id in self.next_deliver..upper {
            if self.managers.contains_key(&block_id)
                || self.ready.contains_key(&block_id)
                || self.reliable_requested.contains(&block_id)
            {
                continue;
            }
            // A hole with no symbols at all — recover it reliably.
            self.reliable_requested.insert(block_id);
            tracing::debug!(block_id, "entirely-lost block -> reliable retransmit");
            out.push(TunnelSignal::ReliableRequest { block: block_id });
        }
        out
    }

    /// Remove `block_id` from the reliable-requested set so that a later
    /// [`Self::tick`] call will emit a fresh [`TunnelSignal::ReliableRequest`]
    /// for it. Call this when `rel_req_tx.try_send` drops the request — the
    /// block must not stay permanently stranded in the set.
    pub fn unmark_reliable_requested(&mut self, block_id: BlockId) {
        self.reliable_requested.remove(&block_id);
    }

    /// Inject a block's bytes delivered reliably via
    /// [`TunnelSignal::ReliableData`], completing it regardless of how many
    /// symbols were received. Returns any bytes that became deliverable (this
    /// block plus any contiguous run it unblocks). This is what guarantees the
    /// stream always terminates: even if FEC never gathers enough symbols, the
    /// reliable channel supplies the block verbatim.
    pub fn on_reliable_block(&mut self, block_id: BlockId, bytes: Vec<u8>) -> Vec<u8> {
        if block_id < self.next_deliver {
            return Vec::new(); // already delivered
        }
        // Retire any in-progress FEC state for this block and mark it ready.
        self.managers.remove(&block_id);
        self.reliable_requested.remove(&block_id);
        self.ready.insert(block_id, bytes);
        // A reliably-completed block is also done with the sender's retained
        // state, so ack it just like a decoded one.
        self.pending_acks.push(block_id);
        self.drain_ready()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use raptun_proto::datagram::SymbolHeader;
    use std::time::Instant;

    const SYM: u16 = 128;
    const K: u32 = 6;

    /// A permissive repair budget for receiver tests that don't exercise the
    /// budget itself. Feeding symbols only ever *releases* against it, which is a
    /// harmless no-op on a fresh budget.
    fn test_budget() -> raptun_fec::RepairBudget {
        let b = raptun_fec::RepairBudget::new(SYM, 0.4);
        b.refresh_ceiling(10_000_000);
        b
    }

    /// Encode a multi-block message, drop ~1/3 of every block's symbols, and
    /// confirm the receiver reconstructs the whole message in order.
    #[test]
    fn multi_block_recovery_in_order() {
        let msg: Vec<u8> = (0..5000).map(|i| (i % 253) as u8).collect();

        let mut sender = FecSender::new(1, SYM, K);
        // repair_count == K gives plenty of headroom to survive 1/3 loss.
        let datagrams = sender.encode_blocks(&msg, K);

        let mut receiver = FecReceiver::new(SYM, K);
        let budget = test_budget();
        let mut assembled = Vec::new();
        for (i, dg) in datagrams.iter().enumerate() {
            // Drop every third datagram to simulate loss.
            if i % 3 == 0 {
                continue;
            }
            let (hdr, payload) = SymbolHeader::parse(dg).unwrap();
            let delivered =
                receiver.on_symbol(hdr.block_id, hdr.actual_k as u32, hdr.esi, payload, Instant::now(), &budget);
            assembled.extend_from_slice(&delivered);
        }

        assert_eq!(
            assembled, msg,
            "FEC pump must recover the full stream in order"
        );
    }

    /// Short payloads must be encoded with a small actual K, not padded to the
    /// negotiated maximum. This is the fix for the P0-1 bandwidth blow-up.
    #[test]
    fn short_payload_uses_small_actual_k() {
        let mut sender = FecSender::new(1, SYM, K);
        // A 100-byte payload needs only ceil((100 + 4) / 128) = 1 source symbol,
        // not the full K = 6.
        let payload = vec![0xABu8; 100];
        let datagrams = sender.encode_one_block(&payload, 2);

        let source_count = datagrams
            .iter()
            .filter(|dg| {
                let (hdr, _) = SymbolHeader::parse(dg).unwrap();
                hdr.esi < hdr.actual_k as u32
            })
            .count();
        assert_eq!(
            source_count, 1,
            "100-byte payload must produce exactly 1 source symbol, not {K}"
        );

        // And it must round-trip.
        let mut receiver = FecReceiver::new(SYM, K);
        let budget = test_budget();
        let mut assembled = Vec::new();
        for dg in &datagrams {
            let (hdr, p) = SymbolHeader::parse(dg).unwrap();
            assembled.extend_from_slice(&receiver.on_symbol(
                hdr.block_id,
                hdr.actual_k as u32,
                hdr.esi,
                p,
                Instant::now(),
                &budget,
            ));
        }
        assert_eq!(assembled, payload);
    }

    #[test]
    fn out_of_order_datagrams_deliver_in_order() {
        let msg: Vec<u8> = (0..3000).map(|i| (i % 251) as u8).collect();
        let mut sender = FecSender::new(9, SYM, K);
        let mut datagrams = sender.encode_blocks(&msg, 2);

        // Reverse arrival order; in-order delivery must still hold.
        datagrams.reverse();

        let mut receiver = FecReceiver::new(SYM, K);
        let budget = test_budget();
        let mut assembled = Vec::new();
        for dg in &datagrams {
            let (hdr, payload) = SymbolHeader::parse(dg).unwrap();
            let delivered =
                receiver.on_symbol(hdr.block_id, hdr.actual_k as u32, hdr.esi, payload, Instant::now(), &budget);
            assembled.extend_from_slice(&delivered);
        }
        assert_eq!(assembled, msg);
    }

    #[test]
    fn additional_repair_is_fresh_and_decodes() {
        // Send a block with too few symbols to decode, then top up via NACK path.
        // Use a full-block payload so the block is encoded with the negotiated K.
        let payload: Vec<u8> = (0..(SYM as usize * K as usize - 4))
            .map(|i| (i % 200) as u8)
            .collect();
        let mut sender = FecSender::new(1, SYM, K);
        let first = sender.encode_one_block(&payload, 0); // K source symbols only

        let mut receiver = FecReceiver::new(SYM, K);
        let budget = test_budget();
        // Deliver only K-2 source symbols: not enough to decode.
        let mut assembled = Vec::new();
        for dg in first.iter().take((K - 2) as usize) {
            let (hdr, pay) = SymbolHeader::parse(dg).unwrap();
            assembled.extend_from_slice(&receiver.on_symbol(
                hdr.block_id,
                hdr.actual_k as u32,
                hdr.esi,
                pay,
                Instant::now(),
                &budget,
            ));
        }
        assert!(assembled.is_empty(), "should not decode yet");

        // NACK top-up: 4 fresh repair symbols for block 0.
        let extra = sender.additional_repair(0, 4);
        for dg in &extra {
            let (hdr, pay) = SymbolHeader::parse(dg).unwrap();
            assembled.extend_from_slice(&receiver.on_symbol(
                hdr.block_id,
                hdr.actual_k as u32,
                hdr.esi,
                pay,
                Instant::now(),
                &budget,
            ));
        }
        assert_eq!(
            assembled, payload,
            "additional repair must complete the block"
        );
    }

    #[test]
    fn tunnel_signal_round_trips() {
        let cases = [
            TunnelSignal::BlockCount { total: 12345 },
            TunnelSignal::HighWater { blocks: 6789 },
            TunnelSignal::Nack {
                block: 7,
                have: 5,
                need: 3,
            },
            TunnelSignal::ReliableRequest { block: 9 },
            TunnelSignal::ReliableData {
                block: 4,
                bytes: vec![1, 2, 3, 4, 5],
            },
            TunnelSignal::Credit { delivered: 98765 },
        ];
        for sig in cases {
            let bytes = sig.encode();
            let (decoded, used) = TunnelSignal::decode(&bytes).unwrap().unwrap();
            assert_eq!(decoded, sig);
            assert_eq!(used, bytes.len());
        }
        // Partial buffer yields None until complete.
        let full = TunnelSignal::Nack {
            block: 1,
            have: 1,
            need: 1,
        }
        .encode();
        assert!(TunnelSignal::decode(&full[..3]).is_none());
        // A ReliableData whose payload has not fully arrived is incomplete.
        let rd = TunnelSignal::ReliableData {
            block: 1,
            bytes: vec![9; 20],
        }
        .encode();
        assert!(TunnelSignal::decode(&rd[..15]).is_none());
        // An unknown tag is reported as Err(1) so the caller can drain it
        // without the buffer deadlocking on an unrecognised byte.
        assert_eq!(TunnelSignal::decode(&[0xFF]).unwrap().unwrap_err(), 1);
        assert!(TunnelSignal::decode(&[]).is_none());
    }

    /// The full Phase-3 convergence loop, driven through the real receiver tick:
    /// a block arrives with too few symbols to decode; after the grace period
    /// (and with a later block progressing so it is judged genuinely behind, not
    /// reordered) the tick emits a NACK; the sender mints the requested fresh
    /// repair; the block then decodes and delivers. No avalanche: exactly the
    /// missing count is requested.
    #[test]
    fn control_tick_nack_recovers_stalled_block() {
        use raptun_fec::link::{LinkState, LossRegime};
        use raptun_fec::RepairBudget;
        use std::time::Duration;

        let mut sender = FecSender::new(1, SYM, K);
        // Block 0: only K-3 source symbols (undecodable). Block 1: full, so the
        // receiver's delivery pointer can advance and mark block 0 as behind.
        // Use full-block payloads so both blocks are encoded with the negotiated K.
        let payload0: Vec<u8> = (0..(SYM as usize * K as usize - 4))
            .map(|i| (i % 200) as u8)
            .collect();
        let payload1: Vec<u8> = (0..(SYM as usize * K as usize - 4))
            .map(|i| (i % 190) as u8)
            .collect();
        let b0 = sender.encode_one_block(&payload0, 0);
        let b1 = sender.encode_one_block(&payload1, K);

        let mut receiver = FecReceiver::new(SYM, K);
        let t0 = Instant::now();
        // Budget with headroom; link is random-loss (FEC-appropriate) and enough
        // wall-clock has passed to exceed the stall grace period.
        let budget = RepairBudget::new(SYM, 0.4);
        budget.refresh_ceiling(10_000_000);

        // Deliver K-3 symbols of block 0 (not enough).
        for dg in b0.iter().take((K - 3) as usize) {
            let (h, p) = SymbolHeader::parse(dg).unwrap();
            receiver.on_symbol(h.block_id, h.actual_k as u32, h.esi, p, t0, &budget);
        }
        // Deliver block 1 fully; it decodes but cannot be delivered yet (block 0
        // is still missing and delivery is in-order). This does NOT advance the
        // delivery floor past block 0.
        for dg in &b1 {
            let (h, p) = SymbolHeader::parse(dg).unwrap();
            receiver.on_symbol(h.block_id, h.actual_k as u32, h.esi, p, t0, &budget);
        }

        let link = LinkState::new(
            Duration::from_millis(20),
            Duration::from_millis(5),
            0.2,
            10_000_000,
            LossRegime::Random,
        );
        let later = t0 + Duration::from_secs(1);

        // Block 0 is the head block: it blocks delivery, so the delivery floor
        // can never advance past it. But block 1 has been *seen*, which is the
        // sequence-progress signal that block 0 is genuinely behind (not merely
        // reordered). So the tick must NACK block 0, requesting exactly the
        // shortfall (K - 3).
        let nacks = receiver.tick(&link, &budget, later);
        assert_eq!(
            nacks.len(),
            1,
            "head block, provably behind, must be NACKed"
        );
        match nacks[0] {
            TunnelSignal::Nack { block, need, .. } => {
                assert_eq!(block, 0);
                assert_eq!(need, 3, "requests exactly the shortfall, no avalanche");
            }
            ref other => panic!("expected a Nack, got {other:?}"),
        }

        // Serve the NACK: the sender mints exactly `need` fresh repair symbols.
        let extra = sender.additional_repair(0, 3);
        assert_eq!(
            extra.len() as u32,
            3,
            "sender mints exactly `need` fresh symbols"
        );

        let mut delivered = Vec::new();
        for dg in &extra {
            let (h, p) = SymbolHeader::parse(dg).unwrap();
            delivered.extend_from_slice(&receiver.on_symbol(h.block_id, h.actual_k as u32, h.esi, p, later, &budget));
        }
        // Block 0 completes, unblocking in-order delivery of both blocks.
        let mut expected = payload0.clone();
        expected.extend_from_slice(&payload1);
        assert_eq!(delivered, expected, "NACK top-up converges the stream");
    }

    /// The convergence lower bound: when the repair budget is exhausted (so the
    /// tick refuses to NACK and instead degrades), the receiver emits a
    /// `ReliableRequest`, the sender answers with the block's bytes, and
    /// `on_reliable_block` completes the stream. Proves no deadlock even when
    /// FEC can make no further progress.
    #[test]
    fn reliable_retransmit_closes_the_lower_bound() {
        use raptun_fec::link::{LinkState, LossRegime};
        use raptun_fec::RepairBudget;
        use std::time::Duration;

        let mut sender = FecSender::new(1, SYM, K);
        let payload0: Vec<u8> = (0..600).map(|i| (i % 240) as u8).collect();
        let payload1: Vec<u8> = (0..300).map(|i| (i % 230) as u8).collect();
        // Block 0: only 1 source symbol delivered (badly stalled). Block 1 full.
        let b0 = sender.encode_one_block(&payload0, 0);
        let b1 = sender.encode_one_block(&payload1, K);

        let mut receiver = FecReceiver::new(SYM, K);
        let t0 = Instant::now();
        // Budget of zero: no repair may be requested, so the manager must
        // degrade block 0 to a reliable retransmit.
        let budget = RepairBudget::new(SYM, 0.4);
        budget.refresh_ceiling(0); // ceiling 0 ⇒ nothing fits
                                   // One symbol of block 0 (far from decodable).
        {
            let (h, p) = SymbolHeader::parse(&b0[0]).unwrap();
            receiver.on_symbol(h.block_id, h.actual_k as u32, h.esi, p, t0, &budget);
        }
        // Deliver block 1 fully (decodes but buffered behind block 0).
        for dg in &b1 {
            let (h, p) = SymbolHeader::parse(dg).unwrap();
            receiver.on_symbol(h.block_id, h.actual_k as u32, h.esi, p, t0, &budget);
        }

        let link = LinkState::new(
            Duration::from_millis(20),
            Duration::from_millis(5),
            0.3,
            0, // cwnd 0 keeps the ceiling at 0
            LossRegime::Random,
        );
        let later = t0 + Duration::from_secs(1);

        // Block 0 is the head block and block 1 has been seen, so it is provably
        // behind. With a zero repair budget the manager cannot NACK for more
        // repair, so it must degrade to a reliable retransmit request.
        let signals = receiver.tick(&link, &budget, later);
        assert_eq!(
            signals.len(),
            1,
            "stalled head block under zero budget acts"
        );
        assert!(
            matches!(signals[0], TunnelSignal::ReliableRequest { block: 0 }),
            "must request reliable retransmit, not NACK, when budget is exhausted: {:?}",
            signals[0]
        );
        // Re-ticking must not spam duplicate requests.
        assert!(
            receiver.tick(&link, &budget, later).is_empty(),
            "reliable request is sent at most once per block"
        );

        // Serve the reliable request from the sender's retained payload and
        // inject it — this is the convergence lower bound.
        let bytes = sender.reliable_payload(0).expect("sender retains block 0");
        let delivered = receiver.on_reliable_block(0, bytes);
        assert!(!delivered.is_empty(), "reliable block completes the stream");

        let mut expected = payload0.clone();
        expected.extend_from_slice(&payload1);
        assert_eq!(
            delivered, expected,
            "reliable retransmit converges the stream"
        );
    }

    /// Regression for the "runs then freezes" stall: a block whose *every*
    /// datagram is lost, with no later block ever arriving (interactive
    /// request/response), must still be recovered. Without the `HighWater`
    /// signal the receiver never learns the block exists — `highest_seen` never
    /// reaches it and no EOF sets `total_blocks` — so the entirely-lost scan
    /// skips it and the stream strands forever while QUIC keepalives keep
    /// flowing. With `set_high_water`, the tick requests it reliably.
    #[test]
    fn entirely_lost_block_recovered_via_high_water_when_idle() {
        use raptun_fec::link::{LinkState, LossRegime};
        use std::time::Duration;

        let mut sender = FecSender::new(1, SYM, K);
        let payload0: Vec<u8> = (0..300).map(|i| (i % 200) as u8).collect();
        let payload1: Vec<u8> = (0..300).map(|i| (i % 190) as u8).collect();
        // Two blocks are produced and their high-water announced, but block 1's
        // datagrams are ALL dropped and no block 2 ever follows.
        let b0 = sender.encode_one_block(&payload0, 0);
        let _b1_all_lost = sender.encode_one_block(&payload1, 0);

        let mut receiver = FecReceiver::new(SYM, K);
        let budget = test_budget();
        let t0 = Instant::now();

        // Deliver block 0 fully so it is delivered and next_deliver advances to 1.
        let mut delivered = Vec::new();
        for dg in &b0 {
            let (h, p) = SymbolHeader::parse(dg).unwrap();
            delivered.extend_from_slice(&receiver.on_symbol(h.block_id, h.actual_k as u32, h.esi, p, t0, &budget));
        }
        assert_eq!(delivered, payload0, "block 0 delivered");
        assert_eq!(receiver.highest_delivered(), 1);

        let link = LinkState::new(
            Duration::from_millis(20),
            Duration::from_millis(5),
            0.2,
            10_000_000,
            LossRegime::Random,
        );
        let later = t0 + Duration::from_secs(1);

        // Without the high-water hint the receiver cannot know block 1 exists:
        // no symbol arrived for it and there is no higher block. The scan finds
        // nothing to do.
        assert!(
            receiver.tick(&link, &budget, later).is_empty(),
            "without high-water, an idle entirely-lost block is invisible"
        );

        // The sender's high-water announcement (2 blocks emitted) reaches the
        // receiver over the reliable stream.
        receiver.set_high_water(2);

        // Now the tick recognizes block 1 exists but has no symbols, and requests
        // it reliably — the escape from the permanent stall.
        let signals = receiver.tick(&link, &budget, later);
        assert!(
            signals
                .iter()
                .any(|s| matches!(s, TunnelSignal::ReliableRequest { block: 1 })),
            "high-water must trigger reliable recovery of the entirely-lost block: {signals:?}"
        );

        // Serve it and confirm the stream converges.
        let bytes = sender.reliable_payload(1).expect("sender retains block 1");
        let out = receiver.on_reliable_block(1, bytes);
        assert_eq!(
            out, payload1,
            "reliable retransmit completes the lost block"
        );
        assert_eq!(receiver.highest_delivered(), 2, "stream advanced past hole");
    }

    /// The sender must not retain block state without bound on a long-lived
    /// connection. After sending far more than the retention window, only the
    /// most recent blocks remain answerable; ancient blocks are evicted.
    #[test]
    fn sender_retention_is_bounded() {
        let mut sender = FecSender::new(1, SYM, 2);
        let payload = vec![0xABu8; sender.block_payload()];
        let window = sender.retain_blocks();
        let total = window + 50;
        for _ in 0..total {
            let _ = sender.encode_one_block(&payload, 0);
        }
        // The oldest blocks are gone (return None), the newest are retained.
        assert!(
            sender.reliable_payload(0).is_none(),
            "ancient block must be evicted"
        );
        assert!(
            sender.reliable_payload(total - 1).is_some(),
            "most recent block must be retained"
        );
        // Retained maps stay within the window (plus the block just added).
        assert!(
            sender.payloads.len() as u64 <= window + 1,
            "retained payloads bounded by the window, got {}",
            sender.payloads.len()
        );
    }

    /// The retention window is a byte budget: retained source bytes stay under
    /// `SENDER_RETAIN_BYTES` regardless of the block geometry.
    #[test]
    fn sender_retention_byte_budget() {
        let mut sender = FecSender::new(1, SYM, 8);
        let cap = sender.block_payload();
        let payload = vec![0x5Au8; cap];
        for _ in 0..(sender.retain_blocks() + 100) {
            let _ = sender.encode_one_block(&payload, 0);
        }
        // Retained raw payloads must not exceed the byte budget (with one block
        // of slack for the just-added block).
        let retained_bytes = sender
            .payloads
            .values()
            .map(|p| p.len() as u64)
            .sum::<u64>();
        assert!(
            retained_bytes <= SENDER_RETAIN_BYTES + cap as u64,
            "retained payload bytes {retained_bytes} exceed budget {SENDER_RETAIN_BYTES}"
        );
    }

    /// `retire_block` advances the per-sender acked counter monotonically. The
    /// post-EOF `up` task uses this counter to break out of its 120 s stall
    /// guard as soon as every block has been acked (regression test for the
    /// 2026-08-16 live-test bug: 973 short tunnels each waited the full 120 s
    /// because the post-EOF stall guard had no "done" signal).
    #[test]
    fn retire_block_advances_acked_counter() {
        let mut sender = FecSender::new(1, SYM, 4);
        assert_eq!(sender.acked_blocks(), 0, "fresh sender has 0 acked blocks");

        // Retiring is unconditional + saturating: a BlockAck from the peer is
        // trusted (the peer is the authority on "I decoded this"), so the
        // counter advances even if the block was already evicted by the
        // retention window. The post-EOF break only requires the counter to
        // reach `next_block` — if eviction lost the payload but the ack still
        // arrives, the sender has nothing more to do anyway.
        sender.retire_block(999);
        assert_eq!(sender.acked_blocks(), 1, "retire advances the counter");

        // Retiring the same id twice still advances the counter; saturating
        // addition prevents any future overflow.
        sender.retire_block(7);
        sender.retire_block(7);
        assert_eq!(
            sender.acked_blocks(),
            3,
            "retire is monotonic and saturating"
        );

        // Retiring many distinct ids advances the counter by one each time.
        for id in 0..10 {
            sender.retire_block(id);
        }
        assert_eq!(
            sender.acked_blocks(),
            13,
            "counter is the total number of retire_block calls"
        );
    }

    /// Build a wire-format datagram that `DatagramHub::dispatch` will accept:
    /// a valid `SymbolHeader` followed by a small payload.
    fn datagram_for(stream: u64, block: u64, esi: u32) -> Vec<u8> {
        use raptun_proto::{datagram::SymbolHeader, Encode};
        let hdr = SymbolHeader {
            stream_id: stream,
            block_id: block,
            actual_k: 6,
            esi,
            flags: raptun_proto::datagram::SymbolFlags::empty(),
        };
        let mut buf = Vec::new();
        hdr.encode(&mut buf);
        buf.extend_from_slice(&[0u8; 16]);
        buf
    }

    #[test]
    fn hub_caps_distinct_pending_streams() {
        // An attacker spraying random 8-byte stream_ids used to create one
        // entry per id in the pending map (capped at MAX_PENDING_PER_STREAM
        // symbols each, but unbounded *in number of streams*). The cap on
        // distinct streams bounds memory to a known worst case.
        let hub = DatagramHub::new();
        for s in 0..(MAX_PENDING_STREAMS as u64 + 5) {
            hub.dispatch(&datagram_for(s, 1, 0));
        }
        let inner = hub.inner.lock().unwrap();
        assert_eq!(
            inner.pending.len(),
            MAX_PENDING_STREAMS,
            "pending stream count must be capped, not grow without bound"
        );
    }

    #[test]
    fn hub_routes_known_stream_and_drops_excess_per_stream() {
        // For a registered stream, dispatch_route returns the sender so the
        // caller can await outside the lock. dispatch() itself is now only for
        // unregistered streams.
        let hub = DatagramHub::new();
        let guard = hub.register(42);
        // dispatch_route returns Some for the registered stream.
        let result = hub.dispatch_route(&datagram_for(42, 1, 0));
        assert!(
            result.is_some(),
            "dispatch_route must return Some for a registered stream"
        );
        drop(guard);
        // Unknown stream: fill to per-stream cap, then verify the cap holds.
        for i in 0..(MAX_PENDING_PER_STREAM + 5) {
            hub.dispatch(&datagram_for(99, i as u64, 0));
        }
        let inner = hub.inner.lock().unwrap();
        assert_eq!(
            inner.pending.get(&99).map(|v| v.len()),
            Some(MAX_PENDING_PER_STREAM),
            "per-stream pending must stop at MAX_PENDING_PER_STREAM"
        );
    }

    /// Regression test for the drop-on-full → in-order stall → credit freeze
    /// deadlock. When the route channel is full, `dispatch_route` must return
    /// a sender whose `.send().await` blocks (parks) rather than dropping the
    /// symbol. This ensures that a slow downstream task propagates backpressure
    /// to the QUIC receive loop rather than corrupting the FEC delivery
    /// frontier.
    #[tokio::test]
    async fn dispatch_route_parks_on_full_channel() {
        let hub = DatagramHub::new();
        let mut guard = hub.register(55);

        // Extract the receiver while keeping the guard alive (dropping the
        // guard would unregister the route, making dispatch_route return None).
        let mut rx = guard.take_rx();

        // Saturate the route channel: send ROUTE_CAPACITY symbols through
        // dispatch_route + send() so the channel is exactly full.
        for esi in 0..(ROUTE_CAPACITY as u32) {
            let dg = datagram_for(55, 0, esi);
            let (tx, sym) = hub
                .dispatch_route(&dg)
                .expect("dispatch_route must return Some for stream 55");
            tx.send(sym)
                .await
                .expect("send must succeed while there is room");
        }

        // The channel is now full. Spawn a task that tries to send one more
        // symbol; it should block until we drain a slot.
        let hub2 = hub.clone();
        let extra_dg = datagram_for(55, 0, ROUTE_CAPACITY as u32);
        let send_task = tokio::spawn(async move {
            let (tx, sym) = hub2
                .dispatch_route(&extra_dg)
                .expect("dispatch_route must return Some for registered stream");
            tx.send(sym).await.ok();
        });

        // Give the task a moment to run and confirm it is parked (not done).
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(
            !send_task.is_finished(),
            "send task must be parked on a full channel, not completed"
        );

        // Drain one slot — the parked send should now complete.
        rx.recv().await.expect("must receive one symbol");
        tokio::time::timeout(std::time::Duration::from_millis(200), send_task)
            .await
            .expect("send task must complete once a slot is freed")
            .expect("send task must not panic");

        drop(guard); // unregister after the test
    }

    /// H1 regression: a tunnel task that holds a `HubGuard` releases the
    /// route on Drop, including when a panic propagates out of the future.
    /// Without the guard, an unwind between `register` and the normal
    /// `unregister` call would leak the route for the lifetime of the
    /// connection.
    #[test]
    fn hub_guard_releases_route_on_drop() {
        let hub = Arc::new(DatagramHub::new());
        {
            let _guard = hub.register(7);
            assert!(
                hub.inner.lock().unwrap().routes.contains_key(&7),
                "guard must keep the route installed while alive"
            );
        }
        assert!(
            !hub.inner.lock().unwrap().routes.contains_key(&7),
            "guard drop must remove the route"
        );
    }

    #[test]
    fn hub_guard_releases_on_panic() {
        let hub = Arc::new(DatagramHub::new());
        // Use catch_unwind so the test process survives the panic; the guard
        // is the *only* thing keeping the route installed, so its Drop on
        // unwind is what we want to verify.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = hub.register(13);
            panic!("simulated tunnel panic");
        }));
        assert!(result.is_err());
        assert!(
            !hub.inner.lock().unwrap().routes.contains_key(&13),
            "panic unwind must trigger HubGuard drop and remove the route"
        );
    }

    /// H2 regression: a `ReliableData` whose length field exceeds the cap
    /// used to be silently rewritten as a `ReliableRequest` for the embedded
    /// block_id, triggering a real reliable retransmit for a block the peer
    /// never actually sent. Now it is reported as garbage (1 byte to drop)
    /// and the caller logs a warning.
    #[test]
    fn oversized_reliable_data_is_garbage_not_a_request() {
        // TAG_RELIABLE_DATA = 4, then 8-byte block_id = 9, then 4-byte
        // length = u32::MAX (> MAX_RELIABLE_DATA = 1 MiB).
        let mut buf = vec![TunnelSignal::TAG_RELIABLE_DATA];
        buf.extend_from_slice(&9u64.to_be_bytes());
        buf.extend_from_slice(&u32::MAX.to_be_bytes());
        let outcome = TunnelSignal::decode(&buf).expect("decode returns outcome");
        match outcome {
            Ok((TunnelSignal::ReliableRequest { .. }, n)) => panic!(
                "oversized ReliableData must NOT synthesise a ReliableRequest; \
                 got Ok with n={n}"
            ),
            Ok((sig, _)) => panic!("unexpected Ok signal: {sig:?}"),
            Err(n) => assert_eq!(n, 1, "drop just the tag byte"),
        }
    }

    /// M3: proactive repair spurts top up blocks that have not been acknowledged
    /// after one RTT, without waiting for a NACK round-trip.
    #[test]
    fn proactive_topups_fire_after_rtt_and_skip_before() {
        use raptun_fec::link::{LinkState, LossRegime};
        use raptun_fec::RepairBudget;
        use std::time::Duration;

        let mut sender = FecSender::new(1, SYM, K);
        let payload: Vec<u8> = (0..400).map(|i| (i % 200) as u8).collect();
        sender.encode_one_block(&payload, 0);

        let budget = RepairBudget::new(SYM, 0.4);
        budget.refresh_ceiling(10_000_000);
        let link = LinkState::new(
            Duration::from_millis(20),
            Duration::from_millis(5),
            0.1,
            10_000_000,
            LossRegime::Random,
        );
        let rtt = Duration::from_millis(20);

        // Just sent: age < RTT, so no proactive top-up.
        let now = Instant::now();
        assert!(sender.proactive_topups(now, rtt, &budget, &link).is_empty());

        // One RTT later: eligible.
        let later = now + rtt + Duration::from_millis(1);
        let tops = sender.proactive_topups(later, rtt, &budget, &link);
        assert_eq!(tops.len(), 1);
        assert_eq!(tops[0].0, 0);
        assert_eq!(tops[0].1, (K / 4).max(1));
    }

    /// M3: proactive repair is suppressed under congestion so it cannot deepen a
    /// collapse.
    #[test]
    fn proactive_topups_skip_congestion() {
        use raptun_fec::link::{LinkState, LossRegime};
        use raptun_fec::RepairBudget;
        use std::time::Duration;

        let mut sender = FecSender::new(1, SYM, K);
        let payload = vec![0xABu8; 100];
        sender.encode_one_block(&payload, 0);

        let budget = RepairBudget::new(SYM, 0.4);
        budget.refresh_ceiling(10_000_000);
        let link = LinkState::new(
            Duration::from_millis(20),
            Duration::from_millis(5),
            0.1,
            10_000_000,
            LossRegime::Congestion,
        );
        let now = Instant::now() + Duration::from_secs(1);
        assert!(sender
            .proactive_topups(now, Duration::from_millis(20), &budget, &link)
            .is_empty());
    }

    /// M3: proactive repair is also suppressed in the Quiescent regime. On a
    /// clean link extra repair symbols are pure waste and can back-pressure the
    /// send buffer, so the sender stays quiet until loss is observed.
    #[test]
    fn proactive_topups_skip_quiescent() {
        use raptun_fec::link::{LinkState, LossRegime};
        use raptun_fec::RepairBudget;
        use std::time::Duration;

        let mut sender = FecSender::new(1, SYM, K);
        let payload = vec![0xABu8; 100];
        sender.encode_one_block(&payload, 0);

        let budget = RepairBudget::new(SYM, 0.4);
        budget.refresh_ceiling(10_000_000);
        let link = LinkState::new(
            Duration::from_millis(20),
            Duration::from_millis(5),
            0.0,
            10_000_000,
            LossRegime::Quiescent,
        );
        let now = Instant::now() + Duration::from_secs(1);
        assert!(sender
            .proactive_topups(now, Duration::from_millis(20), &budget, &link)
            .is_empty());
    }

    /// M3: the per-block proactive counter caps spurts so the sender does not
    /// infinite-loop before the NACK path takes over.
    #[test]
    fn proactive_topups_honour_per_block_cap() {
        use raptun_fec::link::{LinkState, LossRegime};
        use raptun_fec::RepairBudget;
        use std::time::Duration;

        let mut sender = FecSender::new(1, SYM, K);
        let payload = vec![0xCDu8; 100];
        sender.encode_one_block(&payload, 0);

        let budget = RepairBudget::new(SYM, 0.4);
        budget.refresh_ceiling(10_000_000);
        let link = LinkState::new(
            Duration::from_millis(20),
            Duration::from_millis(5),
            0.1,
            10_000_000,
            LossRegime::Random,
        );
        let rtt = Duration::from_millis(20);

        for i in 0..(PROACTIVE_TOPUP_CAP + 2) {
            let now = Instant::now() + rtt + Duration::from_millis(i as u64);
            sender.proactive_topups(now, rtt, &budget, &link);
        }
        assert_eq!(
            sender.proactive_counts.get(&0).copied().unwrap_or(0),
            PROACTIVE_TOPUP_CAP
        );
    }

    /// M3: a zero repair budget prevents proactive spurts, letting the NACK /
    /// degraded path handle recovery.
    #[test]
    fn proactive_topups_respect_budget() {
        use raptun_fec::link::{LinkState, LossRegime};
        use raptun_fec::RepairBudget;
        use std::time::Duration;

        let mut sender = FecSender::new(1, SYM, K);
        let payload = vec![0xEFu8; 100];
        sender.encode_one_block(&payload, 0);

        let budget = RepairBudget::new(SYM, 0.4);
        budget.refresh_ceiling(0); // ceiling 0 ⇒ nothing fits
        let link = LinkState::new(
            Duration::from_millis(20),
            Duration::from_millis(5),
            0.1,
            0,
            LossRegime::Random,
        );
        let now = Instant::now() + Duration::from_secs(1);
        assert!(sender
            .proactive_topups(now, Duration::from_millis(20), &budget, &link)
            .is_empty());
    }
}
