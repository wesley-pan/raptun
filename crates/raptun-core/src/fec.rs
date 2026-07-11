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
}

impl TunnelSignal {
    const TAG_BLOCK_COUNT: u8 = 1;
    const TAG_NACK: u8 = 2;
    const TAG_RELIABLE_REQUEST: u8 = 3;
    const TAG_RELIABLE_DATA: u8 = 4;

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
        }
        b
    }

    /// Try to decode one message from the front of `buf`, returning the message
    /// and the number of bytes consumed, or `None` if more bytes are needed.
    pub fn decode(buf: &[u8]) -> Option<(TunnelSignal, usize)> {
        let tag = *buf.first()?;
        match tag {
            Self::TAG_BLOCK_COUNT => {
                if buf.len() < 1 + 8 {
                    return None;
                }
                let total = u64::from_be_bytes(buf[1..9].try_into().unwrap());
                Some((TunnelSignal::BlockCount { total }, 9))
            }
            Self::TAG_NACK => {
                if buf.len() < 1 + 8 + 4 + 4 {
                    return None;
                }
                let block = u64::from_be_bytes(buf[1..9].try_into().unwrap());
                let have = u32::from_be_bytes(buf[9..13].try_into().unwrap());
                let need = u32::from_be_bytes(buf[13..17].try_into().unwrap());
                Some((TunnelSignal::Nack { block, have, need }, 17))
            }
            Self::TAG_RELIABLE_REQUEST => {
                if buf.len() < 1 + 8 {
                    return None;
                }
                let block = u64::from_be_bytes(buf[1..9].try_into().unwrap());
                Some((TunnelSignal::ReliableRequest { block }, 9))
            }
            Self::TAG_RELIABLE_DATA => {
                if buf.len() < 1 + 8 + 4 {
                    return None;
                }
                let block = u64::from_be_bytes(buf[1..9].try_into().unwrap());
                let len = u32::from_be_bytes(buf[9..13].try_into().unwrap()) as usize;
                if len > Self::MAX_RELIABLE_DATA {
                    // Malformed/hostile length: resync by consuming the header.
                    return Some((TunnelSignal::ReliableRequest { block }, 13));
                }
                let end = 13 + len;
                if buf.len() < end {
                    return None; // need the whole payload
                }
                let bytes = buf[13..end].to_vec();
                Some((TunnelSignal::ReliableData { block, bytes }, end))
            }
            // Unknown tag: consume one byte to resync rather than deadlock.
            _ => Some((TunnelSignal::BlockCount { total: u64::MAX }, 1)),
        }
    }
}

use raptun_fec::codec::{max_payload, RaptorQBlockDecoderImpl, RaptorQBlockEncoder};
use raptun_fec::encoder::BlockEncoder;
use raptun_fec::BlockManager;
use raptun_proto::datagram::SymbolHeader;
use raptun_proto::StreamId;

/// One demultiplexed inbound symbol: its block, encoding-symbol id, and payload.
pub type InboundSymbol = (BlockId, u32, Bytes);

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

struct HubInner {
    routes: HashMap<StreamId, mpsc::UnboundedSender<InboundSymbol>>,
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

    /// Register interest in a tunnel's `stream_id`, returning the channel its
    /// symbols will arrive on. Any symbols buffered before registration are
    /// replayed immediately, in arrival order.
    pub fn register(&self, stream_id: StreamId) -> mpsc::UnboundedReceiver<InboundSymbol> {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut inner = self.inner.lock().unwrap();
        if let Some(buffered) = inner.pending.remove(&stream_id) {
            for sym in buffered {
                let _ = tx.send(sym);
            }
        }
        inner.routes.insert(stream_id, tx);
        rx
    }

    /// Stop routing a tunnel's symbols (tunnel closed).
    pub fn unregister(&self, stream_id: StreamId) {
        let mut inner = self.inner.lock().unwrap();
        inner.routes.remove(&stream_id);
        inner.pending.remove(&stream_id);
    }

    /// Route one received datagram. Symbols for a not-yet-registered stream are
    /// buffered (up to a cap) and replayed when the stream registers.
    pub fn dispatch(&self, datagram: &[u8]) {
        let Ok((hdr, payload)) = SymbolHeader::parse(datagram) else {
            return;
        };
        let sym = (hdr.block_id, hdr.esi, Bytes::copy_from_slice(payload));
        let mut inner = self.inner.lock().unwrap();
        if let Some(tx) = inner.routes.get(&hdr.stream_id) {
            let _ = tx.send(sym);
        } else {
            let buf = inner.pending.entry(hdr.stream_id).or_default();
            if buf.len() < MAX_PENDING_PER_STREAM {
                buf.push(sym);
            }
        }
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
    /// Retained encoders per block, so additional repair can be minted on NACK.
    encoders: HashMap<BlockId, RaptorQBlockEncoder>,
    /// Retained original payload bytes per block, so a stranded block can be
    /// shipped reliably as the convergence lower-bound fallback.
    payloads: HashMap<BlockId, Vec<u8>>,
}

impl FecSender {
    pub fn new(stream_id: StreamId, symbol_size: u16, k: u32) -> Self {
        Self {
            stream_id,
            symbol_size,
            k: k.max(1),
            next_block: 0,
            repair_sent: HashMap::new(),
            encoders: HashMap::new(),
            payloads: HashMap::new(),
        }
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

        let encoder = RaptorQBlockEncoder::new(payload, self.symbol_size, self.k);
        let symbols = encoder.emit(self.stream_id, block_id, repair_count);
        self.repair_sent.insert(block_id, repair_count);
        self.encoders.insert(block_id, encoder);
        // Retain the raw payload for a possible reliable-retransmit fallback.
        self.payloads.insert(block_id, payload.to_vec());

        symbols.into_iter().map(|s| s.datagram.freeze()).collect()
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
        self.payloads.remove(&block_id);
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
    /// Blocks for which a reliable retransmit has already been requested, so the
    /// control tick does not re-request them every cycle while the reliable data
    /// is in flight.
    reliable_requested: std::collections::HashSet<BlockId>,
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
            reliable_requested: std::collections::HashSet::new(),
        }
    }

    /// Record the total block count announced by the sender. Enables detection
    /// of entirely-lost blocks in [`FecReceiver::tick`].
    pub fn set_total_blocks(&mut self, total: u64) {
        self.total_blocks = Some(total);
    }

    /// Feed one received symbol (already split from its datagram header).
    ///
    /// Returns any application bytes that became deliverable as a result —
    /// possibly zero (block not yet complete), possibly several blocks' worth
    /// (this symbol completed a block that unblocked a run of buffered ones).
    pub fn on_symbol(
        &mut self,
        block_id: BlockId,
        esi: u32,
        payload: &[u8],
        now: std::time::Instant,
    ) -> Vec<u8> {
        // Blocks already delivered are ignored (late duplicates).
        if block_id < self.next_deliver {
            return Vec::new();
        }
        self.highest_seen = self.highest_seen.max(block_id);

        let symbol_size = self.symbol_size;
        let k = self.k;
        let mgr = self.managers.entry(block_id).or_insert_with(|| {
            let codec = Box::new(RaptorQBlockDecoderImpl::new(symbol_size, k));
            BlockManager::new(block_id, k, codec)
        });

        if let raptun_fec::DecoderAction::Deliver { bytes } = mgr.on_symbol(now, esi, payload) {
            self.managers.remove(&block_id);
            self.ready.insert(block_id, bytes);
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
    /// degrade decisions) driven by [`crate::session::Session::control_tick`].
    pub fn manager_mut(&mut self, block_id: BlockId) -> Option<&mut BlockManager> {
        self.managers.get_mut(&block_id)
    }

    /// The highest block id we have delivered, for the decoder's sequence
    /// oracle (`later_blocks_progressing`).
    pub fn highest_delivered(&self) -> BlockId {
        self.next_deliver
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
        // prove exists: any block below the highest seen, and — once the total
        // is known — any block below the total.
        let upper = {
            let by_seen = self.highest_seen; // blocks [0, highest_seen) provably exist
            let by_total = self.total_blocks.unwrap_or(0);
            by_seen.max(by_total)
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

    /// Encode a multi-block message, drop ~1/3 of every block's symbols, and
    /// confirm the receiver reconstructs the whole message in order.
    #[test]
    fn multi_block_recovery_in_order() {
        let msg: Vec<u8> = (0..5000).map(|i| (i % 253) as u8).collect();

        let mut sender = FecSender::new(1, SYM, K);
        // repair_count == K gives plenty of headroom to survive 1/3 loss.
        let datagrams = sender.encode_blocks(&msg, K);

        let mut receiver = FecReceiver::new(SYM, K);
        let mut assembled = Vec::new();
        for (i, dg) in datagrams.iter().enumerate() {
            // Drop every third datagram to simulate loss.
            if i % 3 == 0 {
                continue;
            }
            let (hdr, payload) = SymbolHeader::parse(dg).unwrap();
            let delivered = receiver.on_symbol(hdr.block_id, hdr.esi, payload, Instant::now());
            assembled.extend_from_slice(&delivered);
        }

        assert_eq!(
            assembled, msg,
            "FEC pump must recover the full stream in order"
        );
    }

    #[test]
    fn out_of_order_datagrams_deliver_in_order() {
        let msg: Vec<u8> = (0..3000).map(|i| (i % 251) as u8).collect();
        let mut sender = FecSender::new(9, SYM, K);
        let mut datagrams = sender.encode_blocks(&msg, 2);

        // Reverse arrival order; in-order delivery must still hold.
        datagrams.reverse();

        let mut receiver = FecReceiver::new(SYM, K);
        let mut assembled = Vec::new();
        for dg in &datagrams {
            let (hdr, payload) = SymbolHeader::parse(dg).unwrap();
            let delivered = receiver.on_symbol(hdr.block_id, hdr.esi, payload, Instant::now());
            assembled.extend_from_slice(&delivered);
        }
        assert_eq!(assembled, msg);
    }

    #[test]
    fn additional_repair_is_fresh_and_decodes() {
        // Send a block with too few symbols to decode, then top up via NACK path.
        let payload: Vec<u8> = (0..400).map(|i| (i % 200) as u8).collect();
        let mut sender = FecSender::new(1, SYM, K);
        let first = sender.encode_one_block(&payload, 0); // K source symbols only

        let mut receiver = FecReceiver::new(SYM, K);
        // Deliver only K-2 source symbols: not enough to decode.
        let mut assembled = Vec::new();
        for dg in first.iter().take((K - 2) as usize) {
            let (hdr, pay) = SymbolHeader::parse(dg).unwrap();
            assembled.extend_from_slice(&receiver.on_symbol(
                hdr.block_id,
                hdr.esi,
                pay,
                Instant::now(),
            ));
        }
        assert!(assembled.is_empty(), "should not decode yet");

        // NACK top-up: 4 fresh repair symbols for block 0.
        let extra = sender.additional_repair(0, 4);
        for dg in &extra {
            let (hdr, pay) = SymbolHeader::parse(dg).unwrap();
            assembled.extend_from_slice(&receiver.on_symbol(
                hdr.block_id,
                hdr.esi,
                pay,
                Instant::now(),
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
        ];
        for sig in cases {
            let bytes = sig.encode();
            let (decoded, used) = TunnelSignal::decode(&bytes).unwrap();
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
        let payload0: Vec<u8> = (0..500).map(|i| (i % 200) as u8).collect();
        let payload1: Vec<u8> = (0..500).map(|i| (i % 190) as u8).collect();
        let b0 = sender.encode_one_block(&payload0, 0);
        let b1 = sender.encode_one_block(&payload1, K);

        let mut receiver = FecReceiver::new(SYM, K);
        let t0 = Instant::now();

        // Deliver K-3 symbols of block 0 (not enough).
        for dg in b0.iter().take((K - 3) as usize) {
            let (h, p) = SymbolHeader::parse(dg).unwrap();
            receiver.on_symbol(h.block_id, h.esi, p, t0);
        }
        // Deliver block 1 fully; it decodes but cannot be delivered yet (block 0
        // is still missing and delivery is in-order). This does NOT advance the
        // delivery floor past block 0.
        for dg in &b1 {
            let (h, p) = SymbolHeader::parse(dg).unwrap();
            receiver.on_symbol(h.block_id, h.esi, p, t0);
        }

        // Budget with headroom; link is random-loss (FEC-appropriate) and enough
        // wall-clock has passed to exceed the stall grace period.
        let budget = RepairBudget::new(SYM, 0.4);
        budget.refresh_ceiling(10_000_000);
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
            delivered.extend_from_slice(&receiver.on_symbol(h.block_id, h.esi, p, later));
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
        // One symbol of block 0 (far from decodable).
        {
            let (h, p) = SymbolHeader::parse(&b0[0]).unwrap();
            receiver.on_symbol(h.block_id, h.esi, p, t0);
        }
        // Deliver block 1 fully (decodes but buffered behind block 0).
        for dg in &b1 {
            let (h, p) = SymbolHeader::parse(dg).unwrap();
            receiver.on_symbol(h.block_id, h.esi, p, t0);
        }

        // Budget of zero: no repair may be requested, so the manager must
        // degrade block 0 to a reliable retransmit.
        let budget = RepairBudget::new(SYM, 0.4);
        budget.refresh_ceiling(0); // ceiling 0 ⇒ nothing fits
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
}
