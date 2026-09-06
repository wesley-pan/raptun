//! Sender-side FEC: cut a byte stream into source blocks and emit symbols.
//!
//! [`StreamEncoder`] owns the per-stream block sequencing; [`BlockEncoder`]
//! wraps the `raptorq` encoder for a single block and produces both source and
//! repair symbols, each already carrying its
//! [`raptun_proto::datagram::SymbolHeader`].
//!
//! The design leans on RaptorQ being a *systematic* fountain code: the source
//! symbols are the original data verbatim, so on a clean link the receiver
//! reassembles by concatenation with no decode work at all — the GF(256)
//! Gaussian elimination only runs when repair symbols must substitute for lost
//! source symbols. That is why FEC can be left on by default without wasting
//! CPU when the network is healthy.

use bytes::{BufMut, BytesMut};

use raptun_proto::datagram::{SymbolFlags, SymbolHeader, SYMBOL_HEADER_LEN};
use raptun_proto::{BlockId, Encode, StreamId};

/// One encoded symbol ready to be placed in a QUIC datagram: header + payload,
/// serialized into a single contiguous buffer sized to the datagram MTU.
#[derive(Debug, Clone)]
pub struct EncodedSymbol {
    /// Fully framed bytes (header ++ symbol payload) to hand to `send_datagram`.
    pub datagram: BytesMut,
    /// Whether this is a repair symbol, so the caller can account it against
    /// the [`crate::budget::RepairBudget`].
    pub is_repair: bool,
}

/// Encodes a single source block into symbols.
///
/// Wraps `raptorq`'s block encoder behind our own trait so callers and tests
/// don't depend on the concrete codec type; `RealBlockEncoder` (below) is the
/// production implementation.
pub trait BlockEncoder {
    /// The number of source symbols K in this block.
    fn k(&self) -> u32;

    /// Emit the source symbols (ESI `0..K`) plus `repair_count` repair symbols
    /// (ESI `K..K+repair_count`), each framed with its header.
    fn emit(&self, stream_id: StreamId, block_id: BlockId, repair_count: u32)
        -> Vec<EncodedSymbol>;

    /// Emit `extra` *additional* repair symbols beyond those already sent,
    /// continuing the ESI sequence. Used to satisfy a `BlockNack` — RaptorQ can
    /// mint unboundedly many distinct repair symbols, which is why the fallback
    /// never resends original data.
    fn emit_additional_repair(
        &self,
        stream_id: StreamId,
        block_id: BlockId,
        already_sent_repair: u32,
        extra: u32,
    ) -> Vec<EncodedSymbol>;
}

/// Per-stream encoder: accumulates application bytes, slices them into blocks of
/// K source symbols, and drives a [`BlockEncoder`] per block.
pub struct StreamEncoder {
    stream_id: StreamId,
    /// Symbol payload size in bytes (datagram MTU minus header).
    symbol_size: u16,
    /// Source symbols per block (K). May be recomputed as RTT changes; new
    /// blocks pick up the new value.
    block_symbols: u32,
    /// Next block id to assign.
    next_block: BlockId,
    /// Pending bytes not yet forming a full block.
    pending: BytesMut,
}

impl StreamEncoder {
    /// `datagram_mtu` is the maximum QUIC datagram payload; the symbol size is
    /// derived from it so header + symbol fit exactly without IP fragmentation.
    pub fn new(stream_id: StreamId, datagram_mtu: u16, block_symbols: u32) -> Self {
        let symbol_size = datagram_mtu.saturating_sub(SYMBOL_HEADER_LEN as u16).max(1);
        Self {
            stream_id,
            symbol_size,
            block_symbols: block_symbols.max(1),
            next_block: 0,
            pending: BytesMut::new(),
        }
    }

    pub fn symbol_size(&self) -> u16 {
        self.symbol_size
    }

    /// The stream this encoder produces symbols for; used when framing symbols
    /// via [`frame_symbol`].
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Update K for subsequent blocks (e.g. after an RTT change). Does not
    /// affect blocks already emitted.
    pub fn set_block_symbols(&mut self, k: u32) {
        self.block_symbols = k.max(1);
    }

    /// Bytes that constitute one full block at the current geometry.
    fn block_bytes(&self) -> usize {
        self.symbol_size as usize * self.block_symbols as usize
    }

    /// Feed application bytes. Returns fully-formed blocks' raw byte payloads,
    /// each paired with the block id assigned to it. The caller passes each to
    /// [`Self::encode_block`] with the desired repair ratio. Splitting "form the
    /// block" from "encode it" lets the repair ratio be chosen at the last
    /// instant from the freshest telemetry.
    pub fn push(&mut self, data: &[u8]) -> Vec<(BlockId, BytesMut)> {
        self.pending.put_slice(data);
        let mut blocks = Vec::new();
        let block_len = self.block_bytes();
        while self.pending.len() >= block_len {
            let block = self.pending.split_to(block_len);
            let id = self.next_block;
            self.next_block += 1;
            blocks.push((id, block));
        }
        blocks
    }

    /// Flush a partial trailing block (e.g. connection closing). The final block
    /// may be shorter than a full one; RaptorQ pads internally.
    pub fn flush(&mut self) -> Option<(BlockId, BytesMut)> {
        if self.pending.is_empty() {
            return None;
        }
        let block = self.pending.split();
        let id = self.next_block;
        self.next_block += 1;
        Some((id, block))
    }
}

/// Frame a raw symbol payload with its header into a datagram-ready buffer.
///
/// Kept as a free function so both the real and test encoders share exactly one
/// framing implementation.
pub fn frame_symbol(
    stream_id: StreamId,
    block_id: BlockId,
    actual_k: u16,
    esi: u32,
    is_repair: bool,
    payload: &[u8],
) -> EncodedSymbol {
    let mut flags = SymbolFlags::empty();
    if is_repair {
        flags = flags | SymbolFlags::REPAIR;
    }
    let header = SymbolHeader {
        stream_id,
        block_id,
        actual_k,
        esi,
        flags,
    };
    let mut datagram = BytesMut::with_capacity(SYMBOL_HEADER_LEN + payload.len());
    header.encode(&mut datagram);
    datagram.put_slice(payload);
    EncodedSymbol {
        datagram,
        is_repair,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_encoder_forms_full_blocks() {
        // MTU 1200 ⇒ symbol_size = 1200 - SYMBOL_HEADER_LEN = 1178.
        // K = 4 ⇒ block = 4712 bytes.
        let mut enc = StreamEncoder::new(7, 1200, 4);
        let symbol_size = enc.symbol_size();
        assert_eq!(symbol_size, 1200 - SYMBOL_HEADER_LEN as u16);

        let block_len = symbol_size as usize * 4;
        let data = vec![0u8; block_len * 2 + 100]; // two full blocks + remainder
        let blocks = enc.push(&data);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].0, 0);
        assert_eq!(blocks[1].0, 1);

        // Remainder flushes as a short block.
        let tail = enc.flush().unwrap();
        assert_eq!(tail.0, 2);
        assert_eq!(tail.1.len(), 100);
    }

    #[test]
    fn framing_round_trips_through_proto() {
        let sym = frame_symbol(7, 3, 16, 5, true, b"payload");
        let (hdr, payload) = SymbolHeader::parse(&sym.datagram).unwrap();
        assert_eq!(hdr.stream_id, 7);
        assert_eq!(hdr.block_id, 3);
        assert_eq!(hdr.actual_k, 16);
        assert_eq!(hdr.esi, 5);
        assert!(hdr.flags.contains(SymbolFlags::REPAIR));
        assert_eq!(payload, b"payload");
        assert!(sym.is_repair);
    }
}
