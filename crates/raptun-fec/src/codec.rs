//! Real RaptorQ implementations of the FEC block traits, wrapping the
//! `raptorq` crate's per-source-block API.
//!
//! # Block framing
//!
//! Raptun tunnels a *byte stream*, but RaptorQ codes fixed-size *blocks*. To
//! bridge the two we give every block a constant geometry: exactly `K` source
//! symbols of `symbol_size` bytes each. The application bytes for a block are
//! laid out as
//!
//! ```text
//!   [ u32 payload_len ][ payload bytes ][ zero padding ... ]
//!   \___________________ K * symbol_size bytes total ______/
//! ```
//!
//! The 4-byte length prefix lets the receiver, after RaptorQ reconstructs the
//! full padded block, recover the exact original bytes (trimming padding). A
//! constant geometry is what makes the receiver able to construct a
//! `SourceBlockDecoder` for a block it has only seen repair symbols of — it
//! always knows `block_length = K * symbol_size`.
//!
//! # OTI
//!
//! RaptorQ needs an [`ObjectTransmissionInformation`]. We use a single-source-
//! block OTI (`source_blocks = 1`) sized to one Raptun block, and reuse it for
//! encode and decode. Both ends derive it identically from the negotiated
//! `symbol_size` and `K`, so it never has to travel on the wire.

use raptorq::{
    EncodingPacket, ObjectTransmissionInformation, PayloadId, SourceBlockDecoder,
    SourceBlockEncoder,
};

use raptun_proto::{BlockId, StreamId};

use crate::decoder::RaptorQBlockDecoder;
use crate::encoder::{frame_symbol, BlockEncoder, EncodedSymbol};

/// Size of the length prefix that precedes each block's payload.
pub const LEN_PREFIX: usize = 4;

/// Build the per-block OTI for the given geometry. `source_blocks = 1` because
/// each Raptun block is coded independently as one RaptorQ source block.
fn oti_for(symbol_size: u16, k: u32) -> ObjectTransmissionInformation {
    let block_len = symbol_size as u64 * k as u64;
    // alignment 1, sub_blocks 1: simplest valid configuration.
    ObjectTransmissionInformation::new(block_len, symbol_size, 1, 1, 1)
}

/// Pad `payload` into a full `K * symbol_size` block with a length prefix.
///
/// Returns the padded buffer ready to hand to `SourceBlockEncoder`.
pub fn pad_block(payload: &[u8], symbol_size: u16, k: u32) -> Vec<u8> {
    let block_len = symbol_size as usize * k as usize;
    debug_assert!(
        payload.len() + LEN_PREFIX <= block_len,
        "payload {} + prefix exceeds block capacity {}",
        payload.len(),
        block_len
    );
    let mut buf = Vec::with_capacity(block_len);
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
    buf.resize(block_len, 0);
    buf
}

/// Reverse [`pad_block`]: given a reconstructed padded block, return the
/// original payload bytes, or `None` if the length prefix is corrupt.
pub fn unpad_block(block: &[u8]) -> Option<Vec<u8>> {
    if block.len() < LEN_PREFIX {
        return None;
    }
    let len = u32::from_be_bytes([block[0], block[1], block[2], block[3]]) as usize;
    let end = LEN_PREFIX + len;
    if end > block.len() {
        return None;
    }
    Some(block[LEN_PREFIX..end].to_vec())
}

/// The maximum application payload that fits in one block of the given geometry
/// (block capacity minus the length prefix).
pub fn max_payload(symbol_size: u16, k: u32) -> usize {
    symbol_size as usize * k as usize - LEN_PREFIX
}

/// Production [`BlockEncoder`] backed by `raptorq::SourceBlockEncoder`.
pub struct RaptorQBlockEncoder {
    inner: SourceBlockEncoder,
    k: u32,
}

impl RaptorQBlockEncoder {
    /// Build an encoder for one block. `payload` is the raw (unpadded)
    /// application bytes for this block; it is padded to the fixed geometry
    /// internally.
    pub fn new(payload: &[u8], symbol_size: u16, k: u32) -> Self {
        let oti = oti_for(symbol_size, k);
        let padded = pad_block(payload, symbol_size, k);
        // source_block_id is always 0: each block is its own single-SBN object.
        let inner = SourceBlockEncoder::new(0, &oti, &padded);
        Self { inner, k }
    }
}

impl BlockEncoder for RaptorQBlockEncoder {
    fn k(&self) -> u32 {
        self.k
    }

    fn emit(
        &self,
        stream_id: StreamId,
        block_id: BlockId,
        repair_count: u32,
    ) -> Vec<EncodedSymbol> {
        let mut out = Vec::new();
        // Source symbols: ESI 0..K, is_repair = false.
        for pkt in self.inner.source_packets() {
            out.push(frame_from_packet(stream_id, block_id, &pkt, false));
        }
        // Repair symbols: ESI K.., is_repair = true.
        for pkt in self.inner.repair_packets(0, repair_count) {
            out.push(frame_from_packet(stream_id, block_id, &pkt, true));
        }
        out
    }

    fn emit_additional_repair(
        &self,
        stream_id: StreamId,
        block_id: BlockId,
        already_sent_repair: u32,
        extra: u32,
    ) -> Vec<EncodedSymbol> {
        // Continue the repair ESI sequence past what we already sent, so every
        // symbol is fresh and distinct (the fountain-code property that makes
        // the NACK fallback never resend duplicate data).
        self.inner
            .repair_packets(already_sent_repair, extra)
            .iter()
            .map(|pkt| frame_from_packet(stream_id, block_id, pkt, true))
            .collect()
    }
}

/// Frame a raptorq [`EncodingPacket`] into a Raptun datagram symbol. The
/// packet's encoding symbol id becomes our header ESI.
fn frame_from_packet(
    stream_id: StreamId,
    block_id: BlockId,
    pkt: &EncodingPacket,
    is_repair: bool,
) -> EncodedSymbol {
    let esi = pkt.payload_id().encoding_symbol_id();
    frame_symbol(stream_id, block_id, esi, is_repair, pkt.data())
}

/// Production [`RaptorQBlockDecoder`] backed by `raptorq::SourceBlockDecoder`.
pub struct RaptorQBlockDecoderImpl {
    inner: SourceBlockDecoder,
}

impl RaptorQBlockDecoderImpl {
    pub fn new(symbol_size: u16, k: u32) -> Self {
        let oti = oti_for(symbol_size, k);
        let block_len = symbol_size as u64 * k as u64;
        Self {
            inner: SourceBlockDecoder::new(0, &oti, block_len),
        }
    }
}

impl RaptorQBlockDecoder for RaptorQBlockDecoderImpl {
    fn add_symbol(&mut self, esi: u32, payload: &[u8]) -> Option<Vec<u8>> {
        // Reconstruct the raptorq packet from our header ESI + payload and feed
        // it to the source-block decoder. Once enough symbols are present it
        // returns the full padded block, which we then unpad.
        let pkt = EncodingPacket::new(PayloadId::new(0, esi), payload.to_vec());
        self.inner
            .decode(std::iter::once(pkt))
            .and_then(|padded| unpad_block(&padded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use raptun_proto::datagram::SymbolHeader;

    const SYM: u16 = 64;
    const K: u32 = 8;

    #[test]
    fn pad_unpad_round_trips() {
        let payload = b"hello raptun fec";
        let padded = pad_block(payload, SYM, K);
        assert_eq!(padded.len(), SYM as usize * K as usize);
        assert_eq!(unpad_block(&padded).unwrap(), payload);
    }

    /// Encode a block, drop some source symbols, and confirm RaptorQ recovers
    /// the original payload from repair symbols — the core FEC promise.
    #[test]
    fn recovers_from_symbol_loss() {
        let payload: Vec<u8> = (0..300).map(|i| (i % 251) as u8).collect();
        let enc = RaptorQBlockEncoder::new(&payload, SYM, K);
        // Generous repair so recovery is essentially certain.
        let symbols = enc.emit(7, 3, K); // repair_count == K

        // Simulate loss: keep only symbols at even indices, but that still
        // leaves >= K total across source+repair.
        let kept: Vec<_> = symbols
            .iter()
            .enumerate()
            .filter(|(i, _)| i % 2 == 0)
            .map(|(_, s)| s)
            .collect();
        assert!(kept.len() as u32 >= K, "need at least K symbols to decode");

        let mut dec = RaptorQBlockDecoderImpl::new(SYM, K);
        let mut recovered = None;
        for sym in kept {
            let (hdr, pay) = SymbolHeader::parse(&sym.datagram).unwrap();
            assert_eq!(hdr.stream_id, 7);
            assert_eq!(hdr.block_id, 3);
            if let Some(bytes) = dec.add_symbol(hdr.esi, pay) {
                recovered = Some(bytes);
                break;
            }
        }
        assert_eq!(recovered.unwrap(), payload, "FEC must recover lost data");
    }

    #[test]
    fn decodes_from_source_only_no_loss() {
        let payload = b"clean link, all source symbols arrive".to_vec();
        let enc = RaptorQBlockEncoder::new(&payload, SYM, K);
        let symbols = enc.emit(1, 0, 0); // no repair symbols at all
        let mut dec = RaptorQBlockDecoderImpl::new(SYM, K);
        let mut recovered = None;
        for sym in &symbols {
            let (hdr, pay) = SymbolHeader::parse(&sym.datagram).unwrap();
            if let Some(bytes) = dec.add_symbol(hdr.esi, pay) {
                recovered = Some(bytes);
            }
        }
        assert_eq!(recovered.unwrap(), payload);
    }
}
