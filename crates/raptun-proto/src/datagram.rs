//! The fixed-size header prepended to every RaptorQ symbol sent over an
//! unreliable QUIC datagram.
//!
//! # Why a custom header at all?
//!
//! QUIC datagrams (RFC 9221) are *unordered* and *unreliable* — the transport
//! gives us no sequencing and no delivery guarantee, which is exactly what we
//! want (RaptorQ, not QUIC, owns reliability on this path). But because there
//! is no ordering, each symbol must be fully self-describing: the receiver has
//! to attribute a datagram that arrives out of nowhere to the right stream and
//! the right source block, and know whether it is an original or repair symbol.
//!
//! # Layout (16 bytes, big-endian)
//!
//! ```text
//!   0               1               2               3
//!   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                          stream_id (u64)                      |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                          block_id (u64)                       |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |     esi (u24)         | flags (u8)|   ... symbol payload ...
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! `esi` (Encoding Symbol ID) is RaptorQ's own symbol index: values `< K` are
//! source symbols, values `>= K` are repair symbols. 24 bits is ample — RFC6330
//! caps a source block at 56403 symbols, far below 2^24.

use bytes::{Buf, BufMut};

use crate::codec::{ensure, Decode, Encode, WireError};
use crate::{BlockId, StreamId};

/// Serialized size of [`SymbolHeader`] in bytes. Kept as a const so the encoder
/// can subtract it from the datagram MTU to size symbol payloads exactly.
pub const SYMBOL_HEADER_LEN: usize = 8 + 8 + 3 + 1;

crate::bitflags_lite! {
    /// Per-symbol flags packed into the header's trailing byte.
    pub struct SymbolFlags: u8 {
        /// Set when the Encoding Symbol ID is a repair symbol (`esi >= K`).
        /// Redundant with `esi >= K` but lets the receiver classify a symbol
        /// without knowing K yet (K is negotiated per block).
        const REPAIR = 0b0000_0001;
        /// Set on the last symbol the sender intends to originate for this block
        /// under the *current* repair budget. A hint only: the sender may still
        /// emit more repair symbols later if the receiver NACKs.
        const BLOCK_HINT_LAST = 0b0000_0010;
    }
}

/// The self-describing header carried by every symbol datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymbolHeader {
    /// Which tunnelled logical stream this symbol belongs to.
    pub stream_id: StreamId,
    /// Which source block within that stream.
    pub block_id: BlockId,
    /// RaptorQ Encoding Symbol ID (source if `< K`, repair if `>= K`).
    pub esi: u32,
    /// Classification / hint flags.
    pub flags: SymbolFlags,
}

impl SymbolHeader {
    /// Split a received datagram into its header and the symbol payload that
    /// follows. Returns the payload as a sub-slice (no copy).
    pub fn parse<'a>(mut datagram: &'a [u8]) -> Result<(Self, &'a [u8]), WireError> {
        let header = Self::decode(&mut datagram)?;
        // `decode` advanced the &[u8] cursor; whatever remains is the payload.
        Ok((header, datagram))
    }
}

impl Encode for SymbolHeader {
    fn encode(&self, buf: &mut impl BufMut) {
        buf.put_u64(self.stream_id);
        buf.put_u64(self.block_id);
        // esi as u24: write the low 3 bytes, big-endian.
        buf.put_u8((self.esi >> 16) as u8);
        buf.put_u8((self.esi >> 8) as u8);
        buf.put_u8(self.esi as u8);
        buf.put_u8(self.flags.bits());
    }
}

impl Decode for SymbolHeader {
    fn decode(buf: &mut impl Buf) -> Result<Self, WireError> {
        ensure(buf, SYMBOL_HEADER_LEN)?;
        let stream_id = buf.get_u64();
        let block_id = buf.get_u64();
        let esi = (u32::from(buf.get_u8()) << 16)
            | (u32::from(buf.get_u8()) << 8)
            | u32::from(buf.get_u8());
        let flags = SymbolFlags::from_bits_truncate(buf.get_u8());
        Ok(Self {
            stream_id,
            block_id,
            esi,
            flags,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trips() {
        let hdr = SymbolHeader {
            stream_id: 0x0102_0304_0506_0708,
            block_id: 42,
            esi: 0x00AB_CDEF & 0x00FF_FFFF, // fits in u24
            flags: SymbolFlags::REPAIR | SymbolFlags::BLOCK_HINT_LAST,
        };
        let mut buf = Vec::new();
        hdr.encode(&mut buf);
        assert_eq!(buf.len(), SYMBOL_HEADER_LEN);

        let (parsed, payload) = SymbolHeader::parse(&buf).unwrap();
        assert_eq!(parsed, hdr);
        assert!(payload.is_empty());
        assert!(parsed.flags.contains(SymbolFlags::REPAIR));
    }

    #[test]
    fn truncated_header_is_rejected() {
        let buf = [0u8; SYMBOL_HEADER_LEN - 1];
        assert!(matches!(
            SymbolHeader::parse(&buf),
            Err(WireError::Truncated { .. })
        ));
    }
}
