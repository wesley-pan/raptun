//! Minimal, allocation-light wire codec built on [`bytes`].
//!
//! We hand-roll a tiny binary format rather than pull in a full serialization
//! framework for the hot datagram path: every RaptorQ symbol carries a header,
//! so the header codec runs at line rate and must not allocate. All integers
//! are big-endian ("network order") for readability on the wire.

use bytes::{Buf, BufMut};

/// Errors produced while decoding a wire message.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// The buffer ended before a full message could be read.
    #[error("unexpected end of buffer: needed {needed} more bytes")]
    Truncated { needed: usize },

    /// A tag/discriminant byte did not correspond to any known variant.
    #[error("unknown discriminant {discriminant:#04x} for {kind}")]
    UnknownDiscriminant {
        discriminant: u8,
        kind: &'static str,
    },

    /// A length prefix exceeded the caller-supplied sanity bound.
    #[error("length {len} exceeds maximum {max}")]
    LengthTooLarge { len: usize, max: usize },
}

/// Encode `self` by appending to a caller-owned buffer.
///
/// Taking a `&mut impl BufMut` (rather than returning a `Vec`) lets callers
/// reuse a scratch buffer across many messages and avoids a per-message
/// allocation on the send path.
pub trait Encode {
    fn encode(&self, buf: &mut impl BufMut);
}

/// Decode `Self` from the front of a buffer, advancing it past the bytes read.
pub trait Decode: Sized {
    fn decode(buf: &mut impl Buf) -> Result<Self, WireError>;
}

/// Guard against reading past the end of `buf`.
///
/// Every multi-byte read must call this first so a malicious or truncated peer
/// cannot cause a panic in `Buf::get_*`.
pub(crate) fn ensure(buf: &impl Buf, needed: usize) -> Result<(), WireError> {
    if buf.remaining() < needed {
        Err(WireError::Truncated {
            needed: needed - buf.remaining(),
        })
    } else {
        Ok(())
    }
}

/// Write a length-prefixed byte slice (`u32` big-endian length + bytes).
pub(crate) fn put_bytes(buf: &mut impl BufMut, bytes: &[u8]) {
    buf.put_u32(bytes.len() as u32);
    buf.put_slice(bytes);
}

/// Read a length-prefixed byte slice, rejecting lengths above `max` to bound
/// the allocation a peer can force us to make.
pub(crate) fn get_bytes(buf: &mut impl Buf, max: usize) -> Result<Vec<u8>, WireError> {
    ensure(buf, 4)?;
    let len = buf.get_u32() as usize;
    if len > max {
        return Err(WireError::LengthTooLarge { len, max });
    }
    ensure(buf, len)?;
    let mut out = vec![0u8; len];
    buf.copy_to_slice(&mut out);
    Ok(out)
}
