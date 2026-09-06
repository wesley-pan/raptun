//! Raptun wire protocol definitions.
//!
//! Two independent wire formats live here, matching Raptun's two-path data plane:
//!
//! * [`control`] — messages exchanged on the reliable QUIC control stream
//!   (bi-stream #0): handshake, auth, FEC parameter negotiation, and the
//!   block-level NACK that drives the FEC fallback path.
//!
//! * [`datagram`] — the fixed header prepended to every RaptorQ symbol that
//!   travels over an *unreliable* QUIC datagram. It carries just enough routing
//!   information (which logical stream, which source block, which symbol) for
//!   the receiver to reassemble source blocks without any ordering guarantees
//!   from the transport.
//!
//! Keeping these in a dependency-free leaf crate means both client and server —
//! and the fuzz/bench harnesses — share exactly one definition of the wire
//! format, which is the single most important thing to get right for
//! interoperability.

pub mod control;
pub mod datagram;

mod codec;

pub use codec::{Decode, Encode, WireError};

/// A tiny local bitflags implementation, so this leaf crate stays
/// dependency-free. Only the handful of operations Raptun needs are provided;
/// if the flag set grows, swap this for the `bitflags` crate.
///
/// Declared before the modules that use it so macro name resolution (which is
/// textual/top-down within a crate) sees it first.
#[macro_export]
macro_rules! bitflags_lite {
    (
        $(#[$meta:meta])*
        pub struct $name:ident : $ty:ty {
            $(
                $(#[$fmeta:meta])*
                const $flag:ident = $value:expr;
            )*
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name($ty);

        impl $name {
            $(
                $(#[$fmeta])*
                pub const $flag: $name = $name($value);
            )*

            /// The raw bit representation.
            #[inline]
            pub const fn bits(self) -> $ty { self.0 }

            /// Build from raw bits, discarding any unknown bits.
            #[inline]
            pub const fn from_bits_truncate(bits: $ty) -> Self {
                let known = 0 $(| $value)*;
                $name(bits & known)
            }

            /// True if all bits in `other` are set in `self`.
            #[inline]
            pub const fn contains(self, other: $name) -> bool {
                (self.0 & other.0) == other.0
            }

            /// The empty flag set.
            #[inline]
            pub const fn empty() -> Self { $name(0) }
        }

        impl core::ops::BitOr for $name {
            type Output = $name;
            #[inline]
            fn bitor(self, rhs: $name) -> $name { $name(self.0 | rhs.0) }
        }
    };
}

/// Protocol version negotiated in the [`control::Hello`] handshake.
///
/// Bumped on any incompatible change to either wire format. A peer that sees a
/// version it does not understand must refuse the connection rather than guess.
///
/// Version 2 introduces the variable source-block size (`actual_k` in the
/// datagram header). Peers running version 1 are not interoperable with
/// version 2 because the header length and semantics changed.
pub const PROTOCOL_VERSION: u16 = 2;

/// Logical identifier for a source block within a single tunnelled stream.
///
/// Monotonically increasing per stream; wraps are a non-issue in practice
/// because a 64-bit space at realistic symbol rates does not exhaust within any
/// connection's lifetime.
pub type BlockId = u64;

/// Identifier of a tunnelled connection (one local TCP/SOCKS5 accept maps to one).
///
/// This mirrors the QUIC stream id used for the connection's control/metadata
/// exchange, so that datagram-borne symbols can be attributed back to the right
/// logical stream on the receiver.
pub type StreamId = u64;
