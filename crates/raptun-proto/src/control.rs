//! Control-stream messages, exchanged over the reliable QUIC bi-stream #0.
//!
//! This path carries everything that *must not be lost* and where an extra
//! round-trip is acceptable because the traffic is low-volume: the handshake,
//! authentication, per-stream target negotiation, FEC reconfiguration, and the
//! block-level NACK that backs the FEC fallback mechanism.
//!
//! Framing: each message is `u8` discriminant + variant body. Because the
//! control stream is a reliable, ordered QUIC stream, we do *not* add a length
//! prefix per message here — the stream reader frames messages by decoding one
//! at a time. (Length-prefixed byte fields *inside* a message still exist.)

use bytes::{Buf, BufMut};

use crate::codec::{ensure, get_bytes, put_bytes, Decode, Encode, WireError};
use crate::{BlockId, StreamId};

/// Upper bound on any variable-length field in a control message, to cap the
/// allocation a peer can force. Control messages are tiny; 64 KiB is generous.
const MAX_FIELD: usize = 64 * 1024;

/// FEC parameters negotiated at handshake and adjustable at runtime.
///
/// These describe *how* the datagram path is coded. See the design doc's
/// parameter reference for the impact of each field.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct FecParams {
    /// Symbol size in bytes. Both peers must agree; it is sized to fit one
    /// symbol + [`crate::datagram::SYMBOL_HEADER_LEN`] inside one QUIC datagram
    /// without IP fragmentation.
    pub symbol_size: u16,
    /// Source block size K (symbols per block), or 0 to mean "auto / derive
    /// from RTT". The sender picks the concrete K and the receiver learns it
    /// from the arriving symbols, but the negotiated ceiling lives here.
    pub block_size: u16,
    /// Repair overhead as parts-per-thousand (e.g. 150 = 15%). In adaptive mode
    /// this is only the *initial* value; the sender adjusts it at runtime and
    /// announces changes via [`Message::FecReconfig`].
    pub repair_ppm: u16,
}

/// Client -> Server: opens the connection and proposes parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    /// Protocol version the client speaks. Server rejects on mismatch.
    pub version: u16,
    /// Opaque authentication token (see design doc: this is *app-level auth*,
    /// not encryption — QUIC/TLS already encrypts the channel).
    pub auth_token: Vec<u8>,
    /// FEC parameters the client would like to use.
    pub fec: FecParams,
}

/// Server -> Client: confirms the handshake and returns the effective params
/// (which may be clamped down from what the client asked for).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloAck {
    pub version: u16,
    /// Effective FEC params after server-side clamping (e.g. `repair_ppm`
    /// capped by the server's `--fec-max`).
    pub fec: FecParams,
}

/// Client -> Server: asks to open a tunnelled connection to `target`, bound to
/// the QUIC `stream_id` the client will use for this connection's metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenTarget {
    pub stream_id: StreamId,
    /// Destination as `host:port`, resolved on the server side (SOCKS5-like).
    pub target: String,
}

/// The block-level NACK — the heart of the FEC fallback path.
///
/// The receiver reports, for a stalled block, how many symbols it has *already*
/// received. Reporting progress (rather than "I lost packet N") is what makes
/// repair generation idempotent: the sender simply emits `k - have` *fresh*
/// repair symbols, and duplicate NACKs (from a lost NACK being resent) request
/// progressively fewer, so they can never cause a redundancy explosion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockNack {
    pub stream_id: StreamId,
    pub block: BlockId,
    /// Symbols received so far for this block.
    pub have: u32,
    /// Symbols still needed to reach K (i.e. `k - have`).
    pub need: u32,
}

/// The tagged union of all control-stream messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Hello(Hello),
    HelloAck(HelloAck),
    OpenTarget(OpenTarget),
    /// Server -> Client: target opened successfully.
    OpenTargetAck {
        stream_id: StreamId,
    },
    /// Server -> Client: target could not be opened; carries a reason string.
    OpenTargetErr {
        stream_id: StreamId,
        reason: String,
    },
    /// Either direction: change FEC params for subsequent blocks on a stream.
    FecReconfig {
        stream_id: StreamId,
        fec: FecParams,
    },
    /// Receiver -> Sender: request repair symbols for a stalled block.
    BlockNack(BlockNack),
    /// Liveness probe; also used to sample an application-level RTT for the FEC
    /// controller. Carries an opaque nonce echoed back in [`Message::Pong`].
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    /// Graceful shutdown request.
    Goodbye,
}

// --- Discriminants ---------------------------------------------------------
// Kept explicit and stable; never renumber, only append.
const T_HELLO: u8 = 1;
const T_HELLO_ACK: u8 = 2;
const T_OPEN_TARGET: u8 = 3;
const T_OPEN_TARGET_ACK: u8 = 4;
const T_OPEN_TARGET_ERR: u8 = 5;
const T_FEC_RECONFIG: u8 = 6;
const T_BLOCK_NACK: u8 = 7;
const T_PING: u8 = 8;
const T_PONG: u8 = 9;
const T_GOODBYE: u8 = 10;

impl Encode for FecParams {
    fn encode(&self, buf: &mut impl BufMut) {
        buf.put_u16(self.symbol_size);
        buf.put_u16(self.block_size);
        buf.put_u16(self.repair_ppm);
    }
}

impl Decode for FecParams {
    fn decode(buf: &mut impl Buf) -> Result<Self, WireError> {
        ensure(buf, 6)?;
        Ok(Self {
            symbol_size: buf.get_u16(),
            block_size: buf.get_u16(),
            repair_ppm: buf.get_u16(),
        })
    }
}

impl Encode for Message {
    fn encode(&self, buf: &mut impl BufMut) {
        match self {
            Message::Hello(h) => {
                buf.put_u8(T_HELLO);
                buf.put_u16(h.version);
                put_bytes(buf, &h.auth_token);
                h.fec.encode(buf);
            }
            Message::HelloAck(a) => {
                buf.put_u8(T_HELLO_ACK);
                buf.put_u16(a.version);
                a.fec.encode(buf);
            }
            Message::OpenTarget(o) => {
                buf.put_u8(T_OPEN_TARGET);
                buf.put_u64(o.stream_id);
                put_bytes(buf, o.target.as_bytes());
            }
            Message::OpenTargetAck { stream_id } => {
                buf.put_u8(T_OPEN_TARGET_ACK);
                buf.put_u64(*stream_id);
            }
            Message::OpenTargetErr { stream_id, reason } => {
                buf.put_u8(T_OPEN_TARGET_ERR);
                buf.put_u64(*stream_id);
                put_bytes(buf, reason.as_bytes());
            }
            Message::FecReconfig { stream_id, fec } => {
                buf.put_u8(T_FEC_RECONFIG);
                buf.put_u64(*stream_id);
                fec.encode(buf);
            }
            Message::BlockNack(n) => {
                buf.put_u8(T_BLOCK_NACK);
                buf.put_u64(n.stream_id);
                buf.put_u64(n.block);
                buf.put_u32(n.have);
                buf.put_u32(n.need);
            }
            Message::Ping { nonce } => {
                buf.put_u8(T_PING);
                buf.put_u64(*nonce);
            }
            Message::Pong { nonce } => {
                buf.put_u8(T_PONG);
                buf.put_u64(*nonce);
            }
            Message::Goodbye => buf.put_u8(T_GOODBYE),
        }
    }
}

impl Decode for Message {
    fn decode(buf: &mut impl Buf) -> Result<Self, WireError> {
        ensure(buf, 1)?;
        let tag = buf.get_u8();
        Ok(match tag {
            T_HELLO => {
                ensure(buf, 2)?;
                let version = buf.get_u16();
                let auth_token = get_bytes(buf, MAX_FIELD)?;
                let fec = FecParams::decode(buf)?;
                Message::Hello(Hello {
                    version,
                    auth_token,
                    fec,
                })
            }
            T_HELLO_ACK => {
                ensure(buf, 2)?;
                let version = buf.get_u16();
                let fec = FecParams::decode(buf)?;
                Message::HelloAck(HelloAck { version, fec })
            }
            T_OPEN_TARGET => {
                ensure(buf, 8)?;
                let stream_id = buf.get_u64();
                let target = String::from_utf8_lossy(&get_bytes(buf, MAX_FIELD)?).into_owned();
                Message::OpenTarget(OpenTarget { stream_id, target })
            }
            T_OPEN_TARGET_ACK => {
                ensure(buf, 8)?;
                Message::OpenTargetAck {
                    stream_id: buf.get_u64(),
                }
            }
            T_OPEN_TARGET_ERR => {
                ensure(buf, 8)?;
                let stream_id = buf.get_u64();
                let reason = String::from_utf8_lossy(&get_bytes(buf, MAX_FIELD)?).into_owned();
                Message::OpenTargetErr { stream_id, reason }
            }
            T_FEC_RECONFIG => {
                ensure(buf, 8)?;
                let stream_id = buf.get_u64();
                let fec = FecParams::decode(buf)?;
                Message::FecReconfig { stream_id, fec }
            }
            T_BLOCK_NACK => {
                ensure(buf, 8 + 8 + 4 + 4)?;
                Message::BlockNack(BlockNack {
                    stream_id: buf.get_u64(),
                    block: buf.get_u64(),
                    have: buf.get_u32(),
                    need: buf.get_u32(),
                })
            }
            T_PING => {
                ensure(buf, 8)?;
                Message::Ping {
                    nonce: buf.get_u64(),
                }
            }
            T_PONG => {
                ensure(buf, 8)?;
                Message::Pong {
                    nonce: buf.get_u64(),
                }
            }
            T_GOODBYE => Message::Goodbye,
            other => {
                return Err(WireError::UnknownDiscriminant {
                    discriminant: other,
                    kind: "control::Message",
                })
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(msg: Message) {
        let mut buf = Vec::new();
        msg.encode(&mut buf);
        let mut slice = buf.as_slice();
        let decoded = Message::decode(&mut slice).unwrap();
        assert_eq!(decoded, msg);
        assert!(slice.is_empty(), "decoder left trailing bytes");
    }

    #[test]
    fn all_variants_round_trip() {
        let fec = FecParams {
            symbol_size: 1200,
            block_size: 64,
            repair_ppm: 150,
        };
        round_trip(Message::Hello(Hello {
            version: crate::PROTOCOL_VERSION,
            auth_token: b"secret".to_vec(),
            fec: fec.clone(),
        }));
        round_trip(Message::HelloAck(HelloAck {
            version: crate::PROTOCOL_VERSION,
            fec: fec.clone(),
        }));
        round_trip(Message::OpenTarget(OpenTarget {
            stream_id: 7,
            target: "example.com:443".into(),
        }));
        round_trip(Message::BlockNack(BlockNack {
            stream_id: 7,
            block: 3,
            have: 60,
            need: 4,
        }));
        round_trip(Message::Ping { nonce: 99 });
        round_trip(Message::Goodbye);
    }

    #[test]
    fn unknown_tag_errors() {
        let mut slice: &[u8] = &[0xFF];
        assert!(matches!(
            Message::decode(&mut slice),
            Err(WireError::UnknownDiscriminant { .. })
        ));
    }
}
