//! Raptun's forward-error-correction layer, built on RaptorQ (`raptorq` crate).
//!
//! This crate is the design's one genuinely novel piece and is deliberately
//! decoupled from the transport (`raptun-core`) so it can be unit-tested and
//! benchmarked in isolation — feed it bytes and simulated loss, observe what it
//! emits, with no sockets involved.
//!
//! # The model
//!
//! Application bytes for one tunnelled stream are cut into fixed-size *source
//! symbols*. K of them form a *source block*. RaptorQ turns a block into K
//! source symbols plus as many *repair symbols* as we ask for; the receiver can
//! reconstruct the whole block once it holds **any** K (plus a small overhead)
//! of them — it does not matter which ones were lost. That "any K" property is
//! what lets loss recovery happen with *zero extra round trips*, unlike ARQ.
//!
//! # Module map
//!
//! * [`encoder`] — cuts a byte stream into blocks and emits symbols with the
//!   [`raptun_proto::datagram::SymbolHeader`] attached.
//! * [`decoder`] — the receiver's per-block [`decoder::BlockManager`] state
//!   machine (`Filling → Stalled → NackSent → Decoded | Degraded`), which is
//!   the answer to "does the fallback converge under extreme loss?".
//! * [`link`] — a snapshot of live transport telemetry (RTT, jitter, loss,
//!   congestion signal) read from Quinn, plus the sequence-progress oracle the
//!   decoder uses to tell *reordering* apart from *loss*.
//! * [`budget`] — the global in-flight repair budget: the hard ceiling that
//!   makes the redundancy control loop provably non-divergent.
//! * [`strategy`] — the adaptive controller that maps link telemetry to a
//!   repair ratio, including the random-vs-congestion loss discrimination that
//!   decides whether to add or *remove* redundancy.

pub mod budget;
pub mod codec;
pub mod decoder;
pub mod encoder;
pub mod link;
pub mod strategy;

pub use budget::{RepairBudget, SendWindow, TunnelSlot};
pub use codec::{RaptorQBlockDecoderImpl, RaptorQBlockEncoder};
pub use decoder::{BlockManager, BlockOutcome, DecoderAction};
pub use encoder::{BlockEncoder, StreamEncoder};
pub use link::LinkState;
pub use strategy::{FecStrategy, RepairRatio};

/// Errors surfaced by the FEC layer.
#[derive(Debug, thiserror::Error)]
pub enum FecError {
    /// The `raptorq` encoder/decoder rejected the given configuration
    /// (e.g. a symbol size or block size outside the RFC6330-valid range).
    #[error("invalid RaptorQ configuration: {0}")]
    Config(String),

    /// A symbol arrived tagged for a block whose K we have not yet learned and
    /// cannot infer. Treated as droppable, not fatal.
    #[error("symbol for unknown block geometry")]
    UnknownGeometry,
}
