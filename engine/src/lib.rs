// src/lib.rs — EVM-Lineage off-chain engine

pub mod store;
pub mod epsl;
pub mod bcp;
pub mod blob;
pub mod config;

pub use store::{LineageStore, Vertex, VertexHash, Epoch, BranchId};
pub use epsl::{Epsl, EpslConfig, EpochRoot, MerkleTree, MerkleProof};
pub use bcp::{Bcp, BcpConfig, Branch, CommitResult};
pub use blob::{BlobPipeline, BlobConfig, encode_blob, decode_blob, BlobPayload};
pub use config::{EngineConfig, cost_per_event_usd, default_cost_arb, expected_commit_latency_s};

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("store: {0}")]   Store(String),
    #[error("epsl: {0}")]    Epsl(String),
    #[error("bcp: {0}")]     Bcp(String),
    #[error("blob: {0}")]    Blob(String),
    #[error("other: {0}")]   Other(String),
}

pub type Result<T> = std::result::Result<T, EngineError>;

/// SHA-256 content hash.
pub fn sha256(data: &[u8]) -> VertexHash {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}

pub fn to_hex(b: &VertexHash) -> String { hex::encode(b) }
