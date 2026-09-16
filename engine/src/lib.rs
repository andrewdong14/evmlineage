// src/lib.rs — EVM-Lineage off-chain engine

pub mod store;
pub mod epsl;
pub mod bcp;
pub mod blob;
pub mod config;

pub use store::{LineageStore, Vertex, VertexHash, Epoch, BranchId};
pub use epsl::{Epsl, EpslConfig, EpochRoot, MerkleTree, MerkleProof,
               NodeRecord, QueryProof, QueryKind, verify_query};
pub use bcp::{Bcp, BcpConfig, Branch, CommitResult, InMemoryAnchor,
              PruneLog, PruneLogEntry, PRUNE_ENTRY_BYTES};
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

/// SHA-256 — content addressing of data items.
pub fn sha256(data: &[u8]) -> VertexHash {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}

/// keccak-256 — Merkle pair hashing and leaf construction, so proofs
/// verify inside the Solidity assembly loop of LineageAnchor.verifyProof.
pub fn keccak256(data: &[u8]) -> VertexHash {
    use tiny_keccak::{Hasher, Keccak};
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(data);
    k.finalize(&mut out);
    out
}

/// Canonical sort-then-hash: keccak256(min||max) — identical across
/// Python, Rust, and Solidity.
pub fn hash_pair(a: VertexHash, b: VertexHash) -> VertexHash {
    let (l, r) = if a <= b { (a, b) } else { (b, a) };
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&l);
    buf[32..].copy_from_slice(&r);
    keccak256(&buf)
}

pub fn to_hex(b: &VertexHash) -> String { hex::encode(b) }
