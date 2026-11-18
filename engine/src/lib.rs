// src/lib.rs — EVM-Lineage off-chain engine
//
// Mirrors agent/evm_lineage.py byte for byte (tests/conformance.rs checks
// this against testvectors/conformance.json). Everything is in memory.

pub mod merkle;
pub mod skiplist;
pub mod store;
pub mod epsl;
pub mod blob;
pub mod bcp;
pub mod config;
pub mod workload;
pub mod baseline;

pub use store::{LineageStore, Vertex, VertexHash, Epoch, BranchId};
pub use merkle::{MerkleTree, MerkleProof};
pub use epsl::{Epsl, EpslConfig, EpochRoot, MembershipProof, ProofEntry, QueryProof,
               QueryKind, QueryResult, verify_query, chain_link, record_digest,
               node_leaf, skip_level, sentinel_leaf, L_MAX};
pub use bcp::{Bcp, BcpConfig, Branch, CommitResult, InMemoryAnchor,
              PruneLog, PruneLogEntry, PRUNE_ENTRY_BYTES};
pub use blob::{BlobPipeline, Event, encode_blob, decode_blob, encode_events,
               decode_events, raw_event_bytes, blobs_needed, fits_one_transaction, Codec,
               BLOB_USABLE_BYTES, BLOB_GAS_PER_BLOB, BLOB_HEADER_SIZE, MAX_BLOBS_PER_TX};
pub use config::{commit_cost_wei, cost_per_event_usd, expected_commit_latency_s};

use std::sync::atomic::{AtomicU64, Ordering};

static KECCAK_CALLS: AtomicU64 = AtomicU64::new(0);

/// Number of keccak256 evaluations since process start (benchmark counter).
pub fn keccak_calls() -> u64 { KECCAK_CALLS.load(Ordering::Relaxed) }

/// SHA-256 — content addressing of data items.
pub fn sha256(data: &[u8]) -> VertexHash {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}

/// keccak-256 — every hash that the anchor contract may have to recompute.
pub fn keccak256(data: &[u8]) -> VertexHash {
    use tiny_keccak::{Hasher, Keccak};
    KECCAK_CALLS.fetch_add(1, Ordering::Relaxed);
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(data);
    k.finalize(&mut out);
    out
}

/// Sorted-pair hash keccak256(min || max): identical in Python, Rust and
/// the assembly loop of LineageAnchor.verifyProof.
pub fn hash_pair(a: &VertexHash, b: &VertexHash) -> VertexHash {
    let (l, r) = if a <= b { (a, b) } else { (b, a) };
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(l);
    buf[32..].copy_from_slice(r);
    keccak256(&buf)
}

pub fn to_hex(b: &VertexHash) -> String { hex::encode(b) }
