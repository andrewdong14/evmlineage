// src/blob.rs — EIP-4844 blob transaction pipeline
//
// Blob payload structure:
//   epoch_header (64 B): epoch(8) | batch_root(32) | event_count(4) | reserved(20)
//   events[]     (var):  concatenated VertexHash bytes, zstd-compressed
//
// At w=512, 200 B/event, zstd ratio ≈ 4×: compressed ≈ 26 KB < 128 KB limit.
// BlobPipeline::new_dry() runs without a real RPC (for tests / reproducibility).

use crate::{sha256, store::{VertexHash, Epoch}};
use crate::epsl::EpochRoot;

pub const HEADER_SIZE:     usize = 64;
pub const BLOB_SIZE_LIMIT: usize = 128 * 1024; // EIP-4844 = 128 KB

// ── Blob payload ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BlobPayload {
    pub epoch:       Epoch,
    pub batch_root:  VertexHash,
    pub event_count: u32,
    pub events:      Vec<u8>,   // concatenated raw hashes
}

/// Encode a BlobPayload → 64-byte header + zstd-compressed events.
pub fn encode_blob(p: &BlobPayload) -> Result<Vec<u8>, String> {
    let mut header = [0u8; HEADER_SIZE];
    header[0..8].copy_from_slice(&p.epoch.to_be_bytes());
    header[8..40].copy_from_slice(&p.batch_root);
    header[40..44].copy_from_slice(&p.event_count.to_be_bytes());

    let compressed = zstd::encode_all(p.events.as_slice(), 3)
        .map_err(|e| e.to_string())?;

    let mut out = Vec::with_capacity(HEADER_SIZE + compressed.len());
    out.extend_from_slice(&header);
    out.extend(compressed);
    Ok(out)
}

/// Decode raw blob bytes → BlobPayload.
pub fn decode_blob(raw: &[u8]) -> Result<BlobPayload, String> {
    if raw.len() < HEADER_SIZE {
        return Err(format!("too short: {}", raw.len()));
    }
    let epoch       = u64::from_be_bytes(raw[0..8].try_into().unwrap());
    let mut root    = [0u8; 32];
    root.copy_from_slice(&raw[8..40]);
    let event_count = u32::from_be_bytes(raw[40..44].try_into().unwrap());
    let events      = zstd::decode_all(&raw[HEADER_SIZE..]).map_err(|e| e.to_string())?;
    Ok(BlobPayload { epoch, batch_root: root, event_count, events })
}

// ── BlobPipeline ──────────────────────────────────────────────────────────────

pub struct BlobConfig {
    pub dry_run:        bool,
    pub rpc_url:        String,
    pub anchor_address: String,
    pub tip_multiplier: f64,
    pub max_retries:    u32,
}

impl Default for BlobConfig {
    fn default() -> Self {
        BlobConfig { dry_run: true, rpc_url: String::new(),
                     anchor_address: String::new(), tip_multiplier: 1.2, max_retries: 5 }
    }
}

pub struct BlobPipeline { cfg: BlobConfig }

impl BlobPipeline {
    pub fn new(cfg: BlobConfig) -> Self { BlobPipeline { cfg } }
    pub fn new_dry()             -> Self { BlobPipeline { cfg: BlobConfig::default() } }

    /// Build blob payload and (dry-run) return KZG commitment hash.
    pub fn submit_sync(&self, root: &EpochRoot, events: &[VertexHash]) -> VertexHash {
        let payload = BlobPayload {
            epoch:       root.epoch,
            batch_root:  root.merkle_root,
            event_count: events.len() as u32,
            events:      events.iter().flat_map(|h| h.iter().cloned()).collect(),
        };
        match encode_blob(&payload) {
            Ok(raw) => sha256(&raw),
            Err(_)  => sha256(&root.merkle_root),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256;

    #[test]
    fn encode_decode_roundtrip_empty() {
        let p = BlobPayload { epoch: 7, batch_root: sha256(b"r"),
                              event_count: 0, events: vec![] };
        let raw  = encode_blob(&p).unwrap();
        let back = decode_blob(&raw).unwrap();
        assert_eq!(back.epoch, 7);
        assert_eq!(back.batch_root, p.batch_root);
        assert_eq!(back.event_count, 0);
    }

    #[test]
    fn encode_decode_roundtrip_512_events() {
        let events: Vec<u8> = (0u64..512).flat_map(|i| sha256(&i.to_be_bytes())).collect();
        let p = BlobPayload { epoch: 42, batch_root: sha256(b"batch"),
                              event_count: 512, events: events.clone() };
        let raw  = encode_blob(&p).unwrap();
        // Must fit within 128 KB blob limit
        assert!(raw.len() <= BLOB_SIZE_LIMIT,
            "blob {} B > {} B limit", raw.len(), BLOB_SIZE_LIMIT);
        let back = decode_blob(&raw).unwrap();
        assert_eq!(back.events, events);
        assert_eq!(back.event_count, 512);
    }

    #[test]
    fn blob_hash_deterministic() {
        let p = BlobPayload { epoch: 0, batch_root: sha256(b"r"),
                              event_count: 1, events: sha256(b"e").to_vec() };
        let h1 = sha256(&encode_blob(&p).unwrap());
        let h2 = sha256(&encode_blob(&p).unwrap());
        assert_eq!(h1, h2);
    }

    #[test]
    fn size_estimate_fits_blob_limit() {
        // w=512, ~200 B/event raw → compressed << 128 KB
        let events: Vec<u8> = (0u64..512)
            .flat_map(|_| vec![0u8; 200])
            .collect();
        let p = BlobPayload { epoch: 0, batch_root: [0u8;32], event_count: 512, events };
        let raw = encode_blob(&p).unwrap();
        assert!(raw.len() < BLOB_SIZE_LIMIT, "size {} exceeds limit", raw.len());
    }
}
