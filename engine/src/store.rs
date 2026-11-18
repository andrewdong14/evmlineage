// src/store.rs — in-memory store for speculative (Phase 1) writes
//
// Three maps: vertices by content hash (with the bitmask of branches that
// reference them), edges keyed by (source hash, epoch), and an opaque
// key-value area. A durable deployment would keep the same maps in an
// LSM-tree store; this repository does not include one.

use std::collections::HashMap;
use std::sync::Mutex;
use serde::{Serialize, Deserialize};

use crate::sha256;

pub type VertexHash = [u8; 32];
pub type Epoch      = u64;
pub type BranchId   = u64;

// ── Vertex type ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum VertexType {
    OraclePrice    = 0x01,
    AgentDecision  = 0x02,
    TradeOrder     = 0x03,
    PoolState      = 0x04,
    AccountBalance = 0x05,
    AgentMemory    = 0x06,
    Other          = 0xFF,
}
impl Default for VertexType { fn default() -> Self { VertexType::Other } }

/// Max inline content size (bytes); larger items are referenced by hash.
pub const MAX_INLINE: usize = 256;

// ── Vertex record ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vertex {
    pub hash:           VertexHash,
    pub content:        Vec<u8>,
    pub content_inline: bool,
    pub vertex_type:    VertexType,
    pub creation_epoch: Epoch,
    pub agent_id:       VertexHash,
    /// Bitmask of branch IDs referencing this vertex (used for DAG merge deduplication).
    pub branch_mask:    u64,
    pub timestamp_ms:   u64,
}

impl Vertex {
    pub fn new(content: Vec<u8>, vtype: VertexType,
               epoch: Epoch, agent_id: VertexHash, branch_id: BranchId) -> Self {
        let hash   = sha256(&content);
        let inline = content.len() <= MAX_INLINE;
        let ts     = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().as_millis() as u64;
        Vertex { hash, content, content_inline: inline, vertex_type: vtype,
                 creation_epoch: epoch, agent_id,
                 branch_mask: 1u64 << (branch_id & 63), timestamp_ms: ts }
    }
    pub fn merge_branch(&mut self, bid: BranchId) {
        self.branch_mask |= 1u64 << (bid & 63);
    }
}

// ── LineageStore ──────────────────────────────────────────────────────────────

#[derive(Default)]
struct StoreInner {
    vertices:   HashMap<VertexHash, Vertex>,
    /// Outgoing edges per source: (epoch, targets) lists.
    edges:      HashMap<VertexHash, Vec<(Epoch, Vec<VertexHash>)>>,
    raw:        HashMap<Vec<u8>, Vec<u8>>,
    inserts:    u64,
    dag_merges: u64,
}

/// Thread-safe in-memory store for speculative (Phase 1) writes.
pub struct LineageStore {
    inner: Mutex<StoreInner>,
}

impl LineageStore {
    pub fn new() -> Self {
        LineageStore { inner: Mutex::new(StoreInner::default()) }
    }

    /// Insert a vertex, or merge the branch mask if it exists.
    /// Returns (is_new, hash).
    pub fn put_vertex(&self, vtx: Vertex) -> (bool, VertexHash) {
        let hash = vtx.hash;
        let mut g = self.inner.lock().unwrap();
        g.inserts += 1;
        if let Some(existing) = g.vertices.get_mut(&hash) {
            existing.branch_mask |= vtx.branch_mask;
            g.dag_merges += 1;
            return (false, hash);
        }
        g.vertices.insert(hash, vtx);
        (true, hash)
    }

    pub fn get_vertex(&self, hash: &VertexHash) -> Option<Vertex> {
        self.inner.lock().unwrap().vertices.get(hash).cloned()
    }

    /// Add edges src -> targets, recorded under `epoch`.
    pub fn put_edge(&self, src: VertexHash, epoch: Epoch, targets: &[VertexHash]) {
        let mut g = self.inner.lock().unwrap();
        let lists = g.edges.entry(src).or_default();
        let idx = match lists.iter().position(|(ep, _)| *ep == epoch) {
            Some(i) => i,
            None => { lists.push((epoch, Vec::new())); lists.len() - 1 }
        };
        let list = &mut lists[idx].1;
        for t in targets {
            if !list.contains(t) { list.push(*t); }
        }
    }

    /// All targets of `src` recorded in epochs [lo, hi].
    pub fn scan_edges(&self, src: &VertexHash, lo: Epoch, hi: Epoch) -> Vec<VertexHash> {
        let g = self.inner.lock().unwrap();
        let mut lists: Vec<&(Epoch, Vec<VertexHash>)> = match g.edges.get(src) {
            Some(l) => l.iter().filter(|(ep, _)| lo <= *ep && *ep <= hi).collect(),
            None => return Vec::new(),
        };
        lists.sort_by_key(|(ep, _)| *ep);
        lists.into_iter().flat_map(|(_, t)| t.iter().copied()).collect()
    }

    /// Remove the edges src -> targets (Phase-5 garbage collection).
    pub fn drop_edges(&self, src: &VertexHash, targets: &[VertexHash]) {
        let mut g = self.inner.lock().unwrap();
        let empty = match g.edges.get_mut(src) {
            Some(lists) => {
                for (_, list) in lists.iter_mut() { list.retain(|t| !targets.contains(t)); }
                lists.retain(|(_, list)| !list.is_empty());
                lists.is_empty()
            }
            None => false,
        };
        if empty { g.edges.remove(src); }
    }

    /// Delete a vertex and its outgoing edges (Phase-5 garbage collection
    /// of vertices that only pruned branches referenced).
    pub fn remove_vertex(&self, h: &VertexHash) -> bool {
        let mut g = self.inner.lock().unwrap();
        if g.vertices.remove(h).is_none() { return false; }
        g.edges.remove(h);
        true
    }

    pub fn put_raw(&self, key: Vec<u8>, val: Vec<u8>) {
        self.inner.lock().unwrap().raw.insert(key, val);
    }
    pub fn get_raw(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.lock().unwrap().raw.get(key).cloned()
    }

    pub fn vertex_count(&self)  -> usize { self.inner.lock().unwrap().vertices.len() }
    pub fn edge_count(&self) -> usize {
        self.inner.lock().unwrap().edges.values()
            .map(|l| l.iter().map(|(_, t)| t.len()).sum::<usize>()).sum()
    }
    pub fn inserts_total(&self)  -> u64  { self.inner.lock().unwrap().inserts }
    pub fn dag_merges_total(&self) -> u64 { self.inner.lock().unwrap().dag_merges }
    pub fn dedup_ratio(&self)    -> f64  {
        let g = self.inner.lock().unwrap();
        if g.inserts == 0 { 0.0 } else { g.dag_merges as f64 / g.inserts as f64 }
    }
}

impl Default for LineageStore {
    fn default() -> Self { LineageStore::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256;

    #[test]
    fn vertex_hash_is_sha256() {
        let c = b"hello world".to_vec();
        let v = Vertex::new(c.clone(), VertexType::Other, 0, [0u8;32], 0);
        assert_eq!(v.hash, sha256(&c));
    }

    #[test]
    fn dag_merge_updates_branch_mask() {
        let store = LineageStore::new();
        let c = b"shared".to_vec();
        let v1 = Vertex::new(c.clone(), VertexType::OraclePrice, 0, [0u8;32], 1);
        let v2 = Vertex::new(c.clone(), VertexType::OraclePrice, 0, [0u8;32], 2);
        let (new1, _) = store.put_vertex(v1);
        let (new2, _) = store.put_vertex(v2);
        assert!(new1);
        assert!(!new2);  // DAG merge
        assert_eq!(store.dag_merges_total(), 1);
        let stored = store.get_vertex(&sha256(&c)).unwrap();
        assert_ne!(stored.branch_mask & (1 << 2), 0); // branch 2 merged in
    }

    #[test]
    fn edge_scan_and_drop() {
        let store = LineageStore::new();
        let (src, t1, t2, t3) = (sha256(b"src"), sha256(b"t1"), sha256(b"t2"), sha256(b"t3"));
        store.put_edge(src, 0, &[t1]);
        store.put_edge(src, 1, &[t2, t3]);
        store.put_edge(src, 1, &[t2]);                       // duplicate ignored
        assert_eq!(store.scan_edges(&src, 0, 1), vec![t1, t2, t3]);
        assert_eq!(store.scan_edges(&src, 1, 1), vec![t2, t3]);
        assert_eq!(store.edge_count(), 3);
        store.drop_edges(&src, &[t2]);
        assert_eq!(store.scan_edges(&src, 0, 5), vec![t1, t3]);
        store.drop_edges(&src, &[t1, t3]);
        assert!(store.scan_edges(&src, 0, 5).is_empty());
        assert_eq!(store.edge_count(), 0);
    }

    #[test]
    fn inline_flag() {
        let small = Vertex::new(vec![0u8; 100], VertexType::Other, 0, [0u8;32], 0);
        let large = Vertex::new(vec![0u8; 300], VertexType::Other, 0, [0u8;32], 0);
        assert!(small.content_inline);
        assert!(!large.content_inline);
    }
}
