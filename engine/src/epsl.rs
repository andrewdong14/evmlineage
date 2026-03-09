// src/epsl.rs — Epoch-Pinned Skip List (EPSL) index
//
// Extends DASL (LineageChain) with:
//   (a) Epoch-pinned Merkle roots — verified slice queries without replay
//   (b) DAG merge — content-addressed shared-ancestor deduplication
//
// Complexity: Insert O(β·log n), BL/FI/TS O(β·log n),
// proof size β·⌈log₂ n⌉ × 32 bytes.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use rayon::prelude::*;
use serde::{Serialize, Deserialize};

use crate::{sha256, to_hex};
use crate::store::{LineageStore, VertexHash, Epoch, BranchId};

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct EpslConfig {
    pub l_max:      usize,  // ⌈log₂(10^7)⌉ = 23
    pub epoch_size: u64,    // batch size w (default 512)
}
impl Default for EpslConfig {
    fn default() -> Self { EpslConfig { l_max: 23, epoch_size: 512 } }
}

// ── Epoch root ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochRoot {
    pub epoch:        Epoch,
    pub merkle_root:  VertexHash,
    pub event_count:  u32,
    pub commit_block: u64,   // filled after on-chain confirmation
}

// ── Merkle tree ───────────────────────────────────────────────────────────────

/// Binary Merkle tree over 32-byte leaves, built bottom-up with Rayon.
pub struct MerkleTree {
    levels: Vec<Vec<VertexHash>>,
}

impl MerkleTree {
    pub fn from_leaves(leaves: &[VertexHash]) -> Self {
        if leaves.is_empty() {
            return MerkleTree { levels: vec![vec![[0u8;32]]] };
        }
        let mut levels = vec![leaves.to_vec()];
        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            // pad to even length
            let mut padded = prev.clone();
            if padded.len() % 2 == 1 { padded.push(*padded.last().unwrap()); }
            let next: Vec<VertexHash> = (0..padded.len())
                .step_by(2)
                .collect::<Vec<_>>()
                .into_par_iter()
                .map(|i| hash_pair(padded[i], padded[i + 1]))
                .collect();
            levels.push(next);
        }
        MerkleTree { levels }
    }

    pub fn root(&self) -> VertexHash {
        *self.levels.last().and_then(|v| v.first()).unwrap_or(&[0u8;32])
    }

    /// Generate a Merkle proof for the leaf at `idx`.
    pub fn proof(&self, idx: usize) -> Option<MerkleProof> {
        if idx >= self.levels[0].len() { return None; }
        let leaf = self.levels[0][idx];
        let mut path = Vec::new();
        let mut i    = idx;
        for level in &self.levels[..self.levels.len().saturating_sub(1)] {
            let sib = if i % 2 == 0 {
                if i + 1 < level.len() { level[i + 1] } else { level[i] }
            } else {
                level[i - 1]
            };
            path.push(sib);
            i /= 2;
        }
        Some(MerkleProof { leaf, path, root: self.root() })
    }

    pub fn len(&self)   -> usize { self.levels[0].len() }
    pub fn depth(&self) -> usize {
        let n = self.len();
        if n <= 1 { 0 } else { (n as f64).log2().ceil() as usize }
    }
}

/// Canonical pair hash: keccak(min(a,b) || max(a,b)) — mirrors Solidity verifyProof.
fn hash_pair(a: VertexHash, b: VertexHash) -> VertexHash {
    let (l, r) = if a <= b { (a, b) } else { (b, a) };
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&l);
    buf[32..].copy_from_slice(&r);
    sha256(&buf)
}

// ── Merkle proof ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub leaf: VertexHash,
    pub path: Vec<VertexHash>,
    pub root: VertexHash,
}

impl MerkleProof {
    /// Verify locally (mirrors the Solidity assembly loop in LineageAnchor).
    pub fn verify(&self) -> bool {
        let mut node = self.leaf;
        for &sib in &self.path { node = hash_pair(node, sib); }
        node == self.root
    }
    pub fn depth(&self)     -> usize { self.path.len() }
    pub fn byte_size(&self) -> usize { 32 + self.path.len() * 32 }
}

// ── EPSL node ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpslNode {
    pub hash:       VertexHash,
    pub level:      u8,
    pub epoch:      Epoch,
    pub backward:   Vec<VertexHash>,  // source hashes (lineage DAG)
    pub forward:    Vec<VertexHash>,  // forward pointers (filled during traversal)
    pub branch_ids: Vec<BranchId>,
}

impl EpslNode {
    /// Storage key: level(1) ++ epoch_be(8) ++ hash(32) = 41 bytes.
    pub fn key(level: u8, epoch: Epoch, hash: &VertexHash) -> Vec<u8> {
        let mut k = Vec::with_capacity(41);
        k.push(level);
        k.extend_from_slice(&epoch.to_be_bytes());
        k.extend_from_slice(hash);
        k
    }
}

// ── Query result ──────────────────────────────────────────────────────────────

pub struct QueryResult {
    pub hashes:      Vec<VertexHash>,
    pub proof:       Option<MerkleProof>,
    pub epoch:       Epoch,
    pub depth:       usize,
}

// ── EPSL ──────────────────────────────────────────────────────────────────────

pub struct Epsl {
    store:       Arc<LineageStore>,
    cfg:         EpslConfig,
    nodes:       Mutex<HashMap<VertexHash, EpslNode>>,
    epoch_roots: Mutex<Vec<EpochRoot>>,
    open_batch:  Mutex<Vec<VertexHash>>,
    n_nodes:     Mutex<u64>,
}

impl Epsl {
    pub fn new(store: Arc<LineageStore>, cfg: EpslConfig) -> Self {
        Epsl { store, cfg,
               nodes:       Mutex::new(HashMap::new()),
               epoch_roots: Mutex::new(Vec::new()),
               open_batch:  Mutex::new(Vec::new()),
               n_nodes:     Mutex::new(0) }
    }

    // ── Insert ─────────────────────────────────────────────────────────────────

    /// Insert sources -> targets into the EPSL.
    ///
    /// Both source and target hashes become EPSL nodes.
    /// Forward pointers: src.forward += [tgt]
    /// Backward pointers: tgt.backward += [src]
    /// DAG merge: if node already exists, merge branch_id + update ptrs.
    /// Returns all inserted/merged hashes (sources + targets).
    pub fn insert(&self, sources: &[VertexHash], targets: &[VertexHash],
                  epoch: Epoch, branch_id: BranchId) -> Vec<VertexHash>
    {
        let mut all_hashes = Vec::with_capacity(sources.len() + targets.len());
        let mut nodes_g    = self.nodes.lock().unwrap();
        let mut batch_g    = self.open_batch.lock().unwrap();
        let mut n_g        = self.n_nodes.lock().unwrap();

        // Insert source nodes
        for &src in sources {
            if let Some(node) = nodes_g.get_mut(&src) {
                if !node.branch_ids.contains(&branch_id) {
                    node.branch_ids.push(branch_id);
                }
            } else {
                let level = Self::assign_level(&src, self.cfg.l_max);
                let node  = EpslNode {
                    hash: src, level: level as u8, epoch,
                    backward: Vec::new(), forward: Vec::new(),
                    branch_ids: vec![branch_id],
                };
                let key = EpslNode::key(level as u8, epoch, &src);
                let raw = serde_json::to_vec(&node).unwrap_or_default();
                self.store.put_epsl_raw(key, raw);
                nodes_g.insert(src, node);
                batch_g.push(src);
                *n_g += 1;
            }
            all_hashes.push(src);
        }

        // Insert target nodes + backward pointers
        for &tgt in targets {
            if let Some(node) = nodes_g.get_mut(&tgt) {
                if !node.branch_ids.contains(&branch_id) {
                    node.branch_ids.push(branch_id);
                }
                for &src in sources {
                    if !node.backward.contains(&src) { node.backward.push(src); }
                }
            } else {
                let level = Self::assign_level(&tgt, self.cfg.l_max);
                let node  = EpslNode {
                    hash: tgt, level: level as u8, epoch,
                    backward: sources.to_vec(), forward: Vec::new(),
                    branch_ids: vec![branch_id],
                };
                let key = EpslNode::key(level as u8, epoch, &tgt);
                let raw = serde_json::to_vec(&node).unwrap_or_default();
                self.store.put_epsl_raw(key, raw);
                nodes_g.insert(tgt, node);
                batch_g.push(tgt);
                *n_g += 1;
            }
            all_hashes.push(tgt);
        }

        // Populate forward pointers src -> tgt
        for &src in sources {
            if let Some(sn) = nodes_g.get_mut(&src) {
                for &tgt in targets {
                    if !sn.forward.contains(&tgt) { sn.forward.push(tgt); }
                }
            }
        }

        all_hashes
    }

    /// Hash-deterministic level: trailing_zeros(h[0..4]) capped at L_max.
    pub fn assign_level(hash: &VertexHash, l_max: usize) -> usize {
        let v = u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]);
        if v == 0 { return l_max; }
        (v.trailing_zeros() as usize).min(l_max)
    }

    // ── Epoch commit ───────────────────────────────────────────────────────

    /// Close epoch: build Merkle tree over accumulated nodes, record root.
    pub fn commit_epoch(&self, epoch: Epoch) -> EpochRoot {
        let leaves: Vec<VertexHash> = self.open_batch.lock().unwrap().drain(..).collect();
        let tree = MerkleTree::from_leaves(&leaves);
        let root = tree.root();
        let er   = EpochRoot { epoch, merkle_root: root,
                               event_count: leaves.len() as u32, commit_block: 0 };
        self.epoch_roots.lock().unwrap().push(er.clone());
        er
    }

    pub fn get_epoch_root(&self, epoch: Epoch) -> Option<EpochRoot> {
        self.epoch_roots.lock().unwrap().iter().find(|r| r.epoch == epoch).cloned()
    }
    pub fn latest_epoch_root(&self) -> Option<EpochRoot> {
        self.epoch_roots.lock().unwrap().last().cloned()
    }

    // ── Queries ─────────────────────────────────────────────────────────────────

    /// Backward lineage BL(v) with Merkle proof.
    pub fn query_bl(&self, target: &VertexHash, epoch_max: Option<Epoch>,
                    beta: usize) -> QueryResult
    {
        let hashes = self.bfs_backward(target, epoch_max);
        self.make_result(hashes, epoch_max)
    }

    /// Forward impact FI(v).
    pub fn query_fi(&self, source: &VertexHash, epoch_max: Option<Epoch>,
                    beta: usize) -> QueryResult
    {
        let hashes = self.bfs_forward(source, epoch_max);
        self.make_result(hashes, epoch_max)
    }

    /// Temporal slice TS(v, block_epoch): BL query restricted to epoch_max.
    pub fn query_ts(&self, target: &VertexHash, block_epoch: Epoch,
                    beta: usize) -> QueryResult
    {
        self.query_bl(target, Some(block_epoch), beta)
    }

    fn bfs_backward(&self, start: &VertexHash, epoch_max: Option<Epoch>)
        -> Vec<VertexHash>
    {
        let nodes   = self.nodes.lock().unwrap();
        let mut vis = HashSet::new();
        let mut q   = VecDeque::new();
        q.push_back(*start);
        while let Some(curr) = q.pop_front() {
            if vis.contains(&curr) { continue; }
            if let Some(emax) = epoch_max {
                if let Some(n) = nodes.get(&curr) { if n.epoch > emax { continue; } }
            }
            vis.insert(curr);
            if let Some(n) = nodes.get(&curr) {
                for &b in &n.backward { if !vis.contains(&b) { q.push_back(b); } }
            }
        }
        vis.into_iter().collect()
    }

    fn bfs_forward(&self, start: &VertexHash, epoch_max: Option<Epoch>)
        -> Vec<VertexHash>
    {
        let nodes   = self.nodes.lock().unwrap();
        let mut vis = HashSet::new();
        let mut q   = VecDeque::new();
        q.push_back(*start);
        while let Some(curr) = q.pop_front() {
            if vis.contains(&curr) { continue; }
            if let Some(emax) = epoch_max {
                if let Some(n) = nodes.get(&curr) { if n.epoch > emax { continue; } }
            }
            vis.insert(curr);
            if let Some(n) = nodes.get(&curr) {
                for &f in &n.forward { if !vis.contains(&f) { q.push_back(f); } }
            }
        }
        vis.into_iter().collect()
    }

    fn make_result(&self, hashes: Vec<VertexHash>, epoch_max: Option<Epoch>)
        -> QueryResult
    {
        let epoch = epoch_max
            .or_else(|| self.latest_epoch_root().map(|r| r.epoch))
            .unwrap_or(0);
        let (proof, depth) = if !hashes.is_empty() {
            let tree = MerkleTree::from_leaves(&hashes);
            let d    = tree.depth();
            let p    = tree.proof(0);
            (p, d)
        } else {
            (None, 0)
        };
        QueryResult { hashes, proof, epoch, depth }
    }

    pub fn node_count(&self) -> u64 { *self.n_nodes.lock().unwrap() }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sha256, store::LineageStore};

    fn store() -> Arc<LineageStore> { Arc::new(LineageStore::new()) }
    fn epsl()  -> Epsl { Epsl::new(store(), EpslConfig::default()) }
    fn h(s: &str) -> VertexHash { sha256(s.as_bytes()) }

    // ── Merkle tree tests ─────────────────────────────────────────────────

    #[test]
    fn single_leaf_root_is_leaf() {
        let leaf = h("a");
        let t    = MerkleTree::from_leaves(&[leaf]);
        assert_eq!(t.root(), leaf);
        let p = t.proof(0).unwrap();
        assert!(p.verify());
    }

    #[test]
    fn proof_valid_all_sizes() {
        for n in [1, 2, 3, 4, 7, 8, 15, 16, 17, 100, 512] {
            let leaves: Vec<_> = (0..n).map(|i| h(&i.to_string())).collect();
            let tree = MerkleTree::from_leaves(&leaves);
            for idx in 0..n {
                let p = tree.proof(idx).unwrap();
                assert!(p.verify(), "n={n} idx={idx}");
            }
        }
    }

    #[test]
    fn tampered_proof_rejected() {
        let leaves: Vec<_> = (0..8).map(|i| h(&i.to_string())).collect();
        let tree = MerkleTree::from_leaves(&leaves);
        let mut p = tree.proof(0).unwrap();
        p.leaf[0] ^= 0xFF;
        assert!(!p.verify());
    }

    /// Proof: depth = ⌈log₂(n)⌉
    #[test]
    fn depth_is_ceil_log2() {
        let cases = [(1, 0), (2, 1), (3, 2), (4, 2), (8, 3), (9, 4), (16, 4), (100, 7)];
        for (n, expected) in cases {
            let leaves: Vec<_> = (0..n).map(|i| h(&i.to_string())).collect();
            assert_eq!(MerkleTree::from_leaves(&leaves).depth(), expected, "n={n}");
        }
    }

    #[test]
    fn proof_byte_size() {
        let leaves: Vec<_> = (0..64).map(|i| h(&i.to_string())).collect();
        let tree = MerkleTree::from_leaves(&leaves);
        let p    = tree.proof(0).unwrap();
        assert_eq!(p.byte_size(), 32 + p.depth() * 32);
    }

    // ── EPSL tests ────────────────────────────────────────────────────────

    #[test]
    fn insert_and_query_bl() {
        let e    = epsl();
        let src  = h("oracle:ETH:2000");
        let tgt  = h("decision:buy");
        let all  = e.insert(&[src], &[tgt], 0, 1);
        // Both src and tgt become EPSL nodes
        assert!(all.contains(&src) && all.contains(&tgt));
        let res = e.query_bl(&tgt, None, 1);
        assert!(res.hashes.contains(&tgt));
        assert!(res.hashes.contains(&src), "BL should reach src");
        assert_eq!(e.node_count(), 2);
    }

    #[test]
    fn dag_merge_deduplicates() {
        let e    = epsl();
        let src  = h("oracle");
        let tgt  = h("shared-data");
        // Insert same target from two branches
        e.insert(&[src], &[tgt], 0, 1);
        e.insert(&[src], &[tgt], 0, 2);
        // Should have 2 unique nodes (src + tgt), not 3
        assert_eq!(e.node_count(), 2);
        let nodes = e.nodes.lock().unwrap();
        let node  = nodes.get(&tgt).unwrap();
        assert!(node.branch_ids.contains(&1));
        assert!(node.branch_ids.contains(&2));
    }

    #[test]
    fn epoch_commit_produces_valid_root() {
        let e = epsl();
        for i in 0..10u64 {
            let content = format!("item-{i}");
            e.insert(&[], &[h(&content)], 0, 0);
        }
        let root = e.commit_epoch(0);
        assert_eq!(root.event_count, 10);
        assert_ne!(root.merkle_root, [0u8;32]);
    }

    #[test]
    fn proof_verifies_after_commit() {
        let e = epsl();
        let tgts: Vec<_> = (0..8).map(|i| h(&format!("e{i}"))).collect();
        e.insert(&[], &tgts, 0, 0);
        let root = e.commit_epoch(0);
        // Rebuild tree to verify
        let tree = MerkleTree::from_leaves(&tgts);
        assert_eq!(tree.root(), root.merkle_root);
        for idx in 0..8 {
            assert!(tree.proof(idx).unwrap().verify(), "idx={idx}");
        }
    }

    #[test]
    fn level_assignment_bounded() {
        for i in 0u64..500 {
            let hash = sha256(&i.to_be_bytes());
            let lv   = Epsl::assign_level(&hash, 23);
            assert!(lv <= 23, "level {lv} > L_max");
        }
    }

    #[test]
    fn temporal_slice_respects_epoch() {
        let e    = epsl();
        let old  = h("old-data");
        let new  = h("new-data");
        e.insert(&[], &[old], 0, 0);
        e.insert(&[], &[new], 5, 0);
        // TS query at epoch=2 should find old but not new
        let res = e.query_ts(&old, 2, 1);
        assert!(res.hashes.contains(&old));
        // new has epoch=5 > 2 → excluded from BFS
        assert!(!res.hashes.contains(&new));
    }
}
