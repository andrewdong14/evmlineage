// src/epsl.rs — Epoch-Pinned Skip List (EPSL) index
//
// Authentication model (mirrors agent/evm_lineage.py exactly)
// -----------------------------------------------------------
// Every edge is tagged with the epoch it was added in. The node record as
// of epoch e restricts adjacency to edges with epoch <= e. Its digest and
// Merkle leaf are:
//
//     digest_e(v) = keccak256(h | lvl | epoch_be | n_fwd | fwd<=e sorted
//                             | n_bwd | bwd<=e sorted)
//     leaf_e(v)   = keccak256(h || digest_e(v))
//
// Sealing epoch e Merkle-commits leaf_e of every node created at epoch
// <= e, sorted by vertex hash; that root is anchored on-chain by the BCP
// (Invariant I1). Query proofs carry per-node records + inclusion paths,
// and `verify_query` checks inclusion, closure under the traversal
// direction (anti-suppression, attack S1), and the origin — with no
// access to the prover's store. The leaf shape keccak256(h||digest) is
// what makes LineageAnchor.slash's equivocation fraud proof sound.
//
// Reference-implementation notes: sealing recomputes the state tree
// (leaf digests cached, recomputed only for dirty nodes); production
// maintains the tree incrementally for amortised O(log n) inserts.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use rayon::prelude::*;
use serde::{Serialize, Deserialize};

use crate::{keccak256, hash_pair};
use crate::store::{LineageStore, VertexHash, Epoch, BranchId};

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct EpslConfig {
    pub l_max:      usize,  // ceil(log2(10^7)) = 23
    pub epoch_size: u64,    // batch size w (default 512)
}
impl Default for EpslConfig {
    fn default() -> Self { EpslConfig { l_max: 23, epoch_size: 512 } }
}

// ── Epoch root ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochRoot {
    pub epoch:        Epoch,
    pub merkle_root:  VertexHash,  // EPSL state root (anchored on-chain)
    pub event_count:  u32,         // nodes newly sealed in this epoch
    pub commit_block: u64,
}

// ── Merkle tree ───────────────────────────────────────────────────────────────

/// Binary Merkle tree over 32-byte leaves; keccak sorted-pair hashing,
/// odd node promoted (identical to the Python MerkleTree and the
/// Solidity verifyProof loop).
pub struct MerkleTree {
    levels: Vec<Vec<VertexHash>>,
}

impl MerkleTree {
    pub fn from_leaves(leaves: &[VertexHash]) -> Self {
        if leaves.is_empty() {
            return MerkleTree { levels: vec![vec![[0u8; 32]]] };
        }
        let mut levels = vec![leaves.to_vec()];
        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let next: Vec<VertexHash> = (0..prev.len())
                .step_by(2)
                .collect::<Vec<_>>()
                .into_par_iter()
                .map(|i| {
                    if i + 1 < prev.len() { hash_pair(prev[i], prev[i + 1]) }
                    else                  { prev[i] }          // odd: promote
                })
                .collect();
            levels.push(next);
        }
        MerkleTree { levels }
    }

    pub fn root(&self) -> VertexHash {
        *self.levels.last().and_then(|v| v.first()).unwrap_or(&[0u8; 32])
    }

    /// Sibling path for the leaf at `idx` (no left/right flags needed —
    /// pair hashing is order-canonical).
    pub fn proof(&self, idx: usize) -> Option<MerkleProof> {
        if idx >= self.levels[0].len() { return None; }
        let leaf = self.levels[0][idx];
        let mut path = Vec::new();
        let mut i = idx;
        for level in &self.levels[..self.levels.len().saturating_sub(1)] {
            let sib = i ^ 1;
            if sib < level.len() { path.push(level[sib]); }
            i /= 2;
        }
        Some(MerkleProof { leaf, path, root: self.root() })
    }

    pub fn len(&self)      -> usize { self.levels[0].len() }
    pub fn is_empty(&self) -> bool  { self.len() == 0 }
    pub fn depth(&self) -> usize {
        let n = self.len();
        if n <= 1 { 0 } else { (n as f64).log2().ceil() as usize }
    }
}

// ── Merkle proof ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub leaf: VertexHash,
    pub path: Vec<VertexHash>,
    pub root: VertexHash,
}

impl MerkleProof {
    /// Mirrors the Solidity assembly loop in LineageAnchor.verifyProof.
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
    pub epoch:      Epoch,                          // creation epoch
    /// Adjacency: neighbour hash -> epoch the edge was added in.
    pub backward:   BTreeMap<VertexHash, Epoch>,
    pub forward:    BTreeMap<VertexHash, Epoch>,
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

    /// Node record restricted to edges with epoch <= e.
    pub fn record_as_of(&self, e: Epoch) -> NodeRecord {
        NodeRecord {
            hash:  self.hash,
            level: self.level,
            epoch: self.epoch,
            fwd:   self.forward.iter().filter(|(_, ep)| **ep <= e)
                       .map(|(h, _)| *h).collect(),
            bwd:   self.backward.iter().filter(|(_, ep)| **ep <= e)
                       .map(|(h, _)| *h).collect(),
        }
    }
}

/// Serializable per-epoch node record (BTreeMap iteration is sorted by
/// hash, matching Python's sorted() over hex strings byte-for-byte).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRecord {
    pub hash:  VertexHash,
    pub level: u8,
    pub epoch: Epoch,
    pub fwd:   Vec<VertexHash>,
    pub bwd:   Vec<VertexHash>,
}

impl NodeRecord {
    /// Canonical digest — byte-identical to Python `node_record_digest`.
    pub fn digest(&self) -> VertexHash {
        let mut buf = Vec::with_capacity(45 + 32 * (self.fwd.len() + self.bwd.len()) + 8);
        buf.extend_from_slice(&self.hash);
        buf.push(self.level);
        buf.extend_from_slice(&self.epoch.to_be_bytes());
        buf.extend_from_slice(&(self.fwd.len() as u32).to_be_bytes());
        for h in &self.fwd { buf.extend_from_slice(h); }
        buf.extend_from_slice(&(self.bwd.len() as u32).to_be_bytes());
        for h in &self.bwd { buf.extend_from_slice(h); }
        keccak256(&buf)
    }

    /// Merkle leaf: keccak256(vertex_hash || digest) — the shape checked
    /// by LineageAnchor.slash for equivocation fraud proofs.
    pub fn leaf(&self) -> VertexHash {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&self.hash);
        buf[32..].copy_from_slice(&self.digest());
        keccak256(&buf)
    }
}

// ── Query proof / result ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryKind { Bl, Fi, Ts }

#[derive(Debug, Clone)]
pub struct QueryProof {
    pub kind:    QueryKind,
    pub origin:  VertexHash,
    pub epoch:   Epoch,
    pub root:    VertexHash,
    /// True iff generated against a sealed (anchorable) epoch root.
    pub sealed:  bool,
    pub records: Vec<NodeRecord>,        // origin first
    pub paths:   Vec<Vec<VertexHash>>,
}

impl QueryProof {
    pub fn depth(&self) -> usize {
        self.paths.iter().map(|p| p.len()).max().unwrap_or(0)
    }
    pub fn byte_size(&self) -> usize {
        32 * self.records.len()
            + 32 * self.paths.iter().map(|p| p.len()).sum::<usize>()
    }
    pub fn verify(&self, root: &VertexHash) -> bool {
        verify_query(self, root)
    }
}

/// Verify a QueryProof against an (on-chain) epoch root: inclusion of
/// every record, closure under the traversal direction (attack S1), and
/// the origin — with no access to the prover's store.
pub fn verify_query(proof: &QueryProof, root: &VertexHash) -> bool {
    if proof.records.is_empty() || proof.records[0].hash != proof.origin {
        return false;
    }
    if proof.records.len() != proof.paths.len() {
        return false;
    }
    let returned: HashSet<VertexHash> =
        proof.records.iter().map(|r| r.hash).collect();
    for (rec, path) in proof.records.iter().zip(&proof.paths) {
        let mut node = rec.leaf();
        for sib in path { node = hash_pair(node, *sib); }
        if node != *root { return false; }
        let nbs = if proof.kind == QueryKind::Fi { &rec.fwd } else { &rec.bwd };
        for nb in nbs {
            if !returned.contains(nb) { return false; }
        }
    }
    true
}

pub struct QueryResult {
    pub hashes: Vec<VertexHash>,
    pub proof:  Option<QueryProof>,
    pub epoch:  Epoch,
    pub depth:  usize,
}

// ── EPSL ──────────────────────────────────────────────────────────────────────

struct SealedEpoch {
    tree:  MerkleTree,
    index: HashMap<VertexHash, usize>,
}

struct EpslInner {
    nodes:          BTreeMap<VertexHash, EpslNode>,
    epoch_roots:    Vec<EpochRoot>,
    sealed:         HashMap<Epoch, SealedEpoch>,
    leaf_cache:     HashMap<VertexHash, VertexHash>,
    dirty:          HashSet<VertexHash>,
    new_since_seal: u32,
    max_epoch_seen: Epoch,
}

pub struct Epsl {
    store: Arc<LineageStore>,
    cfg:   EpslConfig,
    inner: Mutex<EpslInner>,
}

impl Epsl {
    pub fn new(store: Arc<LineageStore>, cfg: EpslConfig) -> Self {
        Epsl {
            store, cfg,
            inner: Mutex::new(EpslInner {
                nodes:          BTreeMap::new(),
                epoch_roots:    Vec::new(),
                sealed:         HashMap::new(),
                leaf_cache:     HashMap::new(),
                dirty:          HashSet::new(),
                new_since_seal: 0,
                max_epoch_seen: 0,
            }),
        }
    }

    // ── Insert (paper Algorithm 1) ────────────────────────────────────────

    /// Insert sources -> targets. Content addressing gives DAG merge for
    /// free. Returns all touched hashes (sources + targets).
    pub fn insert(&self, sources: &[VertexHash], targets: &[VertexHash],
                  epoch: Epoch, branch_id: BranchId) -> Vec<VertexHash>
    {
        let mut all = Vec::with_capacity(sources.len() + targets.len());
        let mut g = self.inner.lock().unwrap();
        if epoch > g.max_epoch_seen { g.max_epoch_seen = epoch; }

        for &src in sources {
            Self::touch(&mut g, &self.store, src, epoch, branch_id, self.cfg.l_max);
            all.push(src);
        }
        for &tgt in targets {
            Self::touch(&mut g, &self.store, tgt, epoch, branch_id, self.cfg.l_max);
            let mut changed = false;
            if let Some(node) = g.nodes.get_mut(&tgt) {
                for &src in sources {
                    if !node.backward.contains_key(&src) {
                        node.backward.insert(src, epoch);
                        changed = true;
                    }
                }
            }
            if changed { g.dirty.insert(tgt); }
            all.push(tgt);
        }
        for &src in sources {
            let mut changed = false;
            if let Some(node) = g.nodes.get_mut(&src) {
                for &tgt in targets {
                    if !node.forward.contains_key(&tgt) {
                        node.forward.insert(tgt, epoch);
                        changed = true;
                    }
                }
            }
            if changed { g.dirty.insert(src); }
        }
        all
    }

    fn touch(g: &mut EpslInner, store: &LineageStore, h: VertexHash,
             epoch: Epoch, branch_id: BranchId, l_max: usize)
    {
        if let Some(node) = g.nodes.get_mut(&h) {
            if !node.branch_ids.contains(&branch_id) {
                node.branch_ids.push(branch_id);
            }
            return;
        }
        let level = Self::assign_level(&h, l_max) as u8;
        let node = EpslNode {
            hash: h, level, epoch,
            backward: BTreeMap::new(), forward: BTreeMap::new(),
            branch_ids: vec![branch_id],
        };
        let key = EpslNode::key(level, epoch, &h);
        let raw = serde_json::to_vec(&node.record_as_of(epoch)).unwrap_or_default();
        store.put_epsl_raw(key, raw);
        g.nodes.insert(h, node);
        g.dirty.insert(h);
        g.new_since_seal += 1;
    }

    /// Garbage-collect a branch-exclusive node (BCP Phase 5).
    pub fn remove_node(&self, h: &VertexHash) -> bool {
        let mut g = self.inner.lock().unwrap();
        let node = match g.nodes.remove(h) { Some(n) => n, None => return false };
        let bwd: Vec<VertexHash> = node.backward.keys().cloned().collect();
        let fwd: Vec<VertexHash> = node.forward.keys().cloned().collect();
        for nb in bwd {
            if let Some(other) = g.nodes.get_mut(&nb) {
                if other.forward.remove(h).is_some() { g.dirty.insert(nb); }
            }
        }
        for nb in fwd {
            if let Some(other) = g.nodes.get_mut(&nb) {
                if other.backward.remove(h).is_some() { g.dirty.insert(nb); }
            }
        }
        g.leaf_cache.remove(h);
        g.dirty.remove(h);
        g.new_since_seal = g.new_since_seal.saturating_sub(1);
        true
    }

    /// Deterministic skip-list level: trailing zeros of h[0..4], capped.
    /// Yields the geometric distribution P(level >= k) = 2^-k required by
    /// skip-list analysis while staying deterministic across replicas.
    /// NOTE: the paper's Sect. 5.1 formula floor(log2(h mod 2^32)) does
    /// not produce this distribution; the paper text should be corrected
    /// to match (see PAPER_ALIGNMENT.md).
    pub fn assign_level(hash: &VertexHash, l_max: usize) -> usize {
        let v = u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]);
        if v == 0 { return l_max; }
        (v.trailing_zeros() as usize).min(l_max)
    }

    // ── Epoch sealing (Phase 4) ───────────────────────────────────────────

    /// Seal `epoch`: Merkle-commit the EPSL state as of it. The root is
    /// what the BCP submits to the anchor (Invariant I1).
    pub fn commit_epoch(&self, epoch: Epoch) -> EpochRoot {
        let mut g = self.inner.lock().unwrap();
        let keys: Vec<VertexHash> = g.nodes.iter()
            .filter(|(_, n)| n.epoch <= epoch)
            .map(|(h, _)| *h).collect();          // BTreeMap: already sorted
        let mut leaves = Vec::with_capacity(keys.len());
        for h in &keys {
            let cached = if !g.dirty.contains(h) {
                g.leaf_cache.get(h).copied()
            } else { None };
            let leaf = cached.unwrap_or_else(|| {
                g.nodes[h].record_as_of(epoch).leaf()
            });
            g.leaf_cache.insert(*h, leaf);
            leaves.push(leaf);
        }
        g.dirty.clear();
        let new_count = g.new_since_seal;
        g.new_since_seal = 0;
        let tree = if leaves.is_empty() {
            MerkleTree::from_leaves(&[[0u8; 32]])
        } else {
            MerkleTree::from_leaves(&leaves)
        };
        let root = tree.root();
        let index: HashMap<VertexHash, usize> =
            keys.iter().enumerate().map(|(i, h)| (*h, i)).collect();
        g.sealed.insert(epoch, SealedEpoch { tree, index });
        let er = EpochRoot { epoch, merkle_root: root,
                             event_count: new_count, commit_block: 0 };
        g.epoch_roots.push(er.clone());
        er
    }

    pub fn get_epoch_root(&self, epoch: Epoch) -> Option<EpochRoot> {
        self.inner.lock().unwrap()
            .epoch_roots.iter().find(|r| r.epoch == epoch).cloned()
    }
    pub fn latest_epoch_root(&self) -> Option<EpochRoot> {
        self.inner.lock().unwrap().epoch_roots.last().cloned()
    }

    // ── Verified queries (paper Algorithm 2) ─────────────────────────────

    pub fn query_bl(&self, target: &VertexHash, epoch_max: Option<Epoch>,
                    _beta: usize) -> QueryResult {
        self.query(*target, QueryKind::Bl, epoch_max)
    }
    pub fn query_fi(&self, source: &VertexHash, epoch_max: Option<Epoch>,
                    _beta: usize) -> QueryResult {
        self.query(*source, QueryKind::Fi, epoch_max)
    }
    /// TS(v, b): BL restricted to — and proven against — epoch b's root.
    pub fn query_ts(&self, target: &VertexHash, block_epoch: Epoch,
                    _beta: usize) -> QueryResult {
        self.query(*target, QueryKind::Ts, Some(block_epoch))
    }

    fn query(&self, origin: VertexHash, kind: QueryKind,
             epoch_max: Option<Epoch>) -> QueryResult
    {
        let g = self.inner.lock().unwrap();
        let e = epoch_max
            .or_else(|| g.epoch_roots.last().map(|r| r.epoch))
            .unwrap_or(g.max_epoch_seen);

        // BFS over adjacency restricted to epoch <= e.
        let mut visited: Vec<VertexHash> = Vec::new();
        let mut seen: HashSet<VertexHash> = HashSet::new();
        seen.insert(origin);
        let mut queue: VecDeque<VertexHash> = VecDeque::new();
        queue.push_back(origin);
        while let Some(curr) = queue.pop_front() {
            match g.nodes.get(&curr) {
                None => { if curr == origin { visited.push(curr); } }
                Some(node) if node.epoch > e => {
                    if curr == origin { visited.push(curr); }
                }
                Some(node) => {
                    visited.push(curr);
                    let adj = if kind == QueryKind::Fi { &node.forward }
                              else                      { &node.backward };
                    for (nb, ep) in adj {
                        if *ep <= e && !seen.contains(nb) {
                            seen.insert(*nb);
                            queue.push_back(*nb);
                        }
                    }
                }
            }
        }

        let proof = Self::prove(&g, &visited, origin, kind, e);
        let depth = proof.as_ref().map(|p| p.depth()).unwrap_or(0);
        QueryResult { hashes: visited, proof, epoch: e, depth }
    }

    fn prove(g: &EpslInner, visited: &[VertexHash], origin: VertexHash,
             kind: QueryKind, e: Epoch) -> Option<QueryProof>
    {
        match g.nodes.get(&origin) {
            Some(n) if n.epoch <= e => {}
            _ => return None,
        }
        // Sealed epoch: reuse its tree. Unsealed: build an ephemeral one.
        let ephemeral: Option<(MerkleTree, HashMap<VertexHash, usize>)> =
            if g.sealed.contains_key(&e) { None } else {
                let keys: Vec<VertexHash> = g.nodes.iter()
                    .filter(|(_, n)| n.epoch <= e)
                    .map(|(h, _)| *h).collect();
                let leaves: Vec<VertexHash> = keys.iter()
                    .map(|h| g.nodes[h].record_as_of(e).leaf()).collect();
                let tree = if leaves.is_empty() {
                    MerkleTree::from_leaves(&[[0u8; 32]])
                } else { MerkleTree::from_leaves(&leaves) };
                let index: HashMap<VertexHash, usize> =
                    keys.iter().enumerate().map(|(i, h)| (*h, i)).collect();
                Some((tree, index))
            };
        let (tree_ref, index_ref, sealed) = match (&ephemeral, g.sealed.get(&e)) {
            (None, Some(se))       => (&se.tree, &se.index, true),
            (Some((t, idx)), _)    => (t, idx, false),
            _                      => return None,
        };
        let mut records = Vec::with_capacity(visited.len());
        let mut paths   = Vec::with_capacity(visited.len());
        for h in visited {
            let idx = *index_ref.get(h)?;
            let mp  = tree_ref.proof(idx)?;
            records.push(g.nodes[h].record_as_of(e));
            paths.push(mp.path);
        }
        Some(QueryProof { kind, origin, epoch: e, root: tree_ref.root(),
                          sealed, records, paths })
    }

    pub fn node_count(&self) -> u64 {
        self.inner.lock().unwrap().nodes.len() as u64
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — run with `cargo test` (not runnable in the authoring sandbox;
// verify locally before release)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256;

    fn epsl() -> Epsl {
        Epsl::new(Arc::new(LineageStore::new()), EpslConfig::default())
    }
    fn h(s: &str) -> VertexHash { sha256(s.as_bytes()) }

    #[test]
    fn keccak_reference_vectors() {
        assert_eq!(hex::encode(keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
        assert_eq!(hex::encode(keccak256(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
    }

    #[test]
    fn proof_valid_all_sizes() {
        for n in [1usize, 2, 3, 4, 7, 8, 15, 16, 17, 100, 512] {
            let leaves: Vec<_> = (0..n).map(|i| h(&i.to_string())).collect();
            let tree = MerkleTree::from_leaves(&leaves);
            for idx in 0..n {
                assert!(tree.proof(idx).unwrap().verify(), "n={n} idx={idx}");
            }
        }
    }

    #[test]
    fn tampered_proof_rejected() {
        let leaves: Vec<_> = (0..8).map(|i| h(&i.to_string())).collect();
        let mut p = MerkleTree::from_leaves(&leaves).proof(0).unwrap();
        p.leaf[0] ^= 0xFF;
        assert!(!p.verify());
    }

    #[test]
    fn insert_and_query_bl() {
        let e = epsl();
        let src = h("oracle:ETH:2000");
        let tgt = h("decision:buy");
        e.insert(&[src], &[tgt], 0, 1);
        let res = e.query_bl(&tgt, None, 1);
        assert!(res.hashes.contains(&tgt) && res.hashes.contains(&src));
        assert_eq!(e.node_count(), 2);
    }

    #[test]
    fn proof_verifies_against_sealed_root() {
        let e = epsl();
        let src = h("oracle"); let tgt = h("decision");
        e.insert(&[src], &[tgt], 0, 0);
        let root = e.commit_epoch(0);
        let res  = e.query_bl(&tgt, None, 1);
        let p    = res.proof.expect("proof");
        assert!(p.sealed);
        assert_eq!(p.root, root.merkle_root);
        assert!(p.verify(&root.merkle_root));
    }

    #[test]
    fn tampered_record_rejected() {
        let e = epsl();
        let s = h("s"); let t = h("t");
        e.insert(&[s], &[t], 0, 0);
        let root = e.commit_epoch(0).merkle_root;
        let mut p = e.query_bl(&t, None, 1).proof.unwrap();
        assert!(p.verify(&root));
        p.records[0].bwd.clear();          // claim t has no ancestors
        assert!(!p.verify(&root));
    }

    #[test]
    fn suppressed_ancestor_rejected() {
        let e = epsl();
        let a = h("a"); let b = h("b"); let c = h("c");
        e.insert(&[a], &[b], 0, 0);
        e.insert(&[b], &[c], 0, 0);
        let root = e.commit_epoch(0).merkle_root;
        let mut p = e.query_bl(&c, None, 1).proof.unwrap();
        assert!(p.verify(&root));
        let keep: Vec<usize> = p.records.iter().enumerate()
            .filter(|(_, r)| r.hash != a).map(|(i, _)| i).collect();
        p.records = keep.iter().map(|&i| p.records[i].clone()).collect();
        p.paths   = keep.iter().map(|&i| p.paths[i].clone()).collect();
        assert!(!p.verify(&root));
    }

    #[test]
    fn dag_merge_deduplicates() {
        let e = epsl();
        let src = h("oracle"); let tgt = h("shared-data");
        e.insert(&[src], &[tgt], 0, 1);
        e.insert(&[src], &[tgt], 0, 2);
        assert_eq!(e.node_count(), 2);
    }

    #[test]
    fn temporal_slice_pinned_and_excludes_later() {
        let e = epsl();
        let old = h("old-data");
        e.insert(&[], &[old], 0, 0);
        let root0 = e.commit_epoch(0).merkle_root;
        let newer = h("new-data");
        e.insert(&[old], &[newer], 5, 0);
        let _root5 = e.commit_epoch(5).merkle_root;
        let res = e.query_ts(&old, 0, 1);
        assert!(!res.hashes.contains(&newer));
        let p = res.proof.unwrap();
        assert!(p.sealed && p.verify(&root0));
    }

    #[test]
    fn equivocation_leaves_differ() {
        let v = h("v"); let s1 = h("s1"); let s2 = h("s2");
        let base = EpslNode { hash: v, level: 0, epoch: 0,
            backward: BTreeMap::new(), forward: BTreeMap::new(),
            branch_ids: vec![] };
        let mut n1 = base.clone();
        let mut n2 = base;
        n1.backward.insert(s1, 0);
        n2.backward.insert(s2, 0);
        let r1 = n1.record_as_of(0); let r2 = n2.record_as_of(0);
        assert_ne!(r1.digest(), r2.digest());
        assert_ne!(r1.leaf(), r2.leaf());
    }

    #[test]
    fn level_assignment_bounded() {
        for i in 0u64..500 {
            let lv = Epsl::assign_level(&sha256(&i.to_be_bytes()), 23);
            assert!(lv <= 23);
        }
    }
}
