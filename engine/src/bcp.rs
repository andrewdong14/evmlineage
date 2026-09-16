// src/bcp.rs — Branch Commit Protocol (BCP) orchestrator
//
// Five phases per agent decision step (paper Algorithm 3):
//   Phase 1 — Speculative write: ALL beta branches -> off-chain
//             LineageStore only (no EPSL, no chain).
//   Phase 2 — Policy scoring: winner = arg max Score(B, P).
//   Phase 3 — EPSL insertion of the WINNING branch's staged events.
//   Phase 4 — Epoch batch accumulation; when |batch| >= w, seal the
//             epoch, submit the blob, commitRoot(state_root, e, blob).
//   Phase 5 — Prune losers: 96-byte PruneLog entries + GC of
//             branch-exclusive vertices.
//
// E[T_commit] = (w − r) / mu + t_f   (paper Theorem 5)

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};

use crate::{sha256, keccak256, hash_pair};
use crate::store::{LineageStore, Vertex, VertexType, VertexHash, Epoch, BranchId};
use crate::epsl::{Epsl, MerkleTree, MerkleProof};
use crate::blob::BlobPipeline;

// ── Branch ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Branch {
    pub id:           BranchId,
    pub epoch:        Epoch,
    pub score:        f64,
    pub event_hashes: Vec<VertexHash>,
    pub is_winner:    bool,
}

impl Branch {
    pub fn new(id: BranchId, epoch: Epoch) -> Self {
        Branch { id, epoch, score: 0.0, event_hashes: Vec::new(), is_winner: false }
    }

    /// Content hash of the branch: id + sorted event hashes
    /// (byte-identical to Python Branch.branch_hash).
    pub fn branch_hash(&self) -> VertexHash {
        let mut sorted = self.event_hashes.clone();
        sorted.sort();
        let mut buf = Vec::with_capacity(8 + 32 * sorted.len());
        buf.extend_from_slice(&self.id.to_be_bytes());
        for h in &sorted { buf.extend_from_slice(h); }
        sha256(&buf)
    }
}

// ── CommitResult ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitResult {
    pub epoch:        Epoch,
    pub merkle_root:  VertexHash,   // EPSL state root anchored on-chain
    pub blob_hash:    VertexHash,
    pub event_count:  u32,
}

// ── InMemoryAnchor — test double for LineageAnchor.sol ────────────────────────

#[derive(Default)]
struct AnchorInner {
    roots:  HashMap<Epoch, VertexHash>,
    blobs:  HashMap<Epoch, VertexHash>,
    latest: Option<Epoch>,
}

/// Same semantics as the contract: sequential epochs (Invariant I2), no
/// re-commitment, keccak Merkle verification. Swap for an RPC-backed
/// client in live deployments.
pub struct InMemoryAnchor {
    inner: Mutex<AnchorInner>,
}

impl InMemoryAnchor {
    pub fn new() -> Self { InMemoryAnchor { inner: Mutex::new(AnchorInner::default()) } }

    pub fn commit_root(&self, root: VertexHash, epoch: Epoch,
                       blob_hash: VertexHash) -> Result<(), String> {
        let mut g = self.inner.lock().unwrap();
        if g.roots.contains_key(&epoch) {
            return Err(format!("EpochAlreadyCommitted({epoch})"));
        }
        if let Some(latest) = g.latest {
            if epoch != latest + 1 {
                return Err(format!("EpochOutOfOrder(expected {}, got {epoch})", latest + 1));
            }
        }
        g.roots.insert(epoch, root);
        g.blobs.insert(epoch, blob_hash);
        g.latest = Some(epoch);
        Ok(())
    }

    pub fn epoch_root(&self, epoch: Epoch) -> Option<VertexHash> {
        self.inner.lock().unwrap().roots.get(&epoch).copied()
    }
    pub fn epoch_blob_hash(&self, epoch: Epoch) -> Option<VertexHash> {
        self.inner.lock().unwrap().blobs.get(&epoch).copied()
    }
    pub fn latest_epoch(&self) -> Option<Epoch> {
        self.inner.lock().unwrap().latest
    }

    /// Mirror of LineageAnchor.verifyProof (keccak sorted-pair loop).
    pub fn verify_proof(&self, leaf: VertexHash, path: &[VertexHash],
                        epoch: Epoch) -> bool {
        let root = match self.epoch_root(epoch) { Some(r) => r, None => return false };
        let mut node = leaf;
        for &sib in path { node = hash_pair(node, sib); }
        node == root
    }
}

impl Default for InMemoryAnchor {
    fn default() -> Self { Self::new() }
}

// ── PruneLog — 96-byte discarded-branch records (paper Sect. 6.4) ─────────────

pub const PRUNE_ENTRY_BYTES: usize = 96;
pub const PRUNE_BATCH_DEFAULT: usize = 4096;   // M

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PruneLogEntry {
    pub branch_id:   BranchId,
    pub branch_hash: VertexHash,
    pub epoch:       Epoch,
    pub ts_ms:       u64,
}

impl PruneLogEntry {
    /// 96-byte wire format: sha256(branch_id)(32) | branch_hash(32) |
    /// epoch(8) | ts(8) | reserved(16) — identical to the Python layer.
    pub fn pack(&self) -> [u8; PRUNE_ENTRY_BYTES] {
        let mut out = [0u8; PRUNE_ENTRY_BYTES];
        out[..32].copy_from_slice(&sha256(&self.branch_id.to_be_bytes()));
        out[32..64].copy_from_slice(&self.branch_hash);
        out[64..72].copy_from_slice(&self.epoch.to_be_bytes());
        out[72..80].copy_from_slice(&self.ts_ms.to_be_bytes());
        out
    }

    pub fn leaf(&self) -> VertexHash { keccak256(&self.pack()) }
}

#[derive(Default)]
struct PruneLogInner {
    entries: Vec<PruneLogEntry>,
    roots:   Vec<VertexHash>,
}

/// Tamper-evident record of discarded speculative branches, Merkle-
/// anchored every `batch_size` entries. An auditor can prove a branch
/// *was considered* without its content ever reaching the chain.
pub struct PruneLog {
    batch_size: usize,
    inner:      Mutex<PruneLogInner>,
}

impl PruneLog {
    pub fn new(batch_size: usize) -> Self {
        PruneLog { batch_size, inner: Mutex::new(PruneLogInner::default()) }
    }

    pub fn append(&self, entry: PruneLogEntry) {
        let mut g = self.inner.lock().unwrap();
        g.entries.push(entry);
        if g.entries.len() % self.batch_size == 0 {
            let lo = g.entries.len() - self.batch_size;
            let leaves: Vec<VertexHash> =
                g.entries[lo..].iter().map(|e| e.leaf()).collect();
            g.roots.push(MerkleTree::from_leaves(&leaves).root());
        }
    }

    /// Anchor any unanchored tail (operator-defined cadence).
    pub fn flush(&self) -> Option<VertexHash> {
        let mut g = self.inner.lock().unwrap();
        let done = g.roots.len() * self.batch_size;
        if g.entries.len() <= done { return None; }
        let leaves: Vec<VertexHash> =
            g.entries[done..].iter().map(|e| e.leaf()).collect();
        let root = MerkleTree::from_leaves(&leaves).root();
        g.roots.push(root);
        Some(root)
    }

    /// Membership proof for a discarded branch (auditor query).
    pub fn membership_proof(&self, branch_hash: &VertexHash) -> Option<MerkleProof> {
        let g = self.inner.lock().unwrap();
        for batch_i in 0..g.roots.len() {
            let lo = batch_i * self.batch_size;
            let hi = (lo + self.batch_size).min(g.entries.len());
            let batch = &g.entries[lo..hi];
            if let Some(j) = batch.iter().position(|e| &e.branch_hash == branch_hash) {
                let leaves: Vec<VertexHash> = batch.iter().map(|e| e.leaf()).collect();
                return MerkleTree::from_leaves(&leaves).proof(j);
            }
        }
        None
    }

    pub fn contains(&self, branch_hash: &VertexHash) -> bool {
        self.inner.lock().unwrap()
            .entries.iter().any(|e| &e.branch_hash == branch_hash)
    }
    pub fn len(&self) -> usize { self.inner.lock().unwrap().entries.len() }
    pub fn is_empty(&self) -> bool { self.len() == 0 }
    pub fn anchored_roots(&self) -> Vec<VertexHash> {
        self.inner.lock().unwrap().roots.clone()
    }
}

// ── BcpConfig ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BcpConfig {
    pub epoch_size:  u64,     // w = 512
    pub finality_s:  f64,     // Arbitrum ≈ 1 s
    pub arrival_hz:  f64,     // mu = event arrival rate
    pub prune_batch: usize,   // M = 4096
}

impl Default for BcpConfig {
    fn default() -> Self {
        BcpConfig { epoch_size: 512, finality_s: 1.0, arrival_hz: 100.0,
                    prune_batch: PRUNE_BATCH_DEFAULT }
    }
}

// ── Bcp ───────────────────────────────────────────────────────────────────────

type StagedEvent = (Vec<VertexHash>, Vec<VertexHash>);   // (sources, targets)

pub struct Bcp {
    epsl:      Arc<Epsl>,
    store:     Arc<LineageStore>,
    blob:      Arc<BlobPipeline>,
    pub anchor:    Arc<InMemoryAnchor>,
    pub prune_log: Arc<PruneLog>,
    cfg:       BcpConfig,
    batch:     Mutex<Vec<VertexHash>>,
    epoch:     Mutex<Epoch>,
    results:   Mutex<Vec<CommitResult>>,
    pending:   Mutex<HashMap<BranchId, Vec<StagedEvent>>>,
}

impl Bcp {
    pub fn new(epsl: Arc<Epsl>, store: Arc<LineageStore>,
               blob: Arc<BlobPipeline>, cfg: BcpConfig) -> Self {
        let prune_batch = cfg.prune_batch;
        Bcp { epsl, store, blob,
              anchor:    Arc::new(InMemoryAnchor::new()),
              prune_log: Arc::new(PruneLog::new(prune_batch)),
              cfg,
              batch:   Mutex::new(Vec::new()),
              epoch:   Mutex::new(0),
              results: Mutex::new(Vec::new()),
              pending: Mutex::new(HashMap::new()) }
    }

    // ── Phase 1: speculative off-chain write ─────────────────────────────

    /// WriteOff: stage a speculative event in the LineageStore only; the
    /// EPSL and chain are untouched until the branch wins (Phase 3).
    pub fn phase1_write(&self, sources: &[VertexHash], targets: &[VertexHash],
                        branch_id: BranchId) -> Vec<VertexHash>
    {
        let epoch = self.current_epoch();
        for h in sources.iter().chain(targets.iter()) {
            let mut v = Vertex::new(Vec::new(), VertexType::Other,
                                    epoch, [0u8; 32], branch_id);
            v.hash = *h;                       // pre-hashed by the caller
            self.store.put_vertex(v);
        }
        for &src in sources {
            self.store.put_edge(src, epoch, targets);
        }
        self.pending.lock().unwrap()
            .entry(branch_id).or_default()
            .push((sources.to_vec(), targets.to_vec()));
        let mut all = sources.to_vec();
        all.extend_from_slice(targets);
        all
    }

    /// Non-speculative write path (beta = 1): store + EPSL + batch in one
    /// step. Used by services/hooks that do not manage explicit branches.
    pub fn write_direct(&self, sources: &[VertexHash], targets: &[VertexHash],
                        branch_id: BranchId) -> (Vec<VertexHash>, Option<CommitResult>)
    {
        let hashes = self.phase1_write(sources, targets, branch_id);
        let events = self.pending.lock().unwrap().remove(&branch_id)
            .unwrap_or_default();
        let commit = self.insert_and_accumulate(&events);
        (hashes, commit)
    }

    // ── Phase 2: policy scoring ──────────────────────────────────────────

    pub fn phase2_select_winner<F>(branches: &mut Vec<Branch>, scorer: F) -> BranchId
    where F: Fn(&Branch) -> f64
    {
        for b in branches.iter_mut() { b.score = scorer(b); }
        let winner = branches.iter()
            .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap())
            .map(|b| b.id)
            .unwrap_or(0);
        for b in branches.iter_mut() { b.is_winner = b.id == winner; }
        winner
    }

    // ── Phases 3 + 4: EPSL insertion + epoch accumulation ────────────────

    /// Insert the winning branch's staged events into the EPSL and
    /// accumulate them; commit when |batch| >= w.
    pub fn phase3_accumulate(&self, winner: &Branch) -> Option<CommitResult> {
        let mut events = self.pending.lock().unwrap()
            .remove(&winner.id).unwrap_or_default();
        if events.is_empty() && !winner.event_hashes.is_empty() {
            // Synthetic benchmark branch: treat hashes as source-less events.
            events.push((Vec::new(), winner.event_hashes.clone()));
        }
        self.insert_and_accumulate(&events)
    }

    fn insert_and_accumulate(&self, events: &[StagedEvent]) -> Option<CommitResult> {
        let epoch = self.current_epoch();
        let mut leaves = Vec::with_capacity(events.len());
        for (sources, targets) in events {
            self.epsl.insert(sources, targets, epoch, 0);
            let mut s = sources.clone(); s.sort();
            let mut t = targets.clone(); t.sort();
            let mut buf = Vec::with_capacity(32 * (s.len() + t.len()) + 1);
            for h in &s { buf.extend_from_slice(h); }
            buf.push(0);
            for h in &t { buf.extend_from_slice(h); }
            leaves.push(sha256(&buf));
        }
        let commit_args = {
            let mut batch = self.batch.lock().unwrap();
            batch.extend_from_slice(&leaves);
            if batch.len() as u64 >= self.cfg.epoch_size {
                let e = {
                    let mut ep = self.epoch.lock().unwrap();
                    let v = *ep; *ep += 1; v
                };
                Some((e, batch.drain(..).collect::<Vec<_>>()))
            } else { None }
        };
        commit_args.map(|(e, ev)| self.do_commit(e, ev))
    }

    /// Force-seal the current epoch (epoch-end timer path).
    pub fn flush_epoch(&self) -> Option<CommitResult> {
        let commit_args = {
            let mut batch = self.batch.lock().unwrap();
            if batch.is_empty() { return None; }
            let e = {
                let mut ep = self.epoch.lock().unwrap();
                let v = *ep; *ep += 1; v
            };
            (e, batch.drain(..).collect::<Vec<_>>())
        };
        Some(self.do_commit(commit_args.0, commit_args.1))
    }

    fn do_commit(&self, epoch: Epoch, events: Vec<VertexHash>) -> CommitResult {
        let root      = self.epsl.commit_epoch(epoch);           // I1
        let blob_hash = self.blob.submit_sync(&root, &events);
        self.anchor.commit_root(root.merkle_root, epoch, blob_hash)
            .expect("anchor rejected commit (Invariant I2 violated)");
        let result = CommitResult {
            epoch,
            merkle_root: root.merkle_root,
            blob_hash,
            event_count: events.len() as u32,
        };
        self.results.lock().unwrap().push(result.clone());
        result
    }

    // ── Phase 5: prune losers ────────────────────────────────────────────

    /// Append 96-byte PruneLog entries for the losing branches and GC
    /// their branch-exclusive vertices (shared vertices retained by the
    /// DAG-merge branch mask).
    pub fn phase5_prune(&self, branches: &mut [Branch], winner_id: BranchId) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().as_millis() as u64;
        for b in branches.iter_mut() {
            if b.id == winner_id { continue; }
            let staged = self.pending.lock().unwrap()
                .remove(&b.id).unwrap_or_default();
            if b.event_hashes.is_empty() && !staged.is_empty() {
                for (s, t) in &staged {
                    b.event_hashes.extend_from_slice(s);
                    b.event_hashes.extend_from_slice(t);
                }
            }
            self.prune_log.append(PruneLogEntry {
                branch_id: b.id, branch_hash: b.branch_hash(),
                epoch: self.current_epoch(), ts_ms: now,
            });
            let loser_bit = 1u64 << (b.id & 63);
            for (_, targets) in &staged {
                for h in targets {
                    if let Some(v) = self.store.get_vertex(h) {
                        if v.branch_mask & !loser_bit == 0 {
                            self.store.remove_vertex(h);
                        }
                    }
                }
            }
        }
    }

    // ── Metrics ──────────────────────────────────────────────────────────

    /// E[T_commit] = (w − r) / mu + t_f (paper Theorem 5).
    pub fn expected_commit_latency_s(&self) -> f64 {
        let r = self.batch.lock().unwrap().len() as f64;
        (self.cfg.epoch_size as f64 - r).max(0.0) / self.cfg.arrival_hz
            + self.cfg.finality_s
    }

    pub fn current_epoch(&self)    -> Epoch { *self.epoch.lock().unwrap() }
    pub fn batch_fill(&self)       -> usize { self.batch.lock().unwrap().len() }
    pub fn committed_epochs(&self) -> usize { self.results.lock().unwrap().len() }
    pub fn total_pruned(&self)     -> usize { self.prune_log.len() }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — run with `cargo test` (not runnable in the authoring sandbox;
// verify locally before release)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sha256, epsl::EpslConfig};

    fn make_bcp(epoch_size: u64) -> Bcp {
        let store = Arc::new(LineageStore::new());
        let epsl  = Arc::new(Epsl::new(Arc::clone(&store), EpslConfig::default()));
        let blob  = Arc::new(BlobPipeline::new_dry());
        Bcp::new(epsl, store, blob,
                 BcpConfig { epoch_size, ..Default::default() })
    }

    #[test]
    fn speculative_writes_skip_epsl_until_phase3() {
        let store = Arc::new(LineageStore::new());
        let epsl  = Arc::new(Epsl::new(Arc::clone(&store), EpslConfig::default()));
        let blob  = Arc::new(BlobPipeline::new_dry());
        let bcp   = Bcp::new(Arc::clone(&epsl), Arc::clone(&store), blob,
                             BcpConfig { epoch_size: 512, ..Default::default() });
        let shared = sha256(b"oracle-shared");
        let win    = sha256(b"win");
        let lose   = sha256(b"lose");
        let mut b1 = Branch::new(1, 0);
        let mut b2 = Branch::new(2, 0);
        b1.event_hashes = bcp.phase1_write(&[shared], &[win],  1);
        b2.event_hashes = bcp.phase1_write(&[shared], &[lose], 2);
        assert_eq!(epsl.node_count(), 0);                 // Phase 1: store only
        assert_eq!(store.vertex_count(), 3);
        let mut branches = vec![b1.clone(), b2.clone()];
        let wid = Bcp::phase2_select_winner(&mut branches, |b| -(b.id as f64));
        assert_eq!(wid, 1);
        bcp.phase3_accumulate(&branches[0]);
        assert_eq!(epsl.node_count(), 2);                 // shared + win
        bcp.phase5_prune(&mut branches, wid);
        assert_eq!(bcp.total_pruned(), 1);
        assert!(bcp.prune_log.contains(&branches[1].branch_hash()));
        assert!(bcp.store.get_vertex(&lose).is_none());   // GC'd
        assert!(bcp.store.get_vertex(&shared).is_some()); // retained
    }

    #[test]
    fn commit_anchors_state_root_i1_i2() {
        let bcp = make_bcp(2);
        let (_, c1) = bcp.write_direct(&[sha256(b"a")], &[sha256(b"b")], 0);
        assert!(c1.is_none());
        let (_, c2) = bcp.write_direct(&[sha256(b"b")], &[sha256(b"c")], 0);
        let commit = c2.expect("epoch should seal at w=2");
        assert_eq!(commit.epoch, 0);
        assert_eq!(bcp.anchor.epoch_root(0), Some(commit.merkle_root));
        assert_eq!(bcp.anchor.latest_epoch(), Some(0));
    }

    #[test]
    fn anchor_rejects_out_of_order_and_recommit() {
        let a = InMemoryAnchor::new();
        a.commit_root(sha256(b"r0"), 0, sha256(b"b0")).unwrap();
        assert!(a.commit_root(sha256(b"r2"), 2, sha256(b"b2")).is_err());
        assert!(a.commit_root(sha256(b"rx"), 0, sha256(b"bx")).is_err());
        a.commit_root(sha256(b"r1"), 1, sha256(b"b1")).unwrap();
        assert_eq!(a.latest_epoch(), Some(1));
    }

    #[test]
    fn prune_log_entry_is_96_bytes_with_membership() {
        let log = PruneLog::new(4);
        let mut hashes = Vec::new();
        for i in 0..4u64 {
            let bh = sha256(format!("branch-{i}").as_bytes());
            hashes.push(bh);
            let e = PruneLogEntry { branch_id: i, branch_hash: bh,
                                    epoch: 0, ts_ms: 0 };
            assert_eq!(e.pack().len(), PRUNE_ENTRY_BYTES);
            log.append(e);
        }
        assert_eq!(log.anchored_roots().len(), 1);
        let mp = log.membership_proof(&hashes[2]).expect("member");
        assert!(mp.verify());
        assert_eq!(mp.root, log.anchored_roots()[0]);
        assert!(log.membership_proof(&sha256(b"never")).is_none());
    }

    #[test]
    fn expected_commit_latency_formula() {
        let bcp = make_bcp(512);
        let t = bcp.expected_commit_latency_s();
        assert!((t - 6.12).abs() < 0.01, "E[T]={t:.3}");
    }
}
