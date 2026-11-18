// src/bcp.rs — Branch Commit Protocol (paper Sect. 6, Algorithm 3)
//
// Five phases per agent decision step:
//   Phase 1 — Speculative write: ALL beta branches -> LineageStore only.
//   Phase 2 — Policy scoring: winner = arg max Score(B, P).
//   Phase 3 — The WINNING branch's events enter the EPSL (open epoch).
//   Phase 4 — Epoch batching: when the batch holds w events (or on flush),
//             seal the epoch, publish its payload, commitRoot(root, e, data).
//   Phase 5 — Prune the losers: one 96-byte PruneLog entry each, garbage
//             collection of the vertices only they referenced.
//
// Indexing, batching and sealing run under one lock, and the epoch counter
// belongs to the EPSL, so an event can never be tagged with an epoch that
// has already been sealed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::blob::{BlobPipeline, Event};
use crate::epsl::Epsl;
use crate::merkle::{MerkleProof, MerkleTree};
use crate::store::{BranchId, Epoch, LineageStore, Vertex, VertexHash, VertexType};
use crate::{hash_pair, keccak256, sha256};

// ── Branch ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
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

    /// Content hash of the branch: id + sorted vertex hashes
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

#[derive(Debug, Clone)]
pub struct CommitResult {
    pub epoch:         Epoch,
    pub root:          VertexHash,   // EPSL root anchored on-chain
    pub data_hash:     VertexHash,   // commitment to the epoch payload
    pub event_count:   u32,
    pub payload_bytes: usize,
    pub blobs:         usize,
}

// ── InMemoryAnchor — test double for LineageAnchor.sol ────────────────────────

#[derive(Default)]
struct AnchorInner {
    roots:  HashMap<Epoch, VertexHash>,
    data:   HashMap<Epoch, VertexHash>,
    prune:  Vec<VertexHash>,
    latest: Option<Epoch>,
}

/// Same rules as the contract: epochs are committed in sequence and never
/// overwritten (Invariant I2), prune-log batch roots likewise, and proofs
/// are verified by the sorted-pair keccak fold.
#[derive(Default)]
pub struct InMemoryAnchor {
    inner: Mutex<AnchorInner>,
}

impl InMemoryAnchor {
    pub fn new() -> Self { Self::default() }

    pub fn commit_root(&self, root: VertexHash, epoch: Epoch,
                       data_hash: VertexHash) -> Result<(), String> {
        let mut g = self.inner.lock().unwrap();
        if root == [0u8; 32] { return Err("ZeroRoot".into()); }
        if data_hash == [0u8; 32] { return Err("InvalidDataHash".into()); }
        if g.roots.contains_key(&epoch) {
            return Err(format!("EpochAlreadyCommitted({epoch})"));
        }
        if let Some(latest) = g.latest {
            if epoch != latest + 1 {
                return Err(format!("EpochOutOfOrder(expected {}, got {epoch})", latest + 1));
            }
        }
        g.roots.insert(epoch, root);
        g.data.insert(epoch, data_hash);
        g.latest = Some(epoch);
        Ok(())
    }

    pub fn epoch_root(&self, epoch: Epoch) -> Option<VertexHash> {
        self.inner.lock().unwrap().roots.get(&epoch).copied()
    }
    pub fn epoch_data_hash(&self, epoch: Epoch) -> Option<VertexHash> {
        self.inner.lock().unwrap().data.get(&epoch).copied()
    }
    pub fn latest_epoch(&self) -> Option<Epoch> { self.inner.lock().unwrap().latest }

    /// Mirror of LineageAnchor.verifyProof.
    pub fn verify_proof(&self, leaf: VertexHash, path: &[VertexHash], epoch: Epoch) -> bool {
        match self.epoch_root(epoch) {
            Some(root) => path.iter().fold(leaf, |n, s| hash_pair(&n, s)) == root,
            None => false,
        }
    }

    pub fn commit_prune_root(&self, index: usize, root: VertexHash) -> Result<(), String> {
        let mut g = self.inner.lock().unwrap();
        if index != g.prune.len() {
            return Err(format!("PruneBatchOutOfOrder(expected {}, got {index})", g.prune.len()));
        }
        g.prune.push(root);
        Ok(())
    }

    pub fn prune_root(&self, index: usize) -> Option<VertexHash> {
        self.inner.lock().unwrap().prune.get(index).copied()
    }

    pub fn verify_prune_proof(&self, leaf: VertexHash, path: &[VertexHash], index: usize) -> bool {
        match self.prune_root(index) {
            Some(root) => path.iter().fold(leaf, |n, s| hash_pair(&n, s)) == root,
            None => false,
        }
    }
}

// ── PruneLog — 96-byte records of discarded branches (paper Sect. 6.2) ────────

pub const PRUNE_ENTRY_BYTES: usize = 96;
pub const PRUNE_BATCH_DEFAULT: usize = 4096;   // M

#[derive(Debug, Clone)]
pub struct PruneLogEntry {
    pub branch_id:   BranchId,
    pub branch_hash: VertexHash,
    pub epoch:       Epoch,
    pub ts_ms:       u64,
}

impl PruneLogEntry {
    /// 96-byte wire format: sha256(branch id) | branch hash | epoch (8) |
    /// time (8) | reserved (16) — identical to the Python layer.
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
    batches: Vec<(usize, usize)>,     // [lo, hi) per closed batch
    roots:   Vec<VertexHash>,
}

impl PruneLogInner {
    fn done(&self) -> usize { self.batches.last().map(|b| b.1).unwrap_or(0) }

    fn close(&mut self, lo: usize, hi: usize) -> (usize, VertexHash) {
        let leaves: Vec<VertexHash> = self.entries[lo..hi].iter().map(|e| e.leaf()).collect();
        let root = MerkleTree::from_leaves(&leaves).root();
        self.batches.push((lo, hi));
        self.roots.push(root);
        (self.roots.len() - 1, root)
    }
}

/// Tamper-evident record of discarded speculative branches. Entries are
/// grouped into batches of `batch_size`; when a batch closes, `append`
/// returns (batch index, Merkle root) for anchoring.
pub struct PruneLog {
    batch_size: usize,
    inner:      Mutex<PruneLogInner>,
}

impl PruneLog {
    pub fn new(batch_size: usize) -> Self {
        PruneLog { batch_size, inner: Mutex::new(PruneLogInner::default()) }
    }

    pub fn append(&self, entry: PruneLogEntry) -> Option<(usize, VertexHash)> {
        let mut g = self.inner.lock().unwrap();
        g.entries.push(entry);
        let (done, len) = (g.done(), g.entries.len());
        if len - done == self.batch_size { Some(g.close(done, len)) } else { None }
    }

    /// Close the current partial batch (operator-defined cadence).
    pub fn flush(&self) -> Option<(usize, VertexHash)> {
        let mut g = self.inner.lock().unwrap();
        let (done, len) = (g.done(), g.entries.len());
        if len == done { None } else { Some(g.close(done, len)) }
    }

    /// (batch index, proof) for a discarded branch; None if it is unknown
    /// or its batch is still open.
    pub fn membership(&self, branch_hash: &VertexHash) -> Option<(usize, MerkleProof)> {
        let g = self.inner.lock().unwrap();
        for (bi, &(lo, hi)) in g.batches.iter().enumerate() {
            if let Some(j) = g.entries[lo..hi].iter().position(|e| &e.branch_hash == branch_hash) {
                let leaves: Vec<VertexHash> = g.entries[lo..hi].iter().map(|e| e.leaf()).collect();
                return MerkleTree::from_leaves(&leaves).proof(j).map(|p| (bi, p));
            }
        }
        None
    }

    pub fn contains(&self, branch_hash: &VertexHash) -> bool {
        self.inner.lock().unwrap().entries.iter().any(|e| &e.branch_hash == branch_hash)
    }
    pub fn len(&self) -> usize { self.inner.lock().unwrap().entries.len() }
    pub fn is_empty(&self) -> bool { self.len() == 0 }
    pub fn anchored_roots(&self) -> Vec<VertexHash> { self.inner.lock().unwrap().roots.clone() }
}

// ── Bcp ───────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BcpConfig {
    pub epoch_size:  usize,   // w
    pub finality_s:  f64,     // t_inc
    pub arrival_hz:  f64,     // mu
    pub prune_batch: usize,   // M
}

impl Default for BcpConfig {
    fn default() -> Self {
        BcpConfig { epoch_size: 512, finality_s: 1.0, arrival_hz: 100.0,
                    prune_batch: PRUNE_BATCH_DEFAULT }
    }
}

#[derive(Default)]
struct BcpState {
    batch:   Vec<Event>,
    commits: Vec<CommitResult>,
    pending: HashMap<BranchId, Vec<Event>>,
}

pub struct Bcp {
    epsl:          Arc<Epsl>,
    store:         Arc<LineageStore>,
    blob:          Arc<BlobPipeline>,
    pub anchor:    Arc<InMemoryAnchor>,
    pub prune_log: Arc<PruneLog>,
    cfg:           BcpConfig,
    state:         Mutex<BcpState>,
}

impl Bcp {
    pub fn new(epsl: Arc<Epsl>, store: Arc<LineageStore>,
               blob: Arc<BlobPipeline>, cfg: BcpConfig) -> Self {
        assert!(cfg.epoch_size >= 1, "epoch_size must be positive");
        let prune_batch = cfg.prune_batch;
        Bcp { epsl, store, blob,
              anchor:    Arc::new(InMemoryAnchor::new()),
              prune_log: Arc::new(PruneLog::new(prune_batch)),
              cfg,
              state: Mutex::new(BcpState::default()) }
    }

    pub fn store(&self) -> &Arc<LineageStore> { &self.store }

    // ── Phase 1: speculative off-chain write ─────────────────────────────

    /// Stage a speculative event: vertices and edges go to the
    /// LineageStore only. Returns the event's vertex hashes.
    pub fn phase1_write(&self, sources: &[VertexHash], targets: &[VertexHash],
                        branch_id: BranchId) -> Vec<VertexHash> {
        let epoch = self.current_epoch();
        for h in sources.iter().chain(targets.iter()) {
            let mut v = Vertex::new(Vec::new(), VertexType::Other, epoch, [0u8; 32], branch_id);
            v.hash = *h;                       // pre-hashed by the caller
            self.store.put_vertex(v);
        }
        for src in sources {
            self.store.put_edge(*src, epoch, targets);
        }
        self.state.lock().unwrap()
            .pending.entry(branch_id).or_default()
            .push((sources.to_vec(), targets.to_vec()));
        let mut all = sources.to_vec();
        all.extend_from_slice(targets);
        all
    }

    /// Non-speculative write (beta = 1): store, index and batch in one step.
    pub fn write_direct(&self, sources: &[VertexHash], targets: &[VertexHash],
                        branch_id: BranchId) -> (Vec<VertexHash>, Option<CommitResult>) {
        let hashes = self.phase1_write(sources, targets, branch_id);
        let mut st = self.state.lock().unwrap();
        let events = st.pending.remove(&branch_id).unwrap_or_default();
        let commit = self.insert_and_accumulate(&mut st, events);
        (hashes, commit)
    }

    // ── Phase 2: policy scoring ──────────────────────────────────────────

    pub fn phase2_select_winner<F>(branches: &mut [Branch], scorer: F) -> BranchId
    where F: Fn(&Branch) -> f64 {
        for b in branches.iter_mut() { b.score = scorer(b); }
        let winner = branches.iter()
            .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal))
            .map(|b| b.id)
            .unwrap_or(0);
        for b in branches.iter_mut() { b.is_winner = b.id == winner; }
        winner
    }

    // ── Phases 3 + 4: index the winner, batch, commit ────────────────────

    /// Index the winning branch's staged events and add them to the epoch
    /// batch; commits when the batch reaches w events.
    pub fn phase3_accumulate(&self, winner: &Branch) -> Option<CommitResult> {
        let mut st = self.state.lock().unwrap();
        let mut events = st.pending.remove(&winner.id).unwrap_or_default();
        if events.is_empty() && !winner.event_hashes.is_empty() {
            // Nothing staged through phase1_write (synthetic benchmark
            // branches): record the hashes as source-less.
            events.push((Vec::new(), winner.event_hashes.clone()));
        }
        self.insert_and_accumulate(&mut st, events)
    }

    fn insert_and_accumulate(&self, st: &mut BcpState, events: Vec<Event>) -> Option<CommitResult> {
        let mut commit = None;
        for (sources, targets) in events {
            self.epsl.insert(&sources, &targets);
            st.batch.push((sources, targets));
            if st.batch.len() >= self.cfg.epoch_size {
                commit = Some(self.commit_locked(st));
            }
        }
        commit
    }

    /// Seal and commit the open epoch now (epoch-timer path).
    pub fn flush_epoch(&self) -> Option<CommitResult> {
        let mut st = self.state.lock().unwrap();
        if st.batch.is_empty() { return None; }
        Some(self.commit_locked(&mut st))
    }

    fn commit_locked(&self, st: &mut BcpState) -> CommitResult {
        let events = std::mem::take(&mut st.batch);
        let er  = self.epsl.seal();                                    // I1
        let sub = self.blob.submit(&er, &events);
        self.anchor.commit_root(er.root, er.epoch, sub.data_hash)
            .expect("anchor rejected the commit (Invariant I2 violated)");
        let result = CommitResult {
            epoch: er.epoch, root: er.root, data_hash: sub.data_hash,
            event_count: events.len() as u32, payload_bytes: sub.bytes, blobs: sub.blobs,
        };
        st.commits.push(result.clone());
        result
    }

    // ── Phase 5: prune losers ────────────────────────────────────────────

    /// Log every losing branch in the PruneLog and garbage-collect the
    /// vertices that only it referenced.
    pub fn phase5_prune(&self, branches: &mut [Branch], winner_id: BranchId) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().as_millis() as u64;
        for b in branches.iter_mut() {
            if b.id == winner_id { continue; }
            let staged = self.state.lock().unwrap().pending.remove(&b.id).unwrap_or_default();
            if b.event_hashes.is_empty() && !staged.is_empty() {
                for (s, t) in &staged {
                    b.event_hashes.extend_from_slice(s);
                    b.event_hashes.extend_from_slice(t);
                }
            }
            let closed = self.prune_log.append(PruneLogEntry {
                branch_id: b.id, branch_hash: b.branch_hash(),
                epoch: self.current_epoch(), ts_ms: now,
            });
            if let Some((index, root)) = closed {
                self.anchor.commit_prune_root(index, root)
                    .expect("anchor rejected the prune-log root");
            }
            let loser_bit = 1u64 << (b.id & 63);
            for (sources, targets) in &staged {
                let mut gone: Vec<VertexHash> = Vec::new();
                for h in targets {
                    if let Some(v) = self.store.get_vertex(h) {
                        if v.branch_mask & !loser_bit == 0 && !self.epsl.has_vertex(h) {
                            self.store.remove_vertex(h);
                            gone.push(*h);
                        }
                    }
                }
                if !gone.is_empty() {
                    for s in sources { self.store.drop_edges(s, &gone); }
                }
            }
        }
    }

    /// Close and anchor the current partial prune-log batch.
    pub fn flush_prune_log(&self) -> Option<(usize, VertexHash)> {
        let closed = self.prune_log.flush();
        if let Some((index, root)) = closed {
            self.anchor.commit_prune_root(index, root)
                .expect("anchor rejected the prune-log root");
        }
        closed
    }

    // ── Metrics ──────────────────────────────────────────────────────────

    /// E[T_commit] = (w - j) / mu + t_inc (paper Eq. 5).
    pub fn expected_commit_latency_s(&self) -> f64 {
        let j = self.state.lock().unwrap().batch.len() as f64;
        (self.cfg.epoch_size as f64 - j).max(0.0) / self.cfg.arrival_hz + self.cfg.finality_s
    }

    pub fn current_epoch(&self)    -> Epoch { self.epsl.current_epoch() }
    pub fn batch_fill(&self)       -> usize { self.state.lock().unwrap().batch.len() }
    pub fn committed_epochs(&self) -> usize { self.state.lock().unwrap().commits.len() }
    pub fn commits(&self) -> Vec<CommitResult> { self.state.lock().unwrap().commits.clone() }
    pub fn total_pruned(&self)     -> usize { self.prune_log.len() }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::{decode_blob, Codec};
    use crate::epsl::EpslConfig;

    fn h(s: &str) -> VertexHash { sha256(s.as_bytes()) }

    fn make(epoch_size: usize, prune_batch: usize) -> (Arc<Epsl>, Arc<BlobPipeline>, Bcp) {
        let store = Arc::new(LineageStore::new());
        let epsl  = Arc::new(Epsl::new(EpslConfig::default()));
        let blob  = Arc::new(BlobPipeline::with(Codec::Raw, true));
        let bcp   = Bcp::new(Arc::clone(&epsl), store, Arc::clone(&blob),
                             BcpConfig { epoch_size, prune_batch, ..Default::default() });
        (epsl, blob, bcp)
    }

    #[test]
    fn only_the_winner_is_indexed_losers_pruned() {
        let (epsl, _, bcp) = make(512, 4096);
        let (shared, win, lose) = (h("oracle-shared"), h("win"), h("lose"));
        let mut b1 = Branch::new(1, 0);
        let mut b2 = Branch::new(2, 0);
        b1.event_hashes = bcp.phase1_write(&[shared], &[win], 1);
        b2.event_hashes = bcp.phase1_write(&[shared], &[lose], 2);
        assert_eq!(epsl.node_count(), 0);                     // Phase 1: store only
        assert_eq!(bcp.store().vertex_count(), 3);
        let mut branches = vec![b1, b2];
        let wid = Bcp::phase2_select_winner(&mut branches, |b| -(b.id as f64));
        assert_eq!(wid, 1);
        bcp.phase3_accumulate(&branches[0]);
        assert_eq!(epsl.node_count(), 2);                     // shared + win
        assert!(!epsl.has_vertex(&lose));
        bcp.phase5_prune(&mut branches, wid);
        assert_eq!(bcp.total_pruned(), 1);
        assert!(bcp.prune_log.contains(&branches[1].branch_hash()));
        assert!(bcp.store().get_vertex(&lose).is_none());     // collected
        assert!(bcp.store().get_vertex(&shared).is_some());   // shared: kept
        assert_eq!(bcp.store().scan_edges(&shared, 0, 9), vec![win]);   // no dangling edge
    }

    #[test]
    fn epoch_commits_when_full_or_flushed() {
        let (epsl, _, bcp) = make(3, 4096);
        let (a, b, c, d) = (h("a"), h("b"), h("c"), h("d"));
        assert!(bcp.write_direct(&[a], &[b], 0).1.is_none());
        assert!(bcp.write_direct(&[b], &[c], 0).1.is_none());
        let cm = bcp.write_direct(&[c], &[d], 0).1.expect("epoch seals at w = 3");
        assert_eq!((cm.epoch, cm.event_count, cm.blobs), (0, 3, 1));
        assert_eq!(bcp.anchor.epoch_root(0), Some(cm.root));                      // I1
        assert_eq!(epsl.get_epoch_root(0).unwrap().root, cm.root);
        assert_eq!(bcp.anchor.epoch_data_hash(0), Some(cm.data_hash));
        assert!(bcp.flush_epoch().is_none());
        bcp.write_direct(&[d], &[h("e")], 0);
        assert_eq!(bcp.flush_epoch().unwrap().epoch, 1);
        assert_eq!(bcp.anchor.latest_epoch(), Some(1));
    }

    #[test]
    fn anchor_sequential_epochs_i2() {
        let a = InMemoryAnchor::new();
        a.commit_root(h("r0"), 0, h("b0")).unwrap();
        assert!(a.commit_root(h("r2"), 2, h("b2")).is_err());
        assert!(a.commit_root(h("rx"), 0, h("bx")).is_err());
        assert!(a.commit_root([0u8; 32], 1, h("b1")).is_err());
        assert!(a.commit_root(h("r1"), 1, [0u8; 32]).is_err());
        a.commit_root(h("r1"), 1, h("b1")).unwrap();
        assert_eq!(a.latest_epoch(), Some(1));
        assert!(a.commit_prune_root(1, h("p")).is_err());
        a.commit_prune_root(0, h("p0")).unwrap();
        assert_eq!(a.prune_root(0), Some(h("p0")));
    }

    #[test]
    fn prune_log_batches_and_membership() {
        let e = PruneLogEntry { branch_id: 7, branch_hash: h("B7"), epoch: 3, ts_ms: 1 };
        assert_eq!(e.pack().len(), PRUNE_ENTRY_BYTES);
        let log = PruneLog::new(4);
        let hashes: Vec<_> = (0..6).map(|i| h(&format!("branch-{i}"))).collect();
        let closed: Vec<_> = hashes.iter().enumerate()
            .map(|(i, bh)| log.append(PruneLogEntry { branch_id: i as u64, branch_hash: *bh,
                                                      epoch: 0, ts_ms: 0 }))
            .collect();
        assert!(closed[..3].iter().all(|c| c.is_none()) && closed[4].is_none());
        assert_eq!(closed[3].unwrap().0, 0);
        let (bi, mp) = log.membership(&hashes[2]).unwrap();
        assert!(bi == 0 && mp.verify() && mp.root == log.anchored_roots()[0]);
        assert!(log.membership(&hashes[5]).is_none());              // batch still open
        let (idx, root) = log.flush().unwrap();
        assert!(idx == 1 && log.flush().is_none());
        let (bi, mp) = log.membership(&hashes[5]).unwrap();
        assert!(bi == 1 && mp.verify() && mp.root == root);
        let mut last = None;
        for i in 6..10 {
            last = log.append(PruneLogEntry { branch_id: i, branch_hash: h(&format!("branch-{i}")),
                                              epoch: 0, ts_ms: 0 });
        }
        assert_eq!(last.unwrap().0, 2);
        assert_eq!(log.len(), 10);
    }

    #[test]
    fn prune_log_roots_are_anchored() {
        let (_, _, bcp) = make(512, 2);
        let mut bs: Vec<Branch> = (0..4).map(|i| {
            let mut b = Branch::new(i, 0);
            b.event_hashes = vec![h(&format!("pb{i}"))];
            b
        }).collect();
        bcp.phase5_prune(&mut bs, 3);
        assert_eq!(bcp.total_pruned(), 3);
        assert_eq!(bcp.anchor.prune_root(0), Some(bcp.prune_log.anchored_roots()[0]));
        assert!(bcp.anchor.prune_root(1).is_none());
        let (bi, mp) = bcp.prune_log.membership(&bs[1].branch_hash()).unwrap();
        assert!(bcp.anchor.verify_prune_proof(mp.leaf, &mp.path, bi));
        assert_eq!(bcp.flush_prune_log().unwrap().0, 1);
        assert!(bcp.anchor.prune_root(1).is_some());
    }

    #[test]
    fn gc_never_removes_committed_vertices() {
        let (_, _, bcp) = make(512, 4096);
        let (x, y) = (h("gx"), h("gy"));
        bcp.write_direct(&[x], &[y], 0);                    // y is committed
        let mut b = Branch::new(64, 0);                     // 64 & 63 == 0: same mask bit
        b.event_hashes = bcp.phase1_write(&[x], &[y], 64);
        bcp.phase5_prune(std::slice::from_mut(&mut b), u64::MAX);
        assert!(bcp.store().get_vertex(&y).is_some());
    }

    #[test]
    fn winning_branch_may_span_epochs() {
        let (_, _, bcp) = make(2, 4096);
        let mut b = Branch::new(5, 0);
        for i in 0..5 {
            b.event_hashes.extend(bcp.phase1_write(&[h(&format!("m{i}"))],
                                                   &[h(&format!("m{}", i + 1))], 5));
        }
        bcp.phase3_accumulate(&b);
        assert_eq!((bcp.committed_epochs(), bcp.batch_fill()), (2, 1));
    }

    #[test]
    fn index_rebuilds_from_payloads() {
        let (_, blob, bcp) = make(4, 4096);
        for i in 0..18u32 {
            bcp.write_direct(&[h(&format!("in{}", i % 5)), h(&format!("out{}", i.saturating_sub(1)))],
                             &[h(&format!("out{i}"))], 0);
        }
        bcp.flush_epoch();
        let rebuilt = Epsl::default();
        for cm in bcp.commits() {
            let (e, root, events) = decode_blob(&blob.payload(cm.epoch).unwrap()).unwrap();
            assert_eq!((e, root), (cm.epoch, cm.root));
            for (s, t) in &events { rebuilt.insert(s, t); }
            assert_eq!(Some(rebuilt.seal().root), bcp.anchor.epoch_root(cm.epoch));
        }
    }

    #[test]
    fn expected_commit_latency_formula() {
        let (_, _, bcp) = make(512, 4096);
        assert!((bcp.expected_commit_latency_s() - 6.12).abs() < 1e-9);
    }
}
