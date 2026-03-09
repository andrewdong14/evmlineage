// src/bcp.rs — Branch Commit Protocol (BCP) orchestrator
//
// Five phases:
//   Phase 1 — Speculative write: event → EPSL (off-chain, <1 ms)
//   Phase 2 — Policy scoring:    rank β branches, pick winner
//   Phase 3 — Commit winner:     EPSL insert + accumulate in batch
//   Phase 4 — Epoch commit:      when |batch| ≥ w → Merkle root + blob
//   Phase 5 — Prune losers:      record discarded branches
//
// Expected commit latency: E[T_commit] = (w − r) / λ + t_f

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};

use crate::store::{VertexHash, Epoch, BranchId};
use crate::epsl::{Epsl, EpochRoot};
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
}

// ── CommitResult ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitResult {
    pub epoch:        Epoch,
    pub merkle_root:  VertexHash,
    pub blob_hash:    VertexHash,
    pub event_count:  u32,
}

// ── BcpConfig ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BcpConfig {
    pub epoch_size:    u64,    // w = 512
    pub finality_s:    f64,    // Arbitrum ≈ 1 s
    pub arrival_hz:    f64,    // λ = arrival steps/s
}

impl Default for BcpConfig {
    fn default() -> Self {
        BcpConfig { epoch_size: 512, finality_s: 1.0, arrival_hz: 100.0 }
    }
}

// ── Bcp ───────────────────────────────────────────────────────────────────────

pub struct Bcp {
    epsl:    Arc<Epsl>,
    blob:    Arc<BlobPipeline>,
    cfg:     BcpConfig,
    batch:   Mutex<Vec<VertexHash>>,
    epoch:   Mutex<Epoch>,
    results: Mutex<Vec<CommitResult>>,
    pruned:  Mutex<Vec<Branch>>,
}

impl Bcp {
    pub fn new(epsl: Arc<Epsl>, blob: Arc<BlobPipeline>, cfg: BcpConfig) -> Self {
        Bcp { epsl, blob, cfg,
              batch:   Mutex::new(Vec::new()),
              epoch:   Mutex::new(0),
              results: Mutex::new(Vec::new()),
              pruned:  Mutex::new(Vec::new()) }
    }

    // Phase 1: write speculative events
    pub fn phase1_write(&self, sources: &[VertexHash], targets: &[VertexHash],
                        branch_id: BranchId) -> Vec<VertexHash>
    {
        let epoch = *self.epoch.lock().unwrap();
        self.epsl.insert(sources, targets, epoch, branch_id)
    }

    // Phase 2: score + select winner
    pub fn phase2_select_winner<F>(branches: &mut Vec<Branch>, scorer: F) -> BranchId
    where F: Fn(&Branch) -> f64
    {
        for b in branches.iter_mut() { b.score = scorer(b); }
        let winner = branches.iter().enumerate()
            .max_by(|(_, a), (_, b)| a.score.partial_cmp(&b.score).unwrap())
            .map(|(_, b)| b.id)
            .unwrap_or(0);
        for b in branches.iter_mut() { b.is_winner = b.id == winner; }
        winner
    }

    // Phase 3: accumulate winner events; trigger epoch commit when batch full
    pub fn phase3_accumulate(&self, winner: &Branch) -> Option<CommitResult> {
        let mut batch = self.batch.lock().unwrap();
        batch.extend_from_slice(&winner.event_hashes);
        if batch.len() as u64 >= self.cfg.epoch_size {
            let epoch_val = {
                let mut e = self.epoch.lock().unwrap();
                let v = *e;
                *e += 1;
                v
            };
            let batch_snap: Vec<VertexHash> = batch.drain(..).collect();
            drop(batch);
            Some(self.do_commit(epoch_val, batch_snap))
        } else {
            None
        }
    }

    fn do_commit(&self, epoch: Epoch, events: Vec<VertexHash>) -> CommitResult {
        let root      = self.epsl.commit_epoch(epoch);
        let blob_hash = self.blob.submit_sync(&root, &events);
        let result    = CommitResult {
            epoch,
            merkle_root: root.merkle_root,
            blob_hash,
            event_count: events.len() as u32,
        };
        self.results.lock().unwrap().push(result.clone());
        result
    }

    // Phase 5: record pruned branches
    pub fn phase5_prune(&self, branches: &[Branch], winner_id: BranchId) {
        let mut pruned = self.pruned.lock().unwrap();
        for b in branches {
            if b.id != winner_id { pruned.push(b.clone()); }
        }
    }

    // Expected commit latency: E[T_commit] = (w − r) / λ + t_f
    pub fn expected_commit_latency_s(&self) -> f64 {
        let r = self.batch.lock().unwrap().len() as f64;
        (self.cfg.epoch_size as f64 - r) / self.cfg.arrival_hz + self.cfg.finality_s
    }

    pub fn current_epoch(&self)    -> Epoch { *self.epoch.lock().unwrap() }
    pub fn batch_fill(&self)       -> usize { self.batch.lock().unwrap().len() }
    pub fn committed_epochs(&self) -> usize { self.results.lock().unwrap().len() }
    pub fn total_pruned(&self)     -> usize { self.pruned.lock().unwrap().len() }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sha256, store::LineageStore, epsl::{Epsl, EpslConfig}, blob::BlobPipeline};

    fn make_bcp(epoch_size: u64) -> Bcp {
        let store = Arc::new(LineageStore::new());
        let epsl  = Arc::new(Epsl::new(store, EpslConfig::default()));
        let blob  = Arc::new(BlobPipeline::new_dry());
        Bcp::new(epsl, blob, BcpConfig { epoch_size, ..Default::default() })
    }

    #[test]
    fn phase1_write_returns_hashes() {
        let bcp = make_bcp(512);
        let src = sha256(b"src");
        let tgt = sha256(b"tgt");
        let res = bcp.phase1_write(&[src], &[tgt], 1);
        // Both src and tgt are inserted as EPSL nodes
        assert_eq!(res.len(), 2);
        assert!(res.contains(&src) && res.contains(&tgt));
    }

    #[test]
    fn phase2_selects_highest_score() {
        let mut branches = vec![
            Branch { id: 0, epoch: 0, score: 0.0, event_hashes: vec![], is_winner: false },
            Branch { id: 1, epoch: 0, score: 0.0, event_hashes: vec![], is_winner: false },
            Branch { id: 2, epoch: 0, score: 0.0, event_hashes: vec![], is_winner: false },
        ];
        let winner = Bcp::phase2_select_winner(&mut branches, |b| b.id as f64 * 0.5);
        assert_eq!(winner, 2);
        assert!(branches[2].is_winner);
        assert!(!branches[0].is_winner);
    }

    #[test]
    fn epoch_committed_when_batch_full() {
        let bcp = make_bcp(4);  // tiny epoch size for test
        for i in 0u64..5 {
            let events: Vec<_> = (0..4).map(|j| sha256(&(i * 100 + j).to_be_bytes())).collect();
            let winner = Branch { id: i, epoch: i, score: 1.0, event_hashes: events, is_winner: true };
            bcp.phase3_accumulate(&winner);
        }
        // At least one epoch should have been committed
        assert!(bcp.committed_epochs() >= 1, "expected ≥1 epoch, got {}", bcp.committed_epochs());
    }

    #[test]
    fn expected_commit_latency_formula() {
        // E[T] = (w − 0) / 100 + 1.0 = 512/100 + 1 = 6.12
        let bcp = make_bcp(512);
        let t   = bcp.expected_commit_latency_s();
        assert!((t - 6.12).abs() < 0.01, "E[T]={t:.3}");
    }

    #[test]
    fn prune_records_losers() {
        let bcp = make_bcp(512);
        let branches = vec![
            Branch { id: 0, epoch: 0, score: 1.0, event_hashes: vec![], is_winner: true  },
            Branch { id: 1, epoch: 0, score: 0.5, event_hashes: vec![], is_winner: false },
            Branch { id: 2, epoch: 0, score: 0.3, event_hashes: vec![], is_winner: false },
        ];
        bcp.phase5_prune(&branches, 0);
        assert_eq!(bcp.total_pruned(), 2);
    }
}
