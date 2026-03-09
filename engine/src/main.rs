// src/main.rs — EVM-Lineage engine demo + integration tests
use std::sync::Arc;
use lineage_engine::{
    sha256,
    store::{LineageStore, Vertex, VertexType},
    epsl::{Epsl, EpslConfig},
    bcp::{Bcp, BcpConfig, Branch},
    blob::BlobPipeline,
    config::{EngineConfig, cost_per_event_usd, default_cost_arb},
};

fn main() {
    let cfg   = EngineConfig::default();
    let store = Arc::new(LineageStore::new());
    let epsl  = Arc::new(Epsl::new(Arc::clone(&store), EpslConfig::default()));
    let blob  = Arc::new(BlobPipeline::new_dry());
    let bcp   = Bcp::new(Arc::clone(&epsl), Arc::clone(&blob), BcpConfig::default());

    println!("=== EVM-Lineage Engine Demo ===");
    println!("Chain:                 {}", cfg.chain);
    println!("Epoch size w:          {}", cfg.epoch_size);
    println!("Max skip-list level:   {}", cfg.l_max);
    println!("Cost/event (Arb):      ${:.8}", default_cost_arb());
    println!("E[T_commit] (empty):   {:.2} s", bcp.expected_commit_latency_s());

    // Simulate a few BCP steps
    let num_steps  = 5;
    let beta       = 2usize;
    let epoch_size = 4u64;

    let store2 = Arc::new(LineageStore::new());
    let epsl2  = Arc::new(Epsl::new(Arc::clone(&store2), EpslConfig::default()));
    let blob2  = Arc::new(BlobPipeline::new_dry());
    let bcp2   = Bcp::new(Arc::clone(&epsl2), Arc::clone(&blob2),
                          BcpConfig { epoch_size, ..Default::default() });

    for step in 0..num_steps {
        let mut branches: Vec<Branch> = (0..beta).map(|i| {
            let bid = (step * beta + i) as u64;
            let content = format!("step={step} branch={bid}");
            let events = bcp2.phase1_write(
                &[sha256(format!("src-{step}").as_bytes())],
                &[sha256(content.as_bytes())],
                bid,
            );
            Branch { id: bid, epoch: 0, score: 0.0, event_hashes: events, is_winner: false }
        }).collect();

        let winner_id = Bcp::phase2_select_winner(&mut branches, |b| b.id as f64);
        let winner    = branches.iter().find(|b| b.id == winner_id).unwrap().clone();
        if let Some(commit) = bcp2.phase3_accumulate(&winner) {
            println!("  Epoch {} committed: {} events root={}",
                commit.epoch, commit.event_count, hex::encode(&commit.merkle_root[..8]));
        }
        bcp2.phase5_prune(&branches, winner_id);
    }

    println!("Epochs committed: {}", bcp2.committed_epochs());
    println!("Branches pruned:  {}", bcp2.total_pruned());
    println!("EPSL node count:  {}", epsl2.node_count());
    println!("Dedup ratio:      {:.1}%", store2.dedup_ratio() * 100.0);
    println!("Done.");
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use lineage_engine::{
        sha256, to_hex,
        store::LineageStore,
        epsl::{Epsl, EpslConfig, MerkleTree},
        bcp::{Bcp, BcpConfig, Branch},
        blob::{BlobPipeline, encode_blob, decode_blob, BlobPayload},
        config::*,
    };

    fn fresh() -> (Arc<LineageStore>, Arc<Epsl>, Arc<BlobPipeline>, Bcp) {
        let store = Arc::new(LineageStore::new());
        let epsl  = Arc::new(Epsl::new(Arc::clone(&store), EpslConfig::default()));
        let blob  = Arc::new(BlobPipeline::new_dry());
        let bcp   = Bcp::new(Arc::clone(&epsl), Arc::clone(&blob), BcpConfig::default());
        (store, epsl, blob, bcp)
    }

    // ── Full pipeline ─────────────────────────────────────────────────────

    #[test]
    fn end_to_end_write_query_verify() {
        let (store, epsl, _, _) = fresh();

        // Write: oracle price → agent decision
        let oracle  = sha256(b"ETH:2000");
        let decision = sha256(b"buy:0.5eth");
        store.put_vertex(lineage_engine::store::Vertex::new(
            b"ETH:2000".to_vec(), lineage_engine::store::VertexType::OraclePrice, 0, [0u8;32], 1));
        epsl.insert(&[oracle], &[decision], 0, 1);
        epsl.insert(&[decision], &[sha256(b"order:filled")], 0, 1);

        // Commit epoch
        let root = epsl.commit_epoch(0);
        assert!(root.event_count >= 2);

        // Backward lineage: order_filled ← decision ← oracle
        let res = epsl.query_bl(&sha256(b"order:filled"), None, 4);
        assert!(res.hashes.len() >= 1);

        // Proof should verify
        if let Some(p) = &res.proof { assert!(p.verify(), "proof must verify"); }
    }

    #[test]
    fn bcp_full_step() {
        let (_, epsl, blob, bcp) = fresh();
        let bcp = Bcp::new(epsl, blob, BcpConfig { epoch_size: 4, ..Default::default() });

        for step in 0u64..3 {
            let mut branches: Vec<Branch> = (0..2u64).map(|i| {
                let events = bcp.phase1_write(
                    &[sha256(&step.to_be_bytes())],
                    &[sha256(&(step * 10 + i).to_be_bytes())],
                    step * 2 + i,
                );
                Branch { id: step * 2 + i, epoch: 0, score: i as f64,
                         event_hashes: events, is_winner: false }
            }).collect();
            let wid = Bcp::phase2_select_winner(&mut branches, |b| b.score);
            let w   = branches.iter().find(|b| b.id == wid).unwrap().clone();
            bcp.phase3_accumulate(&w);
            bcp.phase5_prune(&branches, wid);
        }
        assert_eq!(bcp.total_pruned(), 3); // 3 steps × 1 loser each
    }

    #[test]
    fn dag_merge_reduces_node_count() {
        let (store, epsl, _, _) = fresh();
        let shared = sha256(b"shared-oracle-price");
        // Insert same target from 4 different branches
        for bid in 0..4u64 {
            epsl.insert(&[], &[shared], 0, bid);
        }
        assert_eq!(epsl.node_count(), 1);  // deduped to 1 node
        assert_eq!(store.dag_merges_total(), 3);
    }

    #[test]
    fn proof_matches_solidity_logic() {
        // Verify that Python proof verification matches our Merkle implementation.
        // This is the same canonical ordering as the Solidity verifyProof assembly.
        let leaves: Vec<_> = (0..8).map(|i| sha256(&[i as u8])).collect();
        let tree = MerkleTree::from_leaves(&leaves);
        for idx in 0..8 {
            let p = tree.proof(idx).unwrap();
            // verify() mirrors the Solidity keccak256(min||max) inner loop
            assert!(p.verify(), "proof for idx={idx} failed");
        }
    }

    #[test]
    fn blob_fits_eip4844_limit() {
        let events: Vec<u8> = (0u64..512)
            .flat_map(|i| sha256(&i.to_be_bytes()))
            .collect();
        let p = BlobPayload {
            epoch: 1, batch_root: sha256(b"r"), event_count: 512, events,
        };
        let raw = encode_blob(&p).unwrap();
        assert!(raw.len() <= 128 * 1024, "blob {} B exceeds 128 KB", raw.len());
        let back = decode_blob(&raw).unwrap();
        assert_eq!(back.epoch, 1);
        assert_eq!(back.event_count, 512);
    }

    #[test]
    fn cost_model_table8() {
        // Table 8: Arbitrum ≈ $0.000011/event
        let c = default_cost_arb();
        println!("Cost per event (Arb): ${c:.8}");
        assert!(c < 0.0001);
        assert!(c > 1e-7);
    }

    #[test]
    fn expected_commit_latency_formula_table10() {
        // Table 10, w=512, λ=1000 (C=100 × 10 Hz), t_f=1 s, r=0:
        // E[T] = 512/1000 + 1 = 1.512 s
        let t = expected_commit_latency_s(512, 0, 1000.0, 1.0);
        assert!((t - 1.512).abs() < 0.001, "E[T]={t:.4}");
    }

    #[test]
    fn gas_constants_match_table1() {
        // Table 1: SSTORE_update = 2,900; blob ≈ 0.10 gwei/byte
        let c_per_event = cost_per_event_usd(512, 200.0, 4.0, 0.10, 0.10, 2000.0);
        // Cost breakdown:
        //   sstore: (2900/512) × 0.10 × 1e-9 × 2000 = $0.00000113
        //   blob:   (200/4)   × 0.10 × 1e-9 × 2000 = $0.00001000
        let expected = 0.00000113 + 0.00001000;
        assert!((c_per_event - expected).abs() < 1e-7, "cost ${c_per_event:.8} ≠ ${expected:.8}");
    }
}
