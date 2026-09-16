// src/main.rs — EVM-Lineage engine demo + integration tests
use std::sync::Arc;
use lineage_engine::{
    sha256,
    store::LineageStore,
    epsl::{Epsl, EpslConfig},
    bcp::{Bcp, BcpConfig, Branch},
    blob::BlobPipeline,
    config::{EngineConfig, default_cost_arb},
};

fn main() {
    let cfg   = EngineConfig::default();
    let store = Arc::new(LineageStore::new());
    let epsl  = Arc::new(Epsl::new(Arc::clone(&store), EpslConfig::default()));
    let blob  = Arc::new(BlobPipeline::new_dry());
    let bcp   = Bcp::new(Arc::clone(&epsl), Arc::clone(&store),
                         Arc::clone(&blob), BcpConfig::default());

    println!("=== EVM-Lineage Engine Demo ===");
    println!("Chain:                 {}", cfg.chain);
    println!("Epoch size w:          {}", cfg.epoch_size);
    println!("Max skip-list level:   {}", cfg.l_max);
    println!("Cost/event (Arb):      ${:.8}", default_cost_arb());
    println!("E[T_commit] (empty):   {:.2} s", bcp.expected_commit_latency_s());

    // Five-phase BCP demo: beta speculative branches per step.
    let num_steps  = 5;
    let beta       = 2u64;
    let store2 = Arc::new(LineageStore::new());
    let epsl2  = Arc::new(Epsl::new(Arc::clone(&store2), EpslConfig::default()));
    let blob2  = Arc::new(BlobPipeline::new_dry());
    let bcp2   = Bcp::new(Arc::clone(&epsl2), Arc::clone(&store2), blob2,
                          BcpConfig { epoch_size: 4, ..Default::default() });

    for step in 0..num_steps {
        let mut branches: Vec<Branch> = (0..beta).map(|i| {
            let bid = step * beta + i + 1;
            let src = sha256(format!("src-{step}").as_bytes());
            let tgt = sha256(format!("step={step} branch={bid}").as_bytes());
            let mut b = Branch::new(bid, bcp2.current_epoch());
            b.event_hashes = bcp2.phase1_write(&[src], &[tgt], bid);
            b
        }).collect();

        let wid    = Bcp::phase2_select_winner(&mut branches, |b| b.id as f64);
        let winner = branches.iter().find(|b| b.id == wid).unwrap().clone();
        if let Some(commit) = bcp2.phase3_accumulate(&winner) {
            println!("  Epoch {} committed: {} events root={}",
                commit.epoch, commit.event_count,
                hex::encode(&commit.merkle_root[..8]));
        }
        bcp2.phase5_prune(&mut branches, wid);
    }
    bcp2.flush_epoch();

    println!("Epochs committed: {}", bcp2.committed_epochs());
    println!("Branches pruned:  {}", bcp2.total_pruned());
    println!("EPSL node count:  {}", epsl2.node_count());
    println!("Dedup ratio:      {:.1}%", store2.dedup_ratio() * 100.0);
    println!("Done.");
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration tests — run with `cargo test`
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use lineage_engine::{
        sha256,
        store::LineageStore,
        epsl::{Epsl, EpslConfig},
        bcp::{Bcp, BcpConfig, Branch},
        blob::{BlobPipeline, encode_blob, decode_blob, BlobPayload},
        config::{cost_per_event_usd, expected_commit_latency_s, default_cost_arb},
    };
    use std::sync::Arc;

    fn fresh(epoch_size: u64) -> (Arc<LineageStore>, Arc<Epsl>, Bcp) {
        let store = Arc::new(LineageStore::new());
        let epsl  = Arc::new(Epsl::new(Arc::clone(&store), EpslConfig::default()));
        let blob  = Arc::new(BlobPipeline::new_dry());
        let bcp   = Bcp::new(Arc::clone(&epsl), Arc::clone(&store), blob,
                             BcpConfig { epoch_size, ..Default::default() });
        (store, epsl, bcp)
    }

    #[test]
    fn end_to_end_write_commit_query_verify_onchain_root() {
        let (_, epsl, bcp) = fresh(2);
        let oracle   = sha256(b"ETH:2000");
        let decision = sha256(b"buy:0.5eth");
        let order    = sha256(b"order:filled");
        bcp.write_direct(&[oracle], &[decision], 0);
        let (_, commit) = bcp.write_direct(&[decision], &[order], 0);
        let commit = commit.expect("epoch sealed at w=2");

        let res = epsl.query_bl(&order, Some(commit.epoch), 4);
        assert!(res.hashes.contains(&oracle));
        assert!(res.hashes.contains(&decision));
        let proof   = res.proof.expect("proof");
        let onchain = bcp.anchor.epoch_root(commit.epoch).expect("root anchored");
        assert!(proof.sealed);
        assert!(proof.verify(&onchain), "proof must verify against ON-CHAIN root");
    }

    #[test]
    fn bcp_full_five_phase_steps() {
        let (_, _, bcp) = fresh(4);
        for step in 0u64..3 {
            let mut branches: Vec<Branch> = (0..2u64).map(|i| {
                let bid = step * 2 + i + 1;
                let mut b = Branch::new(bid, bcp.current_epoch());
                b.event_hashes = bcp.phase1_write(
                    &[sha256(&step.to_be_bytes())],
                    &[sha256(&(step * 10 + i).to_be_bytes())],
                    bid,
                );
                b
            }).collect();
            let wid = Bcp::phase2_select_winner(&mut branches, |b| b.score);
            let w   = branches.iter().find(|b| b.id == wid).unwrap().clone();
            bcp.phase3_accumulate(&w);
            bcp.phase5_prune(&mut branches, wid);
        }
        assert_eq!(bcp.total_pruned(), 3); // 3 steps x 1 loser each
    }

    #[test]
    fn dag_merge_reduces_node_count() {
        let (store, epsl, _) = fresh(512);
        let shared = sha256(b"shared-oracle-price");
        for bid in 0..4u64 {
            epsl.insert(&[], &[shared], 0, bid);
        }
        assert_eq!(epsl.node_count(), 1);
        let _ = store; // store-level merges only occur through phase1_write
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
        assert!(raw.len() <= 128 * 1024);
        let back = decode_blob(&raw).unwrap();
        assert_eq!(back.epoch, 1);
        assert_eq!(back.event_count, 512);
    }

    #[test]
    fn cost_model_consistency() {
        // Analytical cost model (paper Sect. 2.2); regenerate the paper's
        // cost table from measured chain parameters, not from these
        // placeholder defaults.
        let c = default_cost_arb();
        assert!(c > 0.0 && c < 0.0001);
        let l1 = cost_per_event_usd(512, 200.0, 4.0, 10.0, 0.10, 2000.0);
        assert!(l1 > c);
    }

    #[test]
    fn commit_latency_formula() {
        // E[T] = (512 - 0)/1000 + 1 = 1.512 s
        let t = expected_commit_latency_s(512, 0, 1000.0, 1.0);
        assert!((t - 1.512).abs() < 0.001);
    }
}
