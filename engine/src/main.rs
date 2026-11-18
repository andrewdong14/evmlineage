// src/main.rs — EVM-Lineage engine demo: five-phase BCP steps, a verified
// query against the anchored root, and a prune-log membership proof.
use std::sync::Arc;

use lineage_engine::{
    sha256, verify_query, Bcp, BcpConfig, BlobPipeline, Branch, Epsl, EpslConfig, LineageStore,
};

fn main() {
    let store = Arc::new(LineageStore::new());
    let epsl  = Arc::new(Epsl::new(EpslConfig::default()));
    let blob  = Arc::new(BlobPipeline::new_dry());
    let bcp   = Bcp::new(Arc::clone(&epsl), Arc::clone(&store), blob,
                         BcpConfig { epoch_size: 4, prune_batch: 4, ..Default::default() });

    println!("=== EVM-Lineage engine demo ===");
    let beta = 2u64;
    let mut last = sha256(b"genesis observation");
    let mut pruned = Vec::new();
    for step in 0..6u64 {
        // Phase 1: every candidate branch is written to the store only.
        let mut branches: Vec<Branch> = (0..beta).map(|i| {
            let bid = step * beta + i + 1;
            let out = sha256(format!("step {step} candidate {i}").as_bytes());
            let mut b = Branch::new(bid, bcp.current_epoch());
            b.event_hashes = bcp.phase1_write(&[last], &[out], bid);
            b
        }).collect();
        // Phase 2: the policy picks a winner (here: the highest id).
        let wid = Bcp::phase2_select_winner(&mut branches, |b| b.id as f64);
        let winner = branches.iter().find(|b| b.id == wid).unwrap().clone();
        // Phases 3 and 4: index the winner; commit when the epoch is full.
        if let Some(c) = bcp.phase3_accumulate(&winner) {
            println!("  epoch {} committed: {} events, {} payload bytes, root {}…",
                     c.epoch, c.event_count, c.payload_bytes, hex::encode(&c.root[..6]));
        }
        // Phase 5: log and collect the losers.
        bcp.phase5_prune(&mut branches, wid);
        pruned.extend(branches.iter().filter(|b| b.id != wid).map(|b| b.branch_hash()));
        last = winner.event_hashes[1];
    }
    bcp.flush_epoch();
    bcp.flush_prune_log();

    let res = epsl.query_bl(&last, None, None).expect("sealed epoch");
    let proof = res.proof.expect("proof");
    let onchain = bcp.anchor.epoch_root(proof.epoch).expect("root anchored");
    let verified = verify_query(&proof, &onchain);
    println!("epochs committed:   {}", bcp.committed_epochs());
    println!("index vertices:     {}", epsl.node_count());
    println!("branches pruned:    {}", bcp.total_pruned());
    println!("BL(last decision):  {} vertices, proof {} bytes, verifies against anchor: {}",
             res.hashes.len(), proof.byte_size(), verified.as_ref() == Some(&res.hashes));
    let (batch, mp) = bcp.prune_log.membership(&pruned[0]).expect("pruned branch is logged");
    println!("pruned branch proof: batch {batch}, verifies against anchor: {}",
             bcp.anchor.verify_prune_proof(mp.leaf, &mp.path, batch));
}
