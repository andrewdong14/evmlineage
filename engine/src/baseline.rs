// src/baseline.rs — baselines for the evaluation
//
//   flat_rebuild   the sealing strategy of the first version of this
//                  engine: one fixed-shape Merkle tree over all leaves,
//                  rebuilt at every epoch
//   replay_query   no index at all: decode every epoch payload up to the
//                  queried epoch, rebuild adjacency, then traverse

use std::collections::{HashMap, VecDeque};

use crate::blob::decode_blob;
use crate::merkle::MerkleTree;
use crate::store::{Epoch, VertexHash};

/// Rebuild the flat Merkle tree over `leaves` (already in key order), on
/// one thread or on the Rayon pool.
pub fn flat_rebuild(leaves: Vec<VertexHash>, parallel: bool) -> MerkleTree {
    MerkleTree::build(leaves, parallel)
}

/// Answer a lineage query by replaying epoch payloads: `payloads[e]` is the
/// encoded payload of epoch e. Returns the result in BFS order.
pub fn replay_query(payloads: &[Vec<u8>], origin: &VertexHash, forward: bool,
                    epoch: Epoch, max_depth: Option<u32>) -> Result<Vec<VertexHash>, String> {
    let mut adj: HashMap<VertexHash, Vec<VertexHash>> = HashMap::new();
    for raw in payloads.iter().take(epoch as usize + 1) {
        let (_, _, events) = decode_blob(raw)?;
        for (sources, targets) in events {
            for s in &sources {
                for t in &targets {
                    if s == t { continue; }
                    let (a, b) = if forward { (s, t) } else { (t, s) };
                    let list = adj.entry(*a).or_default();
                    if !list.contains(b) { list.push(*b); }
                }
            }
        }
    }
    let mut depth: HashMap<VertexHash, u32> = HashMap::new();
    depth.insert(*origin, 0);
    let mut order = vec![*origin];
    let mut queue = VecDeque::from([*origin]);
    while let Some(h) = queue.pop_front() {
        let d = depth[&h];
        if let Some(md) = max_depth { if d >= md { continue; } }
        if let Some(nbs) = adj.get(&h) {
            for nb in nbs {
                if !depth.contains_key(nb) {
                    depth.insert(*nb, d + 1);
                    order.push(*nb);
                    queue.push_back(*nb);
                }
            }
        }
    }
    Ok(order)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::{encode_blob, Codec, Event};
    use crate::epsl::Epsl;
    use crate::sha256;
    use std::collections::HashSet;

    #[test]
    fn replay_matches_index() {
        let h = |s: &str| sha256(s.as_bytes());
        let epochs: Vec<Vec<Event>> = vec![
            vec![(vec![h("a")], vec![h("b")]), (vec![h("b"), h("x")], vec![h("c")])],
            vec![(vec![h("c")], vec![h("d"), h("e")]), (vec![h("a")], vec![h("e")])],
        ];
        let epsl = Epsl::default();
        let mut payloads = Vec::new();
        for (i, evs) in epochs.iter().enumerate() {
            for (s, t) in evs { epsl.insert(s, t); }
            let er = epsl.seal();
            payloads.push(encode_blob(i as u64, &er.root, evs, Codec::Raw));
        }
        for (origin, fwd, e, d) in [(h("e"), false, 1, None), (h("a"), true, 1, Some(2)),
                                    (h("c"), false, 0, None), (h("a"), true, 0, None)] {
            let kind = if fwd { crate::QueryKind::Fi } else { crate::QueryKind::Bl };
            let want: HashSet<_> = epsl.query(&origin, kind, Some(e), d, false).unwrap()
                .hashes.into_iter().collect();
            let got: HashSet<_> = replay_query(&payloads, &origin, fwd, e, d).unwrap()
                .into_iter().collect();
            assert_eq!(got, want);
        }
    }
}
