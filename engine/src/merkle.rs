// src/merkle.rs — fixed-shape binary Merkle tree (prune-log batches and the
// flat-rebuild baseline)
//
// Sorted-pair keccak hashing; an unpaired node is promoted unchanged, never
// paired with a copy of itself (identical to the Python MerkleTree).

use rayon::prelude::*;

use crate::hash_pair;
use crate::store::VertexHash;

pub struct MerkleTree {
    levels: Vec<Vec<VertexHash>>,
}

impl MerkleTree {
    pub fn from_leaves(leaves: &[VertexHash]) -> Self {
        Self::build(leaves.to_vec(), false)
    }

    /// Same tree, hashing each level on the Rayon pool.
    pub fn from_leaves_parallel(leaves: Vec<VertexHash>) -> Self {
        Self::build(leaves, true)
    }

    /// Build from an owned leaf vector, serially or on the Rayon pool.
    pub fn build(leaves: Vec<VertexHash>, parallel: bool) -> Self {
        if leaves.is_empty() {
            return MerkleTree { levels: vec![vec![[0u8; 32]]] };
        }
        let mut levels = vec![leaves];
        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let pair = |c: &[VertexHash]| if c.len() == 2 { hash_pair(&c[0], &c[1]) } else { c[0] };
            let next: Vec<VertexHash> = if parallel && prev.len() >= 4096 {
                prev.par_chunks(2).map(pair).collect()
            } else {
                prev.chunks(2).map(pair).collect()
            };
            levels.push(next);
        }
        MerkleTree { levels }
    }

    pub fn root(&self) -> VertexHash {
        self.levels.last().unwrap()[0]
    }

    /// Sibling path of leaf `idx`. No left/right flags: pair hashing sorts.
    pub fn path(&self, idx: usize) -> Option<Vec<VertexHash>> {
        if idx >= self.levels[0].len() { return None; }
        let mut path = Vec::new();
        let mut i = idx;
        for level in &self.levels[..self.levels.len() - 1] {
            let sib = i ^ 1;
            if sib < level.len() { path.push(level[sib]); }
            i /= 2;
        }
        Some(path)
    }

    pub fn proof(&self, idx: usize) -> Option<MerkleProof> {
        let path = self.path(idx)?;
        Some(MerkleProof { leaf: self.levels[0][idx], path, root: self.root() })
    }

    pub fn len(&self) -> usize { self.levels[0].len() }
    pub fn is_empty(&self) -> bool { self.len() == 0 }
    pub fn depth(&self) -> usize { self.levels.len() - 1 }
    /// Bytes held by the tree's hash vectors.
    pub fn heap_bytes(&self) -> usize { self.levels.iter().map(|l| l.len() * 32).sum() }
}

#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub leaf: VertexHash,
    pub path: Vec<VertexHash>,
    pub root: VertexHash,
}

impl MerkleProof {
    /// The fold that LineageAnchor.verifyProof runs.
    pub fn verify(&self) -> bool {
        let mut node = self.leaf;
        for sib in &self.path { node = hash_pair(&node, sib); }
        node == self.root
    }
    pub fn depth(&self) -> usize { self.path.len() }
    pub fn byte_size(&self) -> usize { 32 + self.path.len() * 32 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256;

    fn h(s: &str) -> VertexHash { sha256(s.as_bytes()) }

    #[test]
    fn proofs_valid_all_sizes() {
        for n in [1usize, 2, 3, 4, 7, 8, 15, 16, 17, 100, 512] {
            let leaves: Vec<_> = (0..n).map(|i| h(&i.to_string())).collect();
            let tree = MerkleTree::from_leaves(&leaves);
            for idx in 0..n {
                assert!(tree.proof(idx).unwrap().verify(), "n={n} idx={idx}");
            }
        }
        assert_eq!(MerkleTree::from_leaves(&[h("a")]).root(), h("a"));
    }

    #[test]
    fn tampered_proof_rejected() {
        let leaves: Vec<_> = (0..8).map(|i| h(&i.to_string())).collect();
        let mut p = MerkleTree::from_leaves(&leaves).proof(0).unwrap();
        p.leaf[0] ^= 0xFF;
        assert!(!p.verify());
    }

    #[test]
    fn odd_node_promoted_not_duplicated() {
        let (a, b, c) = (h("a"), h("b"), h("c"));
        let r3 = MerkleTree::from_leaves(&[a, b, c]).root();
        assert_ne!(r3, MerkleTree::from_leaves(&[a, b, c, c]).root());
        assert_eq!(r3, hash_pair(&hash_pair(&a, &b), &c));
    }

    #[test]
    fn parallel_build_matches_serial() {
        let leaves: Vec<_> = (0..10_000).map(|i| h(&i.to_string())).collect();
        assert_eq!(MerkleTree::from_leaves(&leaves).root(),
                   MerkleTree::from_leaves_parallel(leaves).root());
    }
}
