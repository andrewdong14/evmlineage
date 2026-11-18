// src/skiplist.rs — persistent authenticated skip list
//
// The construction of Goodrich and Tamassia (commutative hashing) with two
// changes that the EPSL needs:
//
//   * levels are a deterministic function of the key, so the list — and its
//     root label — depend only on the set of (key, leaf) pairs;
//   * nodes are immutable. An insert or update copies the search path and
//     shares everything else with the previous version, so every sealed
//     epoch keeps a readable version of its own.
//
// Shape. A key with level L owns a tower of nodes on levels 0..=L. A node's
// `down` pointer goes to the same tower one level lower; its `right`
// pointer goes to the next tower on the same level only if that tower ends
// there (a "plateau"). Under this rule every node except the root has
// exactly one parent, so the pointers form a binary tree over the leaves:
//
//   label(level 0) = leaf                          if right is none
//                  = pair(leaf, label(right))      otherwise
//   label(level i) = label(down)                   if right is none
//                  = pair(label(down), label(right))
//
// The root is the label of the top node of the sentinel tower (minus
// infinity). A membership path is the list of sibling labels from the leaf
// to the root; folding it with `pair` reproduces the root, which is the
// loop LineageAnchor.verifyProof runs on-chain.
//
// Labels are computed lazily and cached, and writes copy on demand: a node
// that only the version under construction references is changed in place
// (Arc::make_mut), a node that an earlier version still references is
// copied first. A batch of updates therefore allocates each node of the
// new version once, however many updates pass through it.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, OnceLock};

use crate::store::VertexHash;
use crate::{hash_pair, keccak256};

static LIVE_NODES: AtomicI64 = AtomicI64::new(0);

/// Skip-list nodes currently alive in this process (benchmark counter).
pub fn live_nodes() -> i64 { LIVE_NODES.load(Ordering::Relaxed) }

/// Leaf value of the sentinel tower; also the root of the empty list.
pub fn sentinel_leaf() -> VertexHash {
    static S: OnceLock<VertexHash> = OnceLock::new();
    *S.get_or_init(|| keccak256(b"EVM-Lineage/EPSL/sentinel"))
}

pub struct SlNode {
    key:      VertexHash,           // ignored for the sentinel tower
    leaf:     VertexHash,           // level 0 only
    down:     Option<Arc<SlNode>>,  // level > 0 only
    right:    Option<Arc<SlNode>>,
    label:    OnceLock<VertexHash>,
    level:    u8,
    sentinel: bool,
}

pub type Link = Arc<SlNode>;

impl Drop for SlNode {
    fn drop(&mut self) { LIVE_NODES.fetch_sub(1, Ordering::Relaxed); }
}

fn node(key: VertexHash, level: u8, leaf: VertexHash,
        down: Option<Link>, right: Option<Link>, sentinel: bool) -> Link {
    LIVE_NODES.fetch_add(1, Ordering::Relaxed);
    Arc::new(SlNode { key, leaf, down, right, label: OnceLock::new(), level, sentinel })
}

/// A node of the tower of `key` (never the sentinel).
fn tower(key: &VertexHash, level: u8, leaf: &VertexHash,
         down: Option<Link>, right: Option<Link>) -> Link {
    node(*key, level, *leaf, down, right, false)
}

impl Clone for SlNode {
    /// A copy shares the children and starts without a cached label.
    fn clone(&self) -> Self {
        LIVE_NODES.fetch_add(1, Ordering::Relaxed);
        SlNode { key: self.key, leaf: self.leaf, down: self.down.clone(),
                 right: self.right.clone(), label: OnceLock::new(),
                 level: self.level, sentinel: self.sentinel }
    }
}

impl SlNode {
    pub fn level(&self) -> u8 { self.level }

    /// Label of this node (computed on first use).
    pub fn label(&self) -> VertexHash {
        *self.label.get_or_init(|| {
            let own = match &self.down {
                None    => self.leaf,
                Some(d) => d.label(),
            };
            match &self.right {
                None    => own,
                Some(r) => hash_pair(&own, &r.label()),
            }
        })
    }
}

/// Writable access to a node: copies it first if another version still
/// references it, and drops its cached label either way.
fn own(link: &mut Link) -> &mut SlNode {
    let n = Arc::make_mut(link);
    n.label.take();
    n
}

/// The empty list.
pub fn new_list() -> Link {
    node([0u8; 32], 0, sentinel_leaf(), None, None, true)
}

/// Raise the sentinel tower to `level`. A sentinel node without a right
/// neighbour passes its label through, so the root does not change.
pub fn grow(root: &mut Link, level: u8) {
    while root.level < level {
        let l = root.level + 1;
        *root = node([0u8; 32], l, [0u8; 32], Some(root.clone()), None, true);
    }
}

/// Split the sub-list under `link` at `key`: `link` keeps the keys below
/// `key`; the returned node is the new tower node of `key` on the same
/// level, which takes over everything above `key`.
fn split(link: &mut Link, key: &VertexHash, leaf: &VertexHash) -> Link {
    let n = own(link);
    if let Some(r) = n.right.as_mut() {
        if r.key < *key { return split(r, key, leaf); }
    }
    let above = n.right.take();
    let level = n.level;
    match n.down.as_mut() {
        None    => tower(key, 0, leaf, None, above),
        Some(d) => {
            let kd = split(d, key, leaf);
            tower(key, level, &[0u8; 32], Some(kd), above)
        }
    }
}

/// Insert a key that is not yet present; its tower ends on `level`.
/// Requires `root.level() >= level` (see `grow`).
pub fn insert(link: &mut Link, key: &VertexHash, level: u8, leaf: &VertexHash) {
    let n = own(link);
    if let Some(r) = n.right.as_mut() {
        if r.key < *key { return insert(r, key, level, leaf); }
    }
    if n.level > level {
        return insert(n.down.as_mut().expect("upper node has a down pointer"), key, level, leaf);
    }
    let above = n.right.take();
    let k = match n.down.as_mut() {
        None    => tower(key, 0, leaf, None, above),
        Some(d) => {
            let kd = split(d, key, leaf);
            tower(key, level, &[0u8; 32], Some(kd), above)
        }
    };
    n.right = Some(k);
}

/// Replace the leaf of an existing key. Returns false if the key is absent.
pub fn update(link: &mut Link, key: &VertexHash, leaf: &VertexHash) -> bool {
    let n = own(link);
    if let Some(r) = n.right.as_mut() {
        if r.key <= *key { return update(r, key, leaf); }
    }
    match n.down.as_mut() {
        Some(d) => update(d, key, leaf),
        None => {
            if n.sentinel || n.key != *key { return false; }
            n.leaf = *leaf;
            true
        }
    }
}

/// Append the membership path of `key` to `out`, leaf side first.
/// Returns false if the key is absent.
pub fn path(n: &Link, key: &VertexHash, out: &mut Vec<VertexHash>) -> bool {
    if let Some(r) = &n.right {
        if r.key <= *key {
            if !path(r, key, out) { return false; }
            out.push(match &n.down { None => n.leaf, Some(d) => d.label() });
            return true;
        }
    }
    match &n.down {
        Some(d) => {
            if !path(d, key, out) { return false; }
            if let Some(r) = &n.right { out.push(r.label()); }
            true
        }
        None => {
            if n.sentinel || n.key != *key { return false; }
            if let Some(r) = &n.right { out.push(r.label()); }
            true
        }
    }
}

/// All keys in ascending order (tests).
pub fn keys(root: &Link) -> Vec<VertexHash> {
    let mut out = Vec::new();
    let mut stack: Vec<&Link> = vec![root];
    while let Some(x) = stack.pop() {
        if let Some(r) = &x.right { stack.push(r); }
        match &x.down {
            Some(d) => stack.push(d),
            None => if !x.sentinel { out.push(x.key); },
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epsl::skip_level;
    use crate::sha256;

    fn h(s: &str) -> VertexHash { sha256(s.as_bytes()) }
    fn leaf_of(k: &VertexHash) -> VertexHash {
        let mut b = b"leaf".to_vec(); b.extend_from_slice(k); sha256(&b)
    }
    fn build(keys: &[VertexHash]) -> Link {
        let mut root = new_list();
        for k in keys {
            let lv = skip_level(k);
            grow(&mut root, lv);
            insert(&mut root, k, lv, &leaf_of(k));
        }
        root
    }
    fn fold(mut n: VertexHash, p: &[VertexHash]) -> VertexHash {
        for s in p { n = hash_pair(&n, s); }
        n
    }

    #[test]
    fn empty_root_is_sentinel() {
        assert_eq!(new_list().label(), sentinel_leaf());
        assert_ne!(sentinel_leaf(), [0u8; 32]);
        let mut tall = new_list();
        grow(&mut tall, 9);
        assert_eq!(tall.label(), sentinel_leaf());
    }

    #[test]
    fn root_independent_of_insertion_order() {
        let ks: Vec<_> = (0..300).map(|i| h(&i.to_string())).collect();
        let r1 = build(&ks).label();
        let mut rev = ks.clone(); rev.reverse();
        assert_eq!(build(&rev).label(), r1);
        let mut mixed = ks.clone(); mixed.rotate_left(97); mixed.swap(3, 200);
        assert_eq!(build(&mixed).label(), r1);
        let mut sorted = ks.clone(); sorted.sort();
        assert_eq!(keys(&build(&ks)), sorted);
    }

    #[test]
    fn membership_paths_all_keys() {
        for n in [1usize, 2, 3, 5, 8, 33, 200] {
            let ks: Vec<_> = (0..n).map(|i| h(&format!("k{n}-{i}"))).collect();
            let root = build(&ks);
            for k in &ks {
                let mut p = Vec::new();
                assert!(path(&root, k, &mut p));
                assert_eq!(fold(leaf_of(k), &p), root.label(), "n={n}");
            }
            assert!(!path(&root, &h("absent"), &mut Vec::new()));
        }
    }

    #[test]
    fn update_copies_path_old_version_intact() {
        let ks: Vec<_> = (0..64).map(|i| h(&i.to_string())).collect();
        let v1 = build(&ks);
        let k = ks[17];
        let old_label = v1.label();
        let mut v2 = v1.clone();
        assert!(update(&mut v2, &k, &h("new leaf")));
        assert_eq!(v1.label(), old_label);                  // the old version is untouched
        assert_ne!(v1.label(), v2.label());
        let (mut p1, mut p2) = (Vec::new(), Vec::new());
        assert!(path(&v1, &k, &mut p1) && path(&v2, &k, &mut p2));
        assert_eq!(fold(leaf_of(&k), &p1), v1.label());
        assert_eq!(fold(h("new leaf"), &p2), v2.label());
        let mut v3 = v2.clone();
        assert!(!update(&mut v3, &h("absent"), &h("x")));
        assert_eq!(v3.label(), v2.label());
        // in-place path: a second update of the same version changes it again
        assert!(update(&mut v3, &k, &h("newer leaf")));
        assert_ne!(v3.label(), v2.label());
        let mut p3 = Vec::new();
        assert!(path(&v3, &k, &mut p3));
        assert_eq!(fold(h("newer leaf"), &p3), v3.label());
        assert_eq!(fold(h("new leaf"), &p2), v2.label());
    }

    #[test]
    fn path_length_logarithmic() {
        let ks: Vec<_> = (0..2000).map(|i| h(&i.to_string())).collect();
        let root = build(&ks);
        let mut total = 0usize;
        for k in &ks { let mut p = Vec::new(); path(&root, k, &mut p); total += p.len(); }
        let avg = total as f64 / 2000.0;
        let l = 2000f64.log2();
        assert!(avg > l && avg < 2.2 * l, "avg path {avg}");
    }
}
