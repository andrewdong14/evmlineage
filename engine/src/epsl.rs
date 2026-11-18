// src/epsl.rs — Epoch-Pinned Skip List (EPSL)
//
// Mirrors agent/evm_lineage.py exactly; see that file for the prose.
//
// Record of a vertex:  (h, epoch0, bwd, fwd). Each adjacency list is an
// append-only sequence of groups — one per epoch in which it grew, sorted
// by hash inside the group — summarised by a hash chain:
//
//     D' = keccak256(D || be64(epoch) || be32(k) || h_1 .. h_k)     D_0 = 0
//     digest = keccak256(h || be64(epoch0) || D_bwd || D_fwd)
//     leaf   = keccak256(keccak256(h || digest))
//
// The leaves live in a persistent authenticated skip list keyed by h
// (src/skiplist.rs). `seal` extends the chains of the vertices touched in
// the open epoch, writes their new leaves by path copying, and returns the
// root that the BCP anchors on-chain (Invariant I1). A query pinned to a
// sealed epoch returns, per expanded vertex, its record as of that epoch
// and a membership path; `verify_query` recomputes the traversal from
// those records and rejects omitted as well as added vertices.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;

use crate::skiplist::{self, Link};
use crate::store::{Epoch, VertexHash};
use crate::{hash_pair, keccak256};

pub use crate::skiplist::sentinel_leaf;

/// Highest skip-list level.
pub const L_MAX: u8 = 31;

/// Deterministic level of key `h`: trailing zero bits of h (big-endian),
/// capped at L_MAX. The low-order end is used on purpose: the list is
/// ordered by h, so high-order bits would give neighbours equal levels.
pub fn skip_level(h: &VertexHash) -> u8 {
    let v = u32::from_be_bytes([h[28], h[29], h[30], h[31]]);
    if v == 0 { L_MAX } else { (v.trailing_zeros() as u8).min(L_MAX) }
}

/// One link of an adjacency chain (neighbours added in `epoch`, ascending).
pub fn chain_link(head: &VertexHash, epoch: Epoch, hashes: &[VertexHash]) -> VertexHash {
    let mut buf = Vec::with_capacity(44 + 32 * hashes.len());
    buf.extend_from_slice(head);
    buf.extend_from_slice(&epoch.to_be_bytes());
    buf.extend_from_slice(&(hashes.len() as u32).to_be_bytes());
    for h in hashes { buf.extend_from_slice(h); }
    keccak256(&buf)
}

/// Digest of a vertex record (104-byte preimage).
pub fn record_digest(h: &VertexHash, epoch0: Epoch,
                     bwd_head: &VertexHash, fwd_head: &VertexHash) -> VertexHash {
    let mut buf = [0u8; 104];
    buf[..32].copy_from_slice(h);
    buf[32..40].copy_from_slice(&epoch0.to_be_bytes());
    buf[40..72].copy_from_slice(bwd_head);
    buf[72..].copy_from_slice(fwd_head);
    keccak256(&buf)
}

/// Skip-list leaf keccak256(keccak256(h || digest)) — the value that
/// LineageAnchor.slash recomputes from (vertexHash, digest).
pub fn node_leaf(h: &VertexHash, digest: &VertexHash) -> VertexHash {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(h);
    buf[32..].copy_from_slice(digest);
    keccak256(&keccak256(&buf))
}

// ── Configuration and results ────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct EpslConfig {
    /// Number of sealed versions kept readable (None = all). Roots of
    /// older epochs stay available; their versions can be rebuilt by
    /// replaying the epoch payloads.
    pub retain: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochRoot {
    pub epoch:        Epoch,
    pub root:         VertexHash,
    pub new_vertices: u32,
    pub touched:      u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryKind { Bl, Fi, Ts }

impl QueryKind {
    fn code(self) -> u8 { match self { QueryKind::Bl => 0, QueryKind::Fi => 1, QueryKind::Ts => 2 } }
    fn from_code(c: u8) -> Option<Self> {
        match c { 0 => Some(QueryKind::Bl), 1 => Some(QueryKind::Fi), 2 => Some(QueryKind::Ts), _ => None }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s { "BL" => Some(QueryKind::Bl), "FI" => Some(QueryKind::Fi), "TS" => Some(QueryKind::Ts), _ => None }
    }
}

/// Record of one expanded vertex, restricted to the pinned epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofEntry {
    pub h:          VertexHash,
    pub epoch0:     Epoch,
    /// Adjacency in the query direction: (epoch, ascending hashes).
    pub groups:     Vec<(Epoch, Vec<VertexHash>)>,
    /// Chain head of the other direction.
    pub other_head: VertexHash,
    /// Membership path to the epoch root.
    pub path:       Vec<VertexHash>,
}

/// Verifiable answer to a BL / FI / TS query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryProof {
    pub kind:      QueryKind,
    pub origin:    VertexHash,
    pub epoch:     Epoch,
    pub max_depth: Option<u32>,
    /// Root the prover used. A verifier takes the root from the chain.
    pub root:      VertexHash,
    pub entries:   Vec<ProofEntry>,
}

const PROOF_MAGIC: &[u8; 4] = b"ELP2";

impl QueryProof {
    pub fn verify(&self, root: &VertexHash) -> bool { verify_query(self, root).is_some() }

    /// Longest membership path.
    pub fn depth(&self) -> usize { self.entries.iter().map(|e| e.path.len()).max().unwrap_or(0) }
    /// Total number of path hashes.
    pub fn path_hashes(&self) -> usize { self.entries.iter().map(|e| e.path.len()).sum() }
    pub fn byte_size(&self) -> usize { self.to_bytes().len() }

    /// Canonical wire encoding (identical to the Python layer).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(PROOF_MAGIC);
        out.push(self.kind.code());
        out.push(self.max_depth.is_some() as u8);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.max_depth.unwrap_or(0).to_be_bytes());
        out.extend_from_slice(&self.origin);
        out.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());
        for en in &self.entries {
            out.extend_from_slice(&en.h);
            out.extend_from_slice(&en.epoch0.to_be_bytes());
            out.extend_from_slice(&en.other_head);
            out.extend_from_slice(&(en.groups.len() as u32).to_be_bytes());
            for (ep, hs) in &en.groups {
                out.extend_from_slice(&ep.to_be_bytes());
                out.extend_from_slice(&(hs.len() as u32).to_be_bytes());
                for h in hs { out.extend_from_slice(h); }
            }
            out.push(en.path.len() as u8);
            for h in &en.path { out.extend_from_slice(h); }
        }
        out
    }

    pub fn from_bytes(raw: &[u8]) -> Result<QueryProof, String> {
        struct Rd<'a> { raw: &'a [u8], pos: usize }
        impl<'a> Rd<'a> {
            fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
                if self.pos + n > self.raw.len() { return Err("truncated proof".into()); }
                let s = &self.raw[self.pos..self.pos + n];
                self.pos += n;
                Ok(s)
            }
            fn u8(&mut self) -> Result<u8, String> { Ok(self.take(1)?[0]) }
            fn u32(&mut self) -> Result<u32, String> {
                Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
            }
            fn u64(&mut self) -> Result<u64, String> {
                Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
            }
            fn hash(&mut self) -> Result<VertexHash, String> {
                Ok(self.take(32)?.try_into().unwrap())
            }
        }
        let mut r = Rd { raw, pos: 0 };
        if r.take(4)? != PROOF_MAGIC { return Err("not an EVM-Lineage query proof".into()); }
        let kind = QueryKind::from_code(r.u8()?).ok_or("unknown query kind")?;
        let bounded = r.u8()? == 1;
        let epoch = r.u64()?;
        let depth = r.u32()?;
        let origin = r.hash()?;
        let n = r.u32()? as usize;
        let mut entries = Vec::with_capacity(n.min(1 << 16));
        for _ in 0..n {
            let h = r.hash()?;
            let epoch0 = r.u64()?;
            let other_head = r.hash()?;
            let ng = r.u32()? as usize;
            let mut groups = Vec::with_capacity(ng.min(1 << 16));
            for _ in 0..ng {
                let ep = r.u64()?;
                let k = r.u32()? as usize;
                let mut hs = Vec::with_capacity(k.min(1 << 16));
                for _ in 0..k { hs.push(r.hash()?); }
                groups.push((ep, hs));
            }
            let pl = r.u8()? as usize;
            let mut path = Vec::with_capacity(pl);
            for _ in 0..pl { path.push(r.hash()?); }
            entries.push(ProofEntry { h, epoch0, groups, other_head, path });
        }
        if r.pos != raw.len() { return Err("trailing bytes after proof".into()); }
        Ok(QueryProof { kind, origin, epoch, max_depth: if bounded { Some(depth) } else { None },
                        root: [0u8; 32], entries })
    }
}

/// Verify a QueryProof against an (on-chain) epoch root. Returns the
/// authenticated result — every vertex within `max_depth` hops of the
/// origin, BFS order, origin first — or None. Uses only the proof and
/// `root`:
///   1. every entry is well formed and its record hashes into `root`;
///   2. a vertex the recomputed traversal reaches (inside the depth bound)
///      without an entry means a vertex was withheld;
///   3. an entry the traversal never expands means the answer was padded.
pub fn verify_query(proof: &QueryProof, root: &VertexHash) -> Option<Vec<VertexHash>> {
    if proof.entries.is_empty() { return None; }
    if let Some(d) = proof.max_depth { if d < 1 { return None; } }
    let forward = proof.kind == QueryKind::Fi;
    let mut by_hash: HashMap<VertexHash, usize> = HashMap::with_capacity(proof.entries.len());
    for (i, en) in proof.entries.iter().enumerate() {
        if en.epoch0 > proof.epoch { return None; }
        let mut head = [0u8; 32];
        let mut last: Option<Epoch> = None;
        for (ep, hs) in &en.groups {
            if hs.is_empty() || *ep > proof.epoch || *ep < en.epoch0 { return None; }
            if let Some(l) = last { if *ep <= l { return None; } }
            if hs.windows(2).any(|w| w[0] >= w[1]) { return None; }
            head = chain_link(&head, *ep, hs);
            last = Some(*ep);
        }
        let (bwd, fwd) = if forward { (en.other_head, head) } else { (head, en.other_head) };
        let mut node = node_leaf(&en.h, &record_digest(&en.h, en.epoch0, &bwd, &fwd));
        for sib in &en.path { node = hash_pair(&node, sib); }
        if node != *root { return None; }
        if by_hash.insert(en.h, i).is_some() { return None; }
    }
    if proof.entries[0].h != proof.origin { return None; }

    let mut order: Vec<VertexHash> = vec![proof.origin];
    let mut depth: HashMap<VertexHash, u32> = HashMap::new();
    depth.insert(proof.origin, 0);
    let mut expanded = 0usize;
    let mut i = 0;
    while i < order.len() {
        let h = order[i];
        i += 1;
        let d = depth[&h];
        if let Some(md) = proof.max_depth { if d >= md { continue; } }
        let en = &proof.entries[*by_hash.get(&h)?];      // withheld vertex -> None
        expanded += 1;
        for (_, hs) in &en.groups {
            for nb in hs {
                if !depth.contains_key(nb) {
                    depth.insert(*nb, d + 1);
                    order.push(*nb);
                }
            }
        }
    }
    if expanded != by_hash.len() { return None; }         // padded answer
    Some(order)
}

/// Single-vertex proof in the shape LineageAnchor.verifyProof and
/// LineageAnchor.slash consume.
#[derive(Debug, Clone)]
pub struct MembershipProof {
    pub vertex: VertexHash,
    pub epoch:  Epoch,
    pub digest: VertexHash,
    pub leaf:   VertexHash,
    pub path:   Vec<VertexHash>,
    pub root:   VertexHash,
}

impl MembershipProof {
    pub fn verify(&self, root: &VertexHash) -> bool {
        let mut node = node_leaf(&self.vertex, &self.digest);
        if node != self.leaf { return false; }
        for sib in &self.path { node = hash_pair(&node, sib); }
        node == *root
    }
}

#[derive(Debug, Clone)]
pub struct QueryResult {
    /// BFS order, origin first; empty if the origin is unknown at the epoch.
    pub hashes: Vec<VertexHash>,
    pub proof:  Option<QueryProof>,
    /// Epoch the answer is pinned to (None if nothing has been sealed).
    pub epoch:  Option<Epoch>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpslError {
    NotSealed(Epoch),
    NotRetained(Epoch),
    BadDepth,
}

impl std::fmt::Display for EpslError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EpslError::NotSealed(e)   => write!(f, "epoch {e} is not sealed"),
            EpslError::NotRetained(e) => write!(f, "epoch {e} is no longer retained"),
            EpslError::BadDepth       => write!(f, "max_depth must be at least 1"),
        }
    }
}
impl std::error::Error for EpslError {}

// ── Index state ──────────────────────────────────────────────────────────────
//
// Adjacency lives in one append-only arena of u32 words. Each sealed group
// of a vertex's parent or child list is a record
//
//     [prev, epoch, k, head (8 words), id_1 .. id_k]
//
// where `prev` is the offset of the list's previous (older) group, `head`
// the chain head after this group and the ids are the neighbours added in
// `epoch`, ascending by hash. A vertex holds the offset of the latest group
// of each of its two lists. Reading a list as of epoch e walks back from the
// latest group and skips the groups that are newer than e; the head stored
// in the first group that remains is the chain head as of e. Edges of the
// open epoch are kept in a separate list until the epoch is sealed.

const NONE: u32 = u32::MAX;
const GROUP_HEADER: usize = 11;

struct Vtx {
    hash:   VertexHash,
    epoch0: u32,
    bwd:    u32,        // latest sealed group of the parent list, or NONE
    fwd:    u32,        // latest sealed group of the child list, or NONE
}

struct Inner {
    index:    HashMap<VertexHash, u32>,
    vtx:      Vec<Vtx>,
    arena:    Vec<u32>,
    pending:  Vec<(u32, u32)>,           // (source, target) edges of the open epoch
    pending_set: HashSet<u64>,
    first_new: u32,                      // vertices >= first_new were created in the open epoch
    epoch:    u32,                       // the open epoch
    edges:    u64,
    root:     Link,                      // version of the last sealed epoch
    versions: VecDeque<(u32, Link)>,
    roots:    Vec<EpochRoot>,
    seen:     Vec<u32>,                  // BFS scratch: stamp per vertex
    stamp:    u32,
}

pub struct Epsl {
    cfg:   EpslConfig,
    inner: Mutex<Inner>,
}

impl Default for Epsl {
    fn default() -> Self { Epsl::new(EpslConfig::default()) }
}

#[inline]
fn grp_prev(arena: &[u32], off: u32) -> u32 { arena[off as usize] }
#[inline]
fn grp_epoch(arena: &[u32], off: u32) -> u32 { arena[off as usize + 1] }
#[inline]
fn grp_ids(arena: &[u32], off: u32) -> &[u32] {
    let o = off as usize;
    &arena[o + GROUP_HEADER..o + GROUP_HEADER + arena[o + 2] as usize]
}
fn grp_head(arena: &[u32], off: u32) -> VertexHash {
    let mut h = [0u8; 32];
    let o = off as usize + 3;
    for i in 0..8 { h[4 * i..4 * i + 4].copy_from_slice(&arena[o + i].to_ne_bytes()); }
    h
}

/// Latest group of the list at `last` whose epoch is <= e (or NONE).
fn list_as_of(arena: &[u32], mut last: u32, e: u32) -> u32 {
    while last != NONE && grp_epoch(arena, last) > e { last = grp_prev(arena, last); }
    last
}

/// Chain head of the list as of epoch e.
fn head_as_of(arena: &[u32], last: u32, e: u32) -> VertexHash {
    match list_as_of(arena, last, e) {
        NONE => [0u8; 32],
        off  => grp_head(arena, off),
    }
}

/// Offsets of the groups of a list as of epoch e, oldest first.
fn groups_as_of(arena: &[u32], last: u32, e: u32, out: &mut Vec<u32>) {
    out.clear();
    let mut off = list_as_of(arena, last, e);
    while off != NONE {
        out.push(off);
        off = grp_prev(arena, off);
    }
    out.reverse();
}

fn list_contains(arena: &[u32], mut last: u32, id: u32) -> bool {
    while last != NONE {
        if grp_ids(arena, last).contains(&id) { return true; }
        last = grp_prev(arena, last);
    }
    false
}

fn list_len(arena: &[u32], mut last: u32) -> usize {
    let mut n = 0;
    while last != NONE {
        n += arena[last as usize + 2] as usize;
        last = grp_prev(arena, last);
    }
    n
}

#[inline]
fn prefix(h: &VertexHash) -> u64 { u64::from_be_bytes(h[..8].try_into().unwrap()) }

impl Inner {
    /// Append the groups of one direction for the sealed epoch. `keyed`
    /// holds (owner, hash prefix of the neighbour, neighbour) for every new
    /// edge and is sorted here; a run of equal owners becomes one group.
    fn append_groups(&mut self, keyed: &mut Vec<(u32, u64, u32)>, backward: bool, e: u32) {
        keyed.sort_unstable();
        let mut buf: Vec<u8> = Vec::new();
        let mut ids: Vec<u32> = Vec::new();
        let mut i = 0;
        while i < keyed.len() {
            let owner = keyed[i].0;
            let mut j = i;
            while j < keyed.len() && keyed[j].0 == owner { j += 1; }
            ids.clear();
            ids.extend(keyed[i..j].iter().map(|k| k.2));
            // The sort used 8-byte prefixes; settle equal prefixes exactly.
            if keyed[i..j].windows(2).any(|w| w[0].1 == w[1].1) {
                let vtx = &self.vtx;
                ids.sort_unstable_by(|a, b| vtx[*a as usize].hash.cmp(&vtx[*b as usize].hash));
            }
            let prev = if backward { self.vtx[owner as usize].bwd } else { self.vtx[owner as usize].fwd };
            let head = if prev == NONE { [0u8; 32] } else { grp_head(&self.arena, prev) };
            buf.clear();
            buf.extend_from_slice(&head);
            buf.extend_from_slice(&(e as u64).to_be_bytes());
            buf.extend_from_slice(&(ids.len() as u32).to_be_bytes());
            for id in &ids { buf.extend_from_slice(&self.vtx[*id as usize].hash); }
            let new_head = keccak256(&buf);
            let off = self.arena.len();
            assert!(off + GROUP_HEADER + ids.len() < NONE as usize, "adjacency arena is full");
            self.arena.push(prev);
            self.arena.push(e);
            self.arena.push(ids.len() as u32);
            for c in new_head.chunks_exact(4) {
                self.arena.push(u32::from_ne_bytes(c.try_into().unwrap()));
            }
            self.arena.extend_from_slice(&ids);
            let v = &mut self.vtx[owner as usize];
            if backward { v.bwd = off as u32 } else { v.fwd = off as u32 }
            i = j;
        }
    }

    fn entry_groups(&self, offs: &[u32]) -> Vec<(Epoch, Vec<VertexHash>)> {
        offs.iter().map(|&o| {
            (grp_epoch(&self.arena, o) as Epoch,
             grp_ids(&self.arena, o).iter().map(|&i| self.vtx[i as usize].hash).collect())
        }).collect()
    }
}

impl Epsl {
    pub fn new(cfg: EpslConfig) -> Self {
        Epsl {
            cfg,
            inner: Mutex::new(Inner {
                index: HashMap::new(), vtx: Vec::new(), arena: Vec::new(),
                pending: Vec::new(), pending_set: HashSet::new(), first_new: 0,
                epoch: 0, edges: 0, root: skiplist::new_list(),
                versions: VecDeque::new(), roots: Vec::new(),
                seen: Vec::new(), stamp: 0,
            }),
        }
    }

    // ── Writes (paper Algorithm 1) ───────────────────────────────────────

    /// Record one committed lineage event: an edge s -> t for every source
    /// s and target t, tagged with the open epoch. Vertices are created on
    /// first use; an existing edge and self-loops are ignored. Returns the
    /// event's vertex hashes (sources, then targets).
    pub fn insert(&self, sources: &[VertexHash], targets: &[VertexHash]) -> Vec<VertexHash> {
        let mut guard = self.inner.lock().unwrap();
        let g = &mut *guard;
        let e = g.epoch;
        let ids = |list: &[VertexHash], g: &mut Inner| -> Vec<u32> {
            let mut out: Vec<u32> = Vec::with_capacity(list.len());
            for h in list {
                let id = match g.index.get(h) {
                    Some(&id) => id,
                    None => {
                        let id = g.vtx.len() as u32;
                        assert!(id < NONE, "vertex table is full");
                        g.vtx.push(Vtx { hash: *h, epoch0: e, bwd: NONE, fwd: NONE });
                        g.index.insert(*h, id);
                        id
                    }
                };
                if !out.contains(&id) { out.push(id); }
            }
            out
        };
        let src = ids(sources, g);
        let tgt = ids(targets, g);
        for &t in &tgt {
            // A vertex created in the open epoch has no sealed parents.
            let t_sealed = if t < g.first_new { g.vtx[t as usize].bwd } else { NONE };
            for &s in &src {
                if s == t { continue; }
                if t_sealed != NONE && list_contains(&g.arena, t_sealed, s) { continue; }
                if g.pending_set.insert(((s as u64) << 32) | t as u64) {
                    g.pending.push((s, t));
                    g.edges += 1;
                }
            }
        }
        let mut all = Vec::with_capacity(sources.len() + targets.len());
        all.extend_from_slice(sources);
        all.extend_from_slice(targets);
        all
    }

    /// Seal the open epoch: extend the adjacency chains of the touched
    /// vertices, write their new leaves into the skip list (copy on write)
    /// and open the next epoch. The returned root is what the BCP submits
    /// to the anchor contract (Invariant I1).
    pub fn seal(&self) -> EpochRoot {
        let mut guard = self.inner.lock().unwrap();
        let g = &mut *guard;
        let e = g.epoch;
        let pending = std::mem::take(&mut g.pending);
        g.pending_set.clear();

        // One new group per touched list.
        let mut keyed: Vec<(u32, u64, u32)> = pending.iter()
            .map(|&(s, t)| (t, prefix(&g.vtx[s as usize].hash), s)).collect();
        g.append_groups(&mut keyed, true, e);
        keyed.clear();
        keyed.extend(pending.iter().map(|&(s, t)| (s, prefix(&g.vtx[t as usize].hash), t)));
        g.append_groups(&mut keyed, false, e);
        drop(keyed);

        // Touched vertices: the new ones plus the older endpoints of new
        // edges. They are processed in key order, so that consecutive
        // updates share most of their search path, which the skip list
        // changes in place after the first copy.
        let n = g.vtx.len() as u32;
        let mut old: Vec<u32> = pending.iter()
            .flat_map(|&(s, t)| [s, t]).filter(|&id| id < g.first_new).collect();
        old.sort_unstable();
        old.dedup();
        let mut dirty: Vec<u32> = old;
        dirty.extend(g.first_new..n);
        dirty.sort_unstable_by(|a, b| g.vtx[*a as usize].hash.cmp(&g.vtx[*b as usize].hash));

        let mut root = g.root.clone();
        for &id in &dirty {
            let v = &g.vtx[id as usize];
            let bwd = if v.bwd == NONE { [0u8; 32] } else { grp_head(&g.arena, v.bwd) };
            let fwd = if v.fwd == NONE { [0u8; 32] } else { grp_head(&g.arena, v.fwd) };
            let leaf = node_leaf(&v.hash, &record_digest(&v.hash, v.epoch0 as u64, &bwd, &fwd));
            if id >= g.first_new {
                let lv = skip_level(&v.hash);
                skiplist::grow(&mut root, lv);
                skiplist::insert(&mut root, &v.hash, lv, &leaf);
            } else {
                let found = skiplist::update(&mut root, &v.hash, &leaf);
                assert!(found, "index corrupt: sealed vertex missing from the skip list");
            }
        }
        let er = EpochRoot { epoch: e as Epoch, root: root.label(),
                             new_vertices: n - g.first_new, touched: dirty.len() as u32 };
        g.root = root.clone();
        g.versions.push_back((e, root));
        if let Some(k) = self.cfg.retain {
            while g.versions.len() > k.max(1) { g.versions.pop_front(); }
        }
        g.roots.push(er.clone());
        g.first_new = n;
        g.epoch += 1;
        er
    }

    // ── Roots ────────────────────────────────────────────────────────────

    /// The open (unsealed) epoch.
    pub fn current_epoch(&self) -> Epoch { self.inner.lock().unwrap().epoch as Epoch }

    /// The last sealed epoch, if any.
    pub fn latest_sealed(&self) -> Option<Epoch> {
        let e = self.inner.lock().unwrap().epoch;
        if e == 0 { None } else { Some(e as Epoch - 1) }
    }

    pub fn get_epoch_root(&self, epoch: Epoch) -> Option<EpochRoot> {
        self.inner.lock().unwrap().roots.get(epoch as usize).cloned()
    }

    pub fn latest_epoch_root(&self) -> Option<EpochRoot> {
        self.inner.lock().unwrap().roots.last().cloned()
    }

    pub fn retained_epochs(&self) -> Vec<Epoch> {
        self.inner.lock().unwrap().versions.iter().map(|v| v.0 as Epoch).collect()
    }

    // ── Verified queries (paper Algorithm 2) ─────────────────────────────

    pub fn query_bl(&self, target: &VertexHash, epoch: Option<Epoch>,
                    max_depth: Option<u32>) -> Result<QueryResult, EpslError> {
        self.query(target, QueryKind::Bl, epoch, max_depth, true)
    }
    pub fn query_fi(&self, source: &VertexHash, epoch: Option<Epoch>,
                    max_depth: Option<u32>) -> Result<QueryResult, EpslError> {
        self.query(source, QueryKind::Fi, epoch, max_depth, true)
    }
    /// Temporal slice: backward lineage in the graph as it stood at `epoch`,
    /// proven against that epoch's root.
    pub fn query_ts(&self, target: &VertexHash, epoch: Epoch,
                    max_depth: Option<u32>) -> Result<QueryResult, EpslError> {
        self.query(target, QueryKind::Ts, Some(epoch), max_depth, true)
    }

    /// Answer a lineage query pinned to a sealed epoch (default: the
    /// latest). With `prove == false` only the traversal is run.
    pub fn query(&self, origin: &VertexHash, kind: QueryKind, epoch: Option<Epoch>,
                 max_depth: Option<u32>, prove: bool) -> Result<QueryResult, EpslError> {
        if let Some(d) = max_depth { if d < 1 { return Err(EpslError::BadDepth); } }
        let mut guard = self.inner.lock().unwrap();
        let g = &mut *guard;
        let e = match epoch {
            Some(e) => {
                if e >= g.epoch as Epoch { return Err(EpslError::NotSealed(e)); }
                e as u32
            }
            None => {
                if g.epoch == 0 { return Ok(QueryResult { hashes: vec![], proof: None, epoch: None }); }
                g.epoch - 1
            }
        };
        let version: Option<Link> = match g.versions.front() {
            Some(&(first, _)) if e >= first => Some(g.versions[(e - first) as usize].1.clone()),
            _ => None,
        };
        if prove && version.is_none() { return Err(EpslError::NotRetained(e as Epoch)); }
        let oid = match g.index.get(origin) {
            Some(&id) if g.vtx[id as usize].epoch0 <= e => id,
            _ => return Ok(QueryResult { hashes: vec![], proof: None, epoch: Some(e as Epoch) }),
        };

        let forward = kind == QueryKind::Fi;
        if g.seen.len() < g.vtx.len() { g.seen.resize(g.vtx.len(), 0); }
        g.stamp = g.stamp.wrapping_add(1);
        if g.stamp == 0 { g.seen.iter_mut().for_each(|s| *s = 0); g.stamp = 1; }
        let st = g.stamp;

        let mut order: Vec<(u32, u32)> = vec![(oid, 0)];
        g.seen[oid as usize] = st;
        let mut entries: Vec<ProofEntry> = Vec::new();
        let mut offs: Vec<u32> = Vec::new();
        let mut i = 0;
        while i < order.len() {
            let (id, d) = order[i];
            i += 1;
            if let Some(md) = max_depth { if d >= md { continue; } }
            let (list, other) = {
                let v = &g.vtx[id as usize];
                if forward { (v.fwd, v.bwd) } else { (v.bwd, v.fwd) }
            };
            groups_as_of(&g.arena, list, e, &mut offs);
            for &o in &offs {
                let (lo, k) = (o as usize + GROUP_HEADER, g.arena[o as usize + 2] as usize);
                for w in lo..lo + k {
                    let nb = g.arena[w];
                    if g.seen[nb as usize] != st {
                        g.seen[nb as usize] = st;
                        order.push((nb, d + 1));
                    }
                }
            }
            if let (true, Some(ver)) = (prove, &version) {
                let v = &g.vtx[id as usize];
                let mut path = Vec::with_capacity(48);
                let found = skiplist::path(ver, &v.hash, &mut path);
                assert!(found, "index corrupt: vertex missing from sealed version");
                entries.push(ProofEntry {
                    h: v.hash, epoch0: v.epoch0 as Epoch,
                    groups: g.entry_groups(&offs),
                    other_head: head_as_of(&g.arena, other, e),
                    path,
                });
            }
        }
        let hashes: Vec<VertexHash> = order.iter().map(|&(id, _)| g.vtx[id as usize].hash).collect();
        let proof = match (prove, &version) {
            (true, Some(ver)) => Some(QueryProof {
                kind, origin: *origin, epoch: e as Epoch, max_depth,
                root: ver.label(), entries }),
            _ => None,
        };
        Ok(QueryResult { hashes, proof, epoch: Some(e as Epoch) })
    }

    /// Unproven answer that also follows the edges of the open epoch.
    pub fn query_pending(&self, origin: &VertexHash, kind: QueryKind,
                         max_depth: Option<u32>) -> Vec<VertexHash> {
        let guard = self.inner.lock().unwrap();
        let g = &*guard;
        let oid = match g.index.get(origin) { Some(&id) => id, None => return vec![] };
        let forward = kind == QueryKind::Fi;
        let mut open: HashMap<u32, Vec<u32>> = HashMap::new();
        for &(s, t) in &g.pending {
            let (a, b) = if forward { (s, t) } else { (t, s) };
            open.entry(a).or_default().push(b);
        }
        let mut seen: HashSet<u32> = HashSet::from([oid]);
        let mut order: Vec<(u32, u32)> = vec![(oid, 0)];
        let mut offs: Vec<u32> = Vec::new();
        let mut i = 0;
        while i < order.len() {
            let (id, d) = order[i];
            i += 1;
            if let Some(md) = max_depth { if d >= md { continue; } }
            let v = &g.vtx[id as usize];
            groups_as_of(&g.arena, if forward { v.fwd } else { v.bwd }, u32::MAX, &mut offs);
            let sealed = offs.iter().flat_map(|&o| grp_ids(&g.arena, o).iter().copied());
            let pending = open.get(&id).into_iter().flatten().copied();
            for nb in sealed.chain(pending) {
                if seen.insert(nb) { order.push((nb, d + 1)); }
            }
        }
        order.iter().map(|&(id, _)| g.vtx[id as usize].hash).collect()
    }

    /// Membership proof of one vertex record under a retained epoch's root
    /// (default: the latest); None if the vertex did not exist then.
    pub fn membership(&self, h: &VertexHash, epoch: Option<Epoch>) -> Option<MembershipProof> {
        let guard = self.inner.lock().unwrap();
        let g = &*guard;
        if g.epoch == 0 { return None; }
        let e = match epoch { Some(e) if e < g.epoch as Epoch => e as u32, Some(_) => return None,
                              None => g.epoch - 1 };
        let first = g.versions.front()?.0;
        if e < first { return None; }
        let ver = &g.versions[(e - first) as usize].1;
        let id = *g.index.get(h)?;
        let v = &g.vtx[id as usize];
        if v.epoch0 > e { return None; }
        let mut path = Vec::new();
        if !skiplist::path(ver, h, &mut path) { return None; }
        let digest = record_digest(h, v.epoch0 as u64,
                                   &head_as_of(&g.arena, v.bwd, e), &head_as_of(&g.arena, v.fwd, e));
        Some(MembershipProof { vertex: *h, epoch: e as Epoch, digest,
                               leaf: node_leaf(h, &digest), path, root: ver.label() })
    }

    // ── Introspection ────────────────────────────────────────────────────

    pub fn node_count(&self) -> u64 { self.inner.lock().unwrap().vtx.len() as u64 }
    pub fn edge_count(&self) -> u64 { self.inner.lock().unwrap().edges }
    pub fn has_vertex(&self, h: &VertexHash) -> bool { self.inner.lock().unwrap().index.contains_key(h) }

    /// Hash of the i-th vertex in creation order (benchmark sampling).
    pub fn vertex_at(&self, i: u64) -> Option<VertexHash> {
        self.inner.lock().unwrap().vtx.get(i as usize).map(|v| v.hash)
    }

    /// (in-degree, out-degree) of a vertex over sealed epochs.
    pub fn degree(&self, h: &VertexHash) -> Option<(usize, usize)> {
        let g = self.inner.lock().unwrap();
        let v = &g.vtx[*g.index.get(h)? as usize];
        Some((list_len(&g.arena, v.bwd), list_len(&g.arena, v.fwd)))
    }

    /// Bytes used by the vertex table and the adjacency arena (the skip
    /// list and the hash index are not included).
    pub fn graph_heap_bytes(&self) -> usize {
        let g = self.inner.lock().unwrap();
        g.vtx.len() * std::mem::size_of::<Vtx>() + g.arena.len() * 4
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256;

    fn h(s: &str) -> VertexHash { sha256(s.as_bytes()) }

    /// v0 -> v1 -> ... one event per epoch.
    fn chain(n: usize) -> (Epsl, Vec<VertexHash>, Vec<VertexHash>) {
        let e = Epsl::default();
        let vs: Vec<_> = (0..n).map(|i| h(&format!("chain-{i}"))).collect();
        let mut roots = Vec::new();
        e.insert(&[], &[vs[0]]);
        for i in 1..n {
            e.insert(&[vs[i - 1]], &[vs[i]]);
            roots.push(e.seal().root);
        }
        (e, vs, roots)
    }

    #[test]
    fn levels_use_low_order_bits() {
        let mut k = [0u8; 32];
        assert_eq!(skip_level(&k), L_MAX);
        k[31] = 1; assert_eq!(skip_level(&k), 0);
        k[31] = 8; assert_eq!(skip_level(&k), 3);
        let mut hi = [0u8; 32]; hi[0] = 1;
        assert_eq!(skip_level(&hi), L_MAX);
        let n = 4096;
        let ge1 = (0..n).filter(|i| skip_level(&h(&i.to_string())) >= 1).count();
        assert!(ge1 > n * 45 / 100 && ge1 < n * 55 / 100);
    }

    #[test]
    fn insert_dedups_edges_and_ignores_self_loops() {
        let e = Epsl::default();
        let (s, t) = (h("oracle"), h("decision"));
        assert_eq!(e.insert(&[s], &[t]), vec![s, t]);
        e.insert(&[s], &[t]);
        e.insert(&[t], &[t]);
        e.insert(&[s, s], &[t, t]);
        assert_eq!((e.node_count(), e.edge_count()), (2, 1));
    }

    #[test]
    fn seal_opens_next_epoch_and_empty_epoch_keeps_root() {
        let e = Epsl::default();
        assert!(e.latest_sealed().is_none());
        for i in 0..10 { e.insert(&[], &[h(&format!("item-{i}"))]); }
        let r0 = e.seal();
        assert_eq!((r0.epoch, r0.new_vertices, r0.touched), (0, 10, 10));
        assert_ne!(r0.root, sentinel_leaf());
        let r1 = e.seal();
        assert_eq!((r1.epoch, r1.touched), (1, 0));
        assert_eq!(r1.root, r0.root);
        assert_eq!(e.current_epoch(), 2);
    }

    #[test]
    fn root_depends_only_on_records() {
        let evs = [(vec![h("a")], vec![h("b")]), (vec![h("b"), h("c")], vec![h("d")]),
                   (vec![], vec![h("e")])];
        let (e1, e2) = (Epsl::default(), Epsl::default());
        for (s, t) in &evs { e1.insert(s, t); }
        for (s, t) in evs.iter().rev() { e2.insert(s, t); }
        assert_eq!(e1.seal().root, e2.seal().root);
    }

    #[test]
    fn queries_are_pinned_to_sealed_epochs() {
        let e = Epsl::default();
        let (s, t) = (h("oracle"), h("decision"));
        e.insert(&[s], &[t]);
        assert!(e.query_bl(&t, None, None).unwrap().hashes.is_empty());
        assert_eq!(e.query_pending(&t, QueryKind::Bl, None), vec![t, s]);
        let root = e.seal().root;
        let res = e.query_bl(&t, None, None).unwrap();
        assert_eq!(res.hashes, vec![t, s]);
        let p = res.proof.unwrap();
        assert_eq!(p.root, root);
        assert_eq!(verify_query(&p, &root), Some(vec![t, s]));
        assert_eq!(e.query_bl(&t, Some(1), None).unwrap_err(), EpslError::NotSealed(1));
        assert!(e.query_bl(&h("unknown"), None, None).unwrap().proof.is_none());
    }

    #[test]
    fn closure_depth_bound_and_forward() {
        let (e, vs, roots) = chain(5);
        let root = roots.last().unwrap();
        let bl = e.query_bl(&vs[4], None, None).unwrap();
        assert_eq!(bl.hashes, vec![vs[4], vs[3], vs[2], vs[1], vs[0]]);
        assert_eq!(verify_query(bl.proof.as_ref().unwrap(), root), Some(bl.hashes.clone()));
        let fi = e.query_fi(&vs[0], None, None).unwrap();
        assert_eq!(fi.hashes, vs);
        assert!(fi.proof.unwrap().verify(root));

        let d1 = e.query_bl(&vs[4], None, Some(1)).unwrap();
        assert_eq!(d1.hashes, vec![vs[4], vs[3]]);
        assert_eq!(d1.proof.as_ref().unwrap().entries.len(), 1);
        assert!(d1.proof.unwrap().verify(root));

        let mut p3 = e.query_bl(&vs[4], None, Some(3)).unwrap().proof.unwrap();
        assert!(p3.verify(root));
        p3.max_depth = Some(2); assert!(!p3.verify(root));   // padded
        p3.max_depth = Some(4); assert!(!p3.verify(root));   // incomplete
        assert_eq!(e.query_bl(&vs[4], None, Some(0)).unwrap_err(), EpslError::BadDepth);
    }

    #[test]
    fn temporal_slice_pinned_to_past_root() {
        let e = Epsl::default();
        let (old, mid, new) = (h("old"), h("mid"), h("new"));
        e.insert(&[old], &[mid]);
        let r0 = e.seal().root;
        e.insert(&[new], &[mid]);
        e.insert(&[mid], &[h("later")]);
        let r1 = e.seal().root;
        let ts = e.query_ts(&mid, 0, None).unwrap();
        assert_eq!(ts.hashes, vec![mid, old]);
        let p = ts.proof.unwrap();
        assert!(p.verify(&r0) && !p.verify(&r1));
        let now = e.query_bl(&mid, None, None).unwrap();
        assert_eq!(now.hashes.len(), 3);
        let p = now.proof.unwrap();
        assert!(p.verify(&r1));
        assert_eq!(p.entries[0].groups.iter().map(|g| g.0).collect::<Vec<_>>(), vec![0, 1]);
        assert_eq!(e.query_fi(&mid, Some(0), None).unwrap().hashes, vec![mid]);
        assert!(e.query_ts(&h("later"), 0, None).unwrap().proof.is_none());
    }

    #[test]
    fn cycles_terminate() {
        let e = Epsl::default();
        let (a, b) = (h("cyc-a"), h("cyc-b"));
        e.insert(&[a], &[b]);
        e.insert(&[b], &[a]);
        let root = e.seal().root;
        let res = e.query_bl(&a, None, None).unwrap();
        assert_eq!(res.hashes, vec![a, b]);
        assert!(res.proof.unwrap().verify(&root));
    }

    fn tamper_base() -> (Epsl, [VertexHash; 4], VertexHash) {
        let e = Epsl::default();
        let (a, b, c, x) = (h("ta"), h("tb"), h("tc"), h("unrelated"));
        e.insert(&[a], &[b]);
        e.insert(&[b], &[c]);
        e.insert(&[], &[x]);
        let root = e.seal().root;
        (e, [a, b, c, x], root)
    }

    #[test]
    fn tampered_suppressed_and_padded_answers_rejected() {
        let (e, [a, b, c, x], root) = tamper_base();
        let good = || e.query_bl(&c, None, None).unwrap().proof.unwrap();
        assert!(good().verify(&root));

        let mut p = good(); p.entries[0].groups.clear();
        assert!(!p.verify(&root));                                  // parents removed
        let mut p = good(); p.entries[1].other_head = h("forged");
        assert!(!p.verify(&root));
        let mut p = good(); p.entries[0].epoch0 += 1;
        assert!(!p.verify(&root));
        let mut p = good(); p.entries.retain(|en| en.h != a);
        assert!(!p.verify(&root));                                  // ancestor withheld
        let mut p = good(); p.entries.remove(0);
        assert!(!p.verify(&root));                                  // origin withheld
        let mut p = good();
        p.entries.push(e.query_bl(&x, None, None).unwrap().proof.unwrap().entries[0].clone());
        assert!(!p.verify(&root));                                  // unrelated record added
        let mut p = good(); let dup = p.entries[1].clone(); p.entries.push(dup);
        assert!(!p.verify(&root));
        let mut p = good(); p.kind = QueryKind::Fi;
        assert!(!p.verify(&root));
        let mut p = good(); p.entries[0].path.pop();
        assert!(!p.verify(&root));
        let mut p = good(); p.origin = b;
        assert!(!p.verify(&root));
        assert!(!good().verify(&h("another root")));

        let e2 = Epsl::default();
        e2.insert(&[a, b], &[c]);
        let r2 = e2.seal().root;
        let mut p = e2.query_bl(&c, None, None).unwrap().proof.unwrap();
        p.entries[0].groups[0].1.reverse();                         // unsorted group
        assert!(!p.verify(&r2));
    }

    #[test]
    fn proof_wire_format_roundtrip() {
        let (e, [a, _b, c, _x], root) = tamper_base();
        for (kind, origin, depth) in [(QueryKind::Bl, c, None), (QueryKind::Fi, a, Some(1)),
                                      (QueryKind::Ts, c, Some(2))] {
            let p = e.query(&origin, kind, Some(0), depth, true).unwrap().proof.unwrap();
            let raw = p.to_bytes();
            let q = QueryProof::from_bytes(&raw).unwrap();
            assert_eq!(q.to_bytes(), raw);
            assert_eq!(verify_query(&q, &root), verify_query(&p, &root));
            assert!(verify_query(&q, &root).is_some());
            assert!(QueryProof::from_bytes(&raw[..raw.len() - 1]).is_err());
            let mut extra = raw.clone(); extra.push(0);
            assert!(QueryProof::from_bytes(&extra).is_err());
        }
    }

    #[test]
    fn membership_proof_verifies() {
        let (e, [_a, b, _c, _x], root) = tamper_base();
        let mp = e.membership(&b, None).unwrap();
        assert!(mp.verify(&root) && !mp.verify(&h("other")));
        assert!(e.membership(&h("absent"), None).is_none());
    }

    #[test]
    fn randomised_queries_match_naive_bfs() {
        use crate::workload::Rng;
        use std::collections::{HashMap as Map, HashSet as Set, VecDeque as Deque};
        let mut rng = Rng::new(20261118);
        let e = Epsl::default();
        let mut pool: Vec<VertexHash> = (0..30).map(|i| h(&format!("base-{i}"))).collect();
        let mut edges: Vec<(VertexHash, VertexHash, u64)> = Vec::new();
        let mut have: Set<(VertexHash, VertexHash)> = Set::new();
        let mut first: Map<VertexHash, u64> = Map::new();
        let mut roots = Vec::new();
        for ep in 0..7u64 {
            for j in 0..40 {
                let mut srcs: Vec<VertexHash> = Vec::new();
                for _ in 0..rng.below(5) {
                    let x = pool[rng.below(pool.len() as u64) as usize];
                    if !srcs.contains(&x) { srcs.push(x); }
                }
                let tgts: Vec<VertexHash> = if rng.unit() < 0.15 {
                    (0..rng.range(1, 2)).map(|_| pool[rng.below(pool.len() as u64) as usize]).collect()
                } else {
                    (0..rng.range(1, 3)).map(|k| h(&format!("out-{ep}-{j}-{k}"))).collect()
                };
                e.insert(&srcs, &tgts);
                for x in srcs.iter().chain(tgts.iter()) { first.entry(*x).or_insert(ep); }
                for s in &srcs { for t in &tgts {
                    if s != t && have.insert((*s, *t)) { edges.push((*s, *t, ep)); }
                } }
                for t in &tgts { if !pool.contains(t) { pool.push(*t); } }
            }
            roots.push(e.seal().root);
        }
        assert_eq!(e.edge_count() as usize, edges.len());
        let mut checked = 0;
        for _ in 0..400 {
            let origin = pool[rng.below(pool.len() as u64) as usize];
            let kind = [QueryKind::Bl, QueryKind::Fi, QueryKind::Ts][rng.below(3) as usize];
            let ep = rng.below(7);
            let depth = [None, None, Some(1u32), Some(2), Some(3)][rng.below(5) as usize];
            let res = e.query(&origin, kind, Some(ep), depth, true).unwrap();
            if first.get(&origin).map(|f| *f > ep).unwrap_or(true) {
                assert!(res.hashes.is_empty() && res.proof.is_none());
                continue;
            }
            // reference answer: plain BFS over the edge list
            let fwd = kind == QueryKind::Fi;
            let mut adj: Map<VertexHash, Vec<VertexHash>> = Map::new();
            for (s, t, x) in &edges {
                if *x <= ep {
                    let (a, b) = if fwd { (s, t) } else { (t, s) };
                    adj.entry(*a).or_default().push(*b);
                }
            }
            let mut dist: Map<VertexHash, u32> = Map::from([(origin, 0)]);
            let mut queue = Deque::from([origin]);
            while let Some(x) = queue.pop_front() {
                let d = dist[&x];
                if depth.map(|m| d >= m).unwrap_or(false) { continue; }
                for nb in adj.get(&x).into_iter().flatten() {
                    if !dist.contains_key(nb) { dist.insert(*nb, d + 1); queue.push_back(*nb); }
                }
            }
            let got: Set<VertexHash> = res.hashes.iter().copied().collect();
            assert_eq!(got.len(), res.hashes.len());
            assert_eq!(got, dist.keys().copied().collect::<Set<_>>());
            let proof = res.proof.unwrap();
            assert_eq!(verify_query(&proof, &roots[ep as usize]), Some(res.hashes.clone()));
            let parsed = QueryProof::from_bytes(&proof.to_bytes()).unwrap();
            assert_eq!(verify_query(&parsed, &roots[ep as usize]), Some(res.hashes.clone()));
            if ep + 1 < 7 && roots[ep as usize + 1] != roots[ep as usize] {
                assert!(verify_query(&proof, &roots[ep as usize + 1]).is_none());
            }
            let mp = e.membership(&origin, Some(ep)).unwrap();
            assert!(mp.verify(&roots[ep as usize]));
            checked += 1;
        }
        assert!(checked > 200, "checked {checked}");
    }

    #[test]
    fn retention_window() {
        let e = Epsl::new(EpslConfig { retain: Some(2) });
        let vs: Vec<_> = (0..5).map(|i| h(&format!("r{i}"))).collect();
        let mut roots = Vec::new();
        for i in 1..5 { e.insert(&[vs[i - 1]], &[vs[i]]); roots.push(e.seal().root); }
        assert_eq!(e.retained_epochs(), vec![2, 3]);
        assert!(e.query_bl(&vs[4], None, None).unwrap().proof.unwrap().verify(&roots[3]));
        assert!(e.query_ts(&vs[3], 2, None).unwrap().proof.unwrap().verify(&roots[2]));
        assert_eq!(e.query_ts(&vs[1], 0, None).unwrap_err(), EpslError::NotRetained(0));
        assert_eq!(e.get_epoch_root(0).unwrap().root, roots[0]);
        let r = e.query(&vs[1], QueryKind::Bl, Some(0), None, false).unwrap();
        assert_eq!(r.hashes, vec![vs[1], vs[0]]);
    }
}
