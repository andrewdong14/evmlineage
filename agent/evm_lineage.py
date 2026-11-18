"""
evm_lineage.py — reference implementation of EVM-Lineage (Python, stdlib only)

Provides:

  keccak256 / hash_pair      — hashing identical to LineageAnchor.sol
  LineageStore               — in-memory store for speculative (Phase 1) writes
  Epsl                       — Epoch-Pinned Skip List: a persistent authenticated
                               skip list over per-vertex lineage records. One
                               version is sealed per epoch; its root is what the
                               BCP anchors on-chain.
  QueryProof / verify_query  — client-side verification without store access:
                               membership of every expanded record, closure and
                               minimality of the traversal, optional depth bound
  InMemoryAnchor             — test double for LineageAnchor.sol
  PruneLog                   — 96-byte records of discarded branches, Merkle
                               batches of M entries whose roots are anchored
  encode_blob / decode_blob  — epoch payload: the committed events themselves
  Bcp                        — Branch Commit Protocol (five phases per step)
  BranchManager, LineageHook — agent-side integration helpers
  LineageService             — WriteLineage / QueryBL / QueryFI / QueryTS facade
  AeTpcc                     — agent-extended TPC-C lineage workload
  commit_cost_wei, cost_per_event_usd, expected_commit_latency_s

Hashing conventions (identical in Python, Rust and Solidity; H = keccak256):

  content addressing     h(d)     = SHA-256(item bytes)
  pair hash              pair(a,b) = H(min(a,b) || max(a,b))                64 B
  adjacency chain link   D'       = H(D || be64(epoch) || be32(k) || h_1..h_k)
                                    h_i ascending; D_0 = 0^32          44+32k B
  record digest          d        = H(h || be64(epoch0) || D_bwd || D_fwd) 104 B
  skip-list leaf         leaf     = H(H(h || d))                    outer: 32 B
  prune-log leaf                  = H(96-byte entry)

A leaf is the hash of a 32-byte value and an interior label is the hash of a
64-byte value, so an interior label can never be presented as a leaf (this is
the double-hashed leaf convention of OpenZeppelin's MerkleProof; the contract's
slash() relies on it).

Run the tests:        python3 evm_lineage.py
Write test vectors:   python3 evm_lineage.py --vectors ../testvectors/conformance.json
"""

from __future__ import annotations

import hashlib, json, math, random, struct, sys, threading, time, zlib
from collections import OrderedDict, deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

# ══════════════════════════════════════════════════════════════════════════════
# Primitives
# ══════════════════════════════════════════════════════════════════════════════

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def to_hex(b: bytes) -> str:
    return b.hex()

# ── keccak-256 ────────────────────────────────────────────────────────────────
# Pure-stdlib Keccak-256 (the Ethereum variant: 0x01 domain padding, NOT the
# NIST SHA3-256 in hashlib). Used for Merkle pair hashing and leaf
# construction so that proofs generated here verify inside the Solidity
# assembly loop of LineageAnchor.verifyProof. If pycryptodome or pysha3 is
# installed we use it (~50x faster); otherwise the fallback below is used.

_KECCAK_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
# Rotation offsets r[x][y] of Keccak-f[1600].
_KECCAK_ROT = (
    (0, 36, 3, 41, 18), (1, 44, 10, 45, 2), (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56), (27, 20, 39, 8, 14),
)
_U64 = (1 << 64) - 1


def _keccak_f(A: List[List[int]]) -> List[List[int]]:
    for rc in _KECCAK_RC:
        # theta
        C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ (((C[(x + 1) % 5] << 1) | (C[(x + 1) % 5] >> 63)) & _U64)
             for x in range(5)]
        A = [[A[x][y] ^ D[x] for y in range(5)] for x in range(5)]
        # rho + pi
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                r = _KECCAK_ROT[x][y]
                B[y][(2 * x + 3 * y) % 5] = ((A[x][y] << r) | (A[x][y] >> (64 - r))) & _U64
        # chi
        A = [[B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y] & _U64)
              for y in range(5)] for x in range(5)]
        # iota
        A[0][0] ^= rc
    return A


def _keccak256_py(data: bytes) -> bytes:
    rate = 136  # bytes (1088-bit rate / 512-bit capacity)
    pad_len = rate - (len(data) % rate)
    if pad_len == 1:
        padded = data + b"\x81"
    else:
        padded = data + b"\x01" + b"\x00" * (pad_len - 2) + b"\x80"
    A = [[0] * 5 for _ in range(5)]
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            A[i % 5][i // 5] ^= int.from_bytes(block[i * 8:(i + 1) * 8], "little")
        A = _keccak_f(A)
    return b"".join(A[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


def _pick_keccak():
    try:                                   # pycryptodome
        from Crypto.Hash import keccak as _k
        return lambda d: _k.new(digest_bits=256, data=d).digest()
    except ImportError:
        pass
    try:                                   # pysha3
        import sha3 as _s
        return lambda d: _s.keccak_256(d).digest()
    except ImportError:
        pass
    return _keccak256_py


keccak256 = _pick_keccak()


def hash_pair(a: bytes, b: bytes) -> bytes:
    """Canonical sort-then-hash: keccak256(min||max).

    Mirrors the assembly inner loop of LineageAnchor.verifyProof, so a
    proof generated off-chain verifies unchanged on-chain.
    """
    lo, hi = (a, b) if a <= b else (b, a)
    return keccak256(lo + hi)

# ══════════════════════════════════════════════════════════════════════════════
# MerkleTree / MerkleProof — fixed-shape binary tree, used for prune-log batches
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class MerkleProof:
    leaf: bytes
    path: List[bytes]
    root: bytes

    def verify(self) -> bool:
        node = self.leaf
        for sib in self.path:
            node = hash_pair(node, sib)
        return node == self.root

    @property
    def depth(self) -> int:
        return len(self.path)

    @property
    def byte_size(self) -> int:
        return 32 + len(self.path) * 32


class MerkleTree:
    """Binary Merkle tree over 32-byte leaves with sorted-pair keccak hashing.

    An unpaired node is promoted to the next level unchanged. It is never
    paired with a copy of itself: duplicating the last node would give the
    leaf lists [a, b, c] and [a, b, c, c] the same root. The Rust engine and
    the Solidity verifier follow the same rule.
    """

    def __init__(self, leaves: List[bytes]):
        if not leaves:
            self._levels: List[List[bytes]] = [[bytes(32)]]
            return
        self._levels = [list(leaves)]
        while len(self._levels[-1]) > 1:
            prev = self._levels[-1]
            nxt = [hash_pair(prev[i], prev[i + 1]) if i + 1 < len(prev) else prev[i]
                   for i in range(0, len(prev), 2)]
            self._levels.append(nxt)

    def root(self) -> bytes:
        return self._levels[-1][0]

    def proof(self, idx: int) -> Optional[MerkleProof]:
        if idx < 0 or idx >= len(self._levels[0]):
            return None
        leaf = self._levels[0][idx]
        path: List[bytes] = []
        i = idx
        for level in self._levels[:-1]:
            sib = i ^ 1
            if sib < len(level):
                path.append(level[sib])
            i //= 2
        return MerkleProof(leaf=leaf, path=path, root=self.root())

    def __len__(self) -> int:
        return len(self._levels[0])

    def depth(self) -> int:
        n = len(self)
        return 0 if n <= 1 else math.ceil(math.log2(n))

# ══════════════════════════════════════════════════════════════════════════════
# LineageStore — in-memory store for speculative writes
# ══════════════════════════════════════════════════════════════════════════════

MAX_INLINE = 256   # bytes; larger items stored by content hash only

@dataclass
class Vertex:
    """Lineage vertex as kept by the off-chain store (content-addressed)."""
    hash:           bytes
    content:        bytes
    content_inline: bool
    vertex_type:    int          # 0x01–0x06 VertexType enum
    creation_epoch: int
    agent_id:       bytes        # 32 B
    branch_mask:    int          # bitmask of the branches that reference it
    timestamp_ms:   int

    @staticmethod
    def new(content: bytes, vtype: int, epoch: int,
            agent_id: bytes, branch_id: int) -> "Vertex":
        h  = sha256(content)
        ts = int(time.time() * 1000)
        return Vertex(hash=h, content=content,
                      content_inline=len(content) <= MAX_INLINE,
                      vertex_type=vtype, creation_epoch=epoch,
                      agent_id=agent_id,
                      branch_mask=(1 << (branch_id & 63)),
                      timestamp_ms=ts)

    def merge_branch(self, bid: int):
        self.branch_mask |= (1 << (bid & 63))


class LineageStore:
    """Thread-safe in-memory store for speculative (Phase 1) writes.

    Three maps: vertices by content hash (with the bitmask of branches
    that reference them), outgoing edges per source hash as (epoch,
    targets) lists, and an opaque key-value area. A durable deployment
    would keep the same maps in an LSM-tree store; this repository does
    not include one.
    """

    def __init__(self):
        self._lock      = threading.Lock()
        self._vertices: Dict[bytes, Vertex]                        = {}
        self._edges:    Dict[bytes, List[Tuple[int, List[bytes]]]] = {}
        self._raw:      Dict[bytes, bytes]                         = {}
        self._inserts = 0
        self._merges  = 0

    def put_vertex(self, vtx: Vertex) -> Tuple[bool, bytes]:
        """Insert a vertex, or merge the branch mask if it exists.
        Returns (is_new, hash)."""
        with self._lock:
            self._inserts += 1
            ex = self._vertices.get(vtx.hash)
            if ex is not None:
                ex.branch_mask |= vtx.branch_mask
                self._merges += 1
                return False, vtx.hash
            self._vertices[vtx.hash] = vtx
            return True, vtx.hash

    def get_vertex(self, h: bytes) -> Optional[Vertex]:
        with self._lock:
            return self._vertices.get(h)

    def put_edge(self, src: bytes, epoch: int, targets: List[bytes]):
        """Add edges src -> targets, recorded under `epoch`."""
        with self._lock:
            lists = self._edges.setdefault(src, [])
            for ep, lst in lists:
                if ep == epoch:
                    break
            else:
                lst = []
                lists.append((epoch, lst))
            for t in targets:
                if t not in lst:
                    lst.append(t)

    def scan_edges(self, src: bytes, lo: int, hi: int) -> List[bytes]:
        """All targets of src recorded in epochs [lo, hi]."""
        with self._lock:
            out: List[bytes] = []
            for ep, lst in sorted(self._edges.get(src, []), key=lambda x: x[0]):
                if lo <= ep <= hi:
                    out.extend(lst)
            return out

    def drop_edges(self, src: bytes, targets: List[bytes]) -> None:
        """Remove the edges src -> targets (Phase-5 garbage collection)."""
        with self._lock:
            lists = self._edges.get(src)
            if lists is None:
                return
            gone = set(targets)
            kept = [(ep, [t for t in lst if t not in gone]) for ep, lst in lists]
            kept = [(ep, lst) for ep, lst in kept if lst]
            if kept:
                self._edges[src] = kept
            else:
                del self._edges[src]

    def remove_vertex(self, h: bytes) -> bool:
        """Delete a vertex and its outgoing edges (Phase-5 garbage
        collection of vertices that only pruned branches referenced)."""
        with self._lock:
            if h not in self._vertices:
                return False
            del self._vertices[h]
            self._edges.pop(h, None)
            return True

    def put_raw(self, key: bytes, val: bytes):
        with self._lock:
            self._raw[key] = val

    def get_raw(self, key: bytes) -> Optional[bytes]:
        with self._lock:
            return self._raw.get(key)

    @property
    def vertex_count(self) -> int:
        return len(self._vertices)

    @property
    def edge_count(self) -> int:
        with self._lock:
            return sum(len(lst) for lists in self._edges.values() for _, lst in lists)

    @property
    def inserts_total(self) -> int:
        return self._inserts

    @property
    def dag_merges_total(self) -> int:
        return self._merges

    @property
    def dedup_ratio(self) -> float:
        return self._merges / self._inserts if self._inserts else 0.0

# ══════════════════════════════════════════════════════════════════════════════
# Epsl — Epoch-Pinned Skip List (paper Sect. 5)
#
# What is authenticated
# ---------------------
# Every vertex v of the committed lineage graph has a record
#
#     (h, epoch0, bwd, fwd)
#
# where h is the item's content hash, epoch0 the epoch in which v first
# appeared, and bwd / fwd its parent and child lists. Each list is an
# append-only sequence of groups, one per epoch in which the list grew, and
# is summarised by a hash chain over those groups (`chain_link`). The record
# digest covers h, epoch0 and the two chain heads; the leaf is the
# double-hashed pair (h, digest).
#
# The leaves are organised in an authenticated skip list keyed by h
# (Goodrich and Tamassia's construction with commutative hashing). Levels are
# a deterministic function of h, so the structure — and therefore its root —
# depends only on the set of records, not on insertion order. The list is
# persistent: sealing an epoch applies the epoch's changes by path copying,
# and the version of every retained epoch stays readable. Its root is what
# the BCP anchors on-chain (Invariant I1).
#
# What a query proves
# -------------------
# A BL / FI / TS answer carries, for every vertex whose neighbours were
# expanded, its record restricted to the pinned epoch and a membership path
# to that epoch's root. `verify_query` recomputes the traversal from those
# records and accepts only if every expanded vertex is committed under the
# root, every vertex the traversal reaches is expanded (nothing is omitted),
# and no record is supplied that the traversal does not reach (nothing is
# added). A depth bound stops expansion after `max_depth` hops.
# ══════════════════════════════════════════════════════════════════════════════

ZERO32        = bytes(32)
SENTINEL_LEAF = keccak256(b"EVM-Lineage/EPSL/sentinel")
L_MAX         = 31


def skip_level(h: bytes) -> int:
    """Deterministic skip-list level of key h: the number of trailing zero
    bits of h (as a big-endian integer), capped at L_MAX.

    P(level >= k) = 2^-k for uniformly distributed hashes. The level must be
    taken from the low-order end: the list is ordered by h, so bits from the
    high-order end would give neighbouring keys the same level and the list
    would degenerate into long runs.
    """
    v = int.from_bytes(h[28:32], "big")
    if v == 0:
        return L_MAX
    return min((v & -v).bit_length() - 1, L_MAX)


def chain_link(head: bytes, epoch: int, hashes: List[bytes]) -> bytes:
    """One link of an adjacency chain: the neighbours added in `epoch`,
    in ascending order."""
    return keccak256(head + epoch.to_bytes(8, "big")
                     + len(hashes).to_bytes(4, "big") + b"".join(hashes))


def chain_head(groups: Iterable[Tuple[int, List[bytes]]]) -> bytes:
    head = ZERO32
    for ep, hs in groups:
        head = chain_link(head, ep, hs)
    return head


def record_digest(h: bytes, epoch0: int, bwd_head: bytes, fwd_head: bytes) -> bytes:
    """Digest of a vertex record (104-byte preimage)."""
    return keccak256(h + epoch0.to_bytes(8, "big") + bwd_head + fwd_head)


def node_leaf(vertex_hash: bytes, digest: bytes) -> bytes:
    """Skip-list leaf: keccak256(keccak256(vertex_hash || digest)).

    LineageAnchor.slash recomputes exactly this from (vertexHash, digest).
    """
    return keccak256(keccak256(vertex_hash + digest))


# ── Persistent authenticated skip list ────────────────────────────────────────

class _SlNode:
    """Immutable skip-list node. `key is None` marks the sentinel tower
    (minus infinity). A node of level 0 carries the leaf of its key; a node
    of level i > 0 has a `down` pointer to level i-1 of the same tower.
    `right` points to the next tower on this level only if that tower ends
    on this level (the Goodrich-Tamassia "plateau" rule), which makes the
    pointers a binary tree. Labels are computed on demand and cached."""

    __slots__ = ("key", "level", "leaf", "down", "right", "_label")

    def __init__(self, key: Optional[bytes], level: int, leaf: Optional[bytes],
                 down: Optional["_SlNode"], right: Optional["_SlNode"]):
        self.key, self.level, self.leaf = key, level, leaf
        self.down, self.right = down, right
        self._label: Optional[bytes] = None

    def label(self) -> bytes:
        lab = self._label
        if lab is None:
            own = self.leaf if self.level == 0 else self.down.label()
            lab = own if self.right is None else hash_pair(own, self.right.label())
            self._label = lab
        return lab

    def with_right(self, right: Optional["_SlNode"]) -> "_SlNode":
        return _SlNode(self.key, self.level, self.leaf, self.down, right)

    def with_down(self, down: "_SlNode") -> "_SlNode":
        return _SlNode(self.key, self.level, None, down, self.right)


def _sl_new() -> _SlNode:
    return _SlNode(None, 0, SENTINEL_LEAF, None, None)


def _sl_split(n: _SlNode, key: bytes, leaf: bytes) -> Tuple[_SlNode, _SlNode]:
    """Split the sub-list under n at `key`. Returns (n', k): n' keeps the
    keys below `key`; k is the new tower node of `key` on n's level and
    takes over everything above `key`."""
    r = n.right
    if r is not None and r.key < key:
        r2, k = _sl_split(r, key, leaf)
        return n.with_right(r2), k
    if n.level == 0:
        return n.with_right(None), _SlNode(key, 0, leaf, None, r)
    d2, kd = _sl_split(n.down, key, leaf)
    return (_SlNode(n.key, n.level, None, d2, None),
            _SlNode(key, n.level, None, kd, r))


def _sl_insert(n: _SlNode, key: bytes, level: int, leaf: bytes) -> _SlNode:
    """Insert a new key (must be absent) whose tower ends on `level`;
    requires n.level >= level. Returns the copy of n."""
    r = n.right
    if r is not None and r.key < key:
        return n.with_right(_sl_insert(r, key, level, leaf))
    if n.level > level:
        return n.with_down(_sl_insert(n.down, key, level, leaf))
    if level == 0:
        return n.with_right(_SlNode(key, 0, leaf, None, r))
    d2, kd = _sl_split(n.down, key, leaf)
    return _SlNode(n.key, n.level, None, d2, _SlNode(key, level, None, kd, r))


def _sl_update(n: _SlNode, key: bytes, leaf: bytes) -> _SlNode:
    """Replace the leaf of an existing key."""
    r = n.right
    if r is not None and r.key <= key:
        return n.with_right(_sl_update(r, key, leaf))
    if n.level > 0:
        return n.with_down(_sl_update(n.down, key, leaf))
    if n.key != key:
        raise KeyError("skip list: key not present")
    return _SlNode(key, 0, leaf, None, r)


def _sl_path(n: _SlNode, key: bytes, out: List[bytes]) -> bool:
    """Append the membership path of `key` to `out`, bottom-up. Folding the
    key's leaf with the path by `hash_pair` yields the root label."""
    r = n.right
    if r is not None and r.key <= key:
        if not _sl_path(r, key, out):
            return False
        out.append(n.leaf if n.level == 0 else n.down.label())
        return True
    if n.level > 0:
        if not _sl_path(n.down, key, out):
            return False
        if r is not None:
            out.append(r.label())
        return True
    if n.key != key:
        return False
    if r is not None:
        out.append(r.label())
    return True


def _sl_grow(root: _SlNode, level: int) -> _SlNode:
    """Raise the sentinel tower so that it reaches `level`. A sentinel node
    without a right neighbour passes its label through, so growing the
    tower does not change the root."""
    while root.level < level:
        root = _SlNode(None, root.level + 1, None, root, None)
    return root


def sl_keys(root: _SlNode) -> List[bytes]:
    """All keys of a skip-list version in ascending order (test helper)."""
    out: List[bytes] = []
    stack = [root]
    while stack:
        x = stack.pop()
        if x.right is not None:
            stack.append(x.right)
        if x.level == 0:
            if x.key is not None:
                out.append(x.key)
        else:
            stack.append(x.down)
    return out


# ── Vertex records ────────────────────────────────────────────────────────────

class _Adj:
    """One direction of a vertex's adjacency: sealed groups (epoch, sorted
    neighbour hashes), their chain head, and the neighbours added in the
    open epoch."""

    __slots__ = ("groups", "head", "pending", "members")

    def __init__(self):
        self.groups:  List[Tuple[int, List[bytes]]] = []
        self.head:    bytes       = ZERO32
        self.pending: List[bytes] = []
        self.members: Set[bytes]  = set()

    def as_of(self, e: int) -> List[Tuple[int, List[bytes]]]:
        g = self.groups
        if not g or g[-1][0] <= e:
            return g
        lo, hi = 0, len(g)
        while lo < hi:
            mid = (lo + hi) // 2
            if g[mid][0] <= e:
                lo = mid + 1
            else:
                hi = mid
        return g[:lo]

    def head_as_of(self, e: int) -> bytes:
        g = self.groups
        if not g or g[-1][0] <= e:
            return self.head
        return chain_head(self.as_of(e))


class EpslNode:
    """A vertex of the committed lineage graph."""

    __slots__ = ("hash", "epoch", "bwd", "fwd")

    def __init__(self, h: bytes, epoch: int):
        self.hash  = h
        self.epoch = epoch          # epoch in which the vertex first appeared
        self.bwd   = _Adj()         # parents
        self.fwd   = _Adj()         # children

    def digest_as_of(self, e: int) -> bytes:
        return record_digest(self.hash, self.epoch,
                             self.bwd.head_as_of(e), self.fwd.head_as_of(e))

    def leaf_as_of(self, e: int) -> bytes:
        return node_leaf(self.hash, self.digest_as_of(e))


@dataclass
class EpochRoot:
    epoch:        int
    root:         bytes       # skip-list root after sealing `epoch`
    new_vertices: int         # vertices that first appeared in this epoch
    touched:      int         # records that changed in this epoch
    commit_block: int = 0     # filled after on-chain confirmation


@dataclass
class MembershipProof:
    """Single-vertex proof, in the shape LineageAnchor.verifyProof and
    LineageAnchor.slash consume."""
    vertex: bytes
    epoch:  int
    digest: bytes
    leaf:   bytes
    path:   List[bytes]
    root:   bytes

    def verify(self, root: Optional[bytes] = None) -> bool:
        node = node_leaf(self.vertex, self.digest)
        if node != self.leaf:
            return False
        for sib in self.path:
            node = hash_pair(node, sib)
        return node == (self.root if root is None else root)


# ── Query proofs ──────────────────────────────────────────────────────────────

_KIND_CODE = {"BL": 0, "FI": 1, "TS": 2}
_CODE_KIND = {v: k for k, v in _KIND_CODE.items()}
_PROOF_MAGIC = b"ELP2"


@dataclass
class ProofEntry:
    """Record of one expanded vertex, restricted to the pinned epoch."""
    h:          bytes
    epoch0:     int
    groups:     List[Tuple[int, List[bytes]]]   # adjacency in the query direction
    other_head: bytes                           # chain head of the other direction
    path:       List[bytes]                     # membership path to the epoch root


@dataclass
class QueryProof:
    """Verifiable answer to a BL / FI / TS query."""
    kind:      str                    # "BL" | "FI" | "TS"
    origin:    bytes
    epoch:     int                    # pinned epoch
    max_depth: Optional[int]          # None = full transitive closure
    root:      bytes                  # root the prover used (informational)
    entries:   List[ProofEntry]       # expanded vertices in BFS order, origin first

    def verify(self, root: Optional[bytes] = None) -> bool:
        """True iff the proof verifies. Pass the root read from the anchor
        contract; the embedded root is only a convenience for tests."""
        return verify_query(self, self.root if root is None else root) is not None

    def result(self, root: bytes) -> Optional[List[bytes]]:
        return verify_query(self, root)

    @property
    def depth(self) -> int:
        return max((len(en.path) for en in self.entries), default=0)

    @property
    def path_hashes(self) -> int:
        return sum(len(en.path) for en in self.entries)

    @property
    def byte_size(self) -> int:
        return len(self.to_bytes())

    def to_bytes(self) -> bytes:
        """Canonical wire encoding (identical in the Rust engine)."""
        out = bytearray(_PROOF_MAGIC)
        out.append(_KIND_CODE[self.kind])
        out.append(0 if self.max_depth is None else 1)
        out += self.epoch.to_bytes(8, "big")
        out += (self.max_depth or 0).to_bytes(4, "big")
        out += self.origin
        out += len(self.entries).to_bytes(4, "big")
        for en in self.entries:
            out += en.h
            out += en.epoch0.to_bytes(8, "big")
            out += en.other_head
            out += len(en.groups).to_bytes(4, "big")
            for ep, hs in en.groups:
                out += ep.to_bytes(8, "big")
                out += len(hs).to_bytes(4, "big")
                out += b"".join(hs)
            out.append(len(en.path))
            out += b"".join(en.path)
        return bytes(out)

    @staticmethod
    def from_bytes(raw: bytes, root: bytes = ZERO32) -> "QueryProof":
        if raw[:4] != _PROOF_MAGIC:
            raise ValueError("not an EVM-Lineage query proof")
        pos = 4
        def take(n: int) -> bytes:
            nonlocal pos
            if pos + n > len(raw):
                raise ValueError("truncated proof")
            chunk = raw[pos:pos + n]
            pos += n
            return chunk
        kind    = _CODE_KIND[take(1)[0]]
        bounded = take(1)[0] == 1
        epoch   = int.from_bytes(take(8), "big")
        depth   = int.from_bytes(take(4), "big")
        origin  = take(32)
        entries: List[ProofEntry] = []
        for _ in range(int.from_bytes(take(4), "big")):
            h      = take(32)
            epoch0 = int.from_bytes(take(8), "big")
            other  = take(32)
            groups = []
            for _ in range(int.from_bytes(take(4), "big")):
                ep = int.from_bytes(take(8), "big")
                k  = int.from_bytes(take(4), "big")
                groups.append((ep, [take(32) for _ in range(k)]))
            path = [take(32) for _ in range(take(1)[0])]
            entries.append(ProofEntry(h, epoch0, groups, other, path))
        if pos != len(raw):
            raise ValueError("trailing bytes after proof")
        return QueryProof(kind=kind, origin=origin, epoch=epoch,
                          max_depth=depth if bounded else None,
                          root=root, entries=entries)


def verify_query(proof: QueryProof, root: bytes) -> Optional[List[bytes]]:
    """Verify a QueryProof against an (on-chain) epoch root.

    Returns the authenticated result — every vertex within `max_depth` hops
    of the origin in the query direction, in BFS order, origin first — or
    None if the proof is invalid. Uses nothing but the proof and `root`:

      1. every entry is well formed and its record hashes into `root`;
      2. the traversal is recomputed from the entries: a vertex it reaches
         (inside the depth bound) without an entry means an ancestor or
         descendant was withheld;
      3. an entry the traversal never expands means the answer was padded.
    """
    if proof.kind not in _KIND_CODE or not proof.entries:
        return None
    if proof.max_depth is not None and proof.max_depth < 1:
        return None
    forward = proof.kind == "FI"
    by_hash: Dict[bytes, ProofEntry] = {}
    for en in proof.entries:
        if len(en.h) != 32 or en.h in by_hash or en.epoch0 > proof.epoch:
            return None
        head, last = ZERO32, -1
        for ep, hs in en.groups:
            if ep <= last or ep > proof.epoch or ep < en.epoch0 or not hs:
                return None
            for i, x in enumerate(hs):
                if len(x) != 32 or (i and hs[i - 1] >= x):
                    return None
            head, last = chain_link(head, ep, hs), ep
        if len(en.other_head) != 32:
            return None
        bwd, fwd = (en.other_head, head) if forward else (head, en.other_head)
        node = node_leaf(en.h, record_digest(en.h, en.epoch0, bwd, fwd))
        for sib in en.path:
            node = hash_pair(node, sib)
        if node != root:
            return None
        by_hash[en.h] = en
    if proof.entries[0].h != proof.origin:
        return None

    order = [proof.origin]
    depth = {proof.origin: 0}
    expanded = 0
    i = 0
    while i < len(order):
        h = order[i]
        i += 1
        d = depth[h]
        if proof.max_depth is not None and d >= proof.max_depth:
            continue                          # on the depth frontier
        en = by_hash.get(h)
        if en is None:
            return None                       # a reachable vertex was withheld
        expanded += 1
        for _, hs in en.groups:
            for nb in hs:
                if nb not in depth:
                    depth[nb] = d + 1
                    order.append(nb)
    if expanded != len(by_hash):
        return None                           # an unrelated record was added
    return order


@dataclass
class QueryResult:
    hashes: List[bytes]              # BFS order, origin first; [] if unknown
    proof:  Optional[QueryProof]
    epoch:  int                      # epoch the answer is pinned to
    sealed: bool                     # False for answers that include open-epoch edges


class Epsl:
    """Epoch-Pinned Skip List index (paper Sect. 5).

    Usage: `insert` records the edges of committed events in the open
    epoch; `seal` closes the epoch, applies its changes to the skip list
    and returns the new root; `query` answers against any retained sealed
    epoch with a proof. `retain` bounds how many sealed versions stay
    readable (None = all); roots of older epochs stay available.
    """

    def __init__(self, store: Optional["LineageStore"] = None,
                 retain: Optional[int] = None):
        self.store   = store if store is not None else LineageStore()
        self._lock   = threading.RLock()
        self._nodes: Dict[bytes, EpslNode] = {}
        self._dirty: Set[bytes] = set()
        self._epoch  = 0                                   # the open epoch
        self._root   = _sl_new()                           # last sealed version
        self._versions: "OrderedDict[int, _SlNode]" = OrderedDict()
        self._epoch_roots: List[EpochRoot] = []
        self._retain = retain
        self._edges  = 0

    # ── Writes (paper Algorithm 1) ─────────────────────────────────────────

    def insert(self, sources: List[bytes], targets: List[bytes],
               branch_id: int = 0) -> List[bytes]:
        """Record one committed lineage event: an edge s -> t for every
        source s and target t, tagged with the open epoch. Vertices are
        created on first use; an edge that already exists is ignored.
        Returns the event's vertex hashes (sources, then targets)."""
        srcs = list(dict.fromkeys(sources))
        tgts = list(dict.fromkeys(targets))
        for h in srcs + tgts:
            if len(h) != 32:
                raise ValueError("vertex hashes are 32 bytes")
        with self._lock:
            e = self._epoch
            for h in srcs + tgts:
                if h not in self._nodes:
                    self._nodes[h] = EpslNode(h, e)
                    self._dirty.add(h)
            for t in tgts:
                tn = self._nodes[t]
                for s in srcs:
                    if s == t or s in tn.bwd.members:
                        continue
                    sn = self._nodes[s]
                    tn.bwd.members.add(s); tn.bwd.pending.append(s)
                    sn.fwd.members.add(t); sn.fwd.pending.append(t)
                    self._dirty.add(s); self._dirty.add(t)
                    self._edges += 1
        return list(sources) + list(targets)

    def seal(self) -> EpochRoot:
        """Seal the open epoch: extend the adjacency chains of the touched
        vertices, write their new leaves into the skip list by path copying,
        and open the next epoch. The returned root is what the BCP submits
        to the anchor contract (Invariant I1)."""
        with self._lock:
            e, root, new = self._epoch, self._root, 0
            for h in sorted(self._dirty):
                n = self._nodes[h]
                for adj in (n.bwd, n.fwd):
                    if adj.pending:
                        hs = sorted(adj.pending)
                        adj.head = chain_link(adj.head, e, hs)
                        adj.groups.append((e, hs))
                        adj.pending = []
                leaf = node_leaf(h, record_digest(h, n.epoch, n.bwd.head, n.fwd.head))
                if n.epoch == e:
                    level = skip_level(h)
                    root = _sl_insert(_sl_grow(root, level), h, level, leaf)
                    new += 1
                else:
                    root = _sl_update(root, h, leaf)
            er = EpochRoot(epoch=e, root=root.label(), new_vertices=new,
                           touched=len(self._dirty))
            self._dirty.clear()
            self._root = root
            self._versions[e] = root
            if self._retain is not None:
                while len(self._versions) > self._retain:
                    self._versions.popitem(last=False)
            self._epoch_roots.append(er)
            self._epoch += 1
            return er

    # ── Roots ──────────────────────────────────────────────────────────────

    @property
    def current_epoch(self) -> int:
        """The open (unsealed) epoch."""
        with self._lock:
            return self._epoch

    @property
    def latest_sealed(self) -> int:
        """The last sealed epoch, or -1 if none."""
        with self._lock:
            return self._epoch - 1

    def get_epoch_root(self, epoch: int) -> Optional[EpochRoot]:
        with self._lock:
            return self._epoch_roots[epoch] if 0 <= epoch < len(self._epoch_roots) else None

    def latest_epoch_root(self) -> Optional[EpochRoot]:
        with self._lock:
            return self._epoch_roots[-1] if self._epoch_roots else None

    def retained_epochs(self) -> List[int]:
        with self._lock:
            return list(self._versions.keys())

    # ── Verified queries (paper Algorithm 2) ──────────────────────────────

    def query_bl(self, target: bytes, epoch: Optional[int] = None,
                 max_depth: Optional[int] = None) -> QueryResult:
        """Backward lineage: the ancestors of `target` as of `epoch`."""
        return self.query(target, "BL", epoch, max_depth)

    def query_fi(self, source: bytes, epoch: Optional[int] = None,
                 max_depth: Optional[int] = None) -> QueryResult:
        """Forward impact: the descendants of `source` as of `epoch`."""
        return self.query(source, "FI", epoch, max_depth)

    def query_ts(self, target: bytes, epoch: int,
                 max_depth: Optional[int] = None) -> QueryResult:
        """Temporal slice: backward lineage in the graph as it stood at
        `epoch`, proven against the root committed for that epoch."""
        return self.query(target, "TS", epoch, max_depth)

    def query(self, origin: bytes, kind: str = "BL",
              epoch: Optional[int] = None, max_depth: Optional[int] = None,
              prove: bool = True, pending: bool = False) -> QueryResult:
        """Answer a lineage query.

        `epoch` selects the sealed epoch to pin to (default: the latest).
        `max_depth` bounds the number of hops. `prove=False` skips proof
        generation. `pending=True` also follows edges of the open epoch;
        such answers are fresh but cannot carry a proof.
        """
        if kind not in _KIND_CODE:
            raise ValueError(f"unknown query kind {kind!r}")
        if max_depth is not None and max_depth < 1:
            raise ValueError("max_depth must be at least 1")
        forward = kind == "FI"
        with self._lock:
            if pending:
                e, version = self._epoch, None
            else:
                e = self._epoch - 1 if epoch is None else epoch
                if e >= self._epoch:
                    raise ValueError(f"epoch {e} is not sealed")
                version = self._versions.get(e)
                if prove and e >= 0 and version is None:
                    raise ValueError(f"epoch {e} is no longer retained")
            node = self._nodes.get(origin)
            if e < 0 or node is None or node.epoch > e:
                return QueryResult(hashes=[], proof=None, epoch=e, sealed=not pending)

            order = [origin]
            depth = {origin: 0}
            entries: List[ProofEntry] = []
            i = 0
            while i < len(order):
                h = order[i]
                i += 1
                d = depth[h]
                if max_depth is not None and d >= max_depth:
                    continue
                n = self._nodes[h]
                adj, other = (n.fwd, n.bwd) if forward else (n.bwd, n.fwd)
                groups = adj.as_of(e)
                for _, hs in groups:
                    for nb in hs:
                        if nb not in depth:
                            depth[nb] = d + 1
                            order.append(nb)
                if pending:
                    for nb in adj.pending:
                        if nb not in depth:
                            depth[nb] = d + 1
                            order.append(nb)
                elif prove:
                    path: List[bytes] = []
                    if not _sl_path(version, h, path):
                        raise RuntimeError("index corrupt: vertex missing from sealed version")
                    entries.append(ProofEntry(h=h, epoch0=n.epoch, groups=list(groups),
                                              other_head=other.head_as_of(e), path=path))
            proof = None
            if prove and not pending:
                proof = QueryProof(kind=kind, origin=origin, epoch=e,
                                   max_depth=max_depth, root=version.label(),
                                   entries=entries)
            return QueryResult(hashes=order, proof=proof, epoch=e, sealed=not pending)

    def membership(self, h: bytes, epoch: Optional[int] = None
                   ) -> Optional[MembershipProof]:
        """Membership proof of one vertex record under a sealed epoch's
        root, or None if the vertex did not exist at that epoch."""
        with self._lock:
            e = self._epoch - 1 if epoch is None else epoch
            version = self._versions.get(e)
            node = self._nodes.get(h)
            if version is None or node is None or node.epoch > e:
                return None
            path: List[bytes] = []
            if not _sl_path(version, h, path):
                return None
            digest = node.digest_as_of(e)
            return MembershipProof(vertex=h, epoch=e, digest=digest,
                                   leaf=node_leaf(h, digest), path=path,
                                   root=version.label())

    # ── Introspection ──────────────────────────────────────────────────────

    @property
    def node_count(self) -> int:
        with self._lock:
            return len(self._nodes)

    @property
    def edge_count(self) -> int:
        with self._lock:
            return self._edges

    def has_vertex(self, h: bytes) -> bool:
        with self._lock:
            return h in self._nodes

# ══════════════════════════════════════════════════════════════════════════════
# Epoch payloads (EIP-4844 blobs)
#
# The payload of an epoch carries the committed events themselves, so that
# anyone holding it can rebuild the index and recompute the anchored root.
#
#   header (64 B): epoch be64 | root 32 | n_events be32 | body_len be32 |
#                  codec u8 | version u8 | reserved 14
#   body:          varint n_dict | n_dict x 32-byte hashes (first-use order) |
#                  per event: varint |S|, varint |T|, |S|+|T| varint indices
#   codec 0 = body as is, codec 1 = zlib (DEFLATE) over the body
#
# A blob holds 4096 field elements of 32 bytes; 31 bytes of each are usable
# for arbitrary data, and every blob is charged 2^17 blob gas whatever its
# fill level (EIP-4844). Since the Fusaka upgrade a transaction carries at
# most six blobs (EIP-7594), so an epoch whose payload is larger than
# 6 x 126 976 bytes cannot be committed in one transaction.
# ══════════════════════════════════════════════════════════════════════════════

BLOB_HEADER_SIZE  = 64
BLOB_FIELD_ELEMS  = 4096
BLOB_USABLE_BYTES = BLOB_FIELD_ELEMS * 31      # 126 976
BLOB_GAS_PER_BLOB = 1 << 17                    # 131 072
MAX_BLOBS_PER_TX  = 6                          # EIP-7594
PAYLOAD_VERSION   = 2
CODEC_RAW, CODEC_ZLIB = 0, 1

Event = Tuple[List[bytes], List[bytes]]        # (sources, targets)


def _put_varint(out: bytearray, v: int) -> None:
    while v >= 0x80:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)


def _get_varint(raw: bytes, pos: int) -> Tuple[int, int]:
    v = shift = 0
    while True:
        if pos >= len(raw):
            raise ValueError("truncated varint")
        b = raw[pos]
        pos += 1
        v |= (b & 0x7F) << shift
        if b < 0x80:
            return v, pos
        shift += 7


def encode_events(events: List[Event]) -> bytes:
    """Dictionary-code a batch of events: every distinct 32-byte hash is
    stored once; events refer to hashes by index."""
    index: Dict[bytes, int] = {}
    refs = bytearray()
    for sources, targets in events:
        _put_varint(refs, len(sources))
        _put_varint(refs, len(targets))
        for h in list(sources) + list(targets):
            i = index.get(h)
            if i is None:
                i = index[h] = len(index)
            _put_varint(refs, i)
    out = bytearray()
    _put_varint(out, len(index))
    for h in index:                       # dict preserves first-use order
        out += h
    return bytes(out) + bytes(refs)


def decode_events(body: bytes, n_events: int) -> List[Event]:
    n_dict, pos = _get_varint(body, 0)
    if pos + 32 * n_dict > len(body):
        raise ValueError("truncated dictionary")
    table = [body[pos + 32 * i: pos + 32 * (i + 1)] for i in range(n_dict)]
    pos += 32 * n_dict
    events: List[Event] = []
    for _ in range(n_events):
        ns, pos = _get_varint(body, pos)
        nt, pos = _get_varint(body, pos)
        hs = []
        for _ in range(ns + nt):
            i, pos = _get_varint(body, pos)
            hs.append(table[i])
        events.append((hs[:ns], hs[ns:]))
    if pos != len(body):
        raise ValueError("trailing bytes in event body")
    return events


def raw_event_bytes(events: List[Event]) -> int:
    """Size of the events without dictionary coding: 4 B of counts plus
    32 B per referenced hash."""
    return sum(4 + 32 * (len(s) + len(t)) for s, t in events)


def encode_blob(epoch: int, root: bytes, events: List[Event],
                codec: int = CODEC_RAW) -> bytes:
    """Encode an epoch payload (header + event body)."""
    body = encode_events(events)
    if codec == CODEC_ZLIB:
        body = zlib.compress(body, 6)
    elif codec != CODEC_RAW:
        raise ValueError(f"unknown codec {codec}")
    hdr = bytearray(BLOB_HEADER_SIZE)
    struct.pack_into(">Q", hdr, 0, epoch)
    hdr[8:40] = root
    struct.pack_into(">I", hdr, 40, len(events))
    struct.pack_into(">I", hdr, 44, len(body))
    hdr[48] = codec
    hdr[49] = PAYLOAD_VERSION
    return bytes(hdr) + body


def decode_blob(raw: bytes) -> Tuple[int, bytes, List[Event]]:
    """Decode an epoch payload -> (epoch, root, events)."""
    if len(raw) < BLOB_HEADER_SIZE:
        raise ValueError(f"payload too short: {len(raw)} B")
    epoch,    = struct.unpack_from(">Q", raw, 0)
    root       = bytes(raw[8:40])
    n_events, = struct.unpack_from(">I", raw, 40)
    body_len, = struct.unpack_from(">I", raw, 44)
    codec, version = raw[48], raw[49]
    if version != PAYLOAD_VERSION:
        raise ValueError(f"unsupported payload version {version}")
    body = raw[BLOB_HEADER_SIZE:BLOB_HEADER_SIZE + body_len]
    if len(body) != body_len or len(raw) != BLOB_HEADER_SIZE + body_len:
        raise ValueError("payload length mismatch")
    if codec == CODEC_ZLIB:
        body = zlib.decompress(body)
    elif codec != CODEC_RAW:
        raise ValueError(f"unknown codec {codec}")
    return epoch, root, decode_events(body, n_events)


def blobs_needed(payload_bytes: int) -> int:
    """Number of EIP-4844 blobs a payload of this size occupies."""
    return max(1, -(-payload_bytes // BLOB_USABLE_BYTES))


def fits_one_transaction(payload_bytes: int) -> bool:
    """True if the payload fits the blobs that one transaction may carry
    (MAX_BLOBS_PER_TX). commitRoot binds a root to the blobs of its own
    transaction, so a larger epoch has to be split or sealed earlier."""
    return blobs_needed(payload_bytes) <= MAX_BLOBS_PER_TX


class BlobPipeline:
    """Publishes epoch payloads.

    With dry_run=True (the default) nothing is sent: the pipeline records
    the payload size and returns SHA-256(payload) as the data commitment.
    A live deployment sends the payload as the blobs of the commitRoot
    transaction, where the contract checks the commitment against the
    transaction's versioned blob hashes.
    """

    MAX_RETRIES    = 5
    BASE_BACKOFF_S = 0.5

    def __init__(self, dry_run: bool = True, rpc_url: str = "",
                 anchor_address: str = "", codec: int = CODEC_RAW,
                 keep_payloads: bool = False):
        self.dry_run        = dry_run
        self.rpc_url        = rpc_url
        self.anchor_address = anchor_address
        self.codec          = codec
        self.keep_payloads  = keep_payloads
        self._lock          = threading.Lock()
        self._submitted: List[Dict[str, Any]] = []
        self._payloads:  Dict[int, bytes]     = {}

    def submit(self, epoch_root: EpochRoot, events: List[Event]) -> bytes:
        """Encode and publish the payload of a sealed epoch. Returns the
        32-byte data commitment passed to commitRoot."""
        payload   = encode_blob(epoch_root.epoch, epoch_root.root, events, self.codec)
        data_hash = sha256(payload)
        for attempt in range(self.MAX_RETRIES):
            try:
                if not self.dry_run:
                    self._send_blob_tx(epoch_root.epoch, payload)
                break
            except NotImplementedError:
                raise
            except Exception:
                if attempt == self.MAX_RETRIES - 1:
                    raise
                time.sleep(self.BASE_BACKOFF_S * (2 ** attempt))
        with self._lock:
            self._submitted.append({
                "epoch": epoch_root.epoch, "data_hash": data_hash.hex(),
                "bytes": len(payload), "raw_bytes": raw_event_bytes(events),
                "blobs": blobs_needed(len(payload)), "events": len(events),
                "one_tx": fits_one_transaction(len(payload))})
            if self.keep_payloads:
                self._payloads[epoch_root.epoch] = payload
        return data_hash

    def _send_blob_tx(self, epoch: int, payload: bytes):
        """Send the commitRoot transaction with the payload as blob data.
        Not implemented in the reference implementation (dry run only)."""
        raise NotImplementedError("connect an RPC client for live submission")

    def payload(self, epoch: int) -> Optional[bytes]:
        with self._lock:
            return self._payloads.get(epoch)

    @property
    def submissions(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._submitted)

# ══════════════════════════════════════════════════════════════════════════════
# Bcp — Branch Commit Protocol (paper Sect. 6, Algorithm 3)
#
# Five phases per agent decision step:
#   Phase 1 — Speculative write: ALL beta branches -> off-chain LineageStore;
#             the index and the chain are not touched.
#   Phase 2 — Policy scoring: winner = arg max Score(B, P).
#   Phase 3 — The WINNING branch's events enter the EPSL (open epoch).
#   Phase 4 — Epoch batching: when the batch holds w events (or on flush),
#             seal the epoch, publish its payload and call
#             commitRoot(root, epoch, dataHash).
#   Phase 5 — Prune the losers: one 96-byte PruneLog entry each, garbage
#             collection of the vertices only they referenced.
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Branch:
    id:           int
    epoch:        int
    score:        float       = 0.0
    event_hashes: List[bytes] = field(default_factory=list)
    is_winner:    bool        = False

    def branch_hash(self) -> bytes:
        """Content hash of the branch: id + sorted vertex hashes."""
        acc = b"".join(sorted(self.event_hashes))
        return sha256(self.id.to_bytes(8, "big") + acc)


@dataclass
class CommitResult:
    epoch:         int
    root:          bytes        # EPSL root anchored on-chain
    data_hash:     bytes        # commitment to the epoch payload
    event_count:   int
    payload_bytes: int
    blobs:         int


class InMemoryAnchor:
    """Test double for LineageAnchor.sol with the same rules: epochs are
    committed in sequence and never overwritten (Invariant I2), prune-log
    batch roots likewise, and proofs are verified by the sorted-pair keccak
    fold. Swap in an RPC-backed client for a live deployment."""

    def __init__(self):
        self._lock   = threading.Lock()
        self._roots: Dict[int, bytes] = {}
        self._data:  Dict[int, bytes] = {}
        self._prune: List[bytes]      = []
        self._latest = -1

    def commit_root(self, root: bytes, epoch: int, data_hash: bytes) -> None:
        with self._lock:
            if root == bytes(32):
                raise ValueError("ZeroRoot")
            if data_hash == bytes(32):
                raise ValueError("InvalidDataHash")
            if epoch in self._roots:
                raise ValueError(f"EpochAlreadyCommitted({epoch})")
            if self._roots and epoch != self._latest + 1:
                raise ValueError(f"EpochOutOfOrder(expected {self._latest + 1}, got {epoch})")
            self._roots[epoch] = root
            self._data[epoch]  = data_hash
            self._latest = epoch

    def epoch_root(self, epoch: int) -> Optional[bytes]:
        with self._lock:
            return self._roots.get(epoch)

    def epoch_data_hash(self, epoch: int) -> Optional[bytes]:
        with self._lock:
            return self._data.get(epoch)

    @property
    def latest_epoch(self) -> int:
        with self._lock:
            return self._latest

    def verify_proof(self, leaf: bytes, path: List[bytes], epoch: int) -> bool:
        """Mirror of LineageAnchor.verifyProof."""
        root = self.epoch_root(epoch)
        if root is None:
            return False
        node = leaf
        for sib in path:
            node = hash_pair(node, sib)
        return node == root

    def commit_prune_root(self, index: int, root: bytes) -> None:
        with self._lock:
            if index != len(self._prune):
                raise ValueError(f"PruneBatchOutOfOrder(expected {len(self._prune)}, got {index})")
            self._prune.append(root)

    def prune_root(self, index: int) -> Optional[bytes]:
        with self._lock:
            return self._prune[index] if 0 <= index < len(self._prune) else None

    def verify_prune_proof(self, leaf: bytes, path: List[bytes], index: int) -> bool:
        root = self.prune_root(index)
        if root is None:
            return False
        node = leaf
        for sib in path:
            node = hash_pair(node, sib)
        return node == root


PRUNE_ENTRY_BYTES = 96   # branch id (32) | branch hash (32) | epoch (8) | time (8) | reserved (16)


@dataclass
class PruneLogEntry:
    branch_id:   int
    branch_hash: bytes
    epoch:       int
    ts_ms:       int

    def pack(self) -> bytes:
        """96-byte wire format (paper Sect. 6.2)."""
        return (
            sha256(self.branch_id.to_bytes(8, "big"))          # 32 B branch id
            + self.branch_hash                                  # 32 B
            + self.epoch.to_bytes(8, "big")                     # 8 B
            + self.ts_ms.to_bytes(8, "big")                     # 8 B
            + bytes(16)                                         # reserved
        )

    def leaf(self) -> bytes:
        return keccak256(self.pack())


class PruneLog:
    """Tamper-evident record of discarded speculative branches.

    Entries are grouped into batches of `batch_size` (M = 4096). When a
    batch closes, `append` returns (batch index, Merkle root) and the BCP
    anchors the root on-chain. An auditor can then prove that a branch was
    considered and discarded although its content was never anchored.
    """

    DEFAULT_BATCH = 4096

    def __init__(self, batch_size: int = DEFAULT_BATCH):
        self._lock       = threading.Lock()
        self._batch_size = batch_size
        self._entries:   List[PruneLogEntry]   = []
        self._batches:   List[Tuple[int, int]] = []    # [lo, hi) per closed batch
        self._roots:     List[bytes]           = []

    def _close(self, lo: int, hi: int) -> Tuple[int, bytes]:
        root = MerkleTree([e.leaf() for e in self._entries[lo:hi]]).root()
        self._batches.append((lo, hi))
        self._roots.append(root)
        return len(self._roots) - 1, root

    def append(self, entry: PruneLogEntry) -> Optional[Tuple[int, bytes]]:
        with self._lock:
            self._entries.append(entry)
            done = self._batches[-1][1] if self._batches else 0
            if len(self._entries) - done == self._batch_size:
                return self._close(done, len(self._entries))
            return None

    def flush(self) -> Optional[Tuple[int, bytes]]:
        """Close the current partial batch (operator-defined cadence)."""
        with self._lock:
            done = self._batches[-1][1] if self._batches else 0
            if len(self._entries) == done:
                return None
            return self._close(done, len(self._entries))

    def membership(self, branch_hash: bytes) -> Optional[Tuple[int, MerkleProof]]:
        """(batch index, proof) for a discarded branch, or None if it is
        unknown or its batch is still open."""
        with self._lock:
            for bi, (lo, hi) in enumerate(self._batches):
                for j in range(lo, hi):
                    if self._entries[j].branch_hash == branch_hash:
                        tree = MerkleTree([e.leaf() for e in self._entries[lo:hi]])
                        return bi, tree.proof(j - lo)
        return None

    def membership_proof(self, branch_hash: bytes) -> Optional[MerkleProof]:
        found = self.membership(branch_hash)
        return found[1] if found else None

    def contains(self, branch_hash: bytes) -> bool:
        with self._lock:
            return any(e.branch_hash == branch_hash for e in self._entries)

    @property
    def anchored_roots(self) -> List[bytes]:
        with self._lock:
            return list(self._roots)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


class Bcp:
    """Branch Commit Protocol orchestrator (paper Algorithm 3).

    The epoch counter belongs to the EPSL: events are tagged with the open
    epoch when they are indexed, and sealing closes it. Indexing, batching
    and sealing happen under one lock, so an event can never be tagged
    with an epoch that has already been sealed.
    """

    def __init__(self, epsl: Epsl, blob: BlobPipeline,
                 epoch_size: int = 512, finality_s: float = 1.0,
                 arrival_hz: float = 100.0,
                 anchor: Optional[InMemoryAnchor] = None,
                 prune_batch: int = PruneLog.DEFAULT_BATCH):
        if epoch_size < 1:
            raise ValueError("epoch_size must be positive")
        self._epsl       = epsl
        self._blob       = blob
        self._epoch_size = epoch_size
        self._finality_s = finality_s
        self._arrival_hz = arrival_hz
        self.anchor      = anchor if anchor is not None else InMemoryAnchor()
        self.prune_log   = PruneLog(batch_size=prune_batch)
        self._lock       = threading.RLock()
        self._batch:   List[Event]        = []
        self._commits: List[CommitResult] = []
        # Speculative events staged per branch until Phase 3 / 5 resolves them.
        self._pending: Dict[int, List[Event]] = {}

    @property
    def store(self) -> LineageStore:
        return self._epsl.store

    # ── Phase 1: speculative off-chain write ──────────────────────────────

    def phase1_write(self, sources: List[bytes], targets: List[bytes],
                     branch_id: int) -> List[bytes]:
        """Stage a speculative event: vertices and edges go to the
        LineageStore only. Returns the event's vertex hashes."""
        epoch = self.current_epoch
        for h in list(sources) + list(targets):
            self.store.put_vertex(Vertex(
                hash=h, content=b"", content_inline=False, vertex_type=0xFF,
                creation_epoch=epoch, agent_id=bytes(32),
                branch_mask=(1 << (branch_id & 63)),
                timestamp_ms=int(time.time() * 1000)))
        for src in sources:
            self.store.put_edge(src, epoch, list(targets))
        with self._lock:
            self._pending.setdefault(branch_id, []).append(
                (list(sources), list(targets)))
        return list(sources) + list(targets)

    def write_direct(self, sources: List[bytes], targets: List[bytes],
                     branch_id: int = 0) -> List[bytes]:
        """Non-speculative write (beta = 1): store, index and batch in one
        step. Used by LineageService and LineageHook."""
        hashes = self.phase1_write(sources, targets, branch_id)
        with self._lock:
            events = self._pending.pop(branch_id, [])
            self._insert_and_accumulate(events)
        return hashes

    # ── Phase 2: policy scoring ───────────────────────────────────────────

    @staticmethod
    def phase2_score(branches: List[Branch],
                     scorer: Callable[[Branch], float]) -> int:
        """winner = arg max Score(B, P). Returns the winner's id."""
        for b in branches:
            b.score = scorer(b)
        winner = max(branches, key=lambda b: b.score)
        winner.is_winner = True
        return winner.id

    # ── Phases 3 + 4: index the winner, batch, commit ─────────────────────

    def phase3_accumulate(self, winner: Branch) -> Optional[CommitResult]:
        """Index the winning branch's staged events and add them to the
        epoch batch; commits when the batch reaches w events."""
        with self._lock:
            events = self._pending.pop(winner.id, [])
            if not events and winner.event_hashes:
                # Nothing was staged through phase1_write (synthetic
                # benchmark branches): record the hashes as source-less.
                events = [([], list(winner.event_hashes))]
            return self._insert_and_accumulate(events)

    def _insert_and_accumulate(self, events: List[Event]) -> Optional[CommitResult]:
        commit = None
        with self._lock:
            for sources, targets in events:
                self._epsl.insert(sources, targets)
                self._batch.append((list(sources), list(targets)))
                if len(self._batch) >= self._epoch_size:
                    commit = self._commit_locked()
        return commit

    def flush_epoch(self) -> Optional[CommitResult]:
        """Seal and commit the open epoch now (epoch-timer path)."""
        with self._lock:
            if not self._batch:
                return None
            return self._commit_locked()

    def _commit_locked(self) -> CommitResult:
        events, self._batch = self._batch, []
        er        = self._epsl.seal()                              # I1
        data_hash = self._blob.submit(er, events)
        self.anchor.commit_root(er.root, er.epoch, data_hash)      # I2
        sub = self._blob.submissions[-1]
        result = CommitResult(epoch=er.epoch, root=er.root, data_hash=data_hash,
                              event_count=len(events),
                              payload_bytes=sub["bytes"], blobs=sub["blobs"])
        self._commits.append(result)
        return result

    # ── Phase 5: prune losers ─────────────────────────────────────────────

    def phase5_prune(self, branches: List[Branch], winner_id: int):
        """Log every losing branch in the PruneLog and garbage-collect the
        vertices that only it referenced. Vertices shared with another
        branch stay."""
        now = int(time.time() * 1000)
        for b in branches:
            if b.id == winner_id:
                continue
            with self._lock:
                staged = self._pending.pop(b.id, [])
            if staged and not b.event_hashes:
                b.event_hashes = [h for s, t in staged for h in (*s, *t)]
            closed = self.prune_log.append(PruneLogEntry(
                branch_id=b.id, branch_hash=b.branch_hash(),
                epoch=self.current_epoch, ts_ms=now))
            if closed is not None:
                self.anchor.commit_prune_root(*closed)
            self._gc_branch(b, staged)

    def flush_prune_log(self) -> Optional[Tuple[int, bytes]]:
        """Close and anchor the current partial prune-log batch."""
        closed = self.prune_log.flush()
        if closed is not None:
            self.anchor.commit_prune_root(*closed)
        return closed

    def _gc_branch(self, branch: Branch, staged: List[Event]):
        loser_bit = 1 << (branch.id & 63)
        for sources, targets in staged:
            gone = []
            for h in targets:            # sources may pre-exist / be shared
                v = self.store.get_vertex(h)
                if v is not None and (v.branch_mask & ~loser_bit) == 0 \
                        and not self._epsl.has_vertex(h):
                    self.store.remove_vertex(h)
                    gone.append(h)
            if gone:
                for s in sources:
                    self.store.drop_edges(s, gone)

    # ── Metrics ───────────────────────────────────────────────────────────

    def expected_commit_latency_s(self) -> float:
        """E[T_commit] = (w - j) / mu + t_inc (paper Eq. 5)."""
        with self._lock:
            j = len(self._batch)
        return max(0.0, self._epoch_size - j) / self._arrival_hz + self._finality_s

    @property
    def current_epoch(self) -> int:
        return self._epsl.current_epoch

    @property
    def committed_epochs(self) -> int:
        with self._lock:
            return len(self._commits)

    @property
    def commits(self) -> List[CommitResult]:
        with self._lock:
            return list(self._commits)

    @property
    def total_pruned(self) -> int:
        return len(self.prune_log)

    @property
    def batch_fill(self) -> int:
        with self._lock:
            return len(self._batch)

# ══════════════════════════════════════════════════════════════════════════════
# BranchManager — thread-safe branch context manager
# ══════════════════════════════════════════════════════════════════════════════

class BranchContext:
    """Context manager for one speculative branch."""

    def __init__(self, branch: Branch, bcp: Bcp):
        self._branch  = branch
        self._bcp     = bcp
        self._sources: List[bytes] = []
        self._targets: List[bytes] = []

    def __enter__(self) -> "BranchContext":
        return self

    def __exit__(self, *_):
        if self._targets:
            hashes = self._bcp.phase1_write(
                self._sources, self._targets, self._branch.id)
            self._branch.event_hashes.extend(hashes)

    def record_source(self, content: bytes):
        """Record an input. Raw content is content-hashed; a 32-byte value
        is treated as an existing vertex hash."""
        self._sources.append(sha256(content) if len(content) != 32 else content)

    def record_target(self, content: bytes):
        """Record an output (same normalisation as record_source)."""
        self._targets.append(sha256(content) if len(content) != 32 else content)

    def set_score(self, score: float):
        self._branch.score = score

    @property
    def branch(self) -> Branch:
        return self._branch


class BranchManager:
    """Thread-safe manager for BCP decision steps.

    Usage:
        manager = BranchManager(bcp, beta=4)
        with manager.new_step() as step:
            for b in step.branches:
                with step.context(b) as ctx:
                    ctx.record_source(input_hash)
                    ctx.record_target(output_bytes)
                    ctx.set_score(evaluate_output())
            winner_id = step.commit_winner()
    """

    def __init__(self, bcp: Bcp, beta: int = 4):
        self._bcp        = bcp
        self._beta       = beta
        self._lock       = threading.Lock()
        self._branch_ctr = 0
        self._step_ctr   = 0

    @contextmanager
    def new_step(self, beta: Optional[int] = None):
        b = beta or self._beta
        with self._lock:
            step_id  = self._step_ctr;   self._step_ctr   += 1
            bid_base = self._branch_ctr; self._branch_ctr += b
        yield _DecisionStep(step_id, bid_base, b, self._bcp)

    def context(self, branch: Branch) -> BranchContext:
        return BranchContext(branch, self._bcp)


class _DecisionStep:
    def __init__(self, step_id: int, bid_base: int, beta: int, bcp: Bcp):
        self.step_id  = step_id
        self.branches = [Branch(id=bid_base + i, epoch=bcp.current_epoch)
                         for i in range(beta)]
        self._bcp     = bcp

    def context(self, branch: Branch) -> BranchContext:
        return BranchContext(branch, self._bcp)

    def commit_winner(self, scorer: Optional[Callable[[Branch], float]] = None
                      ) -> int:
        if scorer:
            for b in self.branches:
                b.score = scorer(b)
        winner = max(self.branches, key=lambda b: b.score)
        winner.is_winner = True
        self._bcp.phase3_accumulate(winner)
        self._bcp.phase5_prune(self.branches, winner.id)
        return winner.id

# ══════════════════════════════════════════════════════════════════════════════
# LineageHook — node and tool-call callbacks for agent runtimes
# ══════════════════════════════════════════════════════════════════════════════

class LineageHook:
    """Lineage hook with node and tool-call callbacks.

    Turns the input/output pairs of an agent's nodes and tool calls into
    lineage events. The callbacks follow the shape of LangGraph's callback
    interface, but the class imports no agent framework: call the on_*
    methods from the framework's own callbacks, or wrap a node function
    with wrap_node. Thread-safe; branch_id names the branch that the
    events belong to.

    Usage:
        hook = LineageHook(bcp=bcp, branch_id=0)
        hook.on_tool_call("run1", "get_price", {"symbol": "ETH"})
        hook.on_tool_result("run1", "get_price", {"price": 2000})
        wrapped_node = hook.wrap_node("my_node", original_fn)
    """

    def __init__(self, bcp: Bcp, branch_id: int = 0,
                 agent_id: bytes = bytes(32)):
        self._bcp       = bcp
        self._branch_id = branch_id
        self._agent_id  = agent_id
        self._lock      = threading.Lock()
        self._pending:  Dict[str, bytes] = {}   # run_id → source hash

    def on_node_start(self, run_id: str, node_name: str, inputs: Any):
        """Checkpoint: node start — hash inputs as source vertex."""
        content = json.dumps(inputs, default=str, sort_keys=True).encode()
        with self._lock:
            self._pending[run_id] = sha256(content)

    def on_node_end(self, run_id: str, node_name: str, outputs: Any):
        """Checkpoint: node end — emit lineage event input→output."""
        with self._lock:
            source = self._pending.pop(run_id, None)
        content = json.dumps(outputs, default=str, sort_keys=True).encode()
        self._bcp.write_direct(
            [source] if source else [], [sha256(content)], self._branch_id)

    def on_tool_call(self, run_id: str, tool_name: str, tool_input: Any):
        """Checkpoint: tool call — record tool input as source."""
        content = json.dumps({"tool": tool_name, "input": tool_input},
                             default=str, sort_keys=True).encode()
        with self._lock:
            self._pending[run_id] = sha256(content)

    def on_tool_result(self, run_id: str, tool_name: str, result: Any):
        """Checkpoint: tool result — emit lineage event tool_input→result."""
        with self._lock:
            source = self._pending.pop(run_id, None)
        content = json.dumps({"tool": tool_name, "result": result},
                             default=str, sort_keys=True).encode()
        self._bcp.write_direct(
            [source] if source else [], [sha256(content)], self._branch_id)

    def wrap_node(self, name: str, fn: Callable) -> Callable:
        """Wrap a node function (LangGraph-style: state in, state out) with
        automatic lineage recording."""
        def wrapped(state: Any) -> Any:
            run_id = sha256(json.dumps(state, default=str).encode()).hex()
            self.on_node_start(run_id, name, state)
            result = fn(state)
            self.on_node_end(run_id, name, result)
            return result
        return wrapped

# ══════════════════════════════════════════════════════════════════════════════
# LineageService — service facade (WriteLineage / QueryBL / QueryFI /
# QueryTS / Verify). This is the in-process reference of the interface a
# networked deployment would expose. Latency and throughput must be
# MEASURED on the target hardware (see engine/src/bin/bench.rs and
# dataset_gen.py) — nothing is hard-coded here.
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class WriteRequest:
    sources:   List[bytes]
    targets:   List[bytes]
    branch_id: int = 0

@dataclass
class WriteResponse:
    inserted_hashes: List[bytes]
    new_vertices:    int
    epoch:           int          # epoch the event was indexed in

@dataclass
class QueryRequest:
    vertex_hash: bytes
    epoch:       Optional[int] = None     # None = latest sealed epoch
    max_depth:   Optional[int] = None     # None = full transitive closure

@dataclass
class QueryResponse:
    hashes:      List[bytes]
    proof:       Optional[QueryProof]
    epoch:       int
    verified:    bool   # the proof is internally valid for its stated root
    anchored:    bool   # ...and that root is the one on the anchor contract
    proof_bytes: int = 0
    path_hashes: int = 0


class LineageService:
    """Service facade over the BCP and the EPSL.

    Writes take the BCP's direct path. Queries are pinned to a sealed
    epoch and return the QueryProof; `anchored` is True only if the proof
    verifies against the root that the anchor holds for that epoch.
    """

    def __init__(self, epsl: Epsl, bcp: Bcp):
        self._epsl    = epsl
        self._bcp     = bcp
        self._lock    = threading.Lock()
        self._metrics = {"writes_total": 0, "queries_bl": 0,
                         "queries_fi":   0, "queries_ts": 0}

    def write_lineage(self, req: WriteRequest) -> WriteResponse:
        before = self._epsl.node_count
        epoch  = self._bcp.current_epoch
        hashes = self._bcp.write_direct(req.sources, req.targets, req.branch_id)
        with self._lock:
            self._metrics["writes_total"] += 1
        return WriteResponse(inserted_hashes=hashes,
                             new_vertices=self._epsl.node_count - before,
                             epoch=epoch)

    def query_bl(self, req: QueryRequest) -> QueryResponse:
        return self._query("BL", "queries_bl", req)

    def query_fi(self, req: QueryRequest) -> QueryResponse:
        return self._query("FI", "queries_fi", req)

    def query_ts(self, req: QueryRequest) -> QueryResponse:
        if req.epoch is None:
            raise ValueError("QueryTS requires an epoch")
        return self._query("TS", "queries_ts", req)

    def verify(self, resp: QueryResponse) -> bool:
        """Client-side check: verify the response's proof against the root
        fetched independently from the anchor contract."""
        if resp.proof is None:
            return False
        onchain = self._bcp.anchor.epoch_root(resp.proof.epoch)
        if onchain is None:
            return False
        return verify_query(resp.proof, onchain) == resp.hashes

    @property
    def metrics(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._metrics)

    def _query(self, kind: str, counter: str, req: QueryRequest) -> QueryResponse:
        with self._lock:
            self._metrics[counter] += 1
        res   = self._epsl.query(req.vertex_hash, kind, req.epoch, req.max_depth)
        proof = res.proof
        verified = proof is not None and verify_query(proof, proof.root) == res.hashes
        onchain  = self._bcp.anchor.epoch_root(res.epoch) if res.epoch >= 0 else None
        anchored = (proof is not None and onchain is not None
                    and verify_query(proof, onchain) == res.hashes)
        return QueryResponse(hashes=res.hashes, proof=proof, epoch=res.epoch,
                             verified=verified, anchored=anchored,
                             proof_bytes=proof.byte_size if proof else 0,
                             path_hashes=proof.path_hashes if proof else 0)

# ══════════════════════════════════════════════════════════════════════════════
# AeTpcc — agent-extended TPC-C lineage workload (paper Table II)
#
# Rows are versioned: reading a row references its current version, writing
# a row creates a new version (a new item). One lineage event is emitted per
# transaction, with the versions it read as inputs and the versions it wrote
# as outputs, so later transactions build on the outputs of earlier ones.
# The Rust engine carries a port of this generator (engine/src/workload.rs);
# both derive item hashes from "table:key:version" strings.
# ══════════════════════════════════════════════════════════════════════════════

# TPC-C transaction mix
AETPCC_MIX = [
    ("NewOrder",    0.45),
    ("Payment",     0.43),
    ("OrderStatus", 0.04),
    ("Delivery",    0.04),
    ("StockLevel",  0.04),
]

# |S| and |T| per event type as (lo, hi). A New-Order with k in 3..6 order
# lines reads district, customer, k items and k stock rows, and writes the
# district, the order, k order lines and k stock rows.
AETPCC_LINEAGE: Dict[str, Tuple[Tuple[int, int], Tuple[int, int]]] = {
    "NewOrder":    ((8, 14), (8, 14)),
    "Payment":     ((2, 2),  (1, 1)),
    "OrderStatus": ((3, 3),  (1, 1)),
    "Delivery":    ((10, 10), (10, 10)),
    "StockLevel":  ((20, 20), (1, 1)),
    "AgentStep":   ((4, 12), (1, 4)),   # one per decision step, not in the mix
}


@dataclass
class AeTpccEvent:
    tx_type:    str
    tx_id:      int
    branch_id:  int
    sources:    List[bytes]
    targets:    List[bytes]
    latency_ms: float = 0.0


class AeTpcc:
    """Agent-extended TPC-C workload generator (paper Sect. 9.1)."""

    DISTRICTS_PER_WH = 10

    def __init__(self, seed: int = 42, beta: int = 4, warehouses: int = 10,
                 agents: int = 100, tx_per_step: int = 10,
                 customers_per_district: int = 3000, items: int = 100_000):
        self._rng        = random.Random(seed)
        self._beta       = beta
        self._warehouses = warehouses
        self._agents     = agents
        self._tx_per_step = tx_per_step
        self._cpd        = customers_per_district
        self._items      = items
        self._tx_ctr     = 0
        self._step_ctr   = 0
        self._branch_ctr = 0
        self._c_cust     = self._rng.randint(0, 1023)      # NURand constants
        self._c_item     = self._rng.randint(0, 8191)
        self._version: Dict[Tuple[str, int], int] = {}
        self._fresh_ctr: Dict[str, int] = {}
        self._undelivered: List[deque] = [deque() for _ in range(warehouses)]
        self._recent_orders: deque = deque(maxlen=1000)
        self._memory: Dict[int, bytes] = {}

    # ── row versions ───────────────────────────────────────────────────────

    @staticmethod
    def item_hash(table: str, key: int, version: int) -> bytes:
        return sha256(f"{table}:{key}:{version}".encode())

    def _read(self, table: str, key: int) -> bytes:
        return self.item_hash(table, key, self._version.get((table, key), 0))

    def _write(self, table: str, key: int) -> bytes:
        v = self._version.get((table, key), 0) + 1
        self._version[(table, key)] = v
        return self.item_hash(table, key, v)

    def _fresh(self, table: str) -> Tuple[int, bytes]:
        key = self._fresh_ctr.get(table, 0)
        self._fresh_ctr[table] = key + 1
        return key, self.item_hash(table, key, 0)

    def _nurand(self, a: int, c: int, n: int) -> int:
        """TPC-C NURand(A, 0, n-1) with run-time constant c."""
        return ((self._rng.randint(0, a) | self._rng.randint(0, n - 1)) + c) % n

    def _distinct_items(self, k: int) -> List[int]:
        out: List[int] = []
        while len(out) < k:
            i = self._nurand(8191, self._c_item, self._items)
            if i not in out:
                out.append(i)
        return out

    # ── TPC-C transactions ─────────────────────────────────────────────────

    def _pick_tx_type(self) -> str:
        r = self._rng.random()
        cumul = 0.0
        for name, freq in AETPCC_MIX:
            cumul += freq
            if r < cumul:
                return name
        return AETPCC_MIX[-1][0]

    def _district_customer(self) -> Tuple[int, int, int]:
        w = self._rng.randrange(self._warehouses)
        d = w * self.DISTRICTS_PER_WH + self._rng.randrange(self.DISTRICTS_PER_WH)
        c = d * self._cpd + self._nurand(1023, self._c_cust, self._cpd)
        return w, d, c

    def _new_order(self) -> Tuple[List[bytes], List[bytes]]:
        w, d, c = self._district_customer()
        items = self._distinct_items(self._rng.randint(3, 6))
        stock = [w * self._items + i for i in items]
        sources = ([self._read("district", d), self._read("customer", c)]
                   + [self._read("item", i) for i in items]
                   + [self._read("stock", s) for s in stock])
        okey, order = self._fresh("order")
        targets = ([self._write("district", d), order]
                   + [self._fresh("orderline")[1] for _ in items]
                   + [self._write("stock", s) for s in stock])
        self._undelivered[w].append(okey)
        self._recent_orders.append(okey)
        return sources, targets

    def _payment(self) -> Tuple[List[bytes], List[bytes]]:
        _w, d, c = self._district_customer()
        return ([self._read("customer", c), self._read("district", d)],
                [self._write("customer", c)])

    def _order_status(self) -> Tuple[List[bytes], List[bytes]]:
        _w, d, c = self._district_customer()
        sources = [self._read("customer", c)]
        recent = list(self._recent_orders)
        picks = self._rng.sample(recent, 2) if len(recent) >= 2 else []
        sources += [self._read("order", o) for o in picks]
        if not picks:                         # warm-up: no orders yet
            sources += [self._read("district", d),
                        self._read("item", self._nurand(8191, self._c_item, self._items))]
        return sources, [self._fresh("status")[1]]

    def _delivery(self) -> Optional[Tuple[List[bytes], List[bytes]]]:
        w = self._rng.randrange(self._warehouses)
        queue = self._undelivered[w]
        if len(queue) < 10:
            return None
        orders = [queue.popleft() for _ in range(10)]
        return ([self._read("order", o) for o in orders],
                [self._write("order", o) for o in orders])

    def _stock_level(self) -> Tuple[List[bytes], List[bytes]]:
        w = self._rng.randrange(self._warehouses)
        items = self._distinct_items(20)
        return ([self._read("stock", w * self._items + i) for i in items],
                [self._fresh("stocklevel")[1]])

    def next_event(self, branch_id: int = 0,
                   tx_type: Optional[str] = None) -> AeTpccEvent:
        """Next TPC-C transaction as a lineage event."""
        tx_type = tx_type or self._pick_tx_type()
        if tx_type == "Delivery":
            st = self._delivery()
            if st is None:                    # fewer than ten open orders
                tx_type, st = "NewOrder", self._new_order()
        elif tx_type == "NewOrder":
            st = self._new_order()
        elif tx_type == "Payment":
            st = self._payment()
        elif tx_type == "OrderStatus":
            st = self._order_status()
        elif tx_type == "StockLevel":
            st = self._stock_level()
        else:
            raise ValueError(f"unknown transaction type {tx_type!r}")
        ev = AeTpccEvent(tx_type=tx_type, tx_id=self._tx_ctr, branch_id=branch_id,
                         sources=st[0], targets=st[1])
        self._tx_ctr += 1
        return ev

    # ── agent decision steps ───────────────────────────────────────────────

    def agent_step(self, beta: Optional[int] = None) -> List[AeTpccEvent]:
        """One decision step: `beta` candidate events that read the same
        inputs (the agent's last decision and current database rows) and
        produce different decisions. Call `agent_commit` with the winner."""
        beta  = beta or self._beta
        agent = self._step_ctr % self._agents
        self._step_ctr += 1
        n_src = self._rng.randint(4, 12)
        sources: List[bytes] = []
        if agent in self._memory:
            sources.append(self._memory[agent])
        recent = list(self._recent_orders)
        while len(sources) < n_src:
            if recent and self._rng.random() < 0.5:
                h = self._read("order", self._rng.choice(recent))
            else:
                w = self._rng.randrange(self._warehouses)
                h = self._read("stock", w * self._items
                               + self._nurand(8191, self._c_item, self._items))
            if h not in sources:
                sources.append(h)
        n_tgt = self._rng.randint(1, 4)
        out: List[AeTpccEvent] = []
        for _ in range(beta):
            self._branch_ctr += 1
            targets = [self._fresh("decision")[1] for _ in range(n_tgt)]
            out.append(AeTpccEvent(tx_type="AgentStep", tx_id=agent,
                                   branch_id=self._branch_ctr,
                                   sources=list(sources), targets=targets))
        return out

    def agent_commit(self, winner: AeTpccEvent) -> None:
        """Remember the winning decision as the agent's memory."""
        self._memory[winner.tx_id] = winner.targets[0]

    # ── driver ─────────────────────────────────────────────────────────────

    def run(self, bcp: Bcp, n_events: int,
            verbose: bool = False) -> Dict[str, Any]:
        """Drive `n_events` TPC-C transactions through the BCP, plus one
        agent decision step per `tx_per_step` transactions: every candidate
        is Phase-1 written, one wins (Phases 2-4), the others are pruned
        (Phase 5)."""
        counts: Dict[str, int] = {name: 0 for name, _ in AETPCC_MIX}
        counts["AgentStep"] = 0
        latencies: List[float] = []

        for i in range(n_events):
            ev = self.next_event()
            counts[ev.tx_type] += 1
            t0 = time.perf_counter()
            bcp.write_direct(ev.sources, ev.targets, 0)
            latencies.append((time.perf_counter() - t0) * 1000)

            if (i + 1) % self._tx_per_step == 0:
                branches = []
                cands = self.agent_step()
                for aev in cands:
                    counts["AgentStep"] += 1
                    t0 = time.perf_counter()
                    hashes = bcp.phase1_write(aev.sources, aev.targets, aev.branch_id)
                    latencies.append((time.perf_counter() - t0) * 1000)
                    branches.append(Branch(id=aev.branch_id, epoch=bcp.current_epoch,
                                           event_hashes=hashes))
                wid = Bcp.phase2_score(branches, scorer=lambda b: self._rng.random())
                winner = next(b for b in branches if b.id == wid)
                bcp.phase3_accumulate(winner)
                bcp.phase5_prune(branches, wid)
                self.agent_commit(next(a for a in cands if a.branch_id == wid))

        latencies.sort()
        n    = len(latencies)
        p50  = latencies[n // 2]        if n else 0.0
        p99  = latencies[int(n * 0.99)] if n else 0.0
        mean = sum(latencies) / n       if n else 0.0
        stats = {
            "n_events":      n_events,
            "tx_counts":     counts,
            "commits":       bcp.committed_epochs,
            "epsl_nodes":    bcp._epsl.node_count,
            "epsl_edges":    bcp._epsl.edge_count,
            "dedup_ratio":   bcp.store.dedup_ratio,
            "pruned":        bcp.total_pruned,
            "write_p50_ms":  round(p50,  4),
            "write_p99_ms":  round(p99,  4),
            "write_mean_ms": round(mean, 4),
        }
        if verbose:
            print(f"  AE-TPCC {n_events} tx | commits={stats['commits']} "
                  f"| p50={p50:.4f} ms | p99={p99:.4f} ms")
        return stats

# ══════════════════════════════════════════════════════════════════════════════
# Cost model (paper Eq. 1) and commit latency (paper Eq. 5)
# ══════════════════════════════════════════════════════════════════════════════

def commit_cost_wei(commit_gas: int, payload_bytes: int,
                    gas_price_wei: float, blob_gas_price_wei: float) -> float:
    """On-chain cost of one epoch: execution gas of commitRoot plus the
    blob gas of the payload. Blobs are charged whole: ceil(bytes / 126976)
    blobs of 2^17 blob gas each."""
    return (commit_gas * gas_price_wei
            + blobs_needed(payload_bytes) * BLOB_GAS_PER_BLOB * blob_gas_price_wei)


def cost_per_event_usd(epoch_size: int, bytes_per_event: float, commit_gas: int,
                       gas_gwei: float, blob_gwei: float, eth_usd: float) -> float:
    """Amortised on-chain cost per committed event,
    C(w) = (G_commit * p_gas + ceil(w * s / B) * G_blob * p_blob) / w.

    `commit_gas` and `bytes_per_event` are measurements (forge gas report
    and BlobPipeline.submissions); prices are whatever the reader assumes.
    """
    payload = BLOB_HEADER_SIZE + int(math.ceil(epoch_size * bytes_per_event))
    wei = commit_cost_wei(commit_gas, payload, gas_gwei * 1e9, blob_gwei * 1e9)
    return wei / 1e18 * eth_usd / epoch_size


def expected_commit_latency_s(w: int, j: int, mu: float, t_inc: float) -> float:
    """E[T_commit] = (w - j) / mu + t_inc for a batch that already holds j
    of w events, arrival rate mu and inclusion time t_inc."""
    return max(0.0, w - j) / mu + t_inc

# ══════════════════════════════════════════════════════════════════════════════
# Conformance vectors — consumed by the Rust engine (tests/conformance.rs) and
# by the Foundry tests (contracts/test/Conformance.t.sol)
# ══════════════════════════════════════════════════════════════════════════════

def _vec_item(i: int) -> bytes:
    return sha256(b"vector-item-%d" % i)


def conformance_scenario() -> List[List[Event]]:
    """A small deterministic history: six epochs of events over a growing
    item pool, including shared inputs, an output that is derived twice,
    a two-vertex cycle and an input-less output."""
    epochs: List[List[Event]] = []
    nxt = 40                                   # items 0..39 are base inputs
    for e in range(6):
        events: List[Event] = []
        for j in range(12):
            n_s = 1 + (j + e) % 4
            n_t = 1 + (j * 7 + e) % 3
            srcs = [_vec_item((j * 5 + e * 11 + k * 13) % nxt) for k in range(n_s)]
            tgts = [_vec_item(nxt + k) for k in range(n_t)]
            nxt += n_t
            events.append((srcs, tgts))
        if e == 2:
            events.append(([_vec_item(3)], [_vec_item(41)]))   # second derivation of 41
            events.append(([_vec_item(50)], [_vec_item(51)]))  # cycle 50 <-> 51
            events.append(([_vec_item(51)], [_vec_item(50)]))
            events.append(([], [_vec_item(10_000)]))           # no inputs
        epochs.append(events)
    return epochs


def conformance_vectors() -> Dict[str, Any]:
    hx = lambda b: b.hex()
    epsl = Epsl()
    out: Dict[str, Any] = {
        "format": 2,
        "sentinel_leaf": hx(SENTINEL_LEAF),
        "l_max": L_MAX,
        "levels": [{"h": hx(_vec_item(i)), "level": skip_level(_vec_item(i))}
                   for i in range(24)],
        "epochs": [], "membership": [], "queries": [],
    }
    scenario = conformance_scenario()
    for events in scenario:
        for s, t in events:
            epsl.insert(s, t)
        er = epsl.seal()
        out["epochs"].append({
            "epoch": er.epoch, "root": hx(er.root),
            "new_vertices": er.new_vertices, "touched": er.touched,
            "events": [{"s": [hx(x) for x in s], "t": [hx(x) for x in t]}
                       for s, t in events]})
    for i, e in [(0, 0), (41, 1), (41, 5), (50, 3), (10_000, 2), (77, 5)]:
        mp = epsl.membership(_vec_item(i), e)
        assert mp is not None and mp.verify()
        out["membership"].append({
            "h": hx(mp.vertex), "epoch": e, "digest": hx(mp.digest),
            "leaf": hx(mp.leaf), "path": [hx(x) for x in mp.path],
            "root": hx(mp.root)})
    last = scenario[5][-1][1][0]
    for kind, origin, e, depth in [
            ("BL", last, 5, None), ("BL", last, 5, 2), ("BL", _vec_item(41), 1, None),
            ("TS", _vec_item(41), 5, None), ("FI", _vec_item(3), 5, 2),
            ("FI", _vec_item(0), 0, None), ("BL", _vec_item(50), 5, None),
            ("FI", _vec_item(10_000), 5, None)]:
        res = epsl.query(origin, kind, e, depth)
        assert res.proof is not None
        root = epsl.get_epoch_root(e).root
        assert verify_query(res.proof, root) == res.hashes
        out["queries"].append({
            "kind": kind, "origin": hx(origin), "epoch": e, "max_depth": depth,
            "result": [hx(x) for x in res.hashes], "proof": hx(res.proof.to_bytes())})
    er0 = epsl.get_epoch_root(0)
    raw = encode_blob(0, er0.root, scenario[0], CODEC_RAW)
    out["payload"] = {"epoch": 0, "raw": hx(raw), "data_hash": hx(sha256(raw)),
                      "zlib": hx(encode_blob(0, er0.root, scenario[0], CODEC_ZLIB))}
    log = PruneLog(batch_size=5)
    entries = [PruneLogEntry(branch_id=100 + i, branch_hash=sha256(b"pruned-%d" % i),
                             epoch=i // 2, ts_ms=1_700_000_000_000 + i)
               for i in range(5)]
    closed = [log.append(en) for en in entries][-1]
    bi, mp = log.membership(entries[3].branch_hash)
    out["prune"] = {
        "entries": [hx(en.pack()) for en in entries],
        "root": hx(closed[1]), "batch": bi,
        "proof": {"leaf": hx(mp.leaf), "path": [hx(x) for x in mp.path]}}
    # The same membership and prune-log proofs with 0x prefixes, for the
    # Foundry tests (vm.parseJsonBytes32 expects 0x-prefixed hex).
    ox = lambda h: "0x" + h
    out["evm"] = {
        "membership": [{"epoch": m["epoch"], "root": ox(m["root"]), "vertex": ox(m["h"]),
                        "digest": ox(m["digest"]), "leaf": ox(m["leaf"]),
                        "path": [ox(x) for x in m["path"]]} for m in out["membership"]],
        "prune": {"batch": bi, "root": ox(out["prune"]["root"]),
                  "leaf": ox(out["prune"]["proof"]["leaf"]),
                  "path": [ox(x) for x in out["prune"]["proof"]["path"]]},
    }
    return out

# ══════════════════════════════════════════════════════════════════════════════
# Test suite
# ══════════════════════════════════════════════════════════════════════════════

def _naive_reach(edges: List[Tuple[bytes, bytes, int]], origin: bytes, forward: bool,
                 epoch: int, max_depth: Optional[int]) -> Set[bytes]:
    """Reference answer: plain BFS over an edge list (s, t, epoch)."""
    adj: Dict[bytes, Set[bytes]] = {}
    for s, t, ep in edges:
        if ep <= epoch:
            a, b = (s, t) if forward else (t, s)
            adj.setdefault(a, set()).add(b)
    seen = {origin: 0}
    queue = deque([origin])
    while queue:
        h = queue.popleft()
        if max_depth is not None and seen[h] >= max_depth:
            continue
        for nb in adj.get(h, ()):
            if nb not in seen:
                seen[nb] = seen[h] + 1
                queue.append(nb)
    return set(seen)


def _run_tests():
    passed = failed = 0

    def test(name: str, fn: Callable):
        nonlocal passed, failed
        try:
            fn(); print(f"  ✓ {name}"); passed += 1
        except Exception as e:
            import traceback
            print(f"  ✗ {name}: {e}")
            traceback.print_exc(); failed += 1

    def raises(fn: Callable, exc=Exception) -> bool:
        try:
            fn()
        except exc:
            return True
        return False

    H = lambda s: sha256(s if isinstance(s, bytes) else s.encode())

    # ── Hashing primitives ────────────────────────────────────────────────
    print("\n── Hashing primitives " + "─" * 36)

    def t_keccak_vectors():
        assert keccak256(b"").hex() == \
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        assert keccak256(b"abc").hex() == \
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        assert _keccak256_py(b"abc") == keccak256(b"abc")
        assert _keccak256_py(b"x" * 136) == keccak256(b"x" * 136)
    test("keccak256_reference_vectors", t_keccak_vectors)

    def t_canonical_ordering():
        a, b = H("a"), H("b")
        assert hash_pair(a, b) == hash_pair(b, a)
    test("hash_pair_is_commutative", t_canonical_ordering)

    def t_leaf_is_double_hashed():
        v, d = H("v"), H("d")
        assert node_leaf(v, d) == keccak256(keccak256(v + d))
        # the single hash is what an interior node over (v, d) would be
        lo, hi = sorted([v, d])
        assert node_leaf(v, d) != hash_pair(lo, hi)
    test("leaf_is_double_hashed", t_leaf_is_double_hashed)

    # ── MerkleTree (prune-log batches) ────────────────────────────────────
    print("\n── MerkleTree " + "─" * 44)

    def t_merkle_all_sizes():
        for n in [1, 2, 3, 4, 7, 8, 15, 16, 17, 100, 512]:
            leaves = [H(str(i)) for i in range(n)]
            tree   = MerkleTree(leaves)
            for idx in range(n):
                p = tree.proof(idx)
                assert p is not None and p.verify(), f"n={n} idx={idx}"
        assert MerkleTree([H("a")]).root() == H("a")
    test("merkle_proofs_all_sizes", t_merkle_all_sizes)

    def t_merkle_tamper():
        p = MerkleTree([H(str(i)) for i in range(8)]).proof(0)
        p.leaf = bytes([p.leaf[0] ^ 0xFF]) + p.leaf[1:]
        assert not p.verify()
    test("merkle_tampered_proof_rejected", t_merkle_tamper)

    def t_merkle_odd_promoted():
        a, b, c = H("a"), H("b"), H("c")
        assert MerkleTree([a, b, c]).root() != MerkleTree([a, b, c, c]).root()
        assert MerkleTree([a, b, c]).root() == hash_pair(hash_pair(a, b), c)
        for n, exp in [(1, 0), (2, 1), (3, 2), (4, 2), (8, 3), (9, 4), (100, 7)]:
            assert MerkleTree([H(str(i)) for i in range(n)]).depth() == exp
    test("merkle_odd_node_promoted_not_duplicated", t_merkle_odd_promoted)

    # ── LineageStore ──────────────────────────────────────────────────────
    print("\n── LineageStore " + "─" * 42)

    def t_vertex_hash_is_sha256():
        v = Vertex.new(b"hello", 0x01, 0, bytes(32), 0)
        assert v.hash == sha256(b"hello")
    test("vertex_hash_is_sha256", t_vertex_hash_is_sha256)

    def t_dag_merge():
        store = LineageStore()
        v1 = Vertex.new(b"shared", 0x01, 0, bytes(32), 1)
        v2 = Vertex.new(b"shared", 0x01, 0, bytes(32), 2)
        n1, _ = store.put_vertex(v1); n2, _ = store.put_vertex(v2)
        assert n1 and not n2 and store.dag_merges_total == 1
        sv = store.get_vertex(sha256(b"shared"))
        assert sv is not None and (sv.branch_mask & (1 << 2))
    test("store_merges_shared_vertices", t_dag_merge)

    def t_edge_scan():
        store = LineageStore()
        src = H("src"); t1 = H("t1"); t2 = H("t2"); t3 = H("t3")
        store.put_edge(src, 0, [t1]); store.put_edge(src, 1, [t2, t3])
        store.put_edge(src, 1, [t2])                       # duplicate ignored
        assert store.scan_edges(src, 0, 1) == [t1, t2, t3]
        assert store.scan_edges(src, 1, 1) == [t2, t3] and store.edge_count == 3
        store.drop_edges(src, [t2])
        assert store.scan_edges(src, 0, 5) == [t1, t3]
        store.drop_edges(src, [t1, t3])
        assert store.scan_edges(src, 0, 5) == [] and store.edge_count == 0
    test("store_edge_scan_and_drop", t_edge_scan)

    # ── Authenticated skip list ───────────────────────────────────────────
    print("\n── Authenticated skip list " + "─" * 31)

    def build(keys: List[bytes], leaf=lambda k: H(b"leaf" + k)) -> _SlNode:
        root = _sl_new()
        for k in keys:
            lv = skip_level(k)
            root = _sl_insert(_sl_grow(root, lv), k, lv, leaf(k))
        return root

    def fold(leaf: bytes, path: List[bytes]) -> bytes:
        for sib in path:
            leaf = hash_pair(leaf, sib)
        return leaf

    def t_levels():
        hs = [H(str(i)) for i in range(4096)]
        lv = [skip_level(h) for h in hs]
        assert all(0 <= x <= L_MAX for x in lv)
        assert 0.45 < sum(1 for x in lv if x >= 1) / len(lv) < 0.55
        assert 0.20 < sum(1 for x in lv if x >= 2) / len(lv) < 0.30
        assert skip_level(bytes(32)) == L_MAX
        assert skip_level(bytes(31) + b"\x01") == 0
        assert skip_level(bytes(31) + b"\x08") == 3
        assert skip_level(b"\x01" + bytes(31)) == L_MAX     # high-order bits are ignored
    test("levels_are_geometric_and_low_order", t_levels)

    def t_empty_root():
        assert _sl_new().label() == SENTINEL_LEAF != bytes(32)
        assert _sl_grow(_sl_new(), 9).label() == SENTINEL_LEAF
    test("empty_root_is_sentinel", t_empty_root)

    def t_history_independent():
        keys = [H(str(i)) for i in range(300)]
        r1 = build(keys).label()
        rng = random.Random(1)
        for _ in range(3):
            shuffled = keys[:]; rng.shuffle(shuffled)
            assert build(shuffled).label() == r1
        assert sl_keys(build(keys)) == sorted(keys)
    test("root_independent_of_insertion_order", t_history_independent)

    def t_membership_all():
        for n in [1, 2, 3, 5, 8, 33, 200]:
            keys = [H(f"k{n}-{i}") for i in range(n)]
            root = build(keys)
            for k in keys:
                path: List[bytes] = []
                assert _sl_path(root, k, path)
                assert fold(H(b"leaf" + k), path) == root.label(), f"n={n}"
            assert not _sl_path(root, H("absent"), [])
    test("membership_paths_all_keys", t_membership_all)

    def t_update_and_persistence():
        keys = [H(str(i)) for i in range(64)]
        v1 = build(keys)
        k = keys[17]
        v2 = _sl_update(v1, k, H("new leaf"))
        assert v1.label() != v2.label()
        p1: List[bytes] = []; p2: List[bytes] = []
        assert _sl_path(v1, k, p1) and _sl_path(v2, k, p2)
        assert fold(H(b"leaf" + k), p1) == v1.label()       # old version intact
        assert fold(H("new leaf"), p2) == v2.label()
        assert fold(H(b"leaf" + k), p2) != v2.label()
        assert raises(lambda: _sl_update(v1, H("absent"), H("x")), KeyError)
    test("update_copies_path_old_version_intact", t_update_and_persistence)

    def t_path_length_logarithmic():
        keys = [H(str(i)) for i in range(2000)]
        root = build(keys)
        total = 0
        for k in keys:
            path: List[bytes] = []
            _sl_path(root, k, path); total += len(path)
        avg = total / len(keys)
        assert 1.0 * math.log2(2000) < avg < 2.2 * math.log2(2000), avg
    test("path_length_about_1.5_log2_n", t_path_length_logarithmic)

    # ── Adjacency chains ──────────────────────────────────────────────────
    print("\n── Adjacency chains " + "─" * 38)

    def t_chain():
        a, b, c = sorted([H("a"), H("b"), H("c")])
        h1 = chain_link(ZERO32, 0, [a, b])
        h2 = chain_link(h1, 3, [c])
        assert chain_head([(0, [a, b]), (3, [c])]) == h2
        assert chain_head([]) == ZERO32
        assert chain_link(ZERO32, 0, [a, b]) != chain_link(ZERO32, 0, [b, a])
        assert chain_link(ZERO32, 0, [a, b]) != chain_link(ZERO32, 1, [a, b])
        adj = _Adj(); adj.groups = [(0, [a, b]), (3, [c])]; adj.head = h2
        assert adj.as_of(2) == [(0, [a, b])] and adj.head_as_of(2) == h1
        assert adj.as_of(3) == adj.groups and adj.head_as_of(7) == h2
        assert adj.as_of(-1) == [] and adj.head_as_of(-1) == ZERO32
    test("chain_links_and_as_of", t_chain)

    # ── Epsl ──────────────────────────────────────────────────────────────
    print("\n── Epsl " + "─" * 50)

    def t_insert_creates_vertices_and_edges():
        epsl = Epsl()
        s, t_ = H("oracle"), H("decision")
        assert epsl.insert([s], [t_]) == [s, t_]
        epsl.insert([s], [t_])                      # duplicate edge ignored
        epsl.insert([t_], [t_])                     # self-loop ignored
        assert epsl.node_count == 2 and epsl.edge_count == 1
        assert raises(lambda: epsl.insert([b"short"], [t_]), ValueError)
    test("insert_creates_vertices_and_edges", t_insert_creates_vertices_and_edges)

    def t_seal_and_roots():
        epsl = Epsl()
        assert epsl.latest_sealed == -1 and epsl.latest_epoch_root() is None
        for i in range(10):
            epsl.insert([], [H(f"item-{i}")])
        er = epsl.seal()
        assert er.epoch == 0 and er.new_vertices == 10 and er.touched == 10
        assert er.root not in (bytes(32), SENTINEL_LEAF)
        assert epsl.current_epoch == 1 and epsl.get_epoch_root(0) == er
        er1 = epsl.seal()                           # empty epoch: root unchanged
        assert er1.epoch == 1 and er1.root == er.root and er1.touched == 0
    test("seal_returns_root_and_opens_next_epoch", t_seal_and_roots)

    def t_root_depends_only_on_records():
        evs = [([H("a")], [H("b")]), ([H("b"), H("c")], [H("d")]), ([], [H("e")])]
        e1 = Epsl(); e2 = Epsl()
        for s, t_ in evs:
            e1.insert(s, t_)
        for s, t_ in reversed(evs):
            e2.insert(s, t_)
        assert e1.seal().root == e2.seal().root
    test("root_depends_only_on_records", t_root_depends_only_on_records)

    def t_query_needs_seal():
        epsl = Epsl()
        s, t_ = H("oracle"), H("decision")
        epsl.insert([s], [t_])
        assert epsl.query_bl(t_).hashes == []                  # nothing sealed yet
        fresh = epsl.query(t_, "BL", pending=True)
        assert fresh.hashes == [t_, s] and fresh.proof is None and not fresh.sealed
        root = epsl.seal().root
        res = epsl.query_bl(t_)
        assert res.hashes == [t_, s] and res.sealed and res.epoch == 0
        assert res.proof.root == root and verify_query(res.proof, root) == res.hashes
        assert raises(lambda: epsl.query_bl(t_, epoch=1), ValueError)
        assert epsl.query_bl(H("unknown")).proof is None
    test("queries_are_pinned_to_sealed_epochs", t_query_needs_seal)

    def chain_index(n: int = 4):
        """v0 -> v1 -> ... -> v(n-1), one event per epoch."""
        epsl = Epsl()
        vs = [H(f"chain-{i}") for i in range(n)]
        roots = []
        epsl.insert([], [vs[0]])
        for i in range(1, n):
            epsl.insert([vs[i - 1]], [vs[i]])
            roots.append(epsl.seal().root)
        return epsl, vs, roots

    def t_bl_fi_full():
        epsl, vs, roots = chain_index(4)
        bl = epsl.query_bl(vs[3])
        assert bl.hashes == [vs[3], vs[2], vs[1], vs[0]]
        assert verify_query(bl.proof, roots[-1]) == bl.hashes
        fi = epsl.query_fi(vs[0])
        assert fi.hashes == vs
        assert verify_query(fi.proof, roots[-1]) == fi.hashes
        assert len(bl.proof.entries) == 4 and bl.proof.path_hashes > 0
    test("backward_and_forward_closure", t_bl_fi_full)

    def t_depth_bound():
        epsl, vs, roots = chain_index(5)
        res = epsl.query_bl(vs[4], max_depth=1)
        assert res.hashes == [vs[4], vs[3]] and len(res.proof.entries) == 1
        assert verify_query(res.proof, roots[-1]) == res.hashes
        res2 = epsl.query_bl(vs[4], max_depth=3)
        assert res2.hashes == [vs[4], vs[3], vs[2], vs[1]]
        assert verify_query(res2.proof, roots[-1]) == res2.hashes
        # claiming a different bound with the same records fails either way
        res2.proof.max_depth = 2
        assert verify_query(res2.proof, roots[-1]) is None      # padded
        res2.proof.max_depth = 4
        assert verify_query(res2.proof, roots[-1]) is None      # incomplete
        assert raises(lambda: epsl.query_bl(vs[4], max_depth=0), ValueError)
    test("depth_bounded_queries", t_depth_bound)

    def t_ts_pinned():
        epsl = Epsl()
        old, mid, new_ = H("old"), H("mid"), H("new")
        epsl.insert([old], [mid]); r0 = epsl.seal().root
        epsl.insert([new_], [mid]); epsl.insert([mid], [H("later")]); r1 = epsl.seal().root
        ts = epsl.query_ts(mid, 0)
        assert ts.hashes == [mid, old]
        assert verify_query(ts.proof, r0) == ts.hashes
        assert verify_query(ts.proof, r1) is None
        now = epsl.query_bl(mid)
        assert set(now.hashes) == {mid, old, new_}
        assert verify_query(now.proof, r1) == now.hashes
        # the record of `mid` grew by one group in epoch 1
        assert [ep for ep, _ in now.proof.entries[0].groups] == [0, 1]
        assert epsl.query_fi(mid, epoch=0).hashes == [mid]
        assert epsl.query_ts(H("later"), 0).proof is None       # did not exist yet
    test("temporal_slice_pinned_to_past_root", t_ts_pinned)

    def t_cycle():
        epsl = Epsl()
        a, b = H("cyc-a"), H("cyc-b")
        epsl.insert([a], [b]); epsl.insert([b], [a]); root = epsl.seal().root
        res = epsl.query_bl(a)
        assert res.hashes == [a, b] and verify_query(res.proof, root) == res.hashes
    test("cycles_terminate", t_cycle)

    def tamper_base():
        epsl = Epsl()
        a, b, c, x = H("ta"), H("tb"), H("tc"), H("unrelated")
        epsl.insert([a], [b]); epsl.insert([b], [c]); epsl.insert([], [x])
        root = epsl.seal().root
        return epsl, (a, b, c, x), root

    def t_tamper_record():
        epsl, (a, b, c, x), root = tamper_base()
        p = epsl.query_bl(c).proof
        assert verify_query(p, root) is not None
        p.entries[0].groups = []                    # claim c has no parents
        assert verify_query(p, root) is None
        p = epsl.query_bl(c).proof
        p.entries[1].other_head = H("forged")       # forge b's child list digest
        assert verify_query(p, root) is None
        p = epsl.query_bl(c).proof
        p.entries[0].epoch0 += 1
        assert verify_query(p, root) is None
    test("tampered_record_rejected", t_tamper_record)

    def t_tamper_suppress():
        epsl, (a, b, c, x), root = tamper_base()
        p = epsl.query_bl(c).proof
        p.entries = [en for en in p.entries if en.h != a]       # withhold an ancestor
        assert verify_query(p, root) is None
        p = epsl.query_bl(c).proof
        p.entries = p.entries[1:]                               # withhold the origin
        assert verify_query(p, root) is None
    test("suppressed_ancestor_rejected", t_tamper_suppress)

    def t_tamper_padding():
        epsl, (a, b, c, x), root = tamper_base()
        p = epsl.query_bl(c).proof
        extra = epsl.query_bl(x).proof.entries[0]               # valid, but unrelated
        p.entries.append(extra)
        assert verify_query(p, root) is None
        p = epsl.query_bl(c).proof
        p.entries.append(p.entries[1])                          # duplicate
        assert verify_query(p, root) is None
    test("padded_answer_rejected", t_tamper_padding)

    def t_tamper_misc():
        epsl, (a, b, c, x), root = tamper_base()
        p = epsl.query_bl(c).proof
        p.kind = "FI"
        assert verify_query(p, root) is None
        p = epsl.query_bl(c).proof
        p.entries[0].path = p.entries[0].path[:-1]
        assert verify_query(p, root) is None
        p = epsl.query_bl(c).proof
        p.origin = b
        assert verify_query(p, root) is None
        p = epsl.query_bl(c).proof
        assert verify_query(p, H("another root")) is None
        p.epoch = -1
        assert verify_query(p, root) is None
        epsl2 = Epsl()
        epsl2.insert([a, b], [c]); r2 = epsl2.seal().root
        p = epsl2.query_bl(c).proof
        ep, hs = p.entries[0].groups[0]
        p.entries[0].groups[0] = (ep, list(reversed(hs)))       # unsorted group
        assert verify_query(p, r2) is None
    test("malformed_proofs_rejected", t_tamper_misc)

    def t_wire_roundtrip():
        epsl, (a, b, c, x), root = tamper_base()
        for kind, origin, depth in [("BL", c, None), ("FI", a, 1), ("TS", c, 2)]:
            p = epsl.query(origin, kind, 0, depth).proof
            raw = p.to_bytes()
            q = QueryProof.from_bytes(raw)
            assert q.to_bytes() == raw and p.byte_size == len(raw)
            assert verify_query(q, root) == verify_query(p, root) != None
        assert raises(lambda: QueryProof.from_bytes(raw[:-1]), ValueError)
        assert raises(lambda: QueryProof.from_bytes(raw + b"\x00"), ValueError)
        assert raises(lambda: QueryProof.from_bytes(b"nope" + raw[4:]), ValueError)
    test("proof_wire_format_roundtrip", t_wire_roundtrip)

    def t_membership_proof():
        epsl, (a, b, c, x), root = tamper_base()
        mp = epsl.membership(b)
        assert mp is not None and mp.verify() and mp.verify(root)
        assert not mp.verify(H("other"))
        assert epsl.membership(H("absent")) is None
        anchor = InMemoryAnchor(); anchor.commit_root(root, 0, H("payload"))
        assert anchor.verify_proof(mp.leaf, mp.path, 0)
        assert not anchor.verify_proof(mp.leaf, mp.path[:-1], 0)
    test("membership_proof_matches_anchor", t_membership_proof)

    def t_equivocation_leaves_differ():
        v = H("v")
        d1 = record_digest(v, 0, chain_link(ZERO32, 0, [H("s1")]), ZERO32)
        d2 = record_digest(v, 0, chain_link(ZERO32, 0, [H("s2")]), ZERO32)
        assert d1 != d2 and node_leaf(v, d1) != node_leaf(v, d2)
    test("equivocation_leaves_differ", t_equivocation_leaves_differ)

    def t_retention():
        epsl = Epsl(retain=2)
        vs = [H(f"r{i}") for i in range(5)]
        roots = []
        for i in range(1, 5):
            epsl.insert([vs[i - 1]], [vs[i]]); roots.append(epsl.seal().root)
        assert epsl.retained_epochs() == [2, 3]
        assert verify_query(epsl.query_bl(vs[4]).proof, roots[3]) is not None
        assert verify_query(epsl.query_ts(vs[3], 2).proof, roots[2]) is not None
        assert raises(lambda: epsl.query_ts(vs[1], 0), ValueError)
        assert epsl.get_epoch_root(0).root == roots[0]          # roots are kept
        assert epsl.query(vs[1], "BL", 0, prove=False).hashes == [vs[1], vs[0]]
    test("retention_window", t_retention)

    def t_randomised_against_naive():
        rng = random.Random(20261118)
        epsl = Epsl()
        pool = [H(f"base-{i}") for i in range(30)]
        edges: List[Tuple[bytes, bytes, int]] = []
        roots: List[bytes] = []
        for e in range(7):
            for j in range(40):
                srcs = rng.sample(pool, rng.randint(0, 4))
                if rng.random() < 0.15:
                    tgts = rng.sample(pool, rng.randint(1, 2))          # re-derivations
                else:
                    tgts = [H(f"out-{e}-{j}-{k}") for k in range(rng.randint(1, 3))]
                epsl.insert(srcs, tgts)
                for s in srcs:
                    for t_ in tgts:
                        if s != t_ and not any(a == s and b == t_ for a, b, _ in edges):
                            edges.append((s, t_, e))
                pool.extend(x for x in tgts if x not in pool)
            roots.append(epsl.seal().root)
        assert epsl.edge_count == len(edges)
        checked = 0
        for _ in range(250):
            origin = rng.choice(pool)
            kind   = rng.choice(["BL", "FI", "TS"])
            e      = rng.randrange(7)
            depth  = rng.choice([None, None, 1, 2, 3])
            res = epsl.query(origin, kind, e, depth)
            if origin not in epsl._nodes or epsl._nodes[origin].epoch > e:
                assert res.hashes == [] and res.proof is None
                continue
            want = _naive_reach(edges, origin, kind == "FI", e, depth)
            assert set(res.hashes) == want and len(res.hashes) == len(want)
            assert verify_query(res.proof, roots[e]) == res.hashes
            assert verify_query(QueryProof.from_bytes(res.proof.to_bytes()), roots[e]) == res.hashes
            if e + 1 < 7 and roots[e + 1] != roots[e]:
                assert verify_query(res.proof, roots[e + 1]) is None
            checked += 1
        assert checked > 150
    test("randomised_queries_match_naive_bfs", t_randomised_against_naive)

    def t_incremental_equals_rebuild():
        """The persistent structure after many epochs equals a skip list
        built from scratch over the final leaves."""
        rng = random.Random(7)
        epsl = Epsl()
        pool = [H(f"p{i}") for i in range(20)]
        for e in range(5):
            for j in range(25):
                srcs = rng.sample(pool, rng.randint(1, 3))
                tgts = [H(f"q-{e}-{j}")]
                epsl.insert(srcs, tgts); pool.append(tgts[0])
            last = epsl.seal()
        leaves = {h: n.leaf_as_of(4) for h, n in epsl._nodes.items()}
        fresh = build(list(leaves), leaf=lambda k: leaves[k])
        assert fresh.label() == last.root
    test("incremental_versions_equal_rebuild", t_incremental_equals_rebuild)

    # ── Epoch payloads ────────────────────────────────────────────────────
    print("\n── Epoch payloads " + "─" * 40)

    def t_blob_roundtrip():
        a, b, c = H("a"), H("b"), H("c")
        events = [([a, b], [c]), ([c], [H("d"), H("e")]), ([], [H("f")]), ([a], [c])]
        for codec in (CODEC_RAW, CODEC_ZLIB):
            raw = encode_blob(7, H("root"), events, codec)
            e, root, back = decode_blob(raw)
            assert e == 7 and root == H("root") and back == events
        assert encode_blob(7, H("root"), events) == encode_blob(7, H("root"), events)
        assert raises(lambda: decode_blob(raw[:10]), ValueError)
        assert raises(lambda: decode_blob(encode_blob(7, H("root"), events) + b"x"), ValueError)
    test("payload_roundtrip", t_blob_roundtrip)

    def t_blob_dictionary():
        shared = [H(f"s{i}") for i in range(4)]
        events = [(shared, [H(f"t{i}")]) for i in range(100)]
        enc = len(encode_events(events))
        assert enc < raw_event_bytes(events) / 3
        assert blobs_needed(1) == 1 and blobs_needed(BLOB_USABLE_BYTES) == 1
        assert blobs_needed(BLOB_USABLE_BYTES + 1) == 2
        assert BLOB_USABLE_BYTES == 126_976 and BLOB_GAS_PER_BLOB == 131_072
        assert fits_one_transaction(MAX_BLOBS_PER_TX * BLOB_USABLE_BYTES)
        assert not fits_one_transaction(MAX_BLOBS_PER_TX * BLOB_USABLE_BYTES + 1)
    test("payload_dictionary_coding_and_blob_count", t_blob_dictionary)

    def t_blob_pipeline():
        bp = BlobPipeline(dry_run=True, keep_payloads=True)
        epsl = Epsl(); epsl.insert([H("x")], [H("y")]); er = epsl.seal()
        dh = bp.submit(er, [([H("x")], [H("y")])])
        sub = bp.submissions[0]
        assert dh == sha256(bp.payload(0)) and sub["blobs"] == 1 and sub["events"] == 1
        assert sub["one_tx"] is True
        assert raises(lambda: BlobPipeline(dry_run=False).submit(er, []), NotImplementedError)
    test("blob_pipeline_dry_run", t_blob_pipeline)

    # ── Anchor / PruneLog ─────────────────────────────────────────────────
    print("\n── Anchor / PruneLog " + "─" * 37)

    def t_anchor_epoch_monotonic():
        a = InMemoryAnchor()
        a.commit_root(H("r0"), 0, H("b0"))
        assert raises(lambda: a.commit_root(H("r2"), 2, H("b2")), ValueError)
        assert raises(lambda: a.commit_root(H("rx"), 0, H("bx")), ValueError)
        assert raises(lambda: a.commit_root(bytes(32), 1, H("b1")), ValueError)
        assert raises(lambda: a.commit_root(H("r1"), 1, bytes(32)), ValueError)
        a.commit_root(H("r1"), 1, H("b1"))
        assert a.latest_epoch == 1 and a.epoch_data_hash(1) == H("b1")
        assert raises(lambda: a.commit_prune_root(1, H("p")), ValueError)
        a.commit_prune_root(0, H("p0")); assert a.prune_root(0) == H("p0")
    test("anchor_sequential_epochs_I2", t_anchor_epoch_monotonic)

    def t_prune_log():
        e = PruneLogEntry(branch_id=7, branch_hash=H("B7"), epoch=3,
                          ts_ms=1_700_000_000_000)
        assert len(e.pack()) == PRUNE_ENTRY_BYTES == 96
        log = PruneLog(batch_size=4)
        hashes, closed = [], []
        for i in range(6):
            bh = H(f"branch-{i}"); hashes.append(bh)
            closed.append(log.append(PruneLogEntry(i, bh, 0, 0)))
        assert closed[:3] == [None] * 3 and closed[3][0] == 0 and closed[4] is None
        bi, mp = log.membership(hashes[2])
        assert bi == 0 and mp.verify() and mp.root == log.anchored_roots[0]
        assert log.membership(hashes[5]) is None            # batch still open
        idx, root = log.flush()
        assert idx == 1 and log.flush() is None
        bi, mp = log.membership(hashes[5])
        assert bi == 1 and mp.verify() and mp.root == root
        # after a flush the next batch starts from the flush point
        for i in range(6, 10):
            c = log.append(PruneLogEntry(i, H(f"branch-{i}"), 0, 0))
        assert c is not None and c[0] == 2
        assert log.membership_proof(H("never-seen")) is None and len(log) == 10
    test("prune_log_batches_and_membership", t_prune_log)

    # ── Bcp ───────────────────────────────────────────────────────────────
    print("\n── Bcp " + "─" * 51)

    def mk(epoch_size: int = 512, **kw):
        epsl = Epsl()
        return Bcp(epsl, BlobPipeline(keep_payloads=True), epoch_size=epoch_size, **kw), epsl

    def t_phase1_and_2():
        bcp, epsl = mk()
        s, t_ = H("src"), H("tgt")
        assert bcp.phase1_write([s], [t_], 1) == [s, t_]
        assert epsl.node_count == 0 and bcp.store.vertex_count == 2
        bs  = [Branch(id=i, epoch=0) for i in range(3)]
        wid = Bcp.phase2_score(bs, scorer=lambda b: b.id * 0.5)
        assert wid == 2 and bs[2].is_winner
    test("phase1_store_only_phase2_argmax", t_phase1_and_2)

    def t_commit_when_full():
        bcp, epsl = mk(epoch_size=3)
        a, b, c, d = H("a"), H("b"), H("c"), H("d")
        bcp.write_direct([a], [b]); bcp.write_direct([b], [c])
        assert bcp.committed_epochs == 0 and bcp.batch_fill == 2
        bcp.write_direct([c], [d])
        assert bcp.committed_epochs == 1 and bcp.batch_fill == 0
        cm = bcp.commits[0]
        assert cm.epoch == 0 and cm.event_count == 3 and cm.blobs == 1
        assert bcp.anchor.epoch_root(0) == cm.root == epsl.get_epoch_root(0).root   # I1
        assert bcp.anchor.epoch_data_hash(0) == cm.data_hash
        assert bcp.current_epoch == 1 and bcp.flush_epoch() is None
        bcp.write_direct([d], [H("e")])
        cm2 = bcp.flush_epoch()
        assert cm2.epoch == 1 and bcp.anchor.latest_epoch == 1
    test("epoch_commits_when_full_or_flushed", t_commit_when_full)

    def t_latency_formula():
        bcp, _ = mk(epoch_size=512, arrival_hz=100.0, finality_s=1.0)
        assert abs(bcp.expected_commit_latency_s() - 6.12) < 1e-9
        assert abs(expected_commit_latency_s(512, 256, 1000.0, 1.0) - 1.256) < 1e-9
        assert expected_commit_latency_s(512, 600, 1000.0, 1.0) == 1.0
    test("commit_latency_formula", t_latency_formula)

    def t_speculative_branches():
        bcp, epsl = mk()
        shared, win, lose = H("oracle-shared"), H("win"), H("lose")
        b1 = Branch(id=1, epoch=0); b2 = Branch(id=2, epoch=0)
        b1.event_hashes = bcp.phase1_write([shared], [win],  1)
        b2.event_hashes = bcp.phase1_write([shared], [lose], 2)
        assert epsl.node_count == 0 and bcp.store.vertex_count == 3
        wid = Bcp.phase2_score([b1, b2], scorer=lambda b: -b.id)     # b1 wins
        bcp.phase3_accumulate(b1)
        assert epsl.node_count == 2 and not epsl.has_vertex(lose)
        bcp.phase5_prune([b1, b2], wid)
        assert bcp.total_pruned == 1 and bcp.prune_log.contains(b2.branch_hash())
        assert bcp.store.get_vertex(lose) is None                    # collected
        assert bcp.store.get_vertex(shared) is not None              # shared: kept
        assert bcp.store.get_vertex(win) is not None
        assert bcp.store.scan_edges(shared, 0, 9) == [win]           # no dangling edge
    test("only_the_winner_is_indexed_losers_pruned", t_speculative_branches)

    def t_gc_keeps_committed():
        bcp, epsl = mk()
        x, y = H("gx"), H("gy")
        bcp.write_direct([x], [y], 0)                                # y is committed
        b = Branch(id=64, epoch=0)                                   # 64 & 63 == 0: same mask bit
        b.event_hashes = bcp.phase1_write([x], [y], 64)
        bcp.phase5_prune([b], winner_id=-1)
        assert bcp.store.get_vertex(y) is not None
    test("gc_never_removes_committed_vertices", t_gc_keeps_committed)

    def t_prune_roots_anchored():
        bcp, _ = mk(prune_batch=2)
        bs = [Branch(id=i, epoch=0, event_hashes=[H(f"pb{i}")]) for i in range(4)]
        bcp.phase5_prune(bs, winner_id=3)                            # three losers
        assert bcp.total_pruned == 3
        assert bcp.anchor.prune_root(0) == bcp.prune_log.anchored_roots[0]
        assert bcp.anchor.prune_root(1) is None
        bi, mp = bcp.prune_log.membership(bs[1].branch_hash())
        assert bcp.anchor.verify_prune_proof(mp.leaf, mp.path, bi)
        assert bcp.flush_prune_log()[0] == 1 and bcp.anchor.prune_root(1) is not None
    test("prune_log_roots_are_anchored", t_prune_roots_anchored)

    def t_branch_spanning_epochs():
        bcp, epsl = mk(epoch_size=2)
        b = Branch(id=5, epoch=0)
        for i in range(5):
            b.event_hashes += bcp.phase1_write([H(f"m{i}")], [H(f"m{i + 1}")], 5)
        bcp.phase3_accumulate(b)
        assert bcp.committed_epochs == 2 and bcp.batch_fill == 1
        assert [c.event_count for c in bcp.commits] == [2, 2]
    test("winning_branch_may_span_epochs", t_branch_spanning_epochs)

    def t_replay_from_payloads():
        """Anyone holding the epoch payloads can rebuild the index and
        recompute every anchored root."""
        bcp, epsl = mk(epoch_size=16)
        AeTpcc(seed=3, beta=2).run(bcp, 120)
        bcp.flush_epoch()
        rebuilt = Epsl()
        for cm in bcp.commits:
            e, root, events = decode_blob(bcp._blob.payload(cm.epoch))
            assert e == cm.epoch and root == cm.root
            for s, t_ in events:
                rebuilt.insert(s, t_)
            assert rebuilt.seal().root == bcp.anchor.epoch_root(cm.epoch)
    test("index_rebuilds_from_payloads", t_replay_from_payloads)

    # ── BranchManager / LineageHook ───────────────────────────────────────
    print("\n── BranchManager / LineageHook " + "─" * 27)

    def t_branch_context_records():
        bcp, epsl = mk(epoch_size=2)
        mgr = BranchManager(bcp, beta=2)
        with mgr.new_step() as step:
            for b in step.branches:
                with step.context(b) as ctx:
                    ctx.record_source(b"oracle_price")
                    ctx.record_target(H(f"decision-{b.id}"))
                    ctx.set_score(float(b.id))
            wid = step.commit_winner()
        assert wid == 1 and epsl.node_count == 2 and bcp.total_pruned == 1
    test("branch_manager_step", t_branch_context_records)

    def t_hook():
        bcp, epsl = mk()
        hook = LineageHook(bcp, branch_id=0)
        hook.on_tool_call("run1", "get_price", {"symbol": "ETH"})
        hook.on_tool_result("run1", "get_price", {"price": 2000})
        assert epsl.node_count == 2 and epsl.edge_count == 1
        out = hook.wrap_node("n", lambda s: {"r": s.get("x", 0) + 1})({"x": 5})
        assert out["r"] == 6 and epsl.node_count == 4
    test("lineage_hook_records_tool_calls", t_hook)

    # ── LineageService ────────────────────────────────────────────────────
    print("\n── LineageService " + "─" * 40)

    def t_service():
        bcp, epsl = mk(epoch_size=2)
        svc = LineageService(epsl, bcp)
        oracle, decision, order = H("ETH:2050"), H("buy:1ETH"), H("order:123")
        w = svc.write_lineage(WriteRequest([oracle], [decision]))
        assert w.new_vertices == 2 and w.epoch == 0
        svc.write_lineage(WriteRequest([decision], [order]))        # seals epoch 0
        bl = svc.query_bl(QueryRequest(order))
        assert bl.hashes == [order, decision, oracle]
        assert bl.verified and bl.anchored and svc.verify(bl) and bl.proof_bytes > 0
        fi = svc.query_fi(QueryRequest(oracle, max_depth=1))
        assert fi.hashes == [oracle, decision] and fi.anchored
        ts = svc.query_ts(QueryRequest(order, epoch=0))
        assert ts.anchored and ts.hashes == bl.hashes
        assert raises(lambda: svc.query_ts(QueryRequest(order)), ValueError)
        m = svc.metrics
        assert m["writes_total"] == 2 and m["queries_bl"] == 1 and m["queries_fi"] == 1
        # a response whose result list was edited no longer verifies
        bl.hashes = bl.hashes[:-1]
        assert not svc.verify(bl)
    test("service_write_query_verify", t_service)

    def t_service_unsealed():
        bcp, epsl = mk(epoch_size=512)
        svc = LineageService(epsl, bcp)
        svc.write_lineage(WriteRequest([H("in")], [H("out")]))
        resp = svc.query_bl(QueryRequest(H("out")))
        assert resp.hashes == [] and not resp.verified and not resp.anchored
        bcp.flush_epoch()
        resp = svc.query_bl(QueryRequest(H("out")))
        assert resp.anchored and svc.verify(resp)
    test("service_answers_only_from_sealed_epochs", t_service_unsealed)

    # ── Workload ──────────────────────────────────────────────────────────
    print("\n── AE-TPCC workload " + "─" * 38)

    def t_aetpcc_mix():
        gen    = AeTpcc(seed=0, beta=4)
        counts = {name: 0 for name, _ in AETPCC_MIX}
        for _ in range(10_000):
            counts[gen.next_event().tx_type] += 1
        for name, freq in AETPCC_MIX:
            assert abs(counts[name] / 10_000 - freq) < 0.03, name
    test("aetpcc_transaction_mix", t_aetpcc_mix)

    def t_aetpcc_schema():
        gen = AeTpcc(seed=42)
        produced: Set[bytes] = set()
        reused = 0
        for _ in range(3000):
            ev = gen.next_event()
            (s_lo, s_hi), (t_lo, t_hi) = AETPCC_LINEAGE[ev.tx_type]
            assert s_lo <= len(ev.sources) <= s_hi, ev.tx_type
            assert t_lo <= len(ev.targets) <= t_hi, ev.tx_type
            assert len(set(ev.sources)) == len(ev.sources)
            assert not produced & set(ev.targets)            # outputs are new items
            reused += sum(1 for s in ev.sources if s in produced)
            produced |= set(ev.targets)
        assert reused > 500                                  # outputs feed later inputs
        cands = gen.agent_step(beta=4)
        assert len(cands) == 4 and len({tuple(c.sources) for c in cands}) == 1
        assert len({tuple(c.targets) for c in cands}) == 4
        assert 4 <= len(cands[0].sources) <= 12 and 1 <= len(cands[0].targets) <= 4
        gen.agent_commit(cands[2])
        for _ in range(gen._agents - 1):
            gen.agent_step(beta=1)
        assert cands[2].targets[0] in gen.agent_step(beta=1)[0].sources   # memory
    test("aetpcc_event_shapes_and_versions", t_aetpcc_schema)

    def t_aetpcc_run():
        bcp, epsl = mk(epoch_size=64)
        stats = AeTpcc(seed=7, beta=4).run(bcp, n_events=200)
        assert stats["n_events"] == 200 and stats["epsl_nodes"] > 0
        assert stats["tx_counts"]["AgentStep"] == 80 and stats["pruned"] == 60
        assert stats["commits"] == 220 // 64
    test("aetpcc_run_through_bcp", t_aetpcc_run)

    # ── Cost model ────────────────────────────────────────────────────────
    print("\n── Cost model " + "─" * 44)

    def t_cost():
        g = 100_000
        one  = commit_cost_wei(g, 1_000, 1e9, 1e9)
        assert one == g * 1e9 + BLOB_GAS_PER_BLOB * 1e9
        two  = commit_cost_wei(g, BLOB_USABLE_BYTES + 1, 1e9, 1e9)
        assert two - one == BLOB_GAS_PER_BLOB * 1e9
        c64  = cost_per_event_usd(64,  200.0, g, 10.0, 1.0, 2000.0)
        c512 = cost_per_event_usd(512, 200.0, g, 10.0, 1.0, 2000.0)
        assert c64 > c512 > 0
        assert abs(c512 - (g * 10e9 + BLOB_GAS_PER_BLOB * 1e9) / 1e18 * 2000 / 512) < 1e-12
        assert cost_per_event_usd(512, 200.0, g, 30.0, 1.0, 2000.0) > c512
    test("cost_model_whole_blobs", t_cost)

    # ── Conformance vectors ───────────────────────────────────────────────
    print("\n── Conformance vectors " + "─" * 35)

    def t_vectors():
        v1 = conformance_vectors(); v2 = conformance_vectors()
        assert json.dumps(v1, sort_keys=True) == json.dumps(v2, sort_keys=True)
        assert len(v1["epochs"]) == 6 and len(v1["queries"]) == 8
        for q in v1["queries"]:
            p = QueryProof.from_bytes(bytes.fromhex(q["proof"]))
            root = bytes.fromhex(v1["epochs"][q["epoch"]]["root"])
            assert [x.hex() for x in verify_query(p, root)] == q["result"]
    test("conformance_vectors_deterministic", t_vectors)

    print(f"\n{'=' * 55}")
    print(f"  {passed} passed, {failed} failed")
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--vectors":
        with open(sys.argv[2], "w") as fh:
            json.dump(conformance_vectors(), fh, indent=1)
            fh.write("\n")
        print(f"wrote {sys.argv[2]}")
    else:
        _run_tests()
