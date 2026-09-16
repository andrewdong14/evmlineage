"""
evm_lineage.py — Python agent integration layer for EVM-Lineage

Self-contained module (stdlib only).  Provides:

  keccak256 / MerkleTree     — pair hashing identical to LineageAnchor.sol
  LineageStore               — in-memory DAG store with DAG merge (Phase 1 target)
  Epsl                       — Epoch-Pinned Skip List: authenticated index whose
                               per-epoch state roots commit vertex adjacency, so
                               BL/FI/TS answers carry proofs verifiable against
                               the on-chain root (paper Sect. 5)
  QueryProof / verify_query  — client-side verification without store access
  InMemoryAnchor             — test double for LineageAnchor.sol (I1/I2 checks)
  PruneLog                   — 96-byte discarded-branch records, Merkle-anchored
                               every M entries (paper Sect. 6.4)
  BlobPipeline               — EIP-4844 blob encode/decode + retry
  Bcp                        — Branch Commit Protocol: five phases per step
  BranchManager              — thread-safe branch context manager
  LineageHook                — drop-in hook for LangGraph agents
  LineageService             — WriteLineage/QueryBL/FI/TS service
  AeTpcc                     — agent-extended TPC-C workload (paper Table 4)
  cost_per_event_usd         — amortised on-chain cost per event
  expected_commit_latency_s  — expected time from write to commitment

Hashing conventions (identical across Python, Rust, and Solidity):
  * content addressing:   SHA-256 over the data item bytes
  * Merkle pair hashing:  keccak256(min(a,b) || max(a,b))
  * leaf construction:    keccak256(vertex_hash || node_record_digest)
The leaf shape binds a vertex to exactly one adjacency record per epoch,
which is what makes the on-chain equivocation fraud proof
(LineageAnchor.slash) sound.

Run tests:
    python3 evm_lineage.py
"""

from __future__ import annotations

import hashlib, json, math, random, struct, threading, time, zlib
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

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
# MerkleTree / MerkleProof  (, the commit latency formula )
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
    """Binary Merkle tree over 32-byte leaves.

    the commit latency formula : depth = ceil(log2 n), proof_size = 32 + depth*32 bytes.
    """

    def __init__(self, leaves: List[bytes]):
        if not leaves:
            self._levels: List[List[bytes]] = [[bytes(32)]]
            return
        self._levels = [list(leaves)]
        while len(self._levels[-1]) > 1:
            prev = self._levels[-1]
            if len(prev) % 2 == 1:
                prev = prev + [prev[-1]]
            nxt = [hash_pair(prev[i], prev[i+1]) for i in range(0, len(prev), 2)]
            self._levels.append(nxt)

    def root(self) -> bytes:
        return self._levels[-1][0]

    def proof(self, idx: int) -> Optional[MerkleProof]:
        if idx >= len(self._levels[0]):
            return None
        leaf = self._levels[0][idx]
        path: List[bytes] = []
        i = idx
        for level in self._levels[:-1]:
            padded = level + ([level[-1]] if len(level) % 2 == 1 else [])
            path.append(padded[i ^ 1])
            i //= 2
        return MerkleProof(leaf=leaf, path=path, root=self.root())

    def __len__(self) -> int:
        return len(self._levels[0])

    def depth(self) -> int:
        n = len(self)
        return 0 if n <= 1 else math.ceil(math.log2(n))

# ══════════════════════════════════════════════════════════════════════════════
# LineageStore — in-memory DAG store
# ══════════════════════════════════════════════════════════════════════════════

MAX_INLINE = 256   # bytes; larger items stored by content hash only

@dataclass
class Vertex:
    """Lineage DAG vertex (content-addressed; production schema stores
    this in the RocksDB 'vertices' column family)."""
    hash:           bytes
    content:        bytes
    content_inline: bool
    vertex_type:    int          # 0x01–0x06 VertexType enum
    creation_epoch: int
    agent_id:       bytes        # 32 B
    branch_mask:    int          #  DAG merge bitmask
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
    """Thread-safe in-memory lineage DAG store.

    Production backend: RocksDB with three column families
      'vertices'    — universal compaction, 256 MB write buffer
      'edges'       — level compaction,     64 MB write buffer
      'epsl_nodes'  — FIFO compaction,      30-day TTL
    Edge key: (src_hash, epoch) → list[target_hash]  (40 B composite key)
    EPSL key: (level, epoch, hash)                   (41 B composite key)
    """

    def __init__(self):
        self._lock      = threading.Lock()
        self._vertices: Dict[bytes, Vertex]                  = {}
        self._edges:    Dict[Tuple[bytes, int], List[bytes]] = {}
        self._epsl_raw: Dict[bytes, bytes]                   = {}
        self._inserts = 0
        self._merges  = 0

    def put_vertex(self, vtx: Vertex) -> Tuple[bool, bytes]:
        """DAG-merge branch_mask if exists. Returns (is_new, hash)."""
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
        with self._lock:
            lst = self._edges.setdefault((src, epoch), [])
            for t in targets:
                if t not in lst:
                    lst.append(t)

    def scan_edges(self, src: bytes, lo: int, hi: int) -> List[bytes]:
        """Epoch-range scan: all targets from src in [lo, hi]."""
        with self._lock:
            out: List[bytes] = []
            for e in range(lo, hi + 1):
                out.extend(self._edges.get((src, e), []))
            return out

    def put_epsl_raw(self, key: bytes, val: bytes):
        with self._lock:
            self._epsl_raw[key] = val

    def get_epsl_raw(self, key: bytes) -> Optional[bytes]:
        with self._lock:
            return self._epsl_raw.get(key)

    def remove_vertex(self, h: bytes) -> bool:
        """Delete a vertex and its outgoing edge records (Phase-5 GC of
        branch-exclusive vertices; shared vertices are never removed)."""
        with self._lock:
            if h not in self._vertices:
                return False
            del self._vertices[h]
            self._edges = {k: v for k, v in self._edges.items() if k[0] != h}
            return True

    @property
    def vertex_count(self) -> int:
        return len(self._vertices)

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
# Authentication model
# --------------------
# Every edge is tagged with the epoch it was added in. The *node record as
# of epoch e* is the vertex's content hash, deterministic level, creation
# epoch, and its adjacency restricted to edges with epoch <= e. Its digest
# and Merkle leaf are:
#
#     digest_e(v) = keccak256(h | lvl | epoch_be | fwd<=e sorted | 0x00 | bwd<=e sorted)
#     leaf_e(v)   = keccak256(h || digest_e(v))
#
# Sealing epoch e builds a Merkle tree over leaf_e of every node created at
# epoch <= e (sorted by content hash); the root is what the BCP anchors
# on-chain (Invariant I1). A query proof returns, for each visited node,
# its record plus an inclusion path against the pinned epoch's root, so a
# verifier with only the on-chain root can check (1) each record is
# committed, (2) the result is closed under the claimed traversal — no
# ancestor/descendant can be silently suppressed (attack S1), and (3) the
# traversal starts at the queried vertex. The leaf shape keccak256(h||digest)
# binds each vertex hash to exactly one record per epoch, which makes the
# on-chain equivocation fraud proof (LineageAnchor.slash) sound: two valid
# leaves for the same h with different digests prove a fraudulent root.
#
# The deterministic skip-list levels (DASL-style) accelerate ordered
# traversal; correctness and tamper-evidence rest only on the construction
# above.
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class EpochRoot:
    epoch:        int
    merkle_root:  bytes       # EPSL state root as of this epoch (anchored on-chain)
    event_count:  int         # nodes newly sealed in this epoch
    commit_block: int = 0     # filled after on-chain confirmation


@dataclass
class EpslNode:
    """One EPSL node. Adjacency maps carry the epoch each edge was added
    in, which is what lets `record_as_of(e)` reconstruct the node exactly
    as it existed at epoch e (epoch pinning, paper Sect. 5.2)."""

    hash:       bytes
    level:      int
    epoch:      int                                      # creation epoch
    backward:   Dict[bytes, int] = field(default_factory=dict)  # src -> edge epoch
    forward:    Dict[bytes, int] = field(default_factory=dict)  # tgt -> edge epoch
    branch_ids: List[int]        = field(default_factory=list)

    @staticmethod
    def storage_key(level: int, epoch: int, h: bytes) -> bytes:
        """Composite key: level(1B)|epoch_be(8B)|hash(32B) = 41 B."""
        return bytes([level]) + epoch.to_bytes(8, 'big') + h

    def record_as_of(self, e: int) -> Dict[str, Any]:
        """Serializable node record restricted to edges with epoch <= e."""
        return {
            "h":     self.hash.hex(),
            "lvl":   self.level,
            "epoch": self.epoch,
            "fwd":   sorted(k.hex() for k, ep in self.forward.items()  if ep <= e),
            "bwd":   sorted(k.hex() for k, ep in self.backward.items() if ep <= e),
        }


def node_record_digest(rec: Dict[str, Any]) -> bytes:
    """Canonical digest of a node record (identical bytes in Rust)."""
    payload = (
        bytes.fromhex(rec["h"])
        + bytes([rec["lvl"]])
        + rec["epoch"].to_bytes(8, "big")
        + len(rec["fwd"]).to_bytes(4, "big")
        + b"".join(bytes.fromhex(x) for x in rec["fwd"])
        + len(rec["bwd"]).to_bytes(4, "big")
        + b"".join(bytes.fromhex(x) for x in rec["bwd"])
    )
    return keccak256(payload)


def node_leaf(vertex_hash: bytes, digest: bytes) -> bytes:
    """Merkle leaf: keccak256(vertex_hash || record_digest).

    Matches `keccak256(abi.encodePacked(vertexHash, digest))` in
    LineageAnchor.slash, enabling on-chain equivocation fraud proofs.
    """
    return keccak256(vertex_hash + digest)


@dataclass
class QueryProof:
    """Verifiable answer to a BL / FI / TS query.

    `sealed` is True when the proof was generated against a sealed
    (committable) epoch root; False means the epoch had not been sealed
    yet and the root is provisional — cryptographically well-formed but
    not anchorable until `commit_epoch` runs.
    """
    query:     str                    # "BL" | "FI" | "TS"
    origin:    str                    # hex vertex hash the query started from
    epoch:     int                    # pinned epoch
    root:      bytes                  # epoch state root the paths verify against
    sealed:    bool
    records:   List[Dict[str, Any]]  # node records as of `epoch`, origin first
    paths:     List[List[bytes]]      # per-record sibling paths

    def verify(self, root: Optional[bytes] = None) -> bool:
        """Full client-side verification (paper `Verify(pi, Phi)`).

        Pass the independently fetched on-chain root as `root`; when
        omitted, the embedded root is used (sufficient for testing, but a
        real verifier must supply the anchor's root — see LineageService).
        """
        return verify_query(self, root if root is not None else self.root)

    @property
    def depth(self) -> int:
        return max((len(pp) for pp in self.paths), default=0)

    @property
    def byte_size(self) -> int:
        """Wire size of the cryptographic material (leaves + sibling paths)."""
        return 32 * len(self.records) + 32 * sum(len(pp) for pp in self.paths)


def verify_query(proof: QueryProof, root: bytes) -> bool:
    """Verify a QueryProof against an (on-chain) epoch root.

    Checks, with no access to the prover's store:
      1. every returned node record hashes into `root`;
      2. the record set is closed under the traversal direction — every
         neighbour listed by a returned record is itself returned, so the
         prover cannot silently drop an ancestor/descendant (attack S1);
      3. the traversal starts at the claimed origin vertex.
    """
    if not proof.records or proof.records[0]["h"] != proof.origin:
        return False
    if len(proof.records) != len(proof.paths):
        return False
    returned = {r["h"] for r in proof.records}
    direction = "fwd" if proof.query == "FI" else "bwd"
    for rec, path in zip(proof.records, proof.paths):
        leaf = node_leaf(bytes.fromhex(rec["h"]), node_record_digest(rec))
        node = leaf
        for sib in path:
            node = hash_pair(node, sib)
        if node != root:
            return False
        for nb in rec[direction]:
            if nb not in returned:
                return False
    return True


@dataclass
class QueryResult:
    hashes: List[bytes]
    proof:  Optional[QueryProof]
    epoch:  int
    depth:  int


class Epsl:
    """Epoch-Pinned Skip List index (paper Sect. 5).

    Reference-implementation notes:
      * Sealing recomputes the state tree over all live nodes; leaf digests
        are cached and only recomputed for nodes whose adjacency changed
        since the previous seal. Production maintains the tree
        incrementally (amortised O(log n) per insert).
      * Queries pinned to an unsealed epoch build an ephemeral tree so
        they remain answerable; such proofs are flagged `sealed=False`.
    """

    L_MAX = 23   # ceil(log2(10^7))

    def __init__(self, store: LineageStore, epoch_size: int = 512):
        self._store       = store
        self._epoch_size  = epoch_size
        self._lock        = threading.Lock()
        self._nodes:       Dict[bytes, EpslNode] = {}
        self._epoch_roots: List[EpochRoot]       = []
        # sealed epoch -> (tree, sorted node hashes, hash -> leaf index)
        self._sealed: Dict[int, Tuple[MerkleTree, List[bytes], Dict[bytes, int]]] = {}
        self._leaf_cache:  Dict[bytes, bytes] = {}   # valid unless in _dirty
        self._dirty:       Set[bytes] = set()
        self._new_since_seal: int = 0
        self._max_epoch_seen: int = 0

    # ── Insert (paper Algorithm 1) ─────────────────────────────────────────

    def insert(self, sources: List[bytes], targets: List[bytes],
               epoch: int, branch_id: int) -> List[bytes]:
        """Insert one lineage event (sources -> targets).

        Both source and target hashes become EPSL nodes. Content
        addressing gives DAG merge for free: a hash seen before (e.g.
        shared across speculative branches) gains edges and a branch tag
        but no new node. Returns all touched hashes (sources + targets).
        """
        all_hashes: List[bytes] = []
        with self._lock:
            self._max_epoch_seen = max(self._max_epoch_seen, epoch)
            for src in sources:
                self._touch(src, epoch, branch_id)
                all_hashes.append(src)
            for tgt in targets:
                node = self._touch(tgt, epoch, branch_id)
                for src in sources:
                    if src not in node.backward:
                        node.backward[src] = epoch
                        self._dirty.add(tgt)
                all_hashes.append(tgt)
            for src in sources:
                sn = self._nodes[src]
                for tgt in targets:
                    if tgt not in sn.forward:
                        sn.forward[tgt] = epoch
                        self._dirty.add(src)
        return all_hashes

    def _touch(self, h: bytes, epoch: int, branch_id: int) -> EpslNode:
        node = self._nodes.get(h)
        if node is None:
            lv   = self._assign_level(h)
            node = EpslNode(hash=h, level=lv, epoch=epoch,
                            branch_ids=[branch_id])
            self._nodes[h] = node
            self._dirty.add(h)
            self._new_since_seal += 1
            self._store.put_epsl_raw(
                EpslNode.storage_key(lv, epoch, h),
                json.dumps(node.record_as_of(epoch)).encode())
        elif branch_id not in node.branch_ids:
            node.branch_ids.append(branch_id)
        return node

    def remove_node(self, h: bytes) -> bool:
        """Garbage-collect a node and its incident edges (BCP Phase 5).

        Only used for branch-exclusive nodes of pruned speculative
        branches; committed nodes are never removed.
        """
        with self._lock:
            node = self._nodes.pop(h, None)
            if node is None:
                return False
            for nb in node.backward:
                other = self._nodes.get(nb)
                if other and h in other.forward:
                    del other.forward[h]
                    self._dirty.add(nb)
            for nb in node.forward:
                other = self._nodes.get(nb)
                if other and h in other.backward:
                    del other.backward[h]
                    self._dirty.add(nb)
            self._leaf_cache.pop(h, None)
            self._dirty.discard(h)
            self._new_since_seal = max(0, self._new_since_seal - 1)
            return True

    @staticmethod
    def _assign_level(h: bytes) -> int:
        """Deterministic skip-list level: trailing zeros of h[0:4], capped.

        Gives the geometric level distribution P(level >= k) = 2^-k that
        skip-list complexity analysis requires, while remaining
        deterministic across replicas (DASL property). NOTE: the paper's
        Sect. 5.1 formula floor(log2(h mod 2^32)) does not produce this
        distribution; the paper text should be corrected to match this
        (see PAPER_ALIGNMENT.md).
        """
        v = int.from_bytes(h[:4], 'little')
        if v == 0:
            return Epsl.L_MAX
        tz = (v & -v).bit_length() - 1
        return min(tz, Epsl.L_MAX)

    # ── Epoch sealing (paper Sect. 5.2; BCP Phase 4) ──────────────────────

    def _leaves_as_of(self, e: int, use_cache: bool) -> Tuple[List[bytes], List[bytes]]:
        """(sorted node hashes, leaves) for the state as of epoch e."""
        keys = sorted(h for h, n in self._nodes.items() if n.epoch <= e)
        leaves = []
        for h in keys:
            if use_cache and h not in self._dirty and h in self._leaf_cache:
                leaves.append(self._leaf_cache[h])
                continue
            leaf = node_leaf(h, node_record_digest(self._nodes[h].record_as_of(e)))
            if use_cache:
                self._leaf_cache[h] = leaf
            leaves.append(leaf)
        return keys, leaves

    def commit_epoch(self, epoch: int) -> EpochRoot:
        """Seal epoch: Merkle-commit the EPSL state as of `epoch`.

        The returned root is what the BCP submits to the anchor contract
        (Invariant I1: on-chain root == EPSL state root after processing
        all events committed in the epoch).
        """
        with self._lock:
            keys, leaves = self._leaves_as_of(epoch, use_cache=True)
            self._dirty.clear()
            new_count = self._new_since_seal
            self._new_since_seal = 0
            tree  = MerkleTree(leaves) if leaves else MerkleTree([bytes(32)])
            index = {h: i for i, h in enumerate(keys)}
            self._sealed[epoch] = (tree, keys, index)
            er = EpochRoot(epoch=epoch, merkle_root=tree.root(),
                           event_count=new_count)
            self._epoch_roots.append(er)
            return er

    def get_epoch_root(self, epoch: int) -> Optional[EpochRoot]:
        with self._lock:
            return next((r for r in self._epoch_roots if r.epoch == epoch), None)

    def latest_epoch_root(self) -> Optional[EpochRoot]:
        with self._lock:
            return self._epoch_roots[-1] if self._epoch_roots else None

    # ── Verified queries (paper Algorithm 2) ──────────────────────────────

    def query_bl(self, target: bytes, epoch_max: Optional[int] = None,
                 beta: int = 4) -> QueryResult:
        """Backward lineage BL(v) with proof against the pinned root."""
        return self._query(target, "BL", epoch_max)

    def query_fi(self, source: bytes, epoch_max: Optional[int] = None,
                 beta: int = 4) -> QueryResult:
        """Forward impact FI(v) with proof against the pinned root."""
        return self._query(source, "FI", epoch_max)

    def query_ts(self, target: bytes, block_epoch: int,
                 beta: int = 4) -> QueryResult:
        """Temporal slice TS(v, b): BL restricted to the DAG as of
        `block_epoch`, proven against that epoch's (pinned) root."""
        return self._query(target, "TS", block_epoch)

    def _query(self, origin: bytes, kind: str,
               epoch_max: Optional[int]) -> QueryResult:
        with self._lock:
            if epoch_max is not None:
                e = epoch_max
            elif self._epoch_roots:
                e = self._epoch_roots[-1].epoch
            else:
                e = self._max_epoch_seen

            direction = "forward" if kind == "FI" else "backward"
            visited: List[bytes] = []
            seen = {origin}
            queue = deque([origin])
            while queue:
                curr = queue.popleft()
                node = self._nodes.get(curr)
                if node is None or node.epoch > e:
                    if curr == origin:
                        visited.append(curr)     # origin echoed even if absent
                    continue
                visited.append(curr)
                adj = node.forward if direction == "forward" else node.backward
                for nb, ep in adj.items():
                    if ep <= e and nb not in seen:
                        seen.add(nb)
                        queue.append(nb)

            proof = self._prove(visited, origin, kind, e)
        depth = proof.depth if proof else 0
        return QueryResult(hashes=visited, proof=proof, epoch=e, depth=depth)

    def _prove(self, visited: List[bytes], origin: bytes, kind: str,
               e: int) -> Optional[QueryProof]:
        if origin not in self._nodes or self._nodes[origin].epoch > e:
            return None
        sealed = e in self._sealed
        if sealed:
            tree, keys, index = self._sealed[e]
        else:
            keys, leaves = self._leaves_as_of(e, use_cache=False)
            tree  = MerkleTree(leaves) if leaves else MerkleTree([bytes(32)])
            index = {h: i for i, h in enumerate(keys)}
        records, paths = [], []
        for h in visited:
            if h not in index:
                return None
            mp = tree.proof(index[h])
            if mp is None:
                return None
            records.append(self._nodes[h].record_as_of(e))
            paths.append(mp.path)
        return QueryProof(query=kind, origin=origin.hex(), epoch=e,
                          root=tree.root(), sealed=sealed,
                          records=records, paths=paths)

    @property
    def node_count(self) -> int:
        with self._lock:
            return len(self._nodes)

# ══════════════════════════════════════════════════════════════════════════════
# BlobPipeline — EIP-4844 blob encode/decode + retry pipeline
# ══════════════════════════════════════════════════════════════════════════════

BLOB_HEADER_SIZE = 64
BLOB_SIZE_LIMIT  = 128 * 1024   # 128 KB EIP-4844 limit


def encode_blob(epoch: int, batch_root: bytes, events: List[bytes]) -> bytes:
    """Encode epoch events → EIP-4844 blob payload.

    Structure: epoch_header(64B) | zlib-compressed(event_hashes)
    Header:    epoch(8B) | batch_root(32B) | event_count(4B) | reserved(20B)
    """
    hdr = bytearray(BLOB_HEADER_SIZE)
    struct.pack_into('>Q', hdr, 0,  epoch)
    hdr[8:40] = batch_root[:32]
    struct.pack_into('>I', hdr, 40, len(events))
    return bytes(hdr) + zlib.compress(b''.join(events), level=6)


def decode_blob(raw: bytes) -> Tuple[int, bytes, int, bytes]:
    """Decode blob bytes → (epoch, batch_root, event_count, raw_events)."""
    if len(raw) < BLOB_HEADER_SIZE:
        raise ValueError(f"blob too short: {len(raw)} B")
    epoch,       = struct.unpack_from('>Q', raw, 0)
    batch_root    = bytes(raw[8:40])
    event_count,  = struct.unpack_from('>I', raw, 40)
    raw_events    = zlib.decompress(raw[BLOB_HEADER_SIZE:])
    return epoch, batch_root, event_count, raw_events


class BlobPipeline:
    """EIP-4844 blob transaction pipeline.

    Implements:
      - Blob payload encoding / decoding
      - Priority queue of pending epochs (ordered by age — oldest first)
      - EIP-1559 dynamic fee with 1.2× tip multiplier
      - Exponential back-off retry up to MAX_RETRIES=5
      - dry_run=True: hash the payload without real RPC submission
    """

    MAX_RETRIES    = 5
    TIP_MULTIPLIER = 1.2
    BASE_BACKOFF_S = 0.5

    def __init__(self, dry_run: bool = True, rpc_url: str = "",
                 anchor_address: str = ""):
        self.dry_run        = dry_run
        self.rpc_url        = rpc_url
        self.anchor_address = anchor_address
        self._lock          = threading.Lock()
        self._submitted:     List[Dict[str, Any]] = []
        # Priority queue: (age_counter, epoch, blob_bytes) — oldest first
        self._pending:       List[Tuple[int, int, bytes]] = []
        self._age_ctr        = 0

    def submit(self, epoch: int, epoch_root: EpochRoot,
               events: List[bytes]) -> bytes:
        """Encode, enqueue, submit with retry. Returns blob_hash (32 B)."""
        blob = encode_blob(epoch, epoch_root.merkle_root, events)
        if len(blob) > BLOB_SIZE_LIMIT:
            raise ValueError(f"blob {len(blob)} B > {BLOB_SIZE_LIMIT} B limit")
        blob_hash = sha256(blob)

        with self._lock:
            age = self._age_ctr; self._age_ctr += 1
            self._pending.append((age, epoch, blob))
            self._pending.sort(key=lambda x: x[0])   # oldest first

        blob_hash = self._submit_with_retry(epoch, blob, blob_hash)

        with self._lock:
            self._submitted.append({"epoch": epoch,
                                    "blob_hash": blob_hash.hex(),
                                    "size": len(blob),
                                    "event_count": len(events)})
            self._pending = [(a, e, p) for a, e, p in self._pending if e != epoch]
        return blob_hash

    def _submit_with_retry(self, epoch: int, blob: bytes,
                           blob_hash: bytes) -> bytes:
        """Exponential back-off: base_backoff * 2^attempt, up to 5 attempts."""
        for attempt in range(self.MAX_RETRIES):
            try:
                if self.dry_run:
                    return blob_hash
                self._eth_send_blob_tx(epoch, blob)
                return blob_hash
            except Exception:
                if attempt == self.MAX_RETRIES - 1:
                    raise
                time.sleep(self.BASE_BACKOFF_S * (2 ** attempt))
        return blob_hash

    def _eth_send_blob_tx(self, epoch: int, blob: bytes):
        """EIP-4844 type-3 tx with EIP-1559 fee = base_fee * TIP_MULTIPLIER.

        In production: sign tx, eth_sendRawTransaction, poll eth_getTransactionReceipt.
        """
        raise NotImplementedError("Connect rpc_url for live submission")

    @property
    def submissions(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._submitted)

    @property
    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)

# ══════════════════════════════════════════════════════════════════════════════
# Bcp — Branch Commit Protocol (paper Sect. 6, Algorithm 3)
#
# Five phases per agent decision step:
#   Phase 1 — Speculative write: ALL beta branches -> off-chain LineageStore
#             (vertices + edges column families); no EPSL, no chain.
#   Phase 2 — Policy scoring: winner = arg max Score(B, P).
#   Phase 3 — EPSL insertion of the WINNING branch's events only.
#   Phase 4 — Epoch batch accumulation; when |batch| >= w, seal the epoch,
#             submit the blob, and commitRoot(state_root, e, blob_hash).
#   Phase 5 — Prune losers: 96-byte PruneLog entries + GC of
#             branch-exclusive vertices (shared ancestors retained by the
#             DAG-merge branch mask).
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Branch:
    id:           int
    epoch:        int
    score:        float       = 0.0
    event_hashes: List[bytes] = field(default_factory=list)
    is_winner:    bool        = False

    def branch_hash(self) -> bytes:
        """Content hash of the branch: id + sorted event hashes."""
        acc = b"".join(sorted(self.event_hashes))
        return sha256(self.id.to_bytes(8, "big") + acc)


@dataclass
class CommitResult:
    epoch:       int
    merkle_root: bytes        # EPSL state root anchored on-chain
    blob_hash:   bytes
    event_count: int


class InMemoryAnchor:
    """Test double for LineageAnchor.sol with identical semantics:
    sequential epochs (Invariant I2), no re-commitment, keccak Merkle
    verification. Swap in a web3-backed client for live deployment."""

    def __init__(self):
        self._lock  = threading.Lock()
        self._roots: Dict[int, bytes] = {}
        self._blobs: Dict[int, bytes] = {}
        self._latest = -1

    def commit_root(self, root: bytes, epoch: int, blob_hash: bytes) -> None:
        with self._lock:
            if epoch in self._roots:
                raise ValueError(f"EpochAlreadyCommitted({epoch})")
            if self._latest >= 0 and epoch != self._latest + 1:
                raise ValueError(f"EpochOutOfOrder(expected {self._latest + 1}, got {epoch})")
            self._roots[epoch] = root
            self._blobs[epoch] = blob_hash
            self._latest = epoch

    def epoch_root(self, epoch: int) -> Optional[bytes]:
        with self._lock:
            return self._roots.get(epoch)

    def epoch_blob_hash(self, epoch: int) -> Optional[bytes]:
        with self._lock:
            return self._blobs.get(epoch)

    @property
    def latest_epoch(self) -> int:
        with self._lock:
            return self._latest

    def verify_proof(self, leaf: bytes, path: List[bytes], epoch: int) -> bool:
        """Mirror of LineageAnchor.verifyProof (keccak sorted-pair loop)."""
        root = self.epoch_root(epoch)
        if root is None:
            return False
        node = leaf
        for sib in path:
            node = hash_pair(node, sib)
        return node == root


PRUNE_ENTRY_BYTES = 96   # branch_id(32) | branch_hash(32) | epoch(8)+ts(8)+pad(16)


@dataclass
class PruneLogEntry:
    branch_id:   int
    branch_hash: bytes
    epoch:       int
    ts_ms:       int

    def pack(self) -> bytes:
        """96-byte wire format (paper Sect. 6.4)."""
        return (
            sha256(self.branch_id.to_bytes(8, "big"))          # 32 B branch ID
            + self.branch_hash                                  # 32 B
            + self.epoch.to_bytes(8, "big")                     # 8 B
            + self.ts_ms.to_bytes(8, "big")                     # 8 B
            + bytes(16)                                         # reserved
        )

    def leaf(self) -> bytes:
        return keccak256(self.pack())


class PruneLog:
    """Tamper-evident record of discarded speculative branches.

    Entries are 96 bytes and Merkle-anchored every `batch_size` (M=4096)
    entries; the anchored roots are exposed for on-chain commitment at
    lower frequency than epoch roots. An auditor can prove a branch *was
    considered* (membership) without the system paying to store its
    content on-chain (paper Sect. 6.4).
    """

    DEFAULT_BATCH = 4096

    def __init__(self, batch_size: int = DEFAULT_BATCH):
        self._lock       = threading.Lock()
        self._batch_size = batch_size
        self._entries:   List[PruneLogEntry] = []
        self._roots:     List[bytes]         = []

    def append(self, entry: PruneLogEntry) -> None:
        with self._lock:
            self._entries.append(entry)
            if len(self._entries) % self._batch_size == 0:
                batch = self._entries[-self._batch_size:]
                self._roots.append(MerkleTree([e.leaf() for e in batch]).root())

    def flush(self) -> Optional[bytes]:
        """Anchor any unanchored tail (called at operator-defined cadence)."""
        with self._lock:
            done = len(self._roots) * self._batch_size
            tail = self._entries[done:]
            if not tail:
                return None
            root = MerkleTree([e.leaf() for e in tail]).root()
            self._roots.append(root)
            return root

    def membership_proof(self, branch_hash: bytes) -> Optional[MerkleProof]:
        """Prove a discarded branch was considered (auditor query)."""
        with self._lock:
            for batch_i in range(len(self._roots)):
                lo = batch_i * self._batch_size
                batch = self._entries[lo:lo + self._batch_size]
                for j, e in enumerate(batch):
                    if e.branch_hash == branch_hash:
                        return MerkleTree([x.leaf() for x in batch]).proof(j)
        return None

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

    E[T_commit] = (w - r) / mu + t_f   (paper Theorem 5; mu = arrival rate)
    """

    def __init__(self, epsl: Epsl, blob: BlobPipeline,
                 epoch_size: int = 512, finality_s: float = 1.0,
                 arrival_hz: float = 100.0,
                 anchor: Optional[InMemoryAnchor] = None,
                 prune_batch: int = PruneLog.DEFAULT_BATCH):
        self._epsl       = epsl
        self._blob       = blob
        self._epoch_size = epoch_size
        self._finality_s = finality_s
        self._arrival_hz = arrival_hz
        self.anchor      = anchor if anchor is not None else InMemoryAnchor()
        self.prune_log   = PruneLog(batch_size=prune_batch)
        self._lock       = threading.Lock()
        self._batch:   List[bytes]        = []
        self._epoch    = 0
        self._commits: List[CommitResult] = []
        # Speculative events staged per branch until Phase 3/5 resolves them:
        # branch_id -> list of (sources, targets)
        self._pending: Dict[int, List[Tuple[List[bytes], List[bytes]]]] = {}

    @property
    def store(self) -> LineageStore:
        return self._epsl._store

    # ── Phase 1: speculative off-chain write ──────────────────────────────

    def phase1_write(self, sources: List[bytes], targets: List[bytes],
                     branch_id: int) -> List[bytes]:
        """WriteOff: stage a speculative event in the off-chain store.

        Writes vertices + edges to the LineageStore only; the EPSL and
        chain are untouched until the branch wins (Phase 3). Returns the
        event's vertex hashes.
        """
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
        """Non-speculative write path (beta = 1): store + EPSL + batch in
        one step. Used by LineageService and LineageHook when the caller
        does not manage explicit branches."""
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

    # ── Phases 3 + 4: EPSL insertion + epoch batch accumulation ───────────

    def phase3_accumulate(self, winner: Branch) -> Optional[CommitResult]:
        """Insert the winning branch's staged events into the EPSL and
        accumulate them into the epoch batch; commit when |batch| >= w."""
        with self._lock:
            events = self._pending.pop(winner.id, [])
        if not events and winner.event_hashes:
            # Caller staged nothing via phase1 (e.g. synthetic benchmark
            # branches): treat event_hashes as source-less vertices.
            events = [([], list(winner.event_hashes))]
        return self._insert_and_accumulate(events)

    def _insert_and_accumulate(
            self, events: List[Tuple[List[bytes], List[bytes]]]
    ) -> Optional[CommitResult]:
        commit_args = None
        epoch = self.current_epoch
        leaves: List[bytes] = []
        for sources, targets in events:
            self._epsl.insert(sources, targets, epoch, branch_id=0)
            leaves.append(sha256(b"".join(sorted(sources))
                                 + b"\x00" + b"".join(sorted(targets))))
        with self._lock:
            self._batch.extend(leaves)
            if len(self._batch) >= self._epoch_size:
                e = self._epoch
                batch = self._batch[:]
                self._batch.clear()
                self._epoch += 1
                commit_args = (e, batch)
        if commit_args is not None:
            return self._do_commit(*commit_args)
        return None

    def flush_epoch(self) -> Optional[CommitResult]:
        """Force-seal the current epoch (epoch-end timer path)."""
        with self._lock:
            if not self._batch:
                return None
            e = self._epoch
            batch = self._batch[:]
            self._batch.clear()
            self._epoch += 1
        return self._do_commit(e, batch)

    def _do_commit(self, epoch: int, events: List[bytes]) -> CommitResult:
        root      = self._epsl.commit_epoch(epoch)          # I1: state root
        blob_hash = self._blob.submit(epoch, root, events)
        self.anchor.commit_root(root.merkle_root, epoch, blob_hash)  # I2
        result = CommitResult(epoch=epoch, merkle_root=root.merkle_root,
                              blob_hash=blob_hash, event_count=len(events))
        with self._lock:
            self._commits.append(result)
        return result

    # ── Phase 5: prune losers ─────────────────────────────────────────────

    def phase5_prune(self, branches: List[Branch], winner_id: int):
        """Append 96-byte PruneLog entries for the losing branches and
        garbage-collect their branch-exclusive vertices. Vertices shared
        with other branches (DAG merge) are retained."""
        now = int(time.time() * 1000)
        for b in branches:
            if b.id == winner_id:
                continue
            with self._lock:
                staged = self._pending.pop(b.id, [])
            if staged and not b.event_hashes:
                b.event_hashes = [h for s, t in staged for h in (*s, *t)]
            self.prune_log.append(PruneLogEntry(
                branch_id=b.id, branch_hash=b.branch_hash(),
                epoch=self.current_epoch, ts_ms=now))
            self._gc_branch(b, staged)

    def _gc_branch(self, branch: Branch,
                   staged: List[Tuple[List[bytes], List[bytes]]]):
        loser_bit = 1 << (branch.id & 63)
        for sources, targets in staged:
            for h in targets:            # sources may pre-exist / be shared
                v = self.store.get_vertex(h)
                if v is not None and (v.branch_mask & ~loser_bit) == 0:
                    self.store.remove_vertex(h)

    # ── Metrics ───────────────────────────────────────────────────────────

    def expected_commit_latency_s(self) -> float:
        """E[T_commit] = (w - r) / mu + t_f (paper Theorem 5)."""
        with self._lock:
            r = len(self._batch)
        return max(0.0, self._epoch_size - r) / self._arrival_hz + self._finality_s

    @property
    def current_epoch(self) -> int:
        with self._lock:
            return self._epoch

    @property
    def committed_epochs(self) -> int:
        with self._lock:
            return len(self._commits)

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
# LineageHook — LangGraph drop-in hook
# ══════════════════════════════════════════════════════════════════════════════

class LineageHook:
    """Drop-in lineage hook for LangGraph agents.

    Intercepts tool calls via LangGraph's Checkpoint mechanism,
    automatically generating lineage events from tool call input/output pairs.
    Thread-safe; supports nested branching via branch_id.

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
        """Wrap a LangGraph node function with automatic lineage recording."""
        def wrapped(state: Any) -> Any:
            run_id = sha256(json.dumps(state, default=str).encode()).hex()
            self.on_node_start(run_id, name, state)
            result = fn(state)
            self.on_node_end(run_id, name, result)
            return result
        return wrapped

# ══════════════════════════════════════════════════════════════════════════════
# LineageService — service facade (WriteLineage / QueryBL / QueryFI /
# QueryTS / Verify). A production deployment would expose this interface
# over gRPC from the Rust engine; this Python implementation is the
# reference used by the benchmark harness (dataset_gen.py). Latency and
# throughput figures must be MEASURED with the harness on the target
# hardware — none are hard-coded here.
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class WriteRequest:
    sources:   List[bytes]
    targets:   List[bytes]
    branch_id: int
    epoch:     int

@dataclass
class WriteResponse:
    inserted_hashes: List[bytes]
    dedup_count:     int

@dataclass
class QueryRequest:
    vertex_hash: bytes
    epoch_max:   Optional[int]
    beta:        int = 4

@dataclass
class QueryResponse:
    hashes:      List[bytes]
    proof:       Optional[QueryProof]
    proof_root:  bytes
    epoch:       int
    depth:       int
    verified:    bool   # cryptographic verification of the proof
    anchored:    bool   # proof root matches the root committed on-chain
    proof_bytes: int = 0


class LineageService:
    """Service facade: WriteLineage, QueryBL, QueryFI, QueryTS, Verify.

    Writes go through the BCP's direct path (store + EPSL + epoch batch).
    Query responses carry the full QueryProof; `verified` reports
    cryptographic validity, `anchored` additionally requires the proof
    root to equal the root committed on the anchor contract for the
    pinned epoch. `verify()` re-checks a response against the anchor.
    """

    DRAIN_INTERVAL_MS = 100   # legacy buffered-write path (drain_buffer)

    def __init__(self, epsl: Epsl, bcp: Bcp):
        self._epsl    = epsl
        self._bcp     = bcp
        self._lock    = threading.Lock()
        self._write_buf: List[WriteRequest] = []
        self._metrics = {"writes_total": 0, "queries_bl": 0,
                         "queries_fi":   0, "queries_ts": 0}

    def write_lineage(self, req: WriteRequest) -> WriteResponse:
        before = self._epsl.node_count
        hashes = self._bcp.write_direct(req.sources, req.targets, req.branch_id)
        after  = self._epsl.node_count
        dedup  = max(0, len(hashes) - (after - before))
        with self._lock:
            self._metrics["writes_total"] += 1
        return WriteResponse(inserted_hashes=hashes, dedup_count=dedup)

    def query_bl(self, req: QueryRequest) -> QueryResponse:
        with self._lock:
            self._metrics["queries_bl"] += 1
        return self._wrap(self._epsl.query_bl(
            req.vertex_hash, req.epoch_max, req.beta))

    def verify(self, resp: QueryResponse) -> bool:
        """Client-side VerifyProof RPC: check the response's proof against
        the root fetched independently from the anchor contract."""
        if resp.proof is None:
            return False
        onchain = self._bcp.anchor.epoch_root(resp.proof.epoch)
        if onchain is None:
            return False
        return resp.proof.verify(onchain)

    def query_fi(self, req: QueryRequest) -> QueryResponse:
        with self._lock:
            self._metrics["queries_fi"] += 1
        return self._wrap(self._epsl.query_fi(
            req.vertex_hash, req.epoch_max, req.beta))

    def query_ts(self, req: QueryRequest) -> QueryResponse:
        with self._lock:
            self._metrics["queries_ts"] += 1
        if req.epoch_max is None:
            raise ValueError("QueryTS requires epoch_max")
        return self._wrap(self._epsl.query_ts(
            req.vertex_hash, req.epoch_max, req.beta))

    def drain_buffer(self) -> int:
        """Drain write buffer — called every 100 ms."""
        with self._lock:
            buf = self._write_buf[:]
            self._write_buf.clear()
        for r in buf:
            self._bcp.phase1_write(r.sources, r.targets, r.branch_id)
        return len(buf)

    @property
    def metrics(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._metrics)

    def _wrap(self, res: QueryResult) -> QueryResponse:
        proof    = res.proof
        root     = proof.root if proof else bytes(32)
        verified = proof.verify() if proof else False
        onchain  = self._bcp.anchor.epoch_root(res.epoch)
        anchored = bool(proof and proof.sealed and onchain == root
                        and proof.verify(onchain))
        return QueryResponse(hashes=res.hashes, proof=proof,
                             proof_root=root, epoch=res.epoch,
                             depth=res.depth, verified=verified,
                             anchored=anchored,
                             proof_bytes=proof.byte_size if proof else 0)

# ══════════════════════════════════════════════════════════════════════════════
# AeTpcc — benchmark workload simulation
#
# Augments TPC-C transaction mix with lineage annotations (Table AE-TPCC).
# Used to reproduce latency and DAG shape metrics.
# ══════════════════════════════════════════════════════════════════════════════

# TPC-C transaction mix (paper Table 4)
AETPCC_MIX = [
    ("NewOrder",    0.45),
    ("Payment",     0.43),
    ("OrderStatus", 0.04),
    ("Delivery",    0.04),
    ("StockLevel",  0.04),
]

# Lineage annotation per tx type: ((|S| lo, hi), (|T| lo, hi)) — paper Table 4.
AETPCC_LINEAGE: Dict[str, Tuple[Tuple[int, int], Tuple[int, int]]] = {
    "NewOrder":    ((8, 15), (5, 15)),
    "Payment":     ((2, 2),  (1, 1)),
    "OrderStatus": ((3, 3),  (1, 1)),
    "Delivery":    ((10, 10), (10, 10)),
    "StockLevel":  ((20, 20), (1, 1)),
    "AgentStep":   ((4, 12), (1, 4)),   # emitted at beta x f, not in the mix
}


@dataclass
class AeTpccEvent:
    tx_type:    str
    tx_id:      int
    branch_id:  int
    epoch:      int
    sources:    List[bytes]
    targets:    List[bytes]
    latency_ms: float = 0.0


class AeTpcc:
    """Agent-extended TPC-C workload generator (paper Sect. 8.1).

    Generates lineage events matching the paper Table 4 transaction mix
    and |S|/|T| annotation ranges, plus speculative AgentStep branches,
    for regenerating the latency and DAG-shape measurements.
    """

    def __init__(self, seed: int = 42, beta: int = 4,
                 warehouse_count: int = 10):
        self._rng        = random.Random(seed)
        self._beta       = beta
        self._warehouses = warehouse_count
        self._tx_ctr     = 0

    def _pick_tx_type(self) -> str:
        r = self._rng.random()
        cumul = 0.0
        for name, freq in AETPCC_MIX:
            cumul += freq
            if r < cumul:
                return name
        return AETPCC_MIX[-1][0]

    def _gen_keys(self, n: int, prefix: str) -> List[bytes]:
        return [sha256(f"{prefix}:{self._rng.randint(0, 10_000)}".encode())
                for _ in range(n)]

    def next_event(self, epoch: int, branch_id: int,
                   tx_type: Optional[str] = None) -> AeTpccEvent:
        tx_type = tx_type or self._pick_tx_type()
        (s_lo, s_hi), (t_lo, t_hi) = AETPCC_LINEAGE[tx_type]
        ev = AeTpccEvent(
            tx_type=tx_type, tx_id=self._tx_ctr, branch_id=branch_id,
            epoch=epoch,
            sources=self._gen_keys(self._rng.randint(s_lo, s_hi), f"{tx_type}_src"),
            targets=self._gen_keys(self._rng.randint(t_lo, t_hi), f"{tx_type}_tgt"))
        self._tx_ctr += 1
        return ev

    def agent_step(self, epoch: int, branch_id: int) -> AeTpccEvent:
        """One speculative agent decision event (paper Table 4, last row)."""
        return self.next_event(epoch, branch_id, tx_type="AgentStep")

    def run(self, bcp: Bcp, n_events: int,
            verbose: bool = False) -> Dict[str, Any]:
        """Run the workload through the full five-phase BCP.

        TPC-C transactions are non-speculative (write_direct). Every
        decision step additionally spawns `beta` speculative AgentStep
        branches: all are Phase-1 written, one wins (Phase 2/3), the rest
        are pruned into the PruneLog (Phase 5) — matching the paper's
        agentic workload model.
        """
        counts: Dict[str, int] = {name: 0 for name, _ in AETPCC_MIX}
        counts["AgentStep"] = 0
        commits    = 0
        latencies: List[float] = []
        step_i     = 0

        for i in range(n_events):
            epoch = bcp.current_epoch
            ev    = self.next_event(epoch, 0)
            counts[ev.tx_type] += 1
            t0 = time.perf_counter()
            r  = bcp.write_direct(ev.sources, ev.targets, 0)
            ev.latency_ms = (time.perf_counter() - t0) * 1000
            latencies.append(ev.latency_ms)

            if (i + 1) % 10 == 0:      # one agent decision step per 10 tx
                branches = []
                for j in range(self._beta):
                    bid = 1 + step_i * self._beta + j
                    aev = self.agent_step(bcp.current_epoch, bid)
                    counts["AgentStep"] += 1
                    t0 = time.perf_counter()
                    hashes = bcp.phase1_write(aev.sources, aev.targets, bid)
                    latencies.append((time.perf_counter() - t0) * 1000)
                    branches.append(Branch(id=bid, epoch=bcp.current_epoch,
                                           event_hashes=hashes))
                wid = Bcp.phase2_score(
                    branches, scorer=lambda b: self._rng.random())
                winner = next(b for b in branches if b.id == wid)
                if bcp.phase3_accumulate(winner):
                    commits += 1
                bcp.phase5_prune(branches, wid)
                step_i += 1

        commits += bcp.committed_epochs - commits  # count Phase-4 commits from write_direct
        latencies.sort()
        n    = len(latencies)
        p50  = latencies[n // 2]        if n else 0.0
        p99  = latencies[int(n * 0.99)] if n else 0.0
        mean = sum(latencies) / n       if n else 0.0

        stats = {
            "n_events":      n_events,
            "tx_counts":     counts,
            "commits":       commits,
            "epsl_nodes":    bcp._epsl.node_count,
            "dedup_ratio":   bcp.store.dedup_ratio,
            "pruned":        bcp.total_pruned,
            "write_p50_ms":  round(p50,  4),
            "write_p99_ms":  round(p99,  4),
            "write_mean_ms": round(mean, 4),
        }
        if verbose:
            print(f"  AE-TPCC {n_events} events | commits={commits} "
                  f"| p50={p50:.4f} ms | p99={p99:.4f} ms")
        return stats

# ══════════════════════════════════════════════════════════════════════════════
# Cost model (paper Sect. 2.2) and commit latency (paper Theorem 5)
# ══════════════════════════════════════════════════════════════════════════════

def cost_per_event_usd(epoch_size: int = 512, event_bytes: float = 200.0,
                       zstd_ratio: float = 4.0, gas_gwei: float = 0.10,
                       blob_gwei: float = 0.10,
                       eth_usd: float = 2_000.0) -> float:
    """C_sys = (G_SSTORE_update / w) * gas_price + (s_e / z) * blob_price."""
    gwei_to_usd = 1e-9 * eth_usd
    return (2_900.0 / epoch_size) * gas_gwei * gwei_to_usd + \
           (event_bytes / zstd_ratio) * blob_gwei * gwei_to_usd


def expected_commit_latency_s(w: int, r: int, lam: float,
                               t_f: float) -> float:
    """E[T_commit] = (w - r) / mu + t_f (paper Theorem 5)."""
    return max(0.0, w - r) / lam + t_f

# ══════════════════════════════════════════════════════════════════════════════
# Test suite
# ══════════════════════════════════════════════════════════════════════════════

def _run_tests():
    passed = failed = 0

    def test(name: str, fn: Callable):
        nonlocal passed, failed
        try:
            fn(); print(f"  \u2713 {name}"); passed += 1
        except Exception as e:
            import traceback
            print(f"  \u2717 {name}: {e}")
            traceback.print_exc(); failed += 1

    # ── MerkleTree / MerkleProof ──────────────────────────────────────────
    print("\n── MerkleTree / MerkleProof " + "─" * 30)

    def t_single_leaf():
        leaf = sha256(b"a")
        t = MerkleTree([leaf])
        assert t.root() == leaf
        p = t.proof(0); assert p is not None and p.verify()
    test("single_leaf", t_single_leaf)

    def t_two_leaves():
        l0, l1 = sha256(b"x"), sha256(b"y")
        t = MerkleTree([l0, l1])
        p0 = t.proof(0); p1 = t.proof(1)
        assert p0 is not None and p0.verify()
        assert p1 is not None and p1.verify()
        assert p0.root == p1.root
    test("two_leaves", t_two_leaves)

    def t_proof_all_sizes():
        for n in [1, 2, 3, 4, 7, 8, 15, 16, 17, 100, 512]:
            leaves = [sha256(str(i).encode()) for i in range(n)]
            tree   = MerkleTree(leaves)
            for idx in range(n):
                p = tree.proof(idx)
                assert p is not None and p.verify(), f"n={n} idx={idx}"
    test("proof_all_sizes", t_proof_all_sizes)

    def t_tampered_proof_rejected():
        leaves = [sha256(str(i).encode()) for i in range(8)]
        p = MerkleTree(leaves).proof(0)
        assert p is not None
        p.leaf = bytes([p.leaf[0] ^ 0xFF]) + p.leaf[1:]
        assert not p.verify()
    test("tampered_proof_rejected", t_tampered_proof_rejected)

    def t_proof_depth():
        for n, exp in [(1,0),(2,1),(3,2),(4,2),(8,3),(9,4),(16,4),(100,7)]:
            leaves = [sha256(str(i).encode()) for i in range(n)]
            assert MerkleTree(leaves).depth() == exp, f"n={n}"
    test("theorem2_depth", t_proof_depth)

    def t_proof_byte_size():
        leaves = [sha256(str(i).encode()) for i in range(64)]
        p = MerkleTree(leaves).proof(0)
        assert p is not None and p.byte_size == 32 + p.depth * 32
    test("proof_byte_size", t_proof_byte_size)

    def t_canonical_ordering():
        a, b = sha256(b"a"), sha256(b"b")
        assert hash_pair(a, b) == hash_pair(b, a)
    test("canonical_ordering_matches_solidity", t_canonical_ordering)

    # ── LineageStore ──────────────────────────────────────────────────────
    print("\n── LineageStore " + "─" * 44)

    def t_vertex_hash_is_sha256():
        c = b"hello"
        v = Vertex.new(c, 0x01, 0, bytes(32), 0)
        assert v.hash == sha256(c)
    test("vertex_hash_is_sha256", t_vertex_hash_is_sha256)

    def t_dag_merge():
        store = LineageStore()
        c = b"shared"
        v1 = Vertex.new(c, 0x01, 0, bytes(32), 1)
        v2 = Vertex.new(c, 0x01, 0, bytes(32), 2)
        n1, _ = store.put_vertex(v1); n2, _ = store.put_vertex(v2)
        assert n1 and not n2 and store.dag_merges_total == 1
        sv = store.get_vertex(sha256(c))
        assert sv is not None and (sv.branch_mask & (1 << 2))
    test("dag_merge", t_dag_merge)

    def t_edge_scan():
        store = LineageStore()
        src = sha256(b"src"); t1 = sha256(b"t1"); t2 = sha256(b"t2")
        store.put_edge(src, 0, [t1]); store.put_edge(src, 1, [t2])
        assert len(store.scan_edges(src, 0, 1)) == 2
    test("edge_scan", t_edge_scan)

    # ── Epsl ──────────────────────────────────────────
    print("\n── Epsl " + "─" * 46)

    def t_algorithm1_both_nodes():
        """: both src and tgt become EPSL nodes."""
        epsl = Epsl(LineageStore())
        src  = sha256(b"oracle"); tgt = sha256(b"decision")
        epsl.insert([src], [tgt], 0, 1)
        assert epsl.node_count == 2, f"expected 2, got {epsl.node_count}"
    test("algorithm1_both_nodes", t_algorithm1_both_nodes)

    def t_forward_pointers():
        """src.fwd → tgt set at insert time."""
        epsl = Epsl(LineageStore())
        src  = sha256(b"src"); tgt = sha256(b"tgt")
        epsl.insert([src], [tgt], 0, 1)
        assert tgt in epsl._nodes[src].forward
        assert src in epsl._nodes[tgt].backward
    test("forward_pointers", t_forward_pointers)

    def t_query_bl_reaches_src():
        epsl = Epsl(LineageStore())
        src  = sha256(b"oracle"); tgt = sha256(b"decision")
        epsl.insert([src], [tgt], 0, 1)
        res = epsl.query_bl(tgt, beta=1)
        assert src in res.hashes and tgt in res.hashes
    test("query_bl_reaches_src", t_query_bl_reaches_src)

    def t_query_fi_follows_fwd():
        """FI traversal uses forward pointers inserted by."""
        epsl = Epsl(LineageStore())
        a = sha256(b"a"); b_ = sha256(b"b"); c = sha256(b"c")
        epsl.insert([a], [b_], 0, 0)
        epsl.insert([b_], [c],  0, 0)
        res = epsl.query_fi(a, beta=1)
        assert b_ in res.hashes and c in res.hashes
    test("query_fi_follows_fwd", t_query_fi_follows_fwd)

    def t_dag_merge_deduplicates():
        epsl = Epsl(LineageStore())
        src  = sha256(b"oracle"); tgt = sha256(b"shared")
        epsl.insert([src], [tgt], 0, 1)
        epsl.insert([src], [tgt], 0, 2)
        assert epsl.node_count == 2
        assert 1 in epsl._nodes[tgt].branch_ids
        assert 2 in epsl._nodes[tgt].branch_ids
    test("dag_merge_deduplicates", t_dag_merge_deduplicates)

    def t_epoch_commit_valid_root():
        epsl = Epsl(LineageStore())
        for i in range(10):
            epsl.insert([], [sha256(f"item-{i}".encode())], 0, 0)
        root = epsl.commit_epoch(0)
        assert root.event_count == 10 and root.merkle_root != bytes(32)
    test("epoch_commit_valid_root", t_epoch_commit_valid_root)

    def t_proof_verifies_after_commit():
        """Query proofs verify against the sealed (anchorable) state root."""
        epsl = Epsl(LineageStore())
        src_ = sha256(b"oracle"); tgt = sha256(b"decision")
        epsl.insert([src_], [tgt], 0, 0)
        root = epsl.commit_epoch(0)
        res  = epsl.query_bl(tgt)
        assert res.proof is not None and res.proof.sealed
        assert res.proof.root == root.merkle_root
        assert res.proof.verify(root.merkle_root)
    test("proof_verifies_after_commit", t_proof_verifies_after_commit)

    def t_temporal_slice():
        epsl = Epsl(LineageStore())
        old  = sha256(b"old"); new_ = sha256(b"new")
        epsl.insert([], [old],  0, 0)
        epsl.insert([], [new_], 5, 0)
        res = epsl.query_ts(old, block_epoch=2)
        assert old in res.hashes and new_ not in res.hashes
    test("temporal_slice", t_temporal_slice)

    def t_level_bounded():
        for i in range(500):
            lv = Epsl._assign_level(sha256(i.to_bytes(8, 'big')))
            assert 0 <= lv <= Epsl.L_MAX
    test("level_assignment_bounded", t_level_bounded)

    # ── BlobPipeline ──────────────────────────────────────────────────────
    print("\n── BlobPipeline " + "─" * 51)

    def t_encode_decode_roundtrip():
        events = [sha256(str(i).encode()) for i in range(8)]
        root   = sha256(b"root")
        blob   = encode_blob(7, root, events)
        e, br, cnt, raw = decode_blob(blob)
        assert e == 7 and br == root and cnt == 8
        assert raw == b''.join(events)
    test("encode_decode_roundtrip", t_encode_decode_roundtrip)

    def t_blob_size_limit():
        events = [sha256(str(i).encode()) for i in range(512)]
        blob   = encode_blob(0, bytes(32), events)
        assert len(blob) <= BLOB_SIZE_LIMIT
    test("blob_size_limit", t_blob_size_limit)

    def t_blob_hash_deterministic():
        events = [sha256(b"e")]
        b1 = sha256(encode_blob(0, sha256(b"r"), events))
        b2 = sha256(encode_blob(0, sha256(b"r"), events))
        assert b1 == b2
    test("blob_hash_deterministic", t_blob_hash_deterministic)

    def t_blob_retry_queue():
        bp    = BlobPipeline(dry_run=True)
        epsl  = Epsl(LineageStore())
        er    = epsl.commit_epoch(0)
        bp.submit(0, er, [sha256(b"e")])
        assert len(bp.submissions) == 1 and bp.pending_count == 0
    test("blob_retry_queue", t_blob_retry_queue)

    # ── Bcp ─────────────────────────────────────────────
    print("\n── Bcp " + "─" * 49)

    def mk():
        epsl = Epsl(LineageStore()); blob = BlobPipeline()
        return Bcp(epsl, blob, epoch_size=512)

    def t_phase1_returns_src_and_tgt():
        bcp = mk()
        src = sha256(b"src"); tgt = sha256(b"tgt")
        res = bcp.phase1_write([src], [tgt], 1)
        assert src in res and tgt in res
    test("phase1_returns_src_and_tgt", t_phase1_returns_src_and_tgt)

    def t_phase2_score():
        bs  = [Branch(id=i, epoch=0) for i in range(3)]
        wid = Bcp.phase2_score(bs, scorer=lambda b: b.id * 0.5)
        assert wid == 2 and bs[2].is_winner
    test("phase2_score", t_phase2_score)

    def t_epoch_commit_when_full():
        epsl = Epsl(LineageStore()); blob = BlobPipeline()
        bcp  = Bcp(epsl, blob, epoch_size=4)
        for i in range(5):
            evs = [sha256((i * 100 + j).to_bytes(4, 'big')) for j in range(4)]
            bcp.phase3_accumulate(Branch(id=i, epoch=i, event_hashes=evs))
        assert bcp.committed_epochs >= 1
    test("epoch_commit_when_full", t_epoch_commit_when_full)

    def t_theorem4_latency():
        bcp = mk()
        t   = bcp.expected_commit_latency_s()
        assert abs(t - 6.12) < 0.01, f"E[T]={t:.3f}"
    test("theorem4_latency", t_theorem4_latency)

    def t_prune_records_losers():
        bcp = mk()
        bs  = [Branch(id=i, epoch=0, score=float(i)) for i in range(3)]
        bcp.phase5_prune(bs, winner_id=2)
        assert bcp.total_pruned == 2
    test("prune_records_losers", t_prune_records_losers)

    # ── BranchManager / LineageHook ───────────────────────────────────────
    print("\n── BranchManager / LineageHook " + "─" * 35)

    def t_branch_context_records():
        epsl = Epsl(LineageStore()); blob = BlobPipeline()
        bcp  = Bcp(epsl, blob, epoch_size=2)
        mgr  = BranchManager(bcp, beta=2)
        with mgr.new_step() as step:
            for b in step.branches:
                with step.context(b) as ctx:
                    ctx.record_source(b"oracle_price")
                    ctx.record_target(sha256(f"decision-{b.id}".encode()))
                    ctx.set_score(float(b.id))
            step.commit_winner()
        assert epsl.node_count >= 1
    test("branch_context_records", t_branch_context_records)

    def t_hook_records_tool_call():
        bcp  = Bcp(Epsl(LineageStore()), BlobPipeline())
        hook = LineageHook(bcp, branch_id=0)
        hook.on_tool_call("run1", "get_price", {"symbol": "ETH"})
        hook.on_tool_result("run1", "get_price", {"price": 2000})
        assert bcp._epsl.node_count >= 1
    test("hook_records_tool_call", t_hook_records_tool_call)

    def t_hook_wrap_node():
        bcp  = Bcp(Epsl(LineageStore()), BlobPipeline())
        hook = LineageHook(bcp, branch_id=0)
        out  = hook.wrap_node("n", lambda s: {"r": s.get("x",0)+1})({"x": 5})
        assert out["r"] == 6 and bcp._epsl.node_count >= 1
    test("hook_wrap_node", t_hook_wrap_node)

    # ── LineageService gRPC layer ─────────────────────────────────────────
    print("\n── LineageService gRPC layer " + "─" * 38)

    def mk_svc():
        epsl = Epsl(LineageStore()); blob = BlobPipeline()
        bcp  = Bcp(epsl, blob)
        return LineageService(epsl, bcp), epsl

    def t_service_write():
        svc, epsl = mk_svc()
        src = sha256(b"oracle"); tgt = sha256(b"decision")
        resp = svc.write_lineage(WriteRequest([src], [tgt], 0, 0))
        assert src in resp.inserted_hashes and tgt in resp.inserted_hashes
        assert svc.metrics["writes_total"] == 1
    test("service_write_lineage", t_service_write)

    def t_service_query_bl():
        svc, epsl = mk_svc()
        src = sha256(b"A"); tgt = sha256(b"B")
        svc.write_lineage(WriteRequest([src], [tgt], 0, 0))
        resp = svc.query_bl(QueryRequest(tgt, epoch_max=None))
        assert tgt in resp.hashes and src in resp.hashes and resp.verified
    test("service_query_bl", t_service_query_bl)

    def t_service_query_fi():
        svc, _ = mk_svc()
        a = sha256(b"A"); b_ = sha256(b"B"); c = sha256(b"C")
        svc.write_lineage(WriteRequest([a],  [b_], 0, 0))
        svc.write_lineage(WriteRequest([b_], [c],  0, 0))
        resp = svc.query_fi(QueryRequest(a, epoch_max=None))
        assert b_ in resp.hashes and c in resp.hashes
        assert svc.metrics["queries_fi"] == 1
    test("service_query_fi", t_service_query_fi)

    def t_service_query_ts():
        svc, _ = mk_svc()
        old = sha256(b"old"); new_ = sha256(b"new")
        svc.write_lineage(WriteRequest([], [old],  0, 0))
        svc.write_lineage(WriteRequest([], [new_], 5, 0))
        resp = svc.query_ts(QueryRequest(old, epoch_max=2))
        assert old in resp.hashes and new_ not in resp.hashes
    test("service_query_ts", t_service_query_ts)

    def t_service_drain_buffer():
        svc, _ = mk_svc()
        assert svc.drain_buffer() == 0
    test("service_drain_buffer", t_service_drain_buffer)

    # ── benchmark workload ───────────────────────────────────────────
    print("\n── benchmark workload " + "─" * 47)

    def t_aetpcc_tx_mix():
        """Transaction mix must match paper Table 4 proportions within 3%."""
        gen    = AeTpcc(seed=0, beta=4)
        counts = {name: 0 for name, _ in AETPCC_MIX}
        for i in range(10_000):
            counts[gen.next_event(0, 0).tx_type] += 1
        total = sum(counts.values())
        for name, freq in AETPCC_MIX:
            actual = counts[name] / total
            assert abs(actual - freq) < 0.03, f"{name}: {actual:.2f} vs {freq:.2f}"
    test("aetpcc_tx_mix", t_aetpcc_tx_mix)

    def t_aetpcc_lineage_schema():
        """|S| and |T| fall inside the paper Table 4 ranges."""
        gen = AeTpcc(seed=42)
        for _ in range(200):
            ev = gen.next_event(0, 0)
            (s_lo, s_hi), (t_lo, t_hi) = AETPCC_LINEAGE[ev.tx_type]
            assert s_lo <= len(ev.sources) <= s_hi
            assert t_lo <= len(ev.targets) <= t_hi
        aev = gen.agent_step(0, 1)
        assert 4 <= len(aev.sources) <= 12 and 1 <= len(aev.targets) <= 4
    test("aetpcc_lineage_schema", t_aetpcc_lineage_schema)

    def t_aetpcc_run():
        bcp  = Bcp(Epsl(LineageStore()), BlobPipeline(), epoch_size=64)
        gen  = AeTpcc(seed=7, beta=4)
        stats = gen.run(bcp, n_events=200)
        assert stats["n_events"] == 200 and stats["epsl_nodes"] > 0
    test("aetpcc_run", t_aetpcc_run)

    # ── Cost model ─────────────────────────────────────────────────
    print("\n── Cost model " + "─" * 52)

    def t_cost_arb():
        c = cost_per_event_usd()
        assert 1e-7 < c < 1e-4, f"${c:.8f}"
    test("cost_arb", t_cost_arb)

    def t_cost_l1_higher():
        assert cost_per_event_usd(gas_gwei=10.0) > cost_per_event_usd(gas_gwei=0.10)
    test("cost_l1_higher", t_cost_l1_higher)

    def t_larger_epoch_lower_cost():
        assert cost_per_event_usd(epoch_size=32) > cost_per_event_usd(epoch_size=512)
    test("larger_epoch_lower_cost", t_larger_epoch_lower_cost)

    def t_gas_constants():
        sstore = (2900 / 512) * 0.10 * 1e-9 * 2000
        assert abs(sstore - 0.0000011328) < 1e-9
    test("gas_constants", t_gas_constants)

    # ── End-to-end pipelines ──────────────────────────────────────────────
    print("\n── End-to-end pipelines " + "─" * 49)

    def t_full_pipeline():
        epsl = Epsl(LineageStore()); blob = BlobPipeline()
        bcp  = Bcp(epsl, blob, epoch_size=2)
        for step_i in range(3):
            branches = [Branch(id=step_i * 2 + j, epoch=0) for j in range(2)]
            for b in branches:
                hashes = bcp.phase1_write(
                    [sha256(f"src-{step_i}".encode())],
                    [sha256(f"step={step_i}-branch={b.id}".encode())], b.id)
                b.event_hashes = hashes
            wid    = Bcp.phase2_score(branches, scorer=lambda b: float(b.id))
            winner = next(b for b in branches if b.id == wid)
            bcp.phase3_accumulate(winner)
            bcp.phase5_prune(branches, wid)
        assert bcp.committed_epochs >= 1 and bcp.total_pruned == 3
        er = epsl.latest_epoch_root()
        assert er is not None
        res = epsl.query_bl(list(epsl._nodes.keys())[0], beta=4)
        if res.proof:
            assert res.proof.verify()
    test("full_pipeline", t_full_pipeline)

    def t_end_to_end_with_service():
        """3-hop chain: oracle → decision → order, verified via BL + FI."""
        epsl = Epsl(LineageStore()); blob = BlobPipeline()
        bcp  = Bcp(epsl, blob, epoch_size=4)
        svc  = LineageService(epsl, bcp)
        oracle   = sha256(b"ETH:2050")
        decision = sha256(b"buy:1ETH")
        order    = sha256(b"order:123")
        svc.write_lineage(WriteRequest([oracle],   [decision], 0, 0))
        svc.write_lineage(WriteRequest([decision], [order],    0, 0))
        bl = svc.query_bl(QueryRequest(order, epoch_max=None))
        assert oracle in bl.hashes and decision in bl.hashes and bl.verified
        fi = svc.query_fi(QueryRequest(oracle, epoch_max=None))
        assert decision in fi.hashes and order in fi.hashes
    test("end_to_end_with_service", t_end_to_end_with_service)

    # ── Authenticated queries & tamper-evidence (paper Sect. 5, 9) ───────
    print("\n── Authenticated queries / tamper-evidence " + "─" * 24)

    def t_keccak_vectors():
        assert keccak256(b"").hex() == \
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        assert keccak256(b"abc").hex() == \
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    test("keccak256_reference_vectors", t_keccak_vectors)

    def t_end_to_end_anchor_verify():
        """Write -> commit -> query: proof verifies against the ON-CHAIN root
        fetched from the anchor, not one supplied by the prover (D1)."""
        epsl = Epsl(LineageStore()); bcp = Bcp(epsl, BlobPipeline(), epoch_size=2)
        oracle = sha256(b"ETH:2000"); dec = sha256(b"buy"); order = sha256(b"o1")
        bcp.write_direct([oracle], [dec], 0)
        bcp.write_direct([dec], [order], 0)          # fills the epoch -> commit
        assert bcp.committed_epochs == 1
        res = epsl.query_bl(order, epoch_max=0)
        onchain = bcp.anchor.epoch_root(0)
        assert onchain is not None and res.proof is not None
        assert res.proof.sealed and res.proof.verify(onchain)
        assert {oracle, dec, order} <= set(res.hashes)
    test("end_to_end_anchor_verify", t_end_to_end_anchor_verify)

    def t_tampered_record_rejected():
        """S1a: altering a returned record invalidates its inclusion proof."""
        epsl = Epsl(LineageStore())
        s = sha256(b"s"); t_ = sha256(b"t")
        epsl.insert([s], [t_], 0, 0)
        root = epsl.commit_epoch(0).merkle_root
        res = epsl.query_bl(t_)
        assert res.proof.verify(root)
        res.proof.records[0]["bwd"] = []            # claim t_ has no ancestors
        assert not res.proof.verify(root)
    test("tampered_record_rejected", t_tampered_record_rejected)

    def t_suppressed_ancestor_rejected():
        """S1b: silently dropping an ancestor from the result fails the
        closure check even though every remaining proof is valid."""
        epsl = Epsl(LineageStore())
        a = sha256(b"a"); b_ = sha256(b"b"); c = sha256(b"c")
        epsl.insert([a], [b_], 0, 0)
        epsl.insert([b_], [c], 0, 0)
        root = epsl.commit_epoch(0).merkle_root
        res = epsl.query_bl(c)
        assert res.proof.verify(root)
        keep = [i for i, r in enumerate(res.proof.records)
                if r["h"] != a.hex()]
        res.proof.records = [res.proof.records[i] for i in keep]
        res.proof.paths   = [res.proof.paths[i]   for i in keep]
        assert not res.proof.verify(root)
    test("suppressed_ancestor_rejected", t_suppressed_ancestor_rejected)

    def t_ts_pinned_to_past_root():
        """TS(v, e) proves against the root committed AT e; later events are
        excluded and do not disturb old proofs (epoch pinning)."""
        epsl = Epsl(LineageStore()); bcp = Bcp(epsl, BlobPipeline(), epoch_size=1)
        old = sha256(b"old")
        bcp.write_direct([], [old], 0)               # epoch 0 sealed
        root0 = bcp.anchor.epoch_root(0)
        new_ = sha256(b"new")
        bcp.write_direct([old], [new_], 0)           # epoch 1 sealed
        res = epsl.query_ts(old, block_epoch=0)
        assert new_ not in res.hashes
        assert res.proof is not None and res.proof.verify(root0)
        assert not res.proof.verify(bcp.anchor.epoch_root(1))
    test("ts_pinned_to_past_root", t_ts_pinned_to_past_root)

    def t_equivocation_leaves_differ():
        """Two different adjacency records for the same vertex hash yield
        different leaves — the shape LineageAnchor.slash checks."""
        s1, s2, v = sha256(b"s1"), sha256(b"s2"), sha256(b"v")
        n1 = EpslNode(hash=v, level=0, epoch=0, backward={s1: 0})
        n2 = EpslNode(hash=v, level=0, epoch=0, backward={s2: 0})
        d1 = node_record_digest(n1.record_as_of(0))
        d2 = node_record_digest(n2.record_as_of(0))
        assert d1 != d2
        assert node_leaf(v, d1) != node_leaf(v, d2)
    test("equivocation_leaves_differ", t_equivocation_leaves_differ)

    # ── Anchor / PruneLog / Phase semantics (paper Sect. 4, 6) ───────────
    print("\n── Anchor / PruneLog / phase semantics " + "─" * 28)

    def t_anchor_epoch_monotonic():
        """Invariant I2: epochs commit sequentially, no re-commitment."""
        a = InMemoryAnchor()
        a.commit_root(sha256(b"r0"), 0, sha256(b"b0"))
        try:
            a.commit_root(sha256(b"r2"), 2, sha256(b"b2")); assert False
        except ValueError:
            pass
        try:
            a.commit_root(sha256(b"rx"), 0, sha256(b"bx")); assert False
        except ValueError:
            pass
        a.commit_root(sha256(b"r1"), 1, sha256(b"b1"))
        assert a.latest_epoch == 1
    test("anchor_epoch_monotonic_I2", t_anchor_epoch_monotonic)

    def t_prune_log_entry_96B():
        e = PruneLogEntry(branch_id=7, branch_hash=sha256(b"B7"),
                          epoch=3, ts_ms=1_700_000_000_000)
        assert len(e.pack()) == PRUNE_ENTRY_BYTES == 96
    test("prune_log_entry_96B", t_prune_log_entry_96B)

    def t_prune_log_membership():
        """Auditor proves a discarded branch WAS considered (Sect. 6.4)."""
        log = PruneLog(batch_size=4)
        hashes = []
        for i in range(4):
            bh = sha256(f"branch-{i}".encode()); hashes.append(bh)
            log.append(PruneLogEntry(i, bh, 0, 0))
        assert len(log.anchored_roots) == 1
        mp = log.membership_proof(hashes[2])
        assert mp is not None and mp.verify()
        assert mp.root == log.anchored_roots[0]
        assert log.membership_proof(sha256(b"never-seen")) is None
    test("prune_log_membership", t_prune_log_membership)

    def t_speculative_writes_skip_epsl():
        """Phase 1 touches only the store; Phase 3 inserts the winner;
        Phase 5 GCs loser-exclusive vertices but keeps shared ones."""
        epsl = Epsl(LineageStore()); bcp = Bcp(epsl, BlobPipeline(), epoch_size=512)
        shared = sha256(b"oracle-shared")
        b1 = Branch(id=1, epoch=0); b2 = Branch(id=2, epoch=0)
        b1.event_hashes = bcp.phase1_write([shared], [sha256(b"win")],  1)
        b2.event_hashes = bcp.phase1_write([shared], [sha256(b"lose")], 2)
        assert epsl.node_count == 0                       # EPSL untouched
        assert bcp.store.vertex_count == 3
        wid = Bcp.phase2_score([b1, b2], scorer=lambda b: -b.id)  # b1 wins
        bcp.phase3_accumulate(b1)
        assert epsl.node_count == 2                       # shared + win
        bcp.phase5_prune([b1, b2], wid)
        assert bcp.total_pruned == 1
        assert bcp.prune_log.contains(b2.branch_hash())
        assert bcp.store.get_vertex(sha256(b"lose")) is None   # GC'd
        assert bcp.store.get_vertex(shared) is not None        # retained
    test("speculative_writes_skip_epsl", t_speculative_writes_skip_epsl)

    def t_service_anchored_flag():
        """Service marks a response `anchored` only when its proof root
        equals the root on the anchor contract."""
        epsl = Epsl(LineageStore()); bcp = Bcp(epsl, BlobPipeline(), epoch_size=1)
        svc  = LineageService(epsl, bcp)
        s = sha256(b"in"); t_ = sha256(b"out")
        svc.write_lineage(WriteRequest([s], [t_], 0, 0))  # seals epoch 0
        resp = svc.query_bl(QueryRequest(t_, epoch_max=0))
        assert resp.verified and resp.anchored and svc.verify(resp)
        assert resp.proof_bytes > 0
    test("service_anchored_flag", t_service_anchored_flag)

    print(f"\n{'=' * 55}")
    print(f"  {passed} passed, {failed} failed")
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    _run_tests()
