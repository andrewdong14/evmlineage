# EVM-Lineage

Tamper-evident data lineage for autonomous AI agents on EVM-compatible
blockchains — reference implementation accompanying the paper
*"Efficient Tamper-Evident Data Lineage in EVM-Based Blockchains for
Autonomous AI Agents"*.

EVM-Lineage records which inputs an agent read, which outputs it produced
and which speculative branches it explored. The records live off-chain in an
authenticated index; one root per epoch is anchored on a public chain. A
client can then check a lineage answer against the on-chain root: the check
fails if a record was altered, withheld or added.

---

## Status and scope — read this first

This repository is a **reference implementation**. Everything is in memory
and runs in one process.

* **Python layer** (`agent/evm_lineage.py`, stdlib only): the reference for
  every data structure and protocol step — the EPSL index, verified queries,
  the five-phase Branch Commit Protocol, the prune log, epoch payloads, and
  an in-memory anchor with the contract's rules.
* **Rust engine** (`engine/`): the same constructions, byte for byte, built
  for speed. The paper's latency, throughput and memory figures come from
  `engine/src/bin/bench.rs`.
* **Solidity contracts** (`contracts/`): the on-chain anchor (epoch roots,
  proof verification, equivocation fraud proof, prune-log roots), an
  EIP-1967 proxy and a minimal multisig, with Foundry tests. The paper's gas
  figures come from `contracts/test/Gas.t.sol`.
* **Conformance vectors** (`testvectors/conformance.json`): written by the
  Python layer, reproduced exactly by the Rust engine, and verified on the
  contract. This is what backs the claim that a proof generated off-chain
  verifies on-chain.

Not included: durable storage, replication, a network API, live blob
submission. `PAPER_ALIGNMENT.md` lists what changed in this revision and
where the prototype stops.

**Reproducibility.** Every number in the paper's evaluation is produced by a
command in this repository and stored under `results/`; see
[Reproducing the measurements](#reproducing-the-measurements). Nothing here
hard-codes a result.

---

## How it works

**Records.** Every vertex (data item, identified by the SHA-256 of its
content) has a record `(h, epoch0, parents, children)`. Each of the two lists
is append-only and grouped by the epoch in which it grew; a hash chain over
the groups summarises it.

**Index.** The records are the leaves of an authenticated skip list keyed by
`h`. Levels are derived from the key, so the root depends only on the set of
records. The list is persistent: sealing an epoch copies the paths of the
records that changed and shares the rest with earlier versions, so a version
stays readable for as long as it is retained.

**Anchoring.** The Branch Commit Protocol writes every speculative branch to
an off-chain store, puts only the winning branch into the index, and once per
epoch calls `commitRoot(root, epoch, blobHash)`. The epoch's events travel as
the payload (EIP-4844 blobs) of that transaction; anyone who holds the
payloads can rebuild the index and recompute every root. A transaction
carries at most six blobs (EIP-7594), which bounds the size of an epoch:
about 1,700 events of the benchmark workload.

**Queries.** A backward-lineage (BL), forward-impact (FI) or temporal-slice
(TS) query is pinned to a sealed epoch and may be bounded to `k` hops. The
answer carries, for every vertex whose neighbours were followed, its record
as of that epoch and a membership path. `verify_query(proof, root)` — with
`root` read from the contract — recomputes the traversal from those records
and accepts only if

1. every record hashes into the root,
2. every vertex the traversal reaches inside the bound has a record
   (nothing was withheld), and
3. every supplied record is reached (nothing was added).

**Fraud proof.** If a committer anchors a root that holds two different
records for the same vertex, anyone can submit both to `slash()`: half of the
committer's stake goes to the challenger, the rest is burned, and the epoch
is marked disputed.

### Hashing conventions (identical in all three layers; H = keccak256)

| Purpose | Definition |
|---|---|
| Content addressing | `h = SHA-256(item bytes)` |
| Pair hash | `pair(a, b) = H(min(a, b) ‖ max(a, b))` |
| Adjacency chain link | `D' = H(D ‖ be64(epoch) ‖ be32(k) ‖ h_1 … h_k)`, `h_i` ascending, `D_0 = 0` |
| Record digest | `d = H(h ‖ be64(epoch0) ‖ D_parents ‖ D_children)` |
| Skip-list leaf | `leaf = H(H(h ‖ d))` |
| Skip-list level | trailing zero bits of `h`, capped at 31 |
| Prune-log leaf | `H(96-byte entry)` |

The leaf is double-hashed so that an interior node (hash of 64 bytes) can
never be presented as a leaf (hash of 32 bytes); `slash()` relies on this.

---

## Components

```
evmlineage/
├── agent/
│   ├── evm_lineage.py           — reference implementation and its tests
│   └── dataset_gen.py           — Python-side measurement harness
├── engine/                      — Rust engine
│   ├── src/skiplist.rs          — persistent authenticated skip list
│   ├── src/epsl.rs              — records, sealing, queries, proofs, verify_query
│   ├── src/bcp.rs               — five phases, InMemoryAnchor, PruneLog
│   ├── src/blob.rs              — epoch payload encoding
│   ├── src/store.rs             — store for speculative writes
│   ├── src/merkle.rs            — fixed-shape Merkle tree (prune log, baseline)
│   ├── src/workload.rs          — AE-TPCC workload generator
│   ├── src/baseline.rs          — flat-rebuild and replay baselines
│   ├── src/config.rs            — cost model
│   ├── src/bin/bench.rs         — measurement harness
│   ├── src/main.rs              — demo
│   └── tests/conformance.rs     — checks the engine against the vectors
├── contracts/
│   ├── src/LineageAnchor.sol    — anchor, verifyProof, slash, prune roots
│   ├── src/LineageProxy.sol     — EIP-1967 proxy and minimal multisig
│   ├── src/baselines/           — on-chain baselines for the gas comparison
│   ├── test/                    — unit, conformance and gas tests
│   └── gas/                     — gas reports written by the tests
├── testvectors/conformance.json — cross-layer test vectors
├── results/                     — measurements behind the paper's numbers
└── scripts/                     — reproduction and reporting scripts
```

---

## Quick start

### Python (no dependencies; pycryptodome makes keccak about 50x faster)

```bash
cd agent
python3 evm_lineage.py            # tests; ends with "56 passed, 0 failed"
```

### Rust engine (Rust 1.75 or later)

```bash
cd engine
cargo test --release              # unit tests and conformance vectors
cargo run --release --bin lineage-engine      # demo
```

### Solidity contracts (Foundry; solc 0.8.24, EVM version cancun)

```bash
cd contracts
forge install foundry-rs/forge-std@v1.16.1 --no-git    # once
forge test -vv
```

The tests were run with forge 1.7.1 and forge-std v1.16.1.

---

## Agent integration

```python
from evm_lineage import (Bcp, Epsl, BlobPipeline, LineageService,
                         WriteRequest, QueryRequest, sha256)

epsl = Epsl()
bcp  = Bcp(epsl, BlobPipeline(), epoch_size=512)
svc  = LineageService(epsl, bcp)

# Record: sources -> targets (32-byte content hashes)
svc.write_lineage(WriteRequest(
    sources=[sha256(b"oracle:ETH/USD:2000")],
    targets=[sha256(b"decision:buy:0.5")]))

bcp.flush_epoch()                 # seal and anchor the open epoch

# Verified backward lineage, pinned to the last sealed epoch
resp = svc.query_bl(QueryRequest(sha256(b"decision:buy:0.5")))
assert resp.anchored              # the proof verifies against the anchored root
assert svc.verify(resp)           # independent re-check against the anchor
```

Queries see sealed epochs only. `Epsl.query(..., pending=True)` also follows
the edges of the open epoch; such an answer is fresh but carries no proof.
`QueryRequest(h, epoch=e)` pins a query to an earlier epoch, and
`max_depth=k` bounds it to `k` hops.

Speculative branches (`beta` candidate continuations per decision step):

```python
from evm_lineage import BranchManager

mgr = BranchManager(bcp, beta=4)
with mgr.new_step() as step:
    for b in step.branches:
        with step.context(b) as ctx:
            ctx.record_source(b"observation bytes")   # hashed automatically
            ctx.record_target(b"candidate action")
            ctx.set_score(evaluate(b))
    step.commit_winner()      # Phase 3 for the winner, Phase 5 for the rest
```

`phase1_write` stages events in the off-chain store only. The index and the
chain see nothing until a branch wins. Each loser leaves a 96-byte entry in
the prune log; the Merkle root of every batch of entries is anchored, and
`bcp.prune_log.membership(branch_hash)` returns the proof that a discarded
branch was considered.

`LineageHook` (`on_tool_call` / `on_tool_result` / `wrap_node`) adapts this
to LangGraph-style callbacks.

---

## Contracts

```solidity
function commitRoot(bytes32 root, uint64 epoch, bytes32 blobHash) external;
function verifyProof(bytes32 leaf, bytes32[] calldata proof, uint64 epoch)
    public view returns (bool);
function slash(bytes32 vertexHash,
               bytes32 digestA, bytes32[] calldata proofA,
               bytes32 digestB, bytes32[] calldata proofB,
               uint64  epoch) external;
function commitPruneRoot(uint64 index, bytes32 root) external;
function verifyPruneProof(bytes32 leaf, bytes32[] calldata proof, uint64 index)
    external view returns (bool);
function registerCommitter() external payable;
function registerCommitterFor(address committer) external payable;
function requestWithdrawal() external;
function withdrawStake() external;
```

* `commitRoot` enforces sequential epochs and stores three words per epoch:
  the root, the payload commitment, and the committer with the block
  number. If the transaction carries blobs, `blobHash` must equal the
  versioned hash of the blob (or keccak256 of the concatenated hashes when
  there are several); `setRequireBlobs(true)` makes blobs mandatory.
* `verifyProof` folds the sibling path with the sorted-pair hash.
* `slash` takes two record digests of the same vertex with their paths and
  recomputes both leaves on-chain.
* A committer who wants its stake back must call `requestWithdrawal`, can no
  longer commit, and stays slashable for `withdrawDelay` (default 7 days).

`LineageProxy.sol` holds an EIP-1967 proxy and a minimal 3-of-5 multisig
that can act as committer and proxy admin. They are deliberately simple;
a production deployment should use audited implementations.

---

## Reproducing the measurements

```bash
scripts/reproduce.sh              # tests, benchmarks, gas report, results.tex
RUNS=3 scripts/reproduce.sh       # the same with three index runs (run-to-run spread)
EVENTS=100000 scripts/reproduce.sh    # a smaller index run for a small machine
```

The script takes about 20 minutes (35 with `RUNS=3`) and should run on an
otherwise idle machine, because most results are timings. Step by step it
does the following:

```bash
# Engine: index scaling, queries, proofs, memory, flat-rebuild baseline
cd engine
cargo run --release --bin bench -- index   --events 1000000 --replay-max 0 --out ../results
# Replay baseline: a shorter run of the same stream that keeps the payloads
cargo run --release --bin bench -- index   --events 300032 --replay-max 300032 --out ../results/replay
cargo run --release --bin bench -- retain  --out ../results
cargo run --release --bin bench -- write   --tx 200000 --out ../results
cargo run --release --bin bench -- payload --tx 200000 --out ../results
cargo run --release --bin bench -- fixture --out ../contracts/test/fixtures

# Contract: whole-transaction gas (each call is its own transaction)
cd ../contracts
forge test --isolate --match-contract GasTest -vv      # writes gas/gas-report.json

# Optional: the same commits as real transactions on a local devnet,
# including a blob-carrying one (needs anvil and cast)
python3 ../scripts/devnet_gas.py

# LaTeX macros with every number the paper uses
python3 ../scripts/paper_numbers.py
```

`results/README.md` describes each result file and the machine the
committed results were measured on. The index benchmark at one million
events needs about 4 GB of memory.

`agent/dataset_gen.py` runs the same experiments on the Python reference at
a smaller scale.

---

## License

MIT
