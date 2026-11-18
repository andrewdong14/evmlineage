# Paper alignment

How this repository and the paper relate: what was changed in revision 0.2
to make them agree, where the prototype stops, and which claims of the
earlier paper draft were dropped because no code backs them.

The rule that the README states still holds: a number may appear in the
paper only if a command in this repository produced it. `results/` holds the
outputs and `scripts/paper_numbers.py` turns them into the LaTeX macros that
the paper uses.

---

## 1. What revision 0.2 changed

### Index (EPSL)

| First version | Now | Why |
|---|---|---|
| No skip pointers. A level was stored per node but never used; each seal rebuilt one flat Merkle tree over all vertices and kept a full tree per sealed epoch. | A persistent authenticated skip list keyed by vertex hash (`engine/src/skiplist.rs`, `_SlNode` in Python). Sealing copies the search paths of the touched records; versions share everything else. | Sealing was O(n) hashes per epoch and O(n) memory per retained epoch. It is now O(log n) per touched record. `bench index` measures both. |
| Level = trailing zeros of the first four bytes of the hash. | Level = trailing zero bits of the whole hash (its low-order end), capped at 31. | The list is ordered by hash. High-order bits give neighbouring keys equal levels, which degenerates the list into long runs. |
| Record digest hashed the complete parent and child lists. | Each list is a hash chain with one link per epoch in which it grew; the record digest covers the two chain heads. | Appending costs O(new edges) whatever the degree; the head as of a past epoch is a prefix; a proof for one direction carries the other direction as one hash. |
| `verify_query` checked membership and closure, but not that every returned record is reachable from the origin. A prover could pad an answer with unrelated committed records. | The verifier recomputes the traversal from the supplied records: a reachable vertex without a record and a record that is never reached both fail. | Answers are now exact (nothing withheld, nothing added) for both directions. |
| Queries on an unsealed epoch returned a proof against a root that was never anchored. | Queries are pinned to sealed epochs. `pending=True` gives a fresh answer without a proof. | A proof is only meaningful against an anchored root. |
| — | Depth-bounded queries (`max_depth`), `membership()`, a canonical wire format for proofs, a retention window (`retain`). | Needed for the evaluation and for the on-chain checks. |
| Rust: the epoch counter lived in the BCP and could be read before a seal and used after it. | The EPSL owns the epoch; indexing, batching and sealing run under one lock. | An event could be tagged with an epoch that was already sealed. |
| Python duplicated an unpaired Merkle node, Rust promoted it, so the two computed different roots. | Both promote. `testvectors/conformance.json` is written by Python, reproduced by Rust and verified by the contract tests. | "Identical in all three layers" is now tested. |

### Contract

| First version | Now | Why |
|---|---|---|
| Did not compile: a `@title` doc comment preceded an `error` declaration. | Compiles with solc 0.8.24; 23 Foundry tests. | — |
| Storage slot constant was not the hash that its comment named. | `bytes32(uint256(keccak256("evm_lineage.anchor.v2")) - 1)`, checked by a test. | — |
| Leaf = `keccak256(vertexHash ‖ digest)`, the same 64-byte shape as an interior node. | Leaf = `keccak256(keccak256(vertexHash ‖ digest))`. | An interior node over `(a, b)` passed as a record of vertex `a` with digest `b`; with a vertex hash chosen to equal a leaf label, `slash()` could be turned against an honest committer (`testCannotSlashWithInteriorNode`). |
| `deregisterCommitter` paid the stake out at once. | `requestWithdrawal` stops the committer from committing and starts a delay (7 days by default) before `withdrawStake`. | A committer could anchor a fraudulent root and leave before anyone could slash it. |
| `slash` paid the whole stake to the challenger. | Half to the challenger, half burned; the epoch is marked disputed. | A committer could slash itself through a second account and lose nothing. |
| No place for prune-log roots. | `commitPruneRoot`, `verifyPruneProof`. | The paper says these roots are on-chain. |
| `blobHash` was an unchecked argument. | If the transaction carries blobs, `blobHash` must match their versioned hashes (`BLOBHASH`); `setRequireBlobs` makes blobs mandatory. | Binds the anchored root to data that was actually published. |
| The multisig could not attach value and so could never stake. | `registerCommitterFor`; the multisig can receive its stake back. | The paper's committer may be a multisig. |
| Four storage words per epoch. | Three (root, payload commitment, committer and block packed). | Lower commit gas. |

### Payloads, protocol, store, workload

| First version | Now | Why |
|---|---|---|
| The blob held a hash per event. | The payload holds the events (sources and targets). `index_rebuilds_from_payloads` rebuilds the index from payloads and compares every root. | The lineage could not be reconstructed from the blobs. |
| Python compressed with zlib, Rust with zstd. | One format in both layers; DEFLATE is optional and off by default. | Payloads of one layer could not be read by the other. Measured on AE-TPCC, compression saves nothing: events consist of content hashes. |
| Cost model: 2,900 gas per commit and a per-byte blob price. | `commit_gas` is an input (measured: see `results/gas-report.json`); blobs are charged whole, 2^17 blob gas each. | 2,900 gas is one warm storage update, not a `commitRoot` transaction; blobs are not priced per byte. |
| No limit on the size of an epoch's payload. | `MAX_BLOBS_PER_TX = 6` and `fits_one_transaction`; every submission records whether its payload fits one transaction, and `paper_numbers.py` marks epoch sizes that do not. | Since the Fusaka upgrade (EIP-7594) a transaction carries at most six blobs, and `commitRoot` binds a root to the blobs of its own transaction. At about 410 bytes per event this caps an epoch at roughly 1,700 events. |
| Garbage collection scanned every edge of the store per removed vertex and left edges that pointed to removed vertices. | Edges are indexed by source; the edges of collected vertices are removed. | A decision step with eight branches took milliseconds. |
| Branch masks use `branch_id mod 64`; a pruned branch could delete a vertex that a committed event with a colliding id had written. | Vertices that are in the index are never collected. | — |
| After `PruneLog.flush`, the next batch overlapped the flushed entries. | Batches are explicit ranges. | — |
| AE-TPCC drew inputs and outputs from disjoint pools: a bipartite graph of depth one. | Rows are versioned: a write creates a new item, a read references the current version, so outputs feed later inputs. | The graph had no lineage beyond one hop. |
| `drain_buffer`, per-node branch lists and `put_epsl_raw` were never used. | Removed. | — |

---

## 2. Where the prototype stops

These are differences between a deployment and this code. The paper
describes them as limitations.

* **Memory only, one process.** No durable store, replication or network
  API. The whole index must fit in memory (about 590 bytes per vertex at one
  million events).
* **No live blob submission.** `BlobPipeline` only has the dry-run mode
  (commitment = SHA-256 of the payload). `scripts/devnet_gas.py` shows the
  on-chain half with a real blob-carrying transaction on Anvil.
* **An epoch must fit six blobs.** The code reports a payload that needs
  more blobs than one transaction may carry, but it does not split such an
  epoch over several transactions.
* **Retention.** Proofs can be generated for the `retain` most recent
  epochs. Older roots stay on-chain and proofs issued earlier stay valid; an
  older version can only be rebuilt by replaying payloads from the start.
* **No proof of absence.** The engine cannot prove that an item is not in
  the index.
* **Consistency between records is not proven per query.** A committer who
  commits a child list that disagrees with the matching parent list is
  caught by replaying the payload, not by `verify_query` or `slash`.
* **Failures.** If the anchor rejects a commit, the Python layer raises and
  the Rust engine panics; there is no retry or write-ahead log.
* **One global lock** per index; no concurrency benchmark.
* **Proxy and multisig** are minimal examples.
* **Levels are not salted**: an adversary who chooses item contents can
  skew them.

---

## 3. Claims of the earlier draft that were dropped

| Earlier draft | Status |
|---|---|
| RocksDB with three column families, a three-node Raft group, Tokio/Tonic gRPC, 100 ms insert batching | Not in this repository. The paper now describes the in-memory prototype. |
| Baselines Full-replay (`debug_traceBlock`), LineageChain+, CentralDB (PostgreSQL) | Not in this repository. Replaced by baselines that are: full on-chain storage and per-event anchoring (gas), flat Merkle rebuild (sealing), payload replay and unauthenticated traversal (queries). |
| Results at 10^7 events on a three-instance cluster, 100–200 concurrent agents | Replaced by measurements up to 10^6 events on the machine named in `results/README.md`. |
| Node hashes that cover the ancestor subgraph, O(β log n) proof overhead | The index authenticates each record separately; a proof has one membership path per expanded record, O(\|R\| log n) hashes. |
| 2,900 gas per event and a 1.48 M gas commit on L1; 180 gas per event on Arbitrum | One commit costs about 105,000 gas whatever the epoch size (205 gas per event at w = 512). Nothing was measured on Arbitrum. |
| 200-byte events, zstd ratio 4, about 50 bytes of blob space per event | Measured: about 410 bytes per event, incompressible. |
| FI answers sound but not complete | FI answers are checked the same way as BL answers. |
