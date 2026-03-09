# EVM-Lineage

Tamper-evident data lineage for AI agents on EVM-compatible blockchains.

EVM-Lineage records a cryptographically verifiable audit trail of every
decision an autonomous agent makes — which inputs it read, which outputs
it produced, and which speculative branches it explored — anchored to a
public blockchain so no party can alter the history after the fact.

---

## How it works

An agent wraps its operations with the lineage hook. Each operation is
recorded as an edge in a directed acyclic graph: sources → targets. These
edges are indexed in an off-chain skip list and periodically committed to
the chain as a Merkle root stored in a smart contract. Anyone can retrieve
a proof that a specific data item existed at a specific block, verify it
against the on-chain root, and confirm it hasn't been tampered with.

Speculative branches (when an agent evaluates multiple candidate strategies
before picking one) are handled natively: losing branches are pruned and
hash-anchored, winning branches are fully committed. This keeps on-chain
costs low while preserving a complete audit trail.

---

## Components

```
evm_lineage_code/
├── contracts/src/
│   ├── LineageAnchor.sol    — epoch root commitment + Merkle proof verification
│   └── LineageProxy.sol     — upgradeable proxy with multisig admin
│
├── engine/src/
│   ├── store.rs             — in-memory DAG vertex store (RocksDB in production)
│   ├── epsl.rs              — skip list index with epoch versioning and DAG merge
│   ├── bcp.rs               — batch commit orchestrator
│   ├── blob.rs              — EIP-4844 blob encode/decode
│   ├── config.rs            — engine configuration and cost utilities
│   ├── lib.rs               — crate root / public API
│   └── main.rs              — demo binary and integration tests
│
└── agent/
    ├── evm_lineage.py       — Python integration layer (zero external dependencies)
    └── dataset_gen.py       — workload simulator and benchmark data generator
```

---

## Quick start

### Python (no dependencies)

```bash
cd agent
python3 evm_lineage.py
```

Expected output:
```
45 passed, 0 failed
```

### Rust engine

```bash
cd engine
cargo test        # unit + integration tests
cargo run         # demo: prints config, simulates BCP steps
```

Requires Rust 1.75+ (`rustup install stable`).

### Solidity contracts

```bash
cd contracts
forge build
forge test
```

Or with Hardhat:
```bash
npx hardhat compile
npx hardhat test
```

---

## Agent integration

### Python (LangGraph)

```python
from evm_lineage import LineageHook, EngineConfig

hook = LineageHook(config=EngineConfig())

@hook.wrap_node
def my_agent_node(state):
    # your agent logic here
    return new_state
```

Every call to `my_agent_node` automatically records input/output hashes
as a lineage edge and flushes them to the commit buffer.

### Manual event recording

```python
from evm_lineage import LineageService

svc = LineageService()
svc.write_lineage(
    sources=["input_hash_a", "input_hash_b"],
    targets=["output_hash_c"],
    branch_id=0
)

result = svc.query_bl("output_hash_c")                    # backward lineage
result = svc.query_fi("input_hash_a")                     # forward impact
result = svc.query_ts("output_hash_c", block_epoch=1000)  # temporal slice
```

---

## Cost

On-chain costs scale with the epoch batch size `w` (events per commitment).
Larger batches mean lower cost per event but higher latency to first commitment.

```python
from evm_lineage import cost_per_event_usd

# Arbitrum One, w=512
cost = cost_per_event_usd(
    epoch_size=512,
    event_bytes=200.0,
    gas_gwei=0.1,
    blob_gwei=1e-3,
    eth_usd=3000.0,
)
print(f"${cost:.2e}")   # ≈ $1.1e-05 per event
```

Typical ranges:

| Chain | Epoch size | Cost/event |
|-------|-----------|------------|
| Arbitrum One | 64  | ~$8.8e-05 |
| Arbitrum One | 512 | ~$1.1e-05 |
| Ethereum L1  | 64  | ~$2.3e-03 |
| Ethereum L1  | 512 | ~$2.9e-04 |

---

## Generating benchmark data

```bash
cd agent
python3 dataset_gen.py               # all benchmarks (~2-5 min)
python3 dataset_gen.py --events 200  # quick smoke test
```

Options:

```
--latency       latency vs epoch size
--dag-shape     DAG shape metrics vs branching factor
--cost-model    cost sweep across chains and epoch sizes
--throughput    throughput vs drain interval
--events N      events per run (default: 2000)
--seed N        RNG seed (default: 42)
```

Output lands in `agent/datasets/`:

```
datasets/
├── MANIFEST.json
├── cost_model.csv
├── latency.csv
├── dag_shape.csv
├── throughput.csv
└── raw/
    ├── events_beta1.jsonl
    ├── events_beta2.jsonl
    ├── events_beta4.jsonl
    └── events_beta8.jsonl
```

---

## Contracts

### LineageAnchor.sol

Three public functions:

```solidity
function commitRoot(uint64 epoch, bytes32 root) external onlyOrchestrator
function verifyProof(bytes32 leaf, bytes32[] calldata proof, bytes32 root)
    external pure returns (bool)
function slash(uint64 epoch, bytes32 fraudRoot, bytes32[] calldata proof)
    external
```

Proof verification uses an assembly loop for gas efficiency. The canonical
hash ordering (left = min, right = max) is identical across Solidity,
Python, and Rust — proofs generated off-chain can be verified on-chain.

### LineageProxy.sol

EIP-1967 upgradeable proxy with a 3-of-5 multisig admin.

---

## Rust engine

The Rust engine is a production-grade implementation of the same logic as
the Python layer, optimised for throughput.

```bash
cd engine
cargo build --release   # ~2.5 MB binary
cargo doc --open        # HTML API docs
```

Key differences from the Python layer:

| | Rust engine | Python layer |
|---|---|---|
| Concurrency | Tokio async + Rayon | `threading.Lock` |
| Storage | RocksDB | in-memory dict |
| Serialisation | protobuf | JSON / dataclass |
| Proof generation | parallel (Rayon) | sequential |
| Transport | gRPC (tonic) | `LineageService` class |

---

## Design notes

**Merkle proof parity.** All three implementations use the same canonical
ordering: `left, right = min(node, sibling), max(node, sibling)`, then
SHA-256 off-chain and keccak256 on-chain. A proof generated by the Rust
engine can be verified by the Solidity contract.

**DAG merge.** When two branches execute the same operation on the same
inputs, they produce an identical content hash. Rather than duplicating the
node, the existing node's branch bitmask is extended. This is why
deduplication ratio increases with the branching factor.

**Blob archival.** EIP-4844 blobs are only guaranteed available for ~18 days.
Operators should pin blobs to a persistent store (IPFS, Arweave, Filecoin)
within that window. The on-chain KZG commitment hash provides a tamper-evident
link to any archive.

---

## License

MIT
