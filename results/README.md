# Results

The measurements behind the numbers in the paper. Each file is the direct
output of a command in this repository; `scripts/paper_numbers.py` turns
them into `results.tex`, the LaTeX macros that the paper uses. The whole
set is produced by

```bash
RUNS=3 scripts/reproduce.sh
```

| File | Produced by | Contents |
|---|---|---|
| `index.json` | `bench index --events 1000000 --replay-max 0` | Index scaling at seven sizes: sealing time, hashes, flat-rebuild baseline, memory, and for seven query shapes the result size, proof generation, verification, proof size and unauthenticated traversal. With `RUNS=3` this is the last of the three runs |
| `index_run1.json` … `index_run3.json` | the same command, once per run | Every repetition of the index run. Only the sealing time at the largest size is read from them, for the run-to-run spread |
| `index_replay.json` | `bench index --events 300032 --replay-max 300032` | A shorter run of the same event stream that keeps the epoch payloads, with the replay baseline (answering a query from the payloads). Only the `replay_bl2_ms_median` values are used from this file |
| `retain.json` | `bench retain --events 100000` | Skip-list nodes alive for retention windows of 1 to 32 versions |
| `write.json` | `bench write --tx 200000` | Full Branch Commit Protocol with the speculative store, for 1, 2, 4 and 8 branches per decision step |
| `payload.json` | `bench payload --tx 200000` | Epoch payload size per event for six epoch sizes, with and without DEFLATE |
| `hash.json` | `bench hash` | keccak pair-hash throughput of the machine |
| `gas-report.json` | `forge test --isolate --match-contract GasTest` | Whole-transaction gas of the contract's operations, `verifyProof` on 56 proofs exported by the engine, and the two on-chain baselines on 220 workload events |
| `devnet-report.json` | `python3 scripts/devnet_gas.py` | The same commits as real transactions on Anvil, one of them carrying a 256-event payload as a blob |
| `toolchain.json` | `scripts/reproduce.sh` | Versions of the tools that produced the results |
| `results.tex` | `python3 scripts/paper_numbers.py` | LaTeX macros |

The index run exports the membership proofs for the gas test to
`contracts/test/fixtures/membership_fixture.json`, and `bench fixture`
writes the sample of workload events for the gas baselines next to it.

## Machine and software

The committed results were measured in one pass of the script on a virtual
machine with 2 vCPUs (Intel Xeon, 2.3 GHz), 8 GB of memory, Linux, with
nothing else running. Every result file records the machine it was measured
on, and `toolchain.json` the tool versions.

* Engine: Rust 1.97, `--release`, one thread. Sealing, queries and
  verification are single-threaded; the flat-rebuild baseline was also run
  on one thread.
* Contract: solc 0.8.24, optimiser with 200 runs, EVM version cancun,
  forge 1.7.1 with forge-std v1.16.1, in isolation mode (every call is a
  transaction of its own: intrinsic gas and cold storage are included).
  The compiler was the JavaScript build of solc 0.8.24, which is built from
  the same source as the native binary; if a native compiler gives a
  different gas figure, the gas test will show it.
* Devnet check: anvil 1.7.1 with `--hardfork cancun`, transactions sent
  with cast.

The workload is AE-TPCC with seed 42, 10 warehouses, epoch size 512 and a
retention window of 8 versions unless a file's `params` say otherwise. The
generator is deterministic, so the event stream, the graph, every proof and
every gas figure are the same in every run. Timings are not: on this
(shared) virtual machine the median sealing time at one million events was
176, 153 and 197 ms in the three runs. The paper reports the last run and
gives this spread.

To measure on another machine, run `scripts/reproduce.sh` there and copy
`results/results.tex` next to the paper's `main.tex`.
