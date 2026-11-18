"""
dataset_gen.py — Python-side measurement harness for EVM-Lineage
================================================================

Drives the reference implementation (evm_lineage.py) with the AE-TPCC
workload and writes what it measures as CSV and JSON under ./datasets/.

The numbers in the paper come from the Rust engine (engine/src/bin/bench.rs)
and from the Foundry gas test (contracts/test/Gas.t.sol). This harness runs
the same experiments on the Python reference at a smaller scale: it is the
quickest way to see the system work end to end, and a cross-check that the
two implementations behave alike. Python timings are not comparable to the
engine's.

Usage
-----
    python3 dataset_gen.py                 # everything
    python3 dataset_gen.py --latency       # write + verified query latency vs epoch size w
    python3 dataset_gen.py --dag-shape     # graph shape and pruning vs beta
    python3 dataset_gen.py --throughput    # writes through the service facade
    python3 dataset_gen.py --proof-size    # proof size / generate / verify vs index size
    python3 dataset_gen.py --cost-model --commit-gas 105080
                                           # cost sweep from MEASURED inputs
    python3 dataset_gen.py --tx 5000       # TPC-C transactions per run (default 2000)
    python3 dataset_gen.py --seed 42       # RNG seed (default 42)

`--cost-model` needs the execution gas of commitRoot. Pass it with
--commit-gas, or let the harness read contracts/gas/gas-report.json (written
by `forge test --isolate --match-contract GasTest`). Payload bytes per event
are measured here; gas and blob prices are assumptions that you supply.

Requirements: stdlib only. Install pycryptodome for a ~50x faster keccak.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

from evm_lineage import (                                    # noqa: E402
    AeTpcc, Bcp, BlobPipeline, Branch, Epsl, LineageService, QueryRequest,
    WriteRequest, blobs_needed, cost_per_event_usd, expected_commit_latency_s,
    fits_one_transaction, verify_query, BLOB_GAS_PER_BLOB, BLOB_HEADER_SIZE,
)

DATASETS = _HERE / "datasets"


def _write(name: str, rows: List[Dict[str, Any]]) -> None:
    DATASETS.mkdir(exist_ok=True)
    if rows:
        with open(DATASETS / f"{name}.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
    with open(DATASETS / f"{name}.json", "w") as f:
        json.dump(rows, f, indent=2)
    print(f"  wrote datasets/{name}.csv and .json")


def _stats(xs: List[float]) -> Dict[str, float]:
    if not xs:
        return {"p50": 0.0, "p99": 0.0, "mean": 0.0}
    s = sorted(xs)
    n = len(s)
    return {"p50": round(s[n // 2], 4), "p99": round(s[min(n - 1, int(n * 0.99))], 4),
            "mean": round(sum(s) / n, 4)}


def _make(epoch_size: int) -> Tuple[Bcp, Epsl]:
    epsl = Epsl()
    return Bcp(epsl, BlobPipeline(), epoch_size=epoch_size), epsl


def _drive(bcp: Bcp, wl: AeTpcc, n_tx: int, beta: int
           ) -> Tuple[List[float], List[float], List[bytes]]:
    """Run `n_tx` TPC-C transactions plus one agent decision step (beta
    candidates, one winner) per ten transactions through the five BCP
    phases. Returns (transaction write latencies ms, decision-step
    latencies ms, committed output hashes)."""
    tx_lat: List[float] = []
    step_lat: List[float] = []
    outputs: List[bytes] = []
    for i in range(n_tx):
        ev = wl.next_event()
        t0 = time.perf_counter()
        bcp.write_direct(ev.sources, ev.targets, 0)
        tx_lat.append((time.perf_counter() - t0) * 1000)
        outputs.extend(ev.targets)
        if (i + 1) % 10 == 0:
            cands = wl.agent_step(beta)
            t0 = time.perf_counter()
            branches = []
            for c in cands:
                hashes = bcp.phase1_write(c.sources, c.targets, c.branch_id)
                branches.append(Branch(id=c.branch_id, epoch=bcp.current_epoch,
                                       event_hashes=hashes))
            wid = Bcp.phase2_score(branches, scorer=lambda b: wl._rng.random())
            bcp.phase3_accumulate(next(b for b in branches if b.id == wid))
            bcp.phase5_prune(branches, wid)
            step_lat.append((time.perf_counter() - t0) * 1000)
            winner = next(c for c in cands if c.branch_id == wid)
            wl.agent_commit(winner)
            outputs.extend(winner.targets)
    bcp.flush_epoch()
    bcp.flush_prune_log()
    return tx_lat, step_lat, outputs


# ── latency vs epoch size ─────────────────────────────────────────────────────

def gen_latency(n_tx: int, seed: int) -> None:
    print("\n[latency] write and verified-query latency vs epoch size w (beta = 4)")
    rows = []
    for w in (64, 128, 256, 512, 1024):
        bcp, epsl = _make(w)
        wl = AeTpcc(seed=seed, beta=4)
        tx_lat, step_lat, outputs = _drive(bcp, wl, n_tx, 4)
        svc = LineageService(epsl, bcp)
        rng = random.Random(seed + w)
        sample = rng.sample(outputs, min(200, len(outputs)))
        latest = epsl.latest_sealed
        past = max(0, latest - 3)
        lat = {"BL": [], "FI": [], "TS": []}
        anchored = total = 0
        for h in sample:
            for kind, req in (("BL", QueryRequest(h, max_depth=2)),
                              ("FI", QueryRequest(h, max_depth=2)),
                              ("TS", QueryRequest(h, epoch=past, max_depth=2))):
                t0 = time.perf_counter()
                resp = getattr(svc, f"query_{kind.lower()}")(req)
                lat[kind].append((time.perf_counter() - t0) * 1000)
                if resp.proof is not None:
                    total += 1
                    anchored += int(resp.anchored)
        ws, ss = _stats(tx_lat), _stats(step_lat)
        rows.append({
            "epoch_size_w": w, "tx": n_tx, "epochs": bcp.committed_epochs,
            "vertices": epsl.node_count, "edges": epsl.edge_count,
            "write_p50_ms": ws["p50"], "write_p99_ms": ws["p99"],
            "step_p50_ms": ss["p50"], "step_p99_ms": ss["p99"],
            **{f"{k.lower()}2_p50_ms": _stats(v)["p50"] for k, v in lat.items()},
            **{f"{k.lower()}2_p99_ms": _stats(v)["p99"] for k, v in lat.items()},
            "proofs_checked": total, "proofs_anchored": anchored,
        })
        print(f"  w={w:5d}  write p50 {ws['p50']} ms  BL-2 p50 {rows[-1]['bl2_p50_ms']} ms  "
              f"proofs anchored {anchored}/{total}")
        assert anchored == total, "every proof must verify against the anchored root"
    _write("latency", rows)


# ── graph shape and pruning vs beta ───────────────────────────────────────────

def gen_dag_shape(n_tx: int, seed: int) -> None:
    print("\n[dag-shape] graph shape and pruning vs beta (w = 512)")
    rows = []
    for beta in (1, 2, 4, 8):
        bcp, epsl = _make(512)
        wl = AeTpcc(seed=seed, beta=beta)
        _drive(bcp, wl, n_tx, beta)
        nodes = list(epsl._nodes.values())
        fan_in = [len(n.bwd.members) for n in nodes]
        fan_out = [len(n.fwd.members) for n in nodes]
        subs = bcp._blob.submissions
        rows.append({
            "beta": beta, "tx": n_tx, "epochs": bcp.committed_epochs,
            "index_vertices": len(nodes), "index_edges": epsl.edge_count,
            "avg_fan_in": round(sum(fan_in) / len(nodes), 2),
            "max_fan_in": max(fan_in), "max_fan_out": max(fan_out),
            "store_vertices": bcp.store.vertex_count,
            "pruned_branches": bcp.total_pruned,
            "prune_roots_anchored": len(bcp.prune_log.anchored_roots),
            "payload_bytes_per_event": round(sum(s["bytes"] for s in subs)
                                             / sum(s["events"] for s in subs), 1),
        })
        print(f"  beta={beta}  index vertices {len(nodes)}  pruned {bcp.total_pruned}")
    _write("dag_shape", rows)


# ── throughput through the service ────────────────────────────────────────────

def gen_throughput(n_tx: int, seed: int) -> None:
    print("\n[throughput] WriteLineage through the service (w = 512)")
    bcp, epsl = _make(512)
    svc = LineageService(epsl, bcp)
    wl = AeTpcc(seed=seed, beta=1)
    lat = []
    t_all = time.perf_counter()
    for _ in range(n_tx):
        ev = wl.next_event()
        t0 = time.perf_counter()
        svc.write_lineage(WriteRequest(ev.sources, ev.targets))
        lat.append((time.perf_counter() - t0) * 1000)
    wall = time.perf_counter() - t_all
    s = _stats(lat)
    row = {"tx": n_tx, "wall_s": round(wall, 3), "events_per_s": round(n_tx / wall, 1),
           "write_p50_ms": s["p50"], "write_p99_ms": s["p99"],
           "epochs": bcp.committed_epochs, "vertices": epsl.node_count}
    print(f"  {row['events_per_s']} events/s (Python reference)")
    _write("throughput", [row])


# ── proof size vs index size ──────────────────────────────────────────────────

def gen_proof_size(seed: int) -> None:
    print("\n[proof-size] proof size, generation and verification vs index size")
    rows = []
    for n_target in (1_000, 4_000, 16_000):
        epsl = Epsl()
        rng = random.Random(seed + n_target)
        heads: Dict[int, bytes] = {}
        for depth in (10, 50, 100):                  # chains of that many vertices
            prev = None
            for _ in range(depth):
                h = rng.randbytes(32)
                epsl.insert([prev] if prev else [], [h])
                prev = h
            heads[depth] = prev
        while epsl.node_count < n_target:            # filler vertices
            epsl.insert([], [rng.randbytes(32)])
        root = epsl.seal().root
        for depth, head in heads.items():
            t0 = time.perf_counter()
            res = epsl.query_bl(head)
            gen_ms = (time.perf_counter() - t0) * 1000
            t0 = time.perf_counter()
            ok = verify_query(res.proof, root)
            ver_ms = (time.perf_counter() - t0) * 1000
            assert ok == res.hashes
            rows.append({
                "vertices": epsl.node_count, "result_size": len(res.hashes),
                "path_hashes": res.proof.path_hashes,
                "path_hashes_per_vertex": round(res.proof.path_hashes / len(res.hashes), 1),
                "proof_bytes": res.proof.byte_size,
                "generate_ms": round(gen_ms, 3), "verify_ms": round(ver_ms, 3),
            })
            print(f"  n={epsl.node_count:6d}  |R|={len(res.hashes):3d}  "
                  f"{res.proof.byte_size:7d} B  {rows[-1]['path_hashes_per_vertex']} hashes/vertex")
    _write("proof_size", rows)


# ── cost sweep from measured inputs ───────────────────────────────────────────

def _measured_commit_gas(arg: Optional[int]) -> Optional[int]:
    if arg:
        return arg
    report = _HERE.parent / "contracts" / "gas" / "gas-report.json"
    if report.exists():
        return int(json.loads(report.read_text())["commit_steady"])
    return None


def gen_cost_model(n_tx: int, seed: int, commit_gas: Optional[int],
                   gas_gwei: float, blob_gwei: float, eth_usd: float) -> None:
    print("\n[cost-model] on-chain cost per event from measured gas and payload size")
    gas = _measured_commit_gas(commit_gas)
    if gas is None:
        print("  skipped: no measured commit gas. Run the Foundry gas test or pass --commit-gas.")
        return
    bcp, _ = _make(512)
    _drive(bcp, AeTpcc(seed=seed, beta=1), n_tx, 1)
    subs = bcp._blob.submissions
    bytes_per_event = (sum(s["bytes"] - BLOB_HEADER_SIZE for s in subs)
                       / sum(s["events"] for s in subs))
    rows = []
    for w in (64, 128, 256, 512, 1024, 2048):
        payload = BLOB_HEADER_SIZE + int(w * bytes_per_event)
        rows.append({
            "epoch_size_w": w, "commit_gas": gas,
            "payload_bytes_per_event": round(bytes_per_event, 1),
            "blobs_per_epoch": blobs_needed(payload),
            "fits_one_transaction": fits_one_transaction(payload),
            "exec_gas_per_event": round(gas / w, 1),
            "blob_gas_per_event": round(blobs_needed(payload) * BLOB_GAS_PER_BLOB / w, 1),
            "assumed_gas_gwei": gas_gwei, "assumed_blob_gwei": blob_gwei,
            "assumed_eth_usd": eth_usd,
            "usd_per_event": float(f"{cost_per_event_usd(w, bytes_per_event, gas, gas_gwei, blob_gwei, eth_usd):.3g}"),
            "fill_time_s_at_100_events_per_s": expected_commit_latency_s(w, 0, 100.0, 0.0),
        })
        note = "" if rows[-1]["fits_one_transaction"] else "   (more blobs than one transaction may carry)"
        print(f"  w={w:5d}  {rows[-1]['exec_gas_per_event']:8.1f} gas + "
              f"{rows[-1]['blob_gas_per_event']:7.1f} blob gas per event{note}")
    _write("cost_model", rows)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(description="EVM-Lineage measurement harness (Python reference).")
    for flag in ("latency", "dag-shape", "throughput", "proof-size", "cost-model"):
        p.add_argument(f"--{flag}", action="store_true")
    p.add_argument("--tx", type=int, default=2000, help="TPC-C transactions per run")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--commit-gas", type=int, default=None,
                   help="measured execution gas of commitRoot")
    p.add_argument("--gas-gwei", type=float, default=1.0, help="assumed gas price")
    p.add_argument("--blob-gwei", type=float, default=1.0, help="assumed blob gas price")
    p.add_argument("--eth-usd", type=float, default=2000.0, help="assumed ETH price")
    a = p.parse_args()
    chosen = [a.latency, a.dag_shape, a.throughput, a.proof_size, a.cost_model]
    run_all = not any(chosen)
    print(f"EVM-Lineage harness  (tx={a.tx}, seed={a.seed})")
    if run_all or a.latency:
        gen_latency(a.tx, a.seed)
    if run_all or a.dag_shape:
        gen_dag_shape(a.tx, a.seed)
    if run_all or a.throughput:
        gen_throughput(a.tx, a.seed)
    if run_all or a.proof_size:
        gen_proof_size(a.seed)
    if run_all or a.cost_model:
        gen_cost_model(a.tx, a.seed, a.commit_gas, a.gas_gwei, a.blob_gwei, a.eth_usd)
    print("\ndone")


if __name__ == "__main__":
    main()
