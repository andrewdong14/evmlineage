"""
dataset_gen.py — Synthetic dataset generator for EVM-Lineage experiments
=========================================================================

Generates deterministic, reproducible datasets used in evaluation:

  Latency     — WriteLineage / QueryBL / QueryFI / QueryTS latency vs epoch_size w
  DAG shape   — DAG shape metrics (depth, fan-out, dedup ratio) vs beta ∈ {1,2,4,8}
  Cost model  — Cost model sweep (Arbitrum vs Ethereum L1, w ∈ {64,128,256,512,1024})
  Throughput  — Throughput vs drain interval (50ms, 100ms, 200ms, 500ms)

All outputs are written as JSON (machine-readable) and CSV (spreadsheet-friendly)
to the ./datasets/ directory.

Usage
-----
    python3 dataset_gen.py               # generate everything
    python3 dataset_gen.py --latency      # latency only
    python3 dataset_gen.py --dag-shape    # DAG shape only
    python3 dataset_gen.py --cost-model   # cost model only
    python3 dataset_gen.py --throughput   # throughput only
    python3 dataset_gen.py --seed 42     # reproducible RNG seed (default: 42)
    python3 dataset_gen.py --events 5000 # events per workload run (default: 2000)

Outputs
-------
    datasets/
    ├── latency.csv                 — WriteLineage / Query latency vs w
    ├── latency.json
    ├── dag_shape.csv               — DAG depth / fan-out / dedup vs beta
    ├── dag_shape.json
    ├── cost_model.csv              — USD cost per event, two chains
    ├── cost_model.json
    ├── throughput.csv              — drain interval vs throughput
    ├── throughput.json
    └── raw/
        ├── aetpcc_events_beta1.jsonl   — raw event stream (one per line)
        ├── aetpcc_events_beta2.jsonl
        ├── aetpcc_events_beta4.jsonl
        └── aetpcc_events_beta8.jsonl

Each *.jsonl row is a single lineage event:
    {"epoch": 3, "tx_type": "NewOrder", "sources": ["0xabc.."], "targets": ["0xdef.."],
     "latency_ms": 0.021, "branch_id": 2, "commit": false}

Requirements
------------
    stdlib only (no numpy/pandas required); outputs are plain CSV/JSON
    Runs in < 60 s on a laptop for the default --events 2000 setting.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Bootstrap: import evm_lineage from the same directory
# ---------------------------------------------------------------------------
_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE))

try:
    from evm_lineage import (
        Bcp,
        Branch,
        Epsl,
        LineageStore,
        BlobPipeline,
        AeTpcc,
        AeTpccEvent,
        LineageService,
        WriteRequest,
        QueryRequest,
        cost_per_event_usd,
        expected_commit_latency_s,
    )
except ImportError as exc:
    raise SystemExit(
        "Could not import evm_lineage.py — make sure dataset_gen.py "
        "is in the same directory as evm_lineage.py.\n"
        f"  ImportError: {exc}"
    )

# ---------------------------------------------------------------------------
# Output directory
# ---------------------------------------------------------------------------
DATASETS = Path(__file__).parent / "datasets"
RAW_DIR  = DATASETS / "raw"


def _mkdir() -> None:
    DATASETS.mkdir(exist_ok=True)
    RAW_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        return
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"  wrote {path.relative_to(Path.cwd()) if path.is_relative_to(Path.cwd()) else path}")


def _write_json(path: Path, data: Any) -> None:
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  wrote {path.relative_to(Path.cwd()) if path.is_relative_to(Path.cwd()) else path}")


def _percentile(xs: List[float], p: float) -> float:
    if not xs:
        return 0.0
    xs = sorted(xs)
    idx = max(0, int(len(xs) * p / 100) - 1)
    return round(xs[idx], 4)


def _stats(xs: List[float]) -> Dict[str, float]:
    if not xs:
        return {"p50": 0, "p95": 0, "p99": 0, "mean": 0, "min": 0, "max": 0}
    s = sorted(xs)
    n = len(s)
    return {
        "p50":  round(s[n // 2], 4),
        "p95":  round(s[int(n * 0.95)], 4),
        "p99":  round(s[int(n * 0.99)], 4),
        "mean": round(sum(s) / n, 4),
        "min":  round(s[0], 4),
        "max":  round(s[-1], 4),
    }


# ---------------------------------------------------------------------------
# Latency vs epoch_size w
# ---------------------------------------------------------------------------
EPOCH_SIZES_TABLE9 = [64, 128, 256, 512, 1024]
BETA_TABLE9        = 4   # default configuration


def _make_bcp(epoch_size: int, beta: int, rng_seed: int) -> Bcp:
    """Return a fresh BCP instance."""
    return Bcp(Epsl(LineageStore()), BlobPipeline(), epoch_size=epoch_size)


def _drive(bcp: Bcp, wl: AeTpcc, n_events: int, beta: int,
           agent_every: int = 10) -> Tuple[List[float], List[bytes], List[Dict]]:
    """Run the full five-phase workload: TPC-C transactions via the direct
    write path, plus one speculative agent decision step (beta branches,
    one winner, losers pruned) every `agent_every` transactions. Returns
    (write latencies ms, committed target hashes, raw event records)."""
    write_lat:  List[float] = []
    hashes_out: List[bytes] = []
    raw:        List[Dict]  = []
    step_i = 0
    for i in range(n_events):
        ev = wl.next_event(bcp.current_epoch, 0)
        t0 = time.perf_counter()
        bcp.write_direct(ev.sources, ev.targets, 0)
        lat = (time.perf_counter() - t0) * 1000
        write_lat.append(lat)
        hashes_out.extend(ev.targets)
        raw.append({
            "epoch": ev.epoch, "tx_type": ev.tx_type, "branch_id": 0,
            "sources": [s.hex() for s in ev.sources],
            "targets": [t.hex() for t in ev.targets],
            "latency_ms": round(lat, 4), "speculative": False,
        })
        if (i + 1) % agent_every == 0:
            branches = []
            for j in range(beta):
                bid = 1 + step_i * beta + j
                aev = wl.agent_step(bcp.current_epoch, bid)
                t0 = time.perf_counter()
                bh = bcp.phase1_write(aev.sources, aev.targets, bid)
                write_lat.append((time.perf_counter() - t0) * 1000)
                branches.append(Branch(id=bid, epoch=bcp.current_epoch,
                                       event_hashes=bh))
                raw.append({
                    "epoch": aev.epoch, "tx_type": "AgentStep", "branch_id": bid,
                    "sources": [s.hex() for s in aev.sources],
                    "targets": [t.hex() for t in aev.targets],
                    "latency_ms": round(write_lat[-1], 4), "speculative": True,
                })
            wid = Bcp.phase2_score(branches, scorer=lambda b: wl._rng.random())
            winner = next(b for b in branches if b.id == wid)
            bcp.phase3_accumulate(winner)
            bcp.phase5_prune(branches, wid)
            hashes_out.extend(winner.event_hashes)
            step_i += 1
    bcp.flush_epoch()   # seal the tail so queries hit a sealed, anchored root
    return write_lat, hashes_out, raw


def gen_latency(n_events: int, rng_seed: int) -> None:
    """Generate WriteLineage / QueryBL / QueryFI / QueryTS latency data (latency vs w)."""
    print("\n[Latency] Latency vs epoch_size w  (beta=4, benchmark workload)")
    rows: List[Dict[str, Any]] = []

    for w in EPOCH_SIZES_TABLE9:
        print(f"  w={w:4d} ...", end=" ", flush=True)
        rng = random.Random(rng_seed + w)
        bcp = _make_bcp(w, BETA_TABLE9, rng_seed)
        wl  = AeTpcc(beta=BETA_TABLE9, seed=rng_seed + w)

        write_lat, all_hashes, _ = _drive(bcp, wl, n_events, BETA_TABLE9)

        # ── query phase: verified queries against the sealed epoch root ────
        sample = rng.sample(all_hashes, min(200, len(all_hashes)))
        svc    = LineageService(epsl=bcp._epsl, bcp=bcp)
        pinned = bcp.current_epoch - 1          # last sealed epoch
        bl_lat, fi_lat, ts_lat = [], [], []
        n_verified = n_anchored = 0

        for h in sample:
            req = QueryRequest(vertex_hash=h, epoch_max=pinned, beta=BETA_TABLE9)
            t0 = time.perf_counter(); r = svc.query_bl(req)
            bl_lat.append((time.perf_counter() - t0) * 1000)
            n_verified += int(r.verified)
            n_anchored += int(r.anchored)
            t0 = time.perf_counter(); svc.query_fi(req)
            fi_lat.append((time.perf_counter() - t0) * 1000)
            t0 = time.perf_counter(); svc.query_ts(req)
            ts_lat.append((time.perf_counter() - t0) * 1000)

        ws  = _stats(write_lat)
        bls = _stats(bl_lat)
        fis = _stats(fi_lat)
        tss = _stats(ts_lat)
        print(f"write p50={ws['p50']}ms  bl p50={bls['p50']}ms  "
              f"anchored={n_anchored}/{len(sample)}")

        rows.append({
            "epoch_size_w":       w,
            "n_events":           n_events,
            "write_p50_ms":       ws["p50"],  "write_p99_ms":  ws["p99"],
            "query_bl_p50_ms":    bls["p50"], "query_bl_p99_ms": bls["p99"],
            "query_fi_p50_ms":    fis["p50"], "query_fi_p99_ms": fis["p99"],
            "query_ts_p50_ms":    tss["p50"], "query_ts_p99_ms": tss["p99"],
            "queries_verified":   n_verified,
            "queries_anchored":   n_anchored,
            "commits":            len(bcp._commits),
            "epsl_nodes":         bcp._epsl.node_count,
        })

    _write_csv(DATASETS / "latency.csv", rows)
    _write_json(DATASETS / "latency.json", rows)


# ---------------------------------------------------------------------------
# DAG shape vs beta ∈ {1, 2, 4, 8}
# ---------------------------------------------------------------------------
BETA_VALUES_TABLE12 = [1, 2, 4, 8]
W_TABLE12           = 512   # default epoch size


def gen_dag_shape(n_events: int, rng_seed: int) -> None:
    """DAG shape metrics vs beta (paper Table 12 analogue): vertex/edge
    counts, depth, fan-in/out, DAG-merge deduplication, prune-log size."""
    print("\n[DAG shape] DAG shape vs beta  (w=512, five-phase AE-TPCC)")
    rows: List[Dict[str, Any]] = []

    for beta in BETA_VALUES_TABLE12:
        print(f"  beta={beta} ...", end=" ", flush=True)
        bcp = _make_bcp(W_TABLE12, beta, rng_seed)
        wl  = AeTpcc(beta=beta, seed=rng_seed + beta * 1000)

        _, _, raw_events = _drive(bcp, wl, n_events, beta)

        raw_path = RAW_DIR / f"aetpcc_events_beta{beta}.jsonl"
        with open(raw_path, "w") as f:
            for rec in raw_events:
                f.write(json.dumps(rec) + "\n")

        epsl    = bcp._epsl
        nodes   = list(epsl._nodes.values())
        n_nodes = len(nodes)
        n_edges = sum(len(nd.backward) for nd in nodes)

        # sampled backward depth
        rng = random.Random(rng_seed)
        sample_nodes = rng.sample(nodes, min(300, n_nodes)) if n_nodes else []
        depths = []
        for nd in sample_nodes:
            visited, queue, d = set(), [nd.hash], 0
            while queue:
                nxt = []
                for h in queue:
                    if h in visited:
                        continue
                    visited.add(h)
                    parent = epsl._nodes.get(h)
                    if parent:
                        nxt.extend(parent.backward)
                d += 1 if nxt else 0
                queue = nxt
            depths.append(d)
        avg_depth = round(sum(depths) / len(depths), 2) if depths else 0
        max_depth = max(depths) if depths else 0

        fan_in  = [len(nd.backward) for nd in nodes]
        fan_out = [len(nd.forward)  for nd in nodes]
        merged  = sum(1 for c in fan_in if c >= 2)     # DAG-merge vertices

        dedup = round(bcp.store.dedup_ratio, 4)
        print(f"nodes={n_nodes} edges={n_edges} avg_depth={avg_depth} "
              f"dedup={dedup} pruned={bcp.total_pruned}")

        rows.append({
            "beta":            beta,
            "n_events":        n_events,
            "epoch_size_w":    W_TABLE12,
            "epsl_nodes":      n_nodes,
            "epsl_edges":      n_edges,
            "avg_bwd_depth":   avg_depth,
            "max_bwd_depth":   max_depth,
            "avg_fan_in":      round(sum(fan_in) / n_nodes, 2) if n_nodes else 0,
            "avg_fan_out":     round(sum(fan_out) / n_nodes, 2) if n_nodes else 0,
            "max_fan_out":     max(fan_out) if fan_out else 0,
            "merge_vertices":  merged,
            "merge_ratio":     round(merged / n_nodes, 4) if n_nodes else 0,
            "dedup_ratio":     dedup,
            "pruned_branches": bcp.total_pruned,
            "prune_log_roots": len(bcp.prune_log.anchored_roots),
            "commits":         bcp.committed_epochs,
        })

    _write_csv(DATASETS / "dag_shape.csv", rows)
    _write_json(DATASETS / "dag_shape.json", rows)


# ---------------------------------------------------------------------------
# Cost model sweep
# ---------------------------------------------------------------------------
# Chain configurations
CHAIN_CONFIGS = [
    {
        "chain":        "Arbitrum One",
        "gas_gwei":     0.1,    # base fee ~0.1 gwei on Arbitrum
        "blob_gwei":    0.1,    # blob price per byte in gwei (low on L2)
        "eth_usd":      3000.0,
    },
    {
        "chain":        "Ethereum L1",
        "gas_gwei":     30.0,   # base fee ~30 gwei on L1
        "blob_gwei":    10.0,   # blob price per byte in gwei (EIP-4844 L1)
        "eth_usd":      3000.0,
    },
]
EPOCH_SIZES_TABLE8 = [64, 128, 256, 512, 1024]


def gen_cost_model(rng_seed: int) -> None:
    """Generate cost model sweep (C_sys per event, two chains)."""
    print("\n[Cost model] Cost model sweep  (C_sys per lineage event, USD)")
    rows: List[Dict[str, Any]] = []

    for cfg in CHAIN_CONFIGS:
        for w in EPOCH_SIZES_TABLE8:
            cost = cost_per_event_usd(
                epoch_size  = w,
                event_bytes = 200.0,
                gas_gwei    = cfg["gas_gwei"],
                blob_gwei   = cfg["blob_gwei"],
                eth_usd     = cfg["eth_usd"],
            )
            lat = expected_commit_latency_s(
                w   = w,
                r   = 0,
                lam = 1000.0,
                t_f = 1.0,
            )
            row = {
                "chain":              cfg["chain"],
                "epoch_size_w":       w,
                "gas_gwei":           cfg["gas_gwei"],
                "blob_gwei":          cfg["blob_gwei"],
                "eth_usd":            cfg["eth_usd"],
                "cost_per_event_usd": round(cost, 8),
                "cost_per_1k_events_usd": round(cost * 1000, 6),
                "expected_commit_latency_s": round(lat, 3),
            }
            rows.append(row)
            print(f"  {cfg['chain']:20s}  w={w:4d}  "
                  f"cost=${cost:.2e}/event  lat={lat:.2f}s")

    _write_csv(DATASETS / "cost_model.csv", rows)
    _write_json(DATASETS / "cost_model.json", rows)


# ---------------------------------------------------------------------------
# Throughput vs drain interval
# ---------------------------------------------------------------------------
DRAIN_INTERVALS_MS  = [50, 100, 200, 500]   # drain frequency sweep
N_EVENTS_FIG7       = 1000
W_FIG7              = 512
BETA_FIG7           = 4


def gen_throughput(n_events: int, rng_seed: int) -> None:
    """Sustained WriteLineage throughput through the service (w=512)."""
    print("\n[Throughput] WriteLineage throughput  (w=512, beta=4)")
    rows: List[Dict[str, Any]] = []

    for label, batchable in [("direct", False)]:
        bcp = _make_bcp(W_FIG7, BETA_FIG7, rng_seed)
        svc = LineageService(epsl=bcp._epsl, bcp=bcp)
        wl  = AeTpcc(beta=BETA_FIG7, seed=rng_seed)

        wall_start = time.perf_counter()
        latencies: List[float] = []
        for i in range(n_events):
            ev  = wl.next_event(bcp.current_epoch, 0)
            req = WriteRequest(sources=ev.sources, targets=ev.targets,
                               branch_id=0, epoch=bcp.current_epoch)
            t0 = time.perf_counter()
            svc.write_lineage(req)
            latencies.append((time.perf_counter() - t0) * 1000)
        wall_elapsed = time.perf_counter() - wall_start
        throughput   = round(n_events / wall_elapsed, 1)
        ws           = _stats(latencies)

        print(f"  mode={label}: {throughput:.0f} ev/s  write p50={ws['p50']}ms")
        rows.append({
            "mode":            label,
            "n_events":        n_events,
            "wall_time_s":     round(wall_elapsed, 3),
            "throughput_evs":  throughput,
            "write_p50_ms":    ws["p50"],
            "write_p99_ms":    ws["p99"],
            "commits":         bcp.committed_epochs,
            "epsl_nodes":      bcp._epsl.node_count,
        })

    _write_csv(DATASETS / "throughput.csv", rows)
    _write_json(DATASETS / "throughput.json", rows)


def gen_proof_size(rng_seed: int) -> None:
    """Proof size and generate/verify cost vs index size n (paper Fig. 6):
    chains committed at n in {1k, 4k, 16k} vertices, BL result sizes
    |BL| in {10, 50, 100}."""
    print("\n[Proof size] Proof bytes / verify time vs n")
    rows: List[Dict[str, Any]] = []
    for n_target in [1_000, 4_000, 16_000]:
        bcp = _make_bcp(1 << 30, 4, rng_seed)      # single epoch, manual seal
        epsl = bcp._epsl
        rng  = random.Random(rng_seed + n_target)
        # build |BL|-deep chains embedded in filler vertices
        chain_heads: Dict[int, bytes] = {}
        for depth in (10, 50, 100):
            prev = None
            for k in range(depth):
                h = bytes(rng.getrandbits(8) for _ in range(32))
                epsl.insert([prev] if prev else [], [h], 0, 0)
                prev = h
            chain_heads[depth] = prev
        while epsl.node_count < n_target:
            h = bytes(rng.getrandbits(8) for _ in range(32))
            epsl.insert([], [h], 0, 0)
        root = epsl.commit_epoch(0).merkle_root
        for depth, head in chain_heads.items():
            t0 = time.perf_counter()
            res = epsl.query_bl(head, epoch_max=0)
            gen_ms = (time.perf_counter() - t0) * 1000
            t0 = time.perf_counter()
            ok = res.proof.verify(root)
            ver_ms = (time.perf_counter() - t0) * 1000
            assert ok
            rows.append({
                "n_vertices":      epsl.node_count,
                "bl_result_size":  depth,
                "proof_records":   len(res.proof.records),
                "proof_depth":     res.proof.depth,
                "proof_bytes":     res.proof.byte_size,
                "gen_ms":          round(gen_ms, 3),
                "verify_ms":       round(ver_ms, 3),
            })
            print(f"  n={epsl.node_count:6d} |BL|={depth:3d} "
                  f"bytes={res.proof.byte_size:7d} verify={ver_ms:.2f}ms")
    _write_csv(DATASETS / "proof_size.csv", rows)
    _write_json(DATASETS / "proof_size.json", rows)


# ---------------------------------------------------------------------------
# Master summary
# ---------------------------------------------------------------------------

def _write_summary(generated: List[str]) -> None:
    summary = {
        "generated_at":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "generated_files": generated,
        "description": (
            "Synthetic datasets for EVM-Lineage evaluation. "
            "All data is deterministically generated from the benchmark workload "
            "using evm_lineage.py (Python agent integration layer). "
            "See README.md for full details."
        ),
    }
    _write_json(DATASETS / "MANIFEST.json", summary)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Generate EVM-Lineage evaluation datasets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--latency",    action="store_true",
                   help="Generate latency results only.")
    p.add_argument("--dag-shape",  action="store_true", dest="dag_shape",
                   help="Generate DAG shape results only.")
    p.add_argument("--cost-model", action="store_true", dest="cost_model",
                   help="Generate cost model results only.")
    p.add_argument("--throughput", action="store_true",
                   help="Generate throughput results only.")
    p.add_argument("--proof-size", action="store_true", dest="proof_size",
                   help="Generate proof size/verify-time results only.")
    p.add_argument("--events", type=int, default=2000,
                   help="Number of events per workload run (default: 2000).")
    p.add_argument("--seed",   type=int, default=42,
                   help="RNG seed for reproducibility (default: 42).")
    return p.parse_args()


def main() -> None:
    args     = _parse_args()
    n_events = args.events
    seed     = args.seed

    _mkdir()
    generated: List[str] = []

    run_all = not any([args.latency, getattr(args, "dag_shape", False),
                   getattr(args, "cost_model", False), args.throughput,
                   getattr(args, "proof_size", False)])

    print(f"EVM-Lineage dataset generator  (events={n_events}, seed={seed})")
    print(f"Output directory: {DATASETS}\n")

    if run_all or args.latency:
        gen_latency(n_events, seed)
        generated += ["latency.csv", "latency.json"]

    if run_all or getattr(args, "dag_shape", False):
        gen_dag_shape(n_events, seed)
        generated += [
            "dag_shape.csv", "dag_shape.json",
            "raw/aetpcc_events_beta1.jsonl", "raw/aetpcc_events_beta2.jsonl",
            "raw/aetpcc_events_beta4.jsonl", "raw/aetpcc_events_beta8.jsonl",
        ]

    if run_all or getattr(args, "cost_model", False):
        gen_cost_model(seed)
        generated += ["cost_model.csv", "cost_model.json"]

    if run_all or args.throughput:
        gen_throughput(min(n_events, N_EVENTS_FIG7), seed)
        generated += ["throughput.csv", "throughput.json"]

    if run_all or getattr(args, "proof_size", False):
        gen_proof_size(seed)
        generated += ["proof_size.csv", "proof_size.json"]

    _write_summary(generated)
    print(f"\n✓  Done — {len(generated)} files in {DATASETS}/")


if __name__ == "__main__":
    main()
