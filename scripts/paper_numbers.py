#!/usr/bin/env python3
"""
paper_numbers.py — turn the measurements in results/ into LaTeX macros.

Reads   results/index.json, index_run*.json, index_replay.json, retain.json,
        write.json, payload.json, hash.json, gas-report.json,
        devnet-report.json, toolchain.json
Writes  results/results.tex   (\\input by the paper)

Every measured number in the paper's evaluation is one of these macros, so
re-running the benchmarks and this script updates the paper consistently.

    python3 scripts/paper_numbers.py [--out path/to/results.tex]
"""
import argparse
import json
import math
import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent
RES = ROOT / "results"

BLOB_USABLE_BYTES = 4096 * 31       # bytes of payload per blob
MAX_BLOBS_PER_TX = 6                # EIP-7594 (Fusaka): blobs per transaction


def load(name):
    return json.loads((RES / name).read_text())


def num(x, digits=0):
    """Thousands-separated number for LaTeX."""
    if digits == 0:
        s = f"{int(round(x)):,}"
    else:
        s = f"{x:,.{digits}f}"
    return s.replace(",", "\\,")


def sig(x, n=3):
    """Round to n significant digits; plain string with separators."""
    if x == 0:
        return "0"
    d = n - 1 - int(math.floor(math.log10(abs(x))))
    v = round(x, d)
    return num(v, max(d, 0))


def ms(x):
    """Milliseconds with a sensible number of decimals."""
    if x >= 100:
        return num(x)
    if x >= 10:
        return f"{x:.1f}"
    if x >= 1:
        return f"{x:.2f}"
    return f"{x:.3f}"


def kb(b):
    v = b / 1024
    return num(v) if v >= 100 else f"{v:.1f}"


def toolchain():
    """Tool versions recorded by scripts/reproduce.sh; probed if the file is
    missing."""
    f = RES / "toolchain.json"
    if f.exists():
        return json.loads(f.read_text())
    def probe(cmd):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout.strip()
            return out.splitlines()[0] if out else None
        except Exception:
            return None
    toml = (ROOT / "contracts" / "foundry.toml").read_text()
    m = re.search(r'solc(?:_version)?\s*=\s*"([^"]+)"', toml)
    return {"rustc": probe(["rustc", "--version"]), "forge": probe(["forge", "--version"]),
            "solc": m.group(1) if m else None}


def short_version(text, parts=2):
    """'rustc 1.97.0 (2d8144b78 2026-07-07)' -> '1.97'."""
    m = re.search(r"(\d+(?:\.\d+)+)", text or "")
    return ".".join(m.group(1).split(".")[:parts]) if m else "?"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(RES / "results.tex"))
    args = ap.parse_args()

    index, replay = load("index.json"), load("index_replay.json")
    retain, write, payload = load("retain.json"), load("write.json"), load("payload.json")
    hashb, gas, dev = load("hash.json"), load("gas-report.json"), load("devnet-report.json")
    cps = index["checkpoints"]
    last = cps[-1]
    M = {}                                  # macro name -> LaTeX text

    # ── machine and workload ────────────────────────────────────────────
    mach = index["machine"]
    M["CpuCount"] = str(mach["logical_cpus"])
    M["MemGB"] = f"{mach['mem_total_gib']:.0f}"
    model = mach["cpu_model"]
    ghz = re.search(r"@\s*([\d.]+)\s*GHz", model)
    name = " ".join(re.sub(r"\(R\)|\(TM\)|CPU|Processor|@.*", " ", model).split())
    M["CpuDesc"] = name + (f", {float(ghz.group(1)):g}\\,GHz" if ghz else "")
    tools = toolchain()
    M["RustVersion"] = short_version(tools.get("rustc"))
    M["SolcVersion"] = short_version(tools.get("solc"), 3)
    M["PairHashNs"] = num(hashb["ns_per_pair_hash"])
    M["W"] = str(index["params"]["w"])
    M["Retain"] = str(index["params"]["retain"])
    M["QuerySamples"] = str(index["params"]["queries"])
    M["EventsMaxM"] = f"{last['events'] / 1e6:g}"
    M["VerticesMaxM"] = f"{last['vertices'] / 1e6:.2f}"
    M["EdgesMaxM"] = f"{last['edges'] / 1e6:.1f}"
    M["EpochsMax"] = num(last["epochs"])
    M["VerticesPerEvent"] = f"{last['vertices'] / last['events']:.2f}"
    M["EdgesPerEvent"] = f"{last['edges'] / last['events']:.1f}"
    M["SourcesPerEvent"] = f"{payload['sources_per_event']:.1f}"
    M["TargetsPerEvent"] = f"{payload['targets_per_event']:.1f}"
    M["TouchedPerEpoch"] = sig(last["seal_touched_mean"], 2)
    M["AnchorKBMax"] = num(last["epochs"] * 96 / 1024)

    # ── gas ─────────────────────────────────────────────────────────────
    w = index["params"]["w"]
    commit = gas["commit_steady"]
    base = gas["baseline"]
    anchor_ev = base["perevent_total"] / base["events"]
    full_ev = base["onchain_total"] / base["events"]
    M["GasCommit"] = num(commit)
    M["GasCommitFirst"] = num(gas["commit_first"])
    M["GasCommitProxy"] = num(gas["proxy_commit_steady"])
    M["GasCommitMultisig"] = num(gas["multisig_total"])
    M["GasPrune"] = num(gas["prune_steady"])
    M["GasSlash"] = num(gas["slash_two_paths_of_30"])
    M["GasPerEvent"] = num(commit / w)
    M["GasPerEventMultisig"] = num(gas["multisig_total"] / w)
    M["GasBaseAnchor"] = num(anchor_ev)
    M["GasBaseFull"] = num(full_ev)
    M["GasBaseFullM"] = f"{full_ev / 1e6:.2f}"
    M["GasBaseFullPerEdge"] = num(base["onchain_total"] / base["edges"])
    M["GasRatioAnchor"] = sig(anchor_ev / (commit / w), 3)
    M["GasRatioFull"] = sig(full_ev / (commit / w), 2)
    M["GasSampleEvents"] = str(base["events"])
    M["GasSampleEdgesPerEvent"] = f"{base['edges'] / base['events']:.1f}"
    v = gas["verify"]
    xs = list(zip(v["path_len"], v["exec"]))
    n = len(xs)
    sx, sy = sum(x for x, _ in xs), sum(y for _, y in xs)
    sxx, sxy = sum(x * x for x, _ in xs), sum(x * y for x, y in xs)
    slope = (n * sxy - sx * sy) / (n * sxx - sx * sx)
    icpt = (sy - slope * sx) / n
    M["GasVerifyPerHash"] = num(slope)
    M["GasVerifyBase"] = sig(icpt, 2)
    top = [i for i in range(n) if v["events"][i] == max(v["events"])]
    M["GasVerifyMax"] = sig(sum(v["exec"][i] for i in top) / len(top), 2)
    M["GasVerifyTxMax"] = sig(sum(v["log_tx"][i] for i in top) / len(top), 2)
    M["GasVerifyCases"] = str(n)
    M["DevnetCommitBlob"] = num(dev["commit_gas_with_blob"])
    M["DevnetCommitPlain"] = num(sorted(dev["commit_gas_no_blob"][1:])[1])
    M["DevnetBlobGas"] = num(dev["blob_gas_used"])
    M["DevnetPayloadKB"] = kb(dev["payload_bytes"])
    M["DevnetPayloadEvents"] = str(dev["payload_events"])

    rows = [
        ("\\texttt{commitRoot}", commit),
        ("\\texttt{commitRoot} behind the proxy", gas["proxy_commit_steady"]),
        ("\\texttt{commitRoot} through the 3-of-5 multisig$^{\\ast}$", gas["multisig_total"]),
        ("\\texttt{commitPruneRoot}", gas["prune_steady"]),
        ("\\texttt{slash} (two paths of 30 hashes)", gas["slash_two_paths_of_30"]),
    ]
    M["RowsGas"] = " \\\\\n".join(f"{name} & {num(g)}" for name, g in rows) + " \\\\"

    # ── epoch size: gas and payload ─────────────────────────────────────
    rows = []
    fits = []                               # epoch sizes whose worst epoch fits one transaction
    for r in payload["rows"]:
        blobs = math.ceil(r["blobs_per_epoch_mean"] - 1e-9)
        worst = math.ceil(r["payload_bytes_per_epoch_max"] / BLOB_USABLE_BYTES)
        mark = "" if worst <= MAX_BLOBS_PER_TX else "$^{\\dagger}$"
        if worst <= MAX_BLOBS_PER_TX:
            fits.append(r)
        line = (f"{num(r['w'])} & {num(commit / r['w'])} & "
                f"{kb(r['payload_bytes_per_epoch_mean'])} & {blobs}{mark} & "
                f"{num(r['blobs_per_epoch_mean'] * 131072 / r['w'])} & {r['w'] / 100:g}")
        if r["w"] == w:
            line = " & ".join(f"\\textbf{{{c.strip()}}}" for c in line.split("&"))
        rows.append(line)
        if r["w"] == w:
            M["PayloadBytesPerEvent"] = num(r["payload_bytes_per_event"])
            M["RawBytesPerEvent"] = num(r["raw_bytes_per_event"])
            M["PayloadKBEpoch"] = kb(r["payload_bytes_per_epoch_mean"])
            M["BlobsPerEpoch"] = str(blobs)
            M["BlobGasPerEvent"] = num(r["blobs_per_epoch_mean"] * 131072 / r["w"])
            M["ZlibGainPct"] = f"{(1 - r['zlib_bytes_per_event'] / r['raw_bytes_per_event']) * 100:.1f}"
    M["RowsEpoch"] = " \\\\\n".join(rows) + " \\\\"
    # Largest epoch that one transaction can carry: six blobs divided by the
    # worst bytes per event seen at the largest epoch size that still fits,
    # rounded down to hundreds.
    big = max(fits, key=lambda r: r["w"])
    worst_per_event = big["payload_bytes_per_epoch_max"] / big["w"]
    M["MaxEventsPerTx"] = num(int(MAX_BLOBS_PER_TX * BLOB_USABLE_BYTES / worst_per_event) // 100 * 100)
    M["MaxBlobsPerTx"] = str(MAX_BLOBS_PER_TX)
    M["ByRefBytesPerEvent"] = num(payload["by_reference_bytes_per_event_not_implemented"])
    M["PayloadKBPerEvent"] = f"{payload['rows'][3]['payload_bytes_per_event'] / 1024:.2f}"

    # ── sealing: EPSL versus flat rebuild ───────────────────────────────
    def now_rate(c):
        return w / (c["seal_ms_median"] / 1e3 + w * c["insert_us_per_event"] / 1e6)
    M["PlotSealSkip"] = " ".join(f"({c['vertices']},{c['seal_ms_median']:.1f})" for c in cps)
    M["PlotSealFlat"] = " ".join(f"({c['vertices']},{c['flat_rebuild_ms_median']:.1f})" for c in cps)
    first = cps[0]
    M["SealMsMax"] = ms(last["seal_ms_median"])
    M["SealMsMaxPNN"] = ms(last["seal_ms_p99"])
    M["FlatMsMax"] = num(last["flat_rebuild_ms_median"])
    M["FlatSecMax"] = f"{last['flat_rebuild_ms_median'] / 1e3:.1f}"
    M["SealSpeedup"] = sig(last["flat_rebuild_ms_median"] / last["seal_ms_median"], 2)
    M["SealMsMin"] = ms(first["seal_ms_median"])
    M["VerticesMinK"] = f"{first['vertices'] / 1e3:.0f}"
    eq = min(cps, key=lambda c: abs(math.log(c["seal_ms_median"] / c["flat_rebuild_ms_median"])))
    M["CrossVerticesK"] = sig(eq["vertices"] / 1e3, 2)
    M["CrossSealMs"] = ms(eq["seal_ms_median"])
    M["CrossFlatMs"] = ms(eq["flat_rebuild_ms_median"])
    M["HashesPerTouchedMin"] = f"{first['seal_keccak_mean'] / first['seal_touched_mean']:.1f}"
    M["HashesPerTouchedMax"] = f"{last['seal_keccak_mean'] / last['seal_touched_mean']:.1f}"
    M["InsertUs"] = f"{last['insert_us_per_event']:.1f}"
    M["RateMax"] = sig(now_rate(last), 2)
    M["RateMin"] = sig(now_rate(first), 2)
    M["PathLenMax"] = f"{last['skip_path_len_mean']:.1f}"
    M["PathLenMin"] = f"{first['skip_path_len_mean']:.1f}"
    M["FlatDepthMax"] = str(last["flat_path_len"])
    M["PathFactor"] = f"{last['skip_path_len_mean'] / math.log2(last['vertices']):.2f}"
    M["FlatTreeMB"] = num(last["flat_tree_bytes"] / 2**20)
    # Run-to-run spread: reproduce.sh keeps every repetition as index_run<i>.json.
    runs = [json.loads(f.read_text())["checkpoints"][-1]["seal_ms_median"]
            for f in sorted(RES.glob("index_run*.json"))] or [last["seal_ms_median"]]
    M["SealRuns"] = str(len(runs))
    note = f"99th percentile {ms(last['seal_ms_p99'])}\\,ms"
    if len(runs) > 1:
        note += f"; {ms(min(runs))}--{ms(max(runs))}\\,ms across {len(runs)}~runs"
    M["SealNote"] = note

    # ── memory ──────────────────────────────────────────────────────────
    M["RssGB"] = f"{last['rss_bytes'] / 2**30:.2f}"
    M["BytesPerVertex"] = num(last["rss_bytes"] / last["vertices"])
    M["GraphBytesPerVertex"] = num(last["graph_heap_bytes"] / last["vertices"])
    M["NodesPerVertex"] = f"{last['skip_live_nodes'] / last['vertices']:.2f}"
    rr = {r["retain"]: r for r in retain["rows"]}
    ks = sorted(rr)
    per_version = (rr[ks[-1]]["skip_live_nodes"] - rr[ks[-2]]["skip_live_nodes"]) / (ks[-1] - ks[-2])
    M["NodesPerVersionK"] = num(per_version / 1e3)
    M["MBPerVersion"] = f"{per_version * retain['node_bytes'] / 2**20:.0f}"
    M["RetainVerticesM"] = f"{rr[ks[0]]['vertices'] / 1e6:.2f}"
    M["NodeBytes"] = str(retain["node_bytes"])

    # ── queries at the largest index ────────────────────────────────────
    q = {x["query"]: x for x in last["queries"]}
    names = {"BL-1": "$\\BL_1$", "BL-2": "$\\BL_2$", "BL-3": "$\\BL_3$", "BL-4": "$\\BL_4$",
             "FI-1": "$\\FI_1$", "FI-2": "$\\FI_2$", "TS-2": "$\\TS_2$"}
    rows = []
    for key in ("BL-1", "BL-2", "BL-3", "BL-4", "FI-1", "FI-2", "TS-2"):
        x = q[key]
        rows.append(f"{names[key]} & {num(x['result_size_median'])} & {num(x['result_size_p99'])} & "
                    f"{ms(x['prove_ms_median'])} & {ms(x['prove_ms_p99'])} & "
                    f"{ms(x['verify_ms_median'])} & {kb(x['proof_bytes_median'])} & "
                    f"{ms(x['noproof_ms_median'])}")
    M["RowsQueries"] = " \\\\\n".join(rows) + " \\\\"
    tag = {"BL-1": "BLone", "BL-2": "BLtwo", "BL-3": "BLthree", "BL-4": "BLfour",
           "FI-1": "FIone", "FI-2": "FItwo", "TS-2": "TStwo"}
    for key, t in tag.items():
        x = q[key]
        M[t + "R"] = num(x["result_size_median"])
        M[t + "Prove"] = ms(x["prove_ms_median"])
        M[t + "Verify"] = ms(x["verify_ms_median"])
        M[t + "KB"] = kb(x["proof_bytes_median"])
    x = q["FI-2"]
    M["FItwoRPNN"] = num(x["result_size_p99"])
    M["FItwoProvePNN"] = ms(x["prove_ms_p99"])
    M["FItwoMBPNN"] = f"{x['proof_bytes_p99'] / 2**20:.1f}"
    # Cost per expanded record, over the four backward queries (medians).
    bl = [q[k] for k in ("BL-1", "BL-2", "BL-3", "BL-4")]
    us = [x["prove_ms_median"] * 1e3 / x["expanded_median"] for x in bl]
    by = sorted(x["proof_bytes_median"] / x["expanded_median"] for x in bl)
    M["UsPerExpandedMin"] = f"{min(us):.0f}"
    M["UsPerExpandedMax"] = f"{max(us):.0f}"
    M["KBPerExpanded"] = f"{(by[1] + by[2]) / 2 / 1024:.1f}"
    x = q["BL-3"]
    M["AuthFactor"] = sig(x["prove_ms_median"] / x["noproof_ms_median"], 2)
    q0 = {y["query"]: y for y in first["queries"]}
    M["BLtwoProveMin"] = ms(q0["BL-2"]["prove_ms_median"])
    M["BLtwoRMin"] = num(q0["BL-2"]["result_size_median"])

    # ── replay baseline ─────────────────────────────────────────────────
    rep = [c for c in replay["checkpoints"] if c["replay_bl2_ms_median"] is not None]
    by_events = {c["events"]: c for c in cps}
    M["PlotReplay"] = " ".join(f"({c['events']},{c['replay_bl2_ms_median']:.2f})" for c in rep)
    M["PlotBLtwo"] = " ".join(
        f"({c['events']},{[y for y in c['queries'] if y['query'] == 'BL-2'][0]['prove_ms_median']:.3f})"
        for c in cps)
    big = rep[-1]
    ours = [y for y in by_events[big["events"]]["queries"] if y["query"] == "BL-2"][0]
    M["ReplayMsMax"] = num(big["replay_bl2_ms_median"])
    M["ReplaySecMax"] = f"{big['replay_bl2_ms_median'] / 1e3:.1f}"
    M["ReplayEventsK"] = num(big["events"] / 1e3)
    M["ReplayOursMs"] = ms(ours["prove_ms_median"])
    M["ReplayRatio"] = sig(big["replay_bl2_ms_median"] / ours["prove_ms_median"], 2)
    M["ReplayUsPerEvent"] = f"{big['replay_bl2_ms_median'] * 1e3 / big['events']:.1f}"

    # ── write path ──────────────────────────────────────────────────────
    rows = []
    for r in write["rows"]:
        rows.append(f"{r['beta']} & {num(r['committed_events_per_s'])} & "
                    f"{num(r['written_events_per_s'])} & {r['step_us_median']:.0f} & "
                    f"{r['step_us_p99']:.0f} & {num(r['pruned_branches'])}")
    M["RowsWrite"] = " \\\\\n".join(rows) + " \\\\"
    wr = {r["beta"]: r for r in write["rows"]}
    betas = sorted(wr)
    M["WriteRateMin"] = sig(min(r["committed_events_per_s"] for r in write["rows"]), 2)
    M["WriteRateMax"] = sig(max(r["committed_events_per_s"] for r in write["rows"]), 2)
    M["WrittenRateMax"] = sig(wr[betas[-1]]["written_events_per_s"], 2)
    M["StepUsOne"] = f"{wr[betas[0]]['step_us_median']:.0f}"
    M["StepUsMax"] = f"{wr[betas[-1]]['step_us_median']:.0f}"
    M["StepUsPerBranch"] = f"{(wr[betas[-1]]['step_us_median'] - wr[betas[0]]['step_us_median']) / (betas[-1] - betas[0]):.0f}"
    M["StepUsOnePNN"] = f"{wr[betas[0]]['step_us_p99']:.0f}"
    M["StepUsMaxPNN"] = f"{wr[betas[-1]]['step_us_p99']:.0f}"
    M["PrunedMax"] = num(wr[betas[-1]]["pruned_branches"])
    M["BetaMax"] = str(betas[-1])
    M["WriteTxK"] = num(write["params"]["tx"] / 1e3)
    M["WriteVerticesM"] = f"{wr[betas[0]]['index_vertices'] / 1e6:.2f}"
    M["TxUs"] = sig(wr[betas[0]]["tx_us_mean"], 2)

    # ── implementation size ─────────────────────────────────────────────
    def lines(paths):
        return sum(len(p.read_text().splitlines()) for p in paths)
    py = [ROOT / "agent" / "evm_lineage.py"]
    rs = sorted((ROOT / "engine" / "src").rglob("*.rs")) + sorted((ROOT / "engine" / "tests").glob("*.rs"))
    sol = sorted((ROOT / "contracts" / "src").rglob("*.sol"))
    soltest = sorted((ROOT / "contracts" / "test").glob("*.sol"))
    M["LocPython"] = num(lines(py))
    M["LocRust"] = num(lines(rs))
    M["LocSolidity"] = num(lines(sol))
    M["TestsPython"] = str(len(re.findall(r"^    test\(", py[0].read_text(), re.M)))
    M["TestsRust"] = str(sum(len(re.findall(r"#\[test\]", p.read_text())) for p in rs))
    M["TestsSolidity"] = str(sum(len(re.findall(r"function test\w+\(", p.read_text())) for p in soltest))

    out = ["% Generated by scripts/paper_numbers.py from the files in results/.",
           "% Do not edit: re-run the benchmarks and the script instead.", ""]
    for name in sorted(M):
        assert re.fullmatch(r"[A-Za-z]+", name), name
        out.append(f"\\newcommand{{\\r{name}}}{{{M[name]}}}")
    pathlib.Path(args.out).write_text("\n".join(out) + "\n")
    print(f"wrote {args.out} ({len(M)} macros)")


if __name__ == "__main__":
    main()
