// src/bin/bench.rs — measurement harness for the paper's evaluation
//
//   bench index   [--events N] [--w W] [--retain K] [--queries Q] [--seed S]
//                 [--checkpoints a,b,c] [--replay-max N] [--out DIR]
//       Drives the committed AE-TPCC stream through the EPSL and, at each
//       checkpoint, records seal cost, memory, query / proof / verify cost,
//       the flat-rebuild baseline and (up to --replay-max events) the
//       replay baseline. Writes index.json and membership_fixture.json.
//       Defaults: 100 000 events, w = 512, K = 8, 300 queries per type,
//       checkpoints at 1, 3, 10, 30, 100, 300 and 1000 thousand events,
//       replay up to 100 000 events. The replay baseline keeps every
//       payload in memory: pass --replay-max 0 for clean memory figures.
//
//   bench write   [--tx N] [--w W] [--betas 1,2,4,8] [--seed S] [--out DIR]
//       Full five-phase BCP path including the speculative store.
//       Writes write.json.
//
//   bench payload [--tx N] [--ws 64,128,...] [--seed S] [--out DIR]
//       Epoch payload size per event, raw and dictionary-coded, with and
//       without DEFLATE. Writes payload.json.
//
//   bench retain  [--events N] [--retains 1,2,4,...] [--out DIR]
//       Memory cost of keeping K sealed versions readable. Writes retain.json.
//
//   bench fixture [--warmup N] [--count N] [--out DIR]
//       Sample of committed events for the on-chain gas baselines.
//
//   bench hash
//       keccak pair-hash throughput of this machine.
//
// Nothing here is extrapolated: every number written is a measurement of
// this process. Run with `cargo run --release --bin bench -- <command>`.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use lineage_engine::baseline::{flat_rebuild, replay_query};
use lineage_engine::blob::{encode_blob, encode_events, raw_event_bytes, Codec, Event};
use lineage_engine::epsl::{Epsl, EpslConfig, QueryKind};
use lineage_engine::skiplist::live_nodes;
use lineage_engine::workload::{AeTpcc, WlEvent, WorkloadConfig};
use lineage_engine::{
    blobs_needed, hash_pair, keccak_calls, sha256, verify_query, Bcp, BcpConfig, BlobPipeline,
    Branch, LineageStore, VertexHash, BLOB_HEADER_SIZE,
};
use serde_json::{json, Value};

// ── small helpers ────────────────────────────────────────────────────────────

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}
fn arg_u64(args: &[String], name: &str, default: u64) -> u64 {
    arg(args, name).map(|v| v.replace('_', "").parse().expect("number")).unwrap_or(default)
}
fn arg_list(args: &[String], name: &str, default: &[u64]) -> Vec<u64> {
    match arg(args, name) {
        Some(v) => v.split(',').map(|x| x.replace('_', "").parse().expect("number")).collect(),
        None => default.to_vec(),
    }
}

fn rss_bytes() -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest.split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0);
            return kb * 1024;
        }
    }
    0
}

fn pct(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() { return 0.0; }
    let i = ((sorted.len() as f64 - 1.0) * p / 100.0).round() as usize;
    sorted[i.min(sorted.len() - 1)]
}
fn sorted(mut v: Vec<f64>) -> Vec<f64> {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v
}
fn mean(v: &[f64]) -> f64 { if v.is_empty() { 0.0 } else { v.iter().sum::<f64>() / v.len() as f64 } }
fn r3(x: f64) -> f64 { (x * 1000.0).round() / 1000.0 }
fn hex0x(h: &VertexHash) -> String { format!("0x{}", hex::encode(h)) }

fn write_json(dir: &str, name: &str, v: &Value) {
    std::fs::create_dir_all(dir).expect("output directory");
    let path = format!("{dir}/{name}");
    std::fs::write(&path, serde_json::to_string_pretty(v).unwrap() + "\n").expect("write result");
    eprintln!("wrote {path}");
}

fn machine() -> Value {
    let cpu = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let model = cpu.lines().find(|l| l.starts_with("model name"))
        .and_then(|l| l.split(':').nth(1)).unwrap_or("unknown").trim().to_string();
    let cores = cpu.lines().filter(|l| l.starts_with("processor")).count();
    let mem = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mem_kb: u64 = mem.lines().find(|l| l.starts_with("MemTotal"))
        .and_then(|l| l.split_whitespace().nth(1)).and_then(|x| x.parse().ok()).unwrap_or(0);
    json!({ "cpu_model": model, "logical_cpus": cores,
            "mem_total_gib": r3(mem_kb as f64 / 1048576.0),
            "rayon_threads": rayon::current_num_threads() })
}

/// Next batch of committed events: TPC-C transactions plus, after every
/// `tx_per_step` of them, the winning candidate of one agent decision step.
struct Committed {
    gen: AeTpcc,
    tx_since_step: u64,
    pub tx_total: u64,
    pub steps_total: u64,
}

impl Committed {
    fn new(seed: u64) -> Self {
        Committed { gen: AeTpcc::new(WorkloadConfig { seed, beta: 1, ..Default::default() }),
                    tx_since_step: 0, tx_total: 0, steps_total: 0 }
    }
    fn next(&mut self) -> WlEvent {
        if self.tx_since_step == self.gen.config().tx_per_step {
            self.tx_since_step = 0;
            self.steps_total += 1;
            let mut c = self.gen.agent_step(1);
            let w = c.pop().unwrap();
            self.gen.agent_commit(&w);
            return w;
        }
        self.tx_since_step += 1;
        self.tx_total += 1;
        self.gen.next_event()
    }
}

// ── bench index ──────────────────────────────────────────────────────────────

struct QuerySpec { label: &'static str, kind: QueryKind, depth: Option<u32>, old: bool }

const QUERIES: [QuerySpec; 7] = [
    QuerySpec { label: "BL-1", kind: QueryKind::Bl, depth: Some(1), old: false },
    QuerySpec { label: "BL-2", kind: QueryKind::Bl, depth: Some(2), old: false },
    QuerySpec { label: "BL-3", kind: QueryKind::Bl, depth: Some(3), old: false },
    QuerySpec { label: "FI-1", kind: QueryKind::Fi, depth: Some(1), old: false },
    QuerySpec { label: "FI-2", kind: QueryKind::Fi, depth: Some(2), old: false },
    QuerySpec { label: "TS-2", kind: QueryKind::Ts, depth: Some(2), old: true  },
    QuerySpec { label: "BL-4", kind: QueryKind::Bl, depth: Some(4), old: false },
];

fn run_queries(epsl: &Epsl, spec: &QuerySpec, origins: &[VertexHash], pinned: u64,
               root: &VertexHash) -> Value {
    let (mut t_prove, mut t_verify, mut t_plain) = (Vec::new(), Vec::new(), Vec::new());
    let (mut size, mut bytes, mut entries, mut path_len) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for o in origins {
        let t0 = Instant::now();
        let res = epsl.query(o, spec.kind, Some(pinned), spec.depth, true).expect("sealed epoch");
        let dt_prove = t0.elapsed().as_secs_f64() * 1e3;
        let proof = match res.proof { Some(p) => p, None => continue };   // origin younger than the pinned epoch
        let t0 = Instant::now();
        let ok = verify_query(&proof, root);
        let dt_verify = t0.elapsed().as_secs_f64() * 1e3;
        assert_eq!(ok.as_ref(), Some(&res.hashes), "proof must verify against the sealed root");
        let t0 = Instant::now();
        let plain = epsl.query(o, spec.kind, Some(pinned), spec.depth, false).unwrap();
        let dt_plain = t0.elapsed().as_secs_f64() * 1e3;
        assert_eq!(plain.hashes.len(), res.hashes.len());
        t_prove.push(dt_prove); t_verify.push(dt_verify); t_plain.push(dt_plain);
        size.push(res.hashes.len() as f64);
        bytes.push(proof.byte_size() as f64);
        entries.push(proof.entries.len() as f64);
        if !proof.entries.is_empty() {
            path_len.push(proof.path_hashes() as f64 / proof.entries.len() as f64);
        }
    }
    let (tp, tv, tn) = (sorted(t_prove), sorted(t_verify), sorted(t_plain));
    let (sz, by, en) = (sorted(size), sorted(bytes), sorted(entries));
    json!({
        "query": spec.label, "samples": tp.len(), "pinned_epoch": pinned,
        "result_size_median": pct(&sz, 50.0), "result_size_mean": r3(mean(&sz)),
        "result_size_p99": pct(&sz, 99.0),
        "expanded_median": pct(&en, 50.0), "expanded_mean": r3(mean(&en)),
        "prove_ms_median": r3(pct(&tp, 50.0)), "prove_ms_p95": r3(pct(&tp, 95.0)),
        "prove_ms_p99": r3(pct(&tp, 99.0)), "prove_ms_mean": r3(mean(&tp)),
        "verify_ms_median": r3(pct(&tv, 50.0)), "verify_ms_p99": r3(pct(&tv, 99.0)),
        "verify_ms_mean": r3(mean(&tv)),
        "noproof_ms_median": r3(pct(&tn, 50.0)), "noproof_ms_mean": r3(mean(&tn)),
        "proof_bytes_median": pct(&by, 50.0), "proof_bytes_mean": r3(mean(&by)),
        "proof_bytes_p99": pct(&by, 99.0),
        "path_len_mean": r3(mean(&path_len)),
    })
}

fn bench_index(args: &[String]) {
    let n_events = arg_u64(args, "--events", 100_000);
    let w        = arg_u64(args, "--w", 512) as usize;
    let retain   = arg_u64(args, "--retain", 8) as usize;
    let n_query  = arg_u64(args, "--queries", 300) as usize;
    let seed     = arg_u64(args, "--seed", 42);
    let replay_max = arg_u64(args, "--replay-max", 100_000);
    let flat_parallel = args.iter().any(|a| a == "--flat-parallel");
    let out      = arg(args, "--out").unwrap_or_else(|| "results".into());
    let mut checkpoints = arg_list(args, "--checkpoints",
        &[1_000, 3_000, 10_000, 30_000, 100_000, 300_000, 1_000_000]);
    checkpoints.retain(|c| *c <= n_events);
    if checkpoints.last() != Some(&n_events) { checkpoints.push(n_events); }

    let epsl = Epsl::new(EpslConfig { retain: Some(retain) });
    let mut stream = Committed::new(seed);
    let mut recent: VecDeque<WlEvent> = VecDeque::new();       // origins for queries
    let mut payloads: Vec<Vec<u8>> = Vec::new();               // for the replay baseline
    let mut seal_ms: Vec<f64> = Vec::new();
    let mut seal_touched: Vec<f64> = Vec::new();
    let mut seal_hashes: Vec<f64> = Vec::new();
    let mut seal_new_nodes: Vec<f64> = Vec::new();
    let mut insert_s = 0.0f64;
    let mut seal_s = 0.0f64;
    let mut committed = 0u64;
    let mut records: Vec<Value> = Vec::new();
    let mut fixture: Vec<Value> = Vec::new();
    let mut next_cp = 0usize;
    let mut pick = lineage_engine::workload::Rng::new(seed ^ 0xABCD);
    let started = Instant::now();

    while committed < n_events {
        let batch: Vec<WlEvent> = (0..w.min((n_events - committed) as usize))
            .map(|_| stream.next()).collect();
        let t0 = Instant::now();
        for ev in &batch { epsl.insert(&ev.sources, &ev.targets); }
        insert_s += t0.elapsed().as_secs_f64();
        let (k0, n0) = (keccak_calls(), live_nodes());
        let t0 = Instant::now();
        let er = epsl.seal();
        let dt = t0.elapsed().as_secs_f64();
        seal_s += dt;
        seal_ms.push(dt * 1e3);
        seal_touched.push(er.touched as f64);
        seal_hashes.push((keccak_calls() - k0) as f64);
        seal_new_nodes.push((live_nodes() - n0) as f64);
        committed += batch.len() as u64;
        if committed <= replay_max {
            let evs: Vec<Event> = batch.iter().map(|e| (e.sources.clone(), e.targets.clone())).collect();
            payloads.push(encode_blob(er.epoch, &er.root, &evs, Codec::Raw));
        } else if !payloads.is_empty() {
            payloads = Vec::new();          // past the replay limit: free them
        }
        for ev in batch { recent.push_back(ev); }
        while recent.len() > 4 * w { recent.pop_front(); }

        if next_cp < checkpoints.len() && committed >= checkpoints[next_cp] {
            next_cp += 1;
            let latest = er.epoch;
            let vertices = epsl.node_count();
            let tail = |v: &Vec<f64>| -> Vec<f64> { v[v.len().saturating_sub(50)..].to_vec() };
            let s_ms = sorted(tail(&seal_ms));

            // Flat-rebuild baseline: one Merkle tree over all current leaves.
            // (Vertex hashes stand in for the leaves: the cost depends on n only.)
            let mut leaves: Vec<VertexHash> = (0..vertices).map(|i| epsl.vertex_at(i).unwrap()).collect();
            let mut flat_ms = Vec::new();
            let mut flat_bytes = 0usize;
            let mut flat_depth = 0usize;
            let reps = if vertices > 2_000_000 { 1 } else { 3 };
            for rep in 0..reps {
                let l = if rep + 1 == reps { std::mem::take(&mut leaves) } else { leaves.clone() };
                let t0 = Instant::now();
                let tree = flat_rebuild(l, flat_parallel);
                flat_ms.push(t0.elapsed().as_secs_f64() * 1e3);
                flat_bytes = tree.heap_bytes();
                flat_depth = tree.depth();
            }
            drop(leaves);

            // Query origins: outputs (BL, TS) and inputs (FI) of recent events.
            let evs: Vec<&WlEvent> = recent.iter().collect();
            let mut bl_origins = Vec::new();
            let mut fi_origins = Vec::new();
            for _ in 0..n_query {
                let e = evs[pick.below(evs.len() as u64) as usize];
                bl_origins.push(e.targets[pick.below(e.targets.len() as u64) as usize]);
                let e = evs[pick.below(evs.len() as u64) as usize];
                fi_origins.push(e.sources[pick.below(e.sources.len() as u64) as usize]);
            }
            let retained = epsl.retained_epochs();
            let oldest = retained[0];
            let root_latest = epsl.get_epoch_root(latest).unwrap().root;
            let root_oldest = epsl.get_epoch_root(oldest).unwrap().root;
            let mut qres = Vec::new();
            for spec in &QUERIES {
                let (origins, pinned, root) = match (spec.kind, spec.old) {
                    (QueryKind::Fi, _) => (&fi_origins, latest, &root_latest),
                    (_, true)          => (&fi_origins, oldest, &root_oldest),
                    _                  => (&bl_origins, latest, &root_latest),
                };
                qres.push(run_queries(&epsl, spec, origins, pinned, root));
            }

            // Membership proofs for the on-chain gas measurement.
            let mut plen = Vec::new();
            for (j, o) in bl_origins.iter().take(64).enumerate() {
                let mp = epsl.membership(o, Some(latest)).expect("recent vertex");
                assert!(mp.verify(&root_latest));
                plen.push(mp.path.len() as f64);
                if j < 8 {
                    fixture.push(json!({
                        "events": committed, "vertices": vertices, "epoch": latest,
                        "root": hex0x(&mp.root), "leaf": hex0x(&mp.leaf),
                        "vertex": hex0x(&mp.vertex), "digest": hex0x(&mp.digest),
                        "path": mp.path.iter().map(hex0x).collect::<Vec<_>>(),
                    }));
                }
            }

            // Replay baseline (no index): BL-2 answered from the payloads.
            let mut replay_ms = Vec::new();
            if committed <= replay_max && !payloads.is_empty() {
                for o in bl_origins.iter().take(3) {
                    let t0 = Instant::now();
                    let got = replay_query(&payloads, o, false, latest, Some(2)).unwrap();
                    replay_ms.push(t0.elapsed().as_secs_f64() * 1e3);
                    let want = epsl.query(o, QueryKind::Bl, Some(latest), Some(2), false).unwrap();
                    assert_eq!(got.len(), want.hashes.len(), "replay and index agree");
                }
            }

            let rec = json!({
                "events": committed, "tx": stream.tx_total, "agent_steps": stream.steps_total,
                "epochs": latest + 1, "vertices": vertices, "edges": epsl.edge_count(),
                "insert_us_per_event": r3(insert_s * 1e6 / committed as f64),
                "seal_us_per_event": r3(seal_s * 1e6 / committed as f64),
                "index_events_per_s": r3(committed as f64 / (insert_s + seal_s)),
                "seal_ms_median": r3(pct(&s_ms, 50.0)), "seal_ms_p99": r3(pct(&s_ms, 99.0)),
                "seal_ms_mean": r3(mean(&s_ms)),
                "seal_touched_mean": r3(mean(&tail(&seal_touched))),
                "seal_keccak_mean": r3(mean(&tail(&seal_hashes))),
                "seal_new_nodes_mean": r3(mean(&tail(&seal_new_nodes))),
                "flat_rebuild_ms_median": r3(pct(&sorted(flat_ms), 50.0)),
                "flat_tree_bytes": flat_bytes, "flat_path_len": flat_depth,
                "skip_path_len_mean": r3(mean(&plen)),
                "skip_path_len_max": plen.iter().cloned().fold(0.0, f64::max),
                "skip_live_nodes": live_nodes(),
                "retained_versions": retained.len(),
                "graph_heap_bytes": epsl.graph_heap_bytes(),
                "rss_bytes": rss_bytes(),
                "replay_bl2_ms_median": if replay_ms.is_empty() { Value::Null }
                                        else { json!(r3(pct(&sorted(replay_ms), 50.0))) },
                "queries": qres,
                "elapsed_s": r3(started.elapsed().as_secs_f64()),
            });
            eprintln!("checkpoint {} events: {} vertices, seal {:.1} ms, rss {:.2} GiB",
                      committed, vertices, pct(&s_ms, 50.0), rss_bytes() as f64 / 1073741824.0);
            records.push(rec);
        }
    }
    write_json(&out, "index.json", &json!({
        "machine": machine(),
        "params": { "events": n_events, "w": w, "retain": retain, "queries": n_query, "seed": seed,
                    "flat_parallel": flat_parallel },
        "checkpoints": records,
    }));
    write_json(&out, "membership_fixture.json", &json!({ "count": fixture.len(), "cases": fixture }));
}

// ── bench write ──────────────────────────────────────────────────────────────

fn bench_write(args: &[String]) {
    let n_tx  = arg_u64(args, "--tx", 100_000);
    let w     = arg_u64(args, "--w", 512) as usize;
    let seed  = arg_u64(args, "--seed", 42);
    let betas = arg_list(args, "--betas", &[1, 2, 4, 8]);
    let out   = arg(args, "--out").unwrap_or_else(|| "results".into());
    let mut rows = Vec::new();
    for &beta in &betas {
        let store = Arc::new(LineageStore::new());
        let epsl  = Arc::new(Epsl::new(EpslConfig { retain: Some(8) }));
        let blob  = Arc::new(BlobPipeline::new_dry());
        let bcp   = Bcp::new(Arc::clone(&epsl), Arc::clone(&store), Arc::clone(&blob),
                             BcpConfig { epoch_size: w, ..Default::default() });
        let mut gen = AeTpcc::new(WorkloadConfig { seed, beta: beta as usize, ..Default::default() });
        let tx_per_step = gen.config().tx_per_step;
        let (mut t_tx, mut t_step) = (0.0f64, 0.0f64);
        let mut step_us: Vec<f64> = Vec::new();
        let mut steps = 0u64;
        for i in 0..n_tx {
            let ev = gen.next_event();
            let t0 = Instant::now();
            bcp.write_direct(&ev.sources, &ev.targets, 0);
            t_tx += t0.elapsed().as_secs_f64();
            if (i + 1) % tx_per_step == 0 {
                let cands = gen.agent_step(beta as usize);
                let win = gen.pick(cands.len());
                let t0 = Instant::now();
                let mut branches: Vec<Branch> = cands.iter().map(|c| {
                    let mut b = Branch::new(c.branch_id, bcp.current_epoch());
                    b.event_hashes = bcp.phase1_write(&c.sources, &c.targets, c.branch_id);
                    b
                }).collect();
                let wid = cands[win].branch_id;
                for b in branches.iter_mut() { b.is_winner = b.id == wid; }
                bcp.phase3_accumulate(&branches[win]);
                bcp.phase5_prune(&mut branches, wid);
                let dt = t0.elapsed().as_secs_f64();
                t_step += dt;
                step_us.push(dt * 1e6);
                gen.agent_commit(&cands[win]);
                steps += 1;
            }
        }
        let t0 = Instant::now();
        bcp.flush_epoch();
        bcp.flush_prune_log();
        let t_flush = t0.elapsed().as_secs_f64();
        let wall = t_tx + t_step + t_flush;
        let subs = blob.submissions();
        let bytes: usize = subs.iter().map(|s| s.bytes).sum();
        let raw: usize = subs.iter().map(|s| s.raw_bytes).sum();
        let events: usize = subs.iter().map(|s| s.events).sum();
        let st = sorted(step_us);
        rows.push(json!({
            "beta": beta, "tx": n_tx, "agent_steps": steps,
            "committed_events": events, "speculative_events": n_tx + beta * steps,
            "wall_s": r3(wall),
            "committed_events_per_s": r3(events as f64 / wall),
            "written_events_per_s": r3((n_tx + beta * steps) as f64 / wall),
            "tx_us_mean": r3(t_tx * 1e6 / n_tx as f64),
            "step_us_median": r3(pct(&st, 50.0)), "step_us_p99": r3(pct(&st, 99.0)),
            "step_us_mean": r3(mean(&st)),
            "epochs": subs.len(), "pruned_branches": bcp.total_pruned(),
            "prune_roots": bcp.prune_log.anchored_roots().len(),
            "payload_bytes_per_event": r3(bytes as f64 / events as f64),
            "raw_bytes_per_event": r3(raw as f64 / events as f64),
            "index_vertices": epsl.node_count(), "store_vertices": store.vertex_count(),
            "rss_bytes": rss_bytes(),
        }));
        eprintln!("beta={beta}: {:.0} committed events/s", events as f64 / wall);
    }
    write_json(&out, "write.json", &json!({
        "machine": machine(), "params": { "tx": n_tx, "w": w, "seed": seed }, "rows": rows }));
}

// ── bench payload ────────────────────────────────────────────────────────────

fn bench_payload(args: &[String]) {
    let n_tx = arg_u64(args, "--tx", 100_000);
    let seed = arg_u64(args, "--seed", 42);
    let ws   = arg_list(args, "--ws", &[64, 128, 256, 512, 1024, 2048]);
    let out  = arg(args, "--out").unwrap_or_else(|| "results".into());
    let mut stream = Committed::new(seed);
    let mut events: Vec<Event> = Vec::new();
    while stream.tx_total < n_tx {
        let e = stream.next();
        events.push((e.sources, e.targets));
    }
    let n_src: usize = events.iter().map(|e| e.0.len()).sum();
    let n_tgt: usize = events.iter().map(|e| e.1.len()).sum();

    // Size of a stateful encoding that this repository does NOT implement:
    // a hash is sent once, when its vertex is created, and every other
    // occurrence is a varint of the vertex's creation index. Computed on
    // the same trace to show what the self-contained format leaves unused.
    let varint_len = |v: u64| -> usize { (64 - v.max(1).leading_zeros() as usize).div_ceil(7) };
    let mut created: std::collections::HashMap<VertexHash, u64> = std::collections::HashMap::new();
    let mut by_ref_bytes = 0usize;
    for (s, t) in &events {
        by_ref_bytes += varint_len(s.len() as u64) + varint_len(t.len() as u64);
        for h in s.iter().chain(t.iter()) {
            let next = created.len() as u64;
            match created.get(h) {
                Some(id) => by_ref_bytes += varint_len(*id),
                None => { created.insert(*h, next); by_ref_bytes += 32 + varint_len(next); }
            }
        }
    }
    let mut rows = Vec::new();
    for &w in &ws {
        let (mut raw, mut dict, mut zl, mut epochs, mut blobs, mut blobs_zl) = (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
        let mut max_dict = 0usize;
        for chunk in events.chunks(w as usize) {
            if chunk.len() < w as usize { break; }       // full epochs only
            let d = BLOB_HEADER_SIZE + encode_events(chunk).len();
            let z = encode_blob(0, &[0u8; 32], chunk, Codec::Zlib).len();
            raw += raw_event_bytes(chunk);
            dict += d; zl += z; epochs += 1;
            blobs += blobs_needed(d); blobs_zl += blobs_needed(z);
            max_dict = max_dict.max(d);
        }
        let n = (epochs * w as usize) as f64;
        rows.push(json!({
            "w": w, "epochs": epochs,
            "raw_bytes_per_event": r3(raw as f64 / n),
            "payload_bytes_per_event": r3(dict as f64 / n),
            "zlib_bytes_per_event": r3(zl as f64 / n),
            "ratio_dict": r3(raw as f64 / dict as f64),
            "ratio_zlib": r3(raw as f64 / zl as f64),
            "payload_bytes_per_epoch_mean": r3(dict as f64 / epochs as f64),
            "payload_bytes_per_epoch_max": max_dict,
            "blobs_per_epoch_mean": r3(blobs as f64 / epochs as f64),
            "blobs_per_epoch_mean_zlib": r3(blobs_zl as f64 / epochs as f64),
        }));
    }
    write_json(&out, "payload.json", &json!({
        "params": { "tx": n_tx, "seed": seed, "events": events.len() },
        "sources_per_event": r3(n_src as f64 / events.len() as f64),
        "targets_per_event": r3(n_tgt as f64 / events.len() as f64),
        "new_vertices_per_event": r3(created.len() as f64 / events.len() as f64),
        "by_reference_bytes_per_event_not_implemented": r3(by_ref_bytes as f64 / events.len() as f64),
        "rows": rows }));
}

// ── bench retain ─────────────────────────────────────────────────────────────

/// Cost of keeping sealed versions readable: the same run with different
/// retention windows; the difference in live skip-list nodes is the price
/// of the extra versions.
fn bench_retain(args: &[String]) {
    let n_events = arg_u64(args, "--events", 100_000);
    let w        = arg_u64(args, "--w", 512) as usize;
    let seed     = arg_u64(args, "--seed", 42);
    let ks       = arg_list(args, "--retains", &[1, 2, 4, 8, 16, 32]);
    let out      = arg(args, "--out").unwrap_or_else(|| "results".into());
    let mut rows = Vec::new();
    for &k in &ks {
        let nodes0 = live_nodes();
        let epsl = Epsl::new(EpslConfig { retain: Some(k as usize) });
        let mut stream = Committed::new(seed);
        let mut committed = 0u64;
        let mut seal_s = 0.0;
        let mut epochs = 0u64;
        while committed < n_events {
            for _ in 0..w.min((n_events - committed) as usize) {
                let ev = stream.next();
                epsl.insert(&ev.sources, &ev.targets);
                committed += 1;
            }
            let t0 = Instant::now();
            epsl.seal();
            seal_s += t0.elapsed().as_secs_f64();
            epochs += 1;
        }
        rows.push(json!({
            "retain": k, "events": committed, "epochs": epochs, "vertices": epsl.node_count(),
            "skip_live_nodes": live_nodes() - nodes0,
            "seal_ms_mean": r3(seal_s * 1e3 / epochs as f64),
            "rss_bytes": rss_bytes(),
        }));
        eprintln!("retain={k}: {} live skip-list nodes", live_nodes() - nodes0);
    }
    write_json(&out, "retain.json", &json!({
        "params": { "events": n_events, "w": w, "seed": seed },
        "node_bytes": 144, "rows": rows }));
}

// ── bench fixture ────────────────────────────────────────────────────────────

/// A sample of committed workload events for the on-chain gas baselines
/// (contracts/test/fixtures/events_fixture.json).
fn bench_fixture(args: &[String]) {
    let warmup = arg_u64(args, "--warmup", 5_000);
    let count  = arg_u64(args, "--count", 220);
    let seed   = arg_u64(args, "--seed", 42);
    let out    = arg(args, "--out").unwrap_or_else(|| "results".into());
    let mut stream = Committed::new(seed);
    for _ in 0..warmup { stream.next(); }
    let mut events = Vec::new();
    let (mut ns, mut nt, mut edges) = (0usize, 0usize, 0usize);
    for _ in 0..count {
        let e = stream.next();
        ns += e.sources.len(); nt += e.targets.len(); edges += e.sources.len() * e.targets.len();
        events.push(json!({ "type": e.tx_type.name(),
                            "s": e.sources.iter().map(hex0x).collect::<Vec<_>>(),
                            "t": e.targets.iter().map(hex0x).collect::<Vec<_>>() }));
    }
    write_json(&out, "events_fixture.json", &json!({
        "count": count, "warmup": warmup, "seed": seed,
        "sources_per_event": r3(ns as f64 / count as f64),
        "targets_per_event": r3(nt as f64 / count as f64),
        "edges_per_event": r3(edges as f64 / count as f64),
        "events": events }));
}

// ── bench hash ───────────────────────────────────────────────────────────────

fn bench_hash(args: &[String]) {
    let out = arg(args, "--out").unwrap_or_else(|| "results".into());
    let n = 2_000_000u64;
    let mut a = sha256(b"a");
    let b = sha256(b"b");
    let t0 = Instant::now();
    for _ in 0..n { a = hash_pair(&a, &b); }
    let dt = t0.elapsed().as_secs_f64();
    std::hint::black_box(a);
    write_json(&out, "hash.json", &json!({
        "machine": machine(), "pair_hashes": n,
        "ns_per_pair_hash": r3(dt * 1e9 / n as f64),
        "pair_hashes_per_s": r3(n as f64 / dt) }));
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("index")   => bench_index(&args),
        Some("write")   => bench_write(&args),
        Some("payload") => bench_payload(&args),
        Some("retain")  => bench_retain(&args),
        Some("fixture") => bench_fixture(&args),
        Some("hash")    => bench_hash(&args),
        _ => {
            eprintln!("usage: bench <index|write|payload|retain|fixture|hash> [options]  (see the header of src/bin/bench.rs)");
            std::process::exit(2);
        }
    }
}
