// src/workload.rs — agent-extended TPC-C lineage workload (paper Table II)
//
// Port of AeTpcc in agent/evm_lineage.py. Rows are versioned: reading a row
// references its current version, writing a row creates a new version (a
// new item). One lineage event is emitted per transaction. Item hashes are
// SHA-256("table:key:version"), as in the Python generator; the random
// streams of the two generators are not the same.

use std::collections::{HashMap, VecDeque};

use crate::sha256;
use crate::store::VertexHash;

/// SplitMix64 — small deterministic generator for reproducible workloads.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self { Rng(seed) }
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// Uniform in [0, n).
    pub fn below(&mut self, n: u64) -> u64 { self.next_u64() % n }
    /// Uniform in [lo, hi].
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 { lo + self.below(hi - lo + 1) }
    /// Uniform in [0, 1).
    pub fn unit(&mut self) -> f64 { (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64 }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TxType { NewOrder, Payment, OrderStatus, Delivery, StockLevel, AgentStep }

impl TxType {
    pub fn name(self) -> &'static str {
        match self {
            TxType::NewOrder => "NewOrder", TxType::Payment => "Payment",
            TxType::OrderStatus => "OrderStatus", TxType::Delivery => "Delivery",
            TxType::StockLevel => "StockLevel", TxType::AgentStep => "AgentStep",
        }
    }
}

/// TPC-C transaction mix.
pub const MIX: [(TxType, f64); 5] = [
    (TxType::NewOrder, 0.45), (TxType::Payment, 0.43), (TxType::OrderStatus, 0.04),
    (TxType::Delivery, 0.04), (TxType::StockLevel, 0.04),
];

#[derive(Debug, Clone)]
pub struct WlEvent {
    pub tx_type:   TxType,
    pub agent:     u32,          // agent steps only
    pub branch_id: u64,          // agent steps only
    pub sources:   Vec<VertexHash>,
    pub targets:   Vec<VertexHash>,
}

#[derive(Debug, Clone)]
pub struct WorkloadConfig {
    pub seed: u64,
    pub beta: usize,
    pub warehouses: u64,
    pub agents: u32,
    pub tx_per_step: u64,
    pub customers_per_district: u64,
    pub items: u64,
}

impl Default for WorkloadConfig {
    fn default() -> Self {
        WorkloadConfig { seed: 42, beta: 4, warehouses: 10, agents: 100, tx_per_step: 10,
                         customers_per_district: 3000, items: 100_000 }
    }
}

const DISTRICTS_PER_WH: u64 = 10;

pub struct AeTpcc {
    cfg:        WorkloadConfig,
    rng:        Rng,
    c_cust:     u64,
    c_item:     u64,
    version:    HashMap<(&'static str, u64), u32>,
    fresh_ctr:  HashMap<&'static str, u64>,
    undelivered: Vec<VecDeque<u64>>,
    recent_orders: VecDeque<u64>,
    memory:     HashMap<u32, VertexHash>,
    step_ctr:   u64,
    branch_ctr: u64,
}

pub fn item_hash(table: &str, key: u64, version: u32) -> VertexHash {
    sha256(format!("{table}:{key}:{version}").as_bytes())
}

impl AeTpcc {
    pub fn new(cfg: WorkloadConfig) -> Self {
        let mut rng = Rng::new(cfg.seed);
        let c_cust = rng.range(0, 1023);
        let c_item = rng.range(0, 8191);
        AeTpcc { undelivered: (0..cfg.warehouses).map(|_| VecDeque::new()).collect(),
                 cfg, rng, c_cust, c_item, version: HashMap::new(), fresh_ctr: HashMap::new(),
                 recent_orders: VecDeque::new(), memory: HashMap::new(),
                 step_ctr: 0, branch_ctr: 0 }
    }

    pub fn config(&self) -> &WorkloadConfig { &self.cfg }

    fn read(&self, table: &'static str, key: u64) -> VertexHash {
        item_hash(table, key, *self.version.get(&(table, key)).unwrap_or(&0))
    }

    fn write(&mut self, table: &'static str, key: u64) -> VertexHash {
        let v = self.version.entry((table, key)).or_insert(0);
        *v += 1;
        item_hash(table, key, *v)
    }

    fn fresh(&mut self, table: &'static str) -> (u64, VertexHash) {
        let c = self.fresh_ctr.entry(table).or_insert(0);
        let key = *c;
        *c += 1;
        (key, item_hash(table, key, 0))
    }

    /// TPC-C NURand(A, 0, n-1) with run-time constant c.
    fn nurand(&mut self, a: u64, c: u64, n: u64) -> u64 {
        ((self.rng.range(0, a) | self.rng.below(n)) + c) % n
    }

    fn distinct_items(&mut self, k: usize) -> Vec<u64> {
        let mut out: Vec<u64> = Vec::with_capacity(k);
        while out.len() < k {
            let i = self.nurand(8191, self.c_item, self.cfg.items);
            if !out.contains(&i) { out.push(i); }
        }
        out
    }

    fn district_customer(&mut self) -> (u64, u64, u64) {
        let w = self.rng.below(self.cfg.warehouses);
        let d = w * DISTRICTS_PER_WH + self.rng.below(DISTRICTS_PER_WH);
        let c = d * self.cfg.customers_per_district
            + self.nurand(1023, self.c_cust, self.cfg.customers_per_district);
        (w, d, c)
    }

    fn pick_tx_type(&mut self) -> TxType {
        let r = self.rng.unit();
        let mut cumul = 0.0;
        for (t, f) in MIX {
            cumul += f;
            if r < cumul { return t; }
        }
        TxType::StockLevel
    }

    fn new_order(&mut self) -> (Vec<VertexHash>, Vec<VertexHash>) {
        let (w, d, c) = self.district_customer();
        let k = self.rng.range(3, 6) as usize;
        let items = self.distinct_items(k);
        let stock: Vec<u64> = items.iter().map(|i| w * self.cfg.items + i).collect();
        let mut sources = vec![self.read("district", d), self.read("customer", c)];
        for &i in &items { sources.push(self.read("item", i)); }
        for &s in &stock { sources.push(self.read("stock", s)); }
        let (okey, order) = self.fresh("order");
        let mut targets = vec![self.write("district", d), order];
        for _ in &items { let (_, h) = self.fresh("orderline"); targets.push(h); }
        for &s in &stock { targets.push(self.write("stock", s)); }
        self.undelivered[w as usize].push_back(okey);
        self.recent_orders.push_back(okey);
        if self.recent_orders.len() > 1000 { self.recent_orders.pop_front(); }
        (sources, targets)
    }

    fn payment(&mut self) -> (Vec<VertexHash>, Vec<VertexHash>) {
        let (_, d, c) = self.district_customer();
        (vec![self.read("customer", c), self.read("district", d)],
         vec![self.write("customer", c)])
    }

    fn order_status(&mut self) -> (Vec<VertexHash>, Vec<VertexHash>) {
        let (_, d, c) = self.district_customer();
        let mut sources = vec![self.read("customer", c)];
        let n = self.recent_orders.len() as u64;
        if n >= 2 {
            let a = self.rng.below(n);
            let mut b = self.rng.below(n - 1);
            if b >= a { b += 1; }
            for i in [a, b] {
                let o = self.recent_orders[i as usize];
                sources.push(self.read("order", o));
            }
        } else {                              // warm-up: no orders yet
            sources.push(self.read("district", d));
            let i = self.nurand(8191, self.c_item, self.cfg.items);
            sources.push(self.read("item", i));
        }
        let (_, st) = self.fresh("status");
        (sources, vec![st])
    }

    fn delivery(&mut self) -> Option<(Vec<VertexHash>, Vec<VertexHash>)> {
        let w = self.rng.below(self.cfg.warehouses) as usize;
        if self.undelivered[w].len() < 10 { return None; }
        let orders: Vec<u64> = (0..10).map(|_| self.undelivered[w].pop_front().unwrap()).collect();
        let sources = orders.iter().map(|&o| self.read("order", o)).collect();
        let targets = orders.iter().map(|&o| self.write("order", o)).collect();
        Some((sources, targets))
    }

    fn stock_level(&mut self) -> (Vec<VertexHash>, Vec<VertexHash>) {
        let w = self.rng.below(self.cfg.warehouses);
        let items = self.distinct_items(20);
        let sources = items.iter().map(|i| self.read("stock", w * self.cfg.items + i)).collect();
        let (_, sl) = self.fresh("stocklevel");
        (sources, vec![sl])
    }

    /// Next TPC-C transaction as a lineage event.
    pub fn next_event(&mut self) -> WlEvent {
        let mut tx = self.pick_tx_type();
        let (sources, targets) = match tx {
            TxType::Delivery => match self.delivery() {
                Some(st) => st,
                None => { tx = TxType::NewOrder; self.new_order() }   // fewer than ten open orders
            },
            TxType::NewOrder    => self.new_order(),
            TxType::Payment     => self.payment(),
            TxType::OrderStatus => self.order_status(),
            TxType::StockLevel  => self.stock_level(),
            TxType::AgentStep   => unreachable!(),
        };
        WlEvent { tx_type: tx, agent: 0, branch_id: 0, sources, targets }
    }

    /// One decision step: `beta` candidate events that read the same inputs
    /// (the agent's last decision and current database rows) and produce
    /// different decisions. Call `agent_commit` with the winner.
    pub fn agent_step(&mut self, beta: usize) -> Vec<WlEvent> {
        let agent = (self.step_ctr % self.cfg.agents as u64) as u32;
        self.step_ctr += 1;
        let n_src = self.rng.range(4, 12) as usize;
        let mut sources: Vec<VertexHash> = Vec::with_capacity(n_src);
        if let Some(m) = self.memory.get(&agent) { sources.push(*m); }
        while sources.len() < n_src {
            let n = self.recent_orders.len() as u64;
            let h = if n > 0 && self.rng.unit() < 0.5 {
                let o = self.recent_orders[self.rng.below(n) as usize];
                self.read("order", o)
            } else {
                let w = self.rng.below(self.cfg.warehouses);
                let i = self.nurand(8191, self.c_item, self.cfg.items);
                self.read("stock", w * self.cfg.items + i)
            };
            if !sources.contains(&h) { sources.push(h); }
        }
        let n_tgt = self.rng.range(1, 4) as usize;
        (0..beta).map(|_| {
            self.branch_ctr += 1;
            let targets = (0..n_tgt).map(|_| self.fresh("decision").1).collect();
            WlEvent { tx_type: TxType::AgentStep, agent, branch_id: self.branch_ctr,
                      sources: sources.clone(), targets }
        }).collect()
    }

    /// Remember the winning decision as the agent's memory.
    pub fn agent_commit(&mut self, winner: &WlEvent) {
        self.memory.insert(winner.agent, winner.targets[0]);
    }

    /// Uniform pick among `n` candidates (the benchmark's stand-in policy).
    pub fn pick(&mut self, n: usize) -> usize { self.rng.below(n as u64) as usize }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn mix_and_event_shapes() {
        let mut gen = AeTpcc::new(WorkloadConfig { seed: 1, ..Default::default() });
        let mut counts: HashMap<TxType, usize> = HashMap::new();
        let mut produced: HashSet<VertexHash> = HashSet::new();
        let mut reused = 0usize;
        for _ in 0..10_000 {
            let ev = gen.next_event();
            *counts.entry(ev.tx_type).or_default() += 1;
            let (s, t) = (ev.sources.len(), ev.targets.len());
            let ok = match ev.tx_type {
                TxType::NewOrder    => (8..=14).contains(&s) && s == t,
                TxType::Payment     => (s, t) == (2, 1),
                TxType::OrderStatus => (s, t) == (3, 1),
                TxType::Delivery    => (s, t) == (10, 10),
                TxType::StockLevel  => (s, t) == (20, 1),
                TxType::AgentStep   => false,
            };
            assert!(ok, "{:?} {s} {t}", ev.tx_type);
            for x in &ev.targets { assert!(produced.insert(*x), "outputs are new items"); }
            reused += ev.sources.iter().filter(|x| produced.contains(*x)).count();
        }
        for (t, f) in MIX {
            let got = counts[&t] as f64 / 10_000.0;
            assert!((got - f).abs() < 0.03, "{:?}: {got}", t);
        }
        assert!(reused > 2_000, "outputs feed later inputs");
    }

    #[test]
    fn agent_candidates_share_inputs() {
        let mut gen = AeTpcc::new(WorkloadConfig { agents: 3, ..Default::default() });
        for _ in 0..50 { gen.next_event(); }
        let c = gen.agent_step(4);
        assert_eq!(c.len(), 4);
        assert!(c.iter().all(|e| e.sources == c[0].sources));
        assert!((4..=12).contains(&c[0].sources.len()) && (1..=4).contains(&c[0].targets.len()));
        assert_ne!(c[0].targets, c[1].targets);
        gen.agent_commit(&c[2]);
        gen.agent_step(1); gen.agent_step(1);               // agents 1 and 2
        assert!(gen.agent_step(1)[0].sources.contains(&c[2].targets[0]));   // agent 0 again
    }

    #[test]
    fn item_hash_matches_python() {
        // sha256("stock:7:2")
        assert_eq!(hex::encode(item_hash("stock", 7, 2)),
                   hex::encode(sha256(b"stock:7:2")));
    }
}
