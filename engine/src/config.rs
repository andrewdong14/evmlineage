// src/config.rs — Engine configuration and cost model utilities

/// Compute amortised cost per lineage event in USD.
///
/// C = (G_SSTORE_update / w) × gas_price  +  (s_e / z) × blob_price
pub fn cost_per_event_usd(
    epoch_size:    u64,    // w
    event_bytes:   f64,    // s_e (average event size in bytes)
    zstd_ratio:    f64,    // z (compression ratio)
    gas_price_gwei: f64,   // Arbitrum ≈ 0.10, L1 ≈ 10
    blob_gwei:     f64,    // ≈ 0.10 gwei/byte (post-Dencun)
    eth_usd:       f64,    // ETH price in USD
) -> f64 {
    let gwei_to_usd = 1e-9 * eth_usd;
    let sstore_cost = (2_900.0 / epoch_size as f64) * gas_price_gwei * gwei_to_usd;
    let blob_cost   = (event_bytes / zstd_ratio) * blob_gwei * gwei_to_usd;
    sstore_cost + blob_cost
}

/// Default cost at Arbitrum One with w=512 epoch size.
pub fn default_cost_arb() -> f64 {
    cost_per_event_usd(512, 200.0, 4.0, 0.10, 0.10, 2_000.0)
}

/// Expected commit latency formula:
/// E[T_commit] = (w − r) / λ + t_f
pub fn expected_commit_latency_s(
    w: u64, r: u64, lambda: f64, finality_s: f64
) -> f64 {
    ((w as f64 - r as f64).max(0.0)) / lambda + finality_s
}

/// Full engine configuration.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    // Chain
    pub chain:          String,
    pub eth_price_usd:  f64,
    pub gas_price_gwei: f64,
    pub blob_gwei:      f64,
    pub finality_s:     f64,
    pub rpc_url:        String,
    pub anchor_address: String,
    // EPSL
    pub l_max:          usize,   // max skip-list level; 23 fits up to 10^7 nodes
    pub epsl_ttl_secs:  u64,     // off-chain index retention (seconds)
    // BCP
    pub epoch_size:     u64,     // events per epoch commitment
    pub beta:           usize,   // speculative branches per step
    pub concurrency:    usize,   // concurrent agents
    pub step_freq_hz:   f64,     // agent decision frequency (Hz)
    // RocksDB tuning
    pub vertices_write_buf_mb: usize,  // 256
    pub edges_write_buf_mb:    usize,  // 64
    pub block_cache_gb:        usize,  // 64
    pub l0_trigger:            i32,    // 8
    // Runtime
    pub db_path:   String,
    pub grpc_addr: String,
    pub dry_run:   bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            chain:          "arbitrum".into(),
            eth_price_usd:  2_000.0,
            gas_price_gwei: 0.10,
            blob_gwei:      0.10,
            finality_s:     1.0,
            rpc_url:        String::new(),
            anchor_address: String::new(),
            l_max:          23,
            epsl_ttl_secs:  30 * 86_400,
            epoch_size:     512,
            beta:           4,
            concurrency:    100,
            step_freq_hz:   10.0,
            vertices_write_buf_mb: 256,
            edges_write_buf_mb:     64,
            block_cache_gb:         64,
            l0_trigger:              8,
            db_path:   "/var/lib/evm-lineage/db".into(),
            grpc_addr: "[::]:50051".into(),
            dry_run:   true,
        }
    }
}

impl EngineConfig {
    pub fn cost_per_event_usd(&self) -> f64 {
        cost_per_event_usd(self.epoch_size, 200.0, 4.0,
                           self.gas_price_gwei, self.blob_gwei, self.eth_price_usd)
    }
    pub fn arrival_hz(&self) -> f64 {
        self.step_freq_hz * self.concurrency as f64
    }
    pub fn expected_commit_latency_s(&self, batch_fill: u64) -> f64 {
        expected_commit_latency_s(self.epoch_size, batch_fill,
                                  self.arrival_hz(), self.finality_s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_arb_matches_table8() {
        // Table 8: EVM-Lineage on Arbitrum ≈ $0.000011/event
        let c = default_cost_arb();
        assert!(c < 0.0001 && c > 0.0, "cost ${c:.8}");
    }

    #[test]
    fn cost_l1_higher_than_arb() {
        let arb = cost_per_event_usd(512, 200.0, 4.0, 0.10,  0.10, 2000.0);
        let l1  = cost_per_event_usd(512, 200.0, 4.0, 10.0,  0.10, 2000.0);
        assert!(l1 > arb);
    }

    #[test]
    fn larger_epoch_lower_cost() {
        let c512  = cost_per_event_usd(512,  200.0, 4.0, 0.10, 0.10, 2000.0);
        let c32   = cost_per_event_usd(32,   200.0, 4.0, 0.10, 0.10, 2000.0);
        assert!(c32 > c512, "smaller epoch should cost more per event");
    }

    #[test]
    fn expected_commit_latency_formula() {
        // w=512, r=0, λ=1000, t_f=1 → (512)/1000 + 1 = 1.512
        let t = expected_commit_latency_s(512, 0, 1000.0, 1.0);
        assert!((t - 1.512).abs() < 0.001);
        // r=256 → (256)/1000 + 1 = 1.256
        let t2 = expected_commit_latency_s(512, 256, 1000.0, 1.0);
        assert!((t2 - 1.256).abs() < 0.001);
    }

    #[test]
    fn default_config_values() {
        let c = EngineConfig::default();
        assert_eq!(c.l_max, 23);
        assert_eq!(c.epoch_size, 512);
        assert_eq!(c.beta, 4);
    }
}
