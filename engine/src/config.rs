// src/config.rs — cost model (paper Eq. 1) and commit latency (paper Eq. 5)

use crate::blob::{blobs_needed, BLOB_GAS_PER_BLOB, BLOB_HEADER_SIZE};

/// On-chain cost of one epoch in wei: execution gas of commitRoot plus the
/// blob gas of the payload. Blobs are charged whole.
pub fn commit_cost_wei(commit_gas: u64, payload_bytes: usize,
                       gas_price_wei: f64, blob_gas_price_wei: f64) -> f64 {
    commit_gas as f64 * gas_price_wei
        + (blobs_needed(payload_bytes) as u64 * BLOB_GAS_PER_BLOB) as f64 * blob_gas_price_wei
}

/// Amortised on-chain cost per committed event in USD,
/// C(w) = (G_commit * p_gas + ceil(w * s / B) * G_blob * p_blob) / w.
/// `commit_gas` and `bytes_per_event` are measurements; the prices are
/// whatever the reader assumes.
pub fn cost_per_event_usd(epoch_size: u64, bytes_per_event: f64, commit_gas: u64,
                          gas_gwei: f64, blob_gwei: f64, eth_usd: f64) -> f64 {
    let payload = BLOB_HEADER_SIZE + (epoch_size as f64 * bytes_per_event).ceil() as usize;
    let wei = commit_cost_wei(commit_gas, payload, gas_gwei * 1e9, blob_gwei * 1e9);
    wei / 1e18 * eth_usd / epoch_size as f64
}

/// E[T_commit] = (w - j) / mu + t_inc for a batch that already holds j of
/// w events, arrival rate mu and inclusion time t_inc.
pub fn expected_commit_latency_s(w: u64, j: u64, mu: f64, t_inc: f64) -> f64 {
    (w as f64 - j as f64).max(0.0) / mu + t_inc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::BLOB_USABLE_BYTES;

    #[test]
    fn blobs_are_charged_whole() {
        let g = 100_000u64;
        let one = commit_cost_wei(g, 1_000, 1e9, 1e9);
        assert_eq!(one, g as f64 * 1e9 + BLOB_GAS_PER_BLOB as f64 * 1e9);
        let two = commit_cost_wei(g, BLOB_USABLE_BYTES + 1, 1e9, 1e9);
        assert_eq!(two - one, BLOB_GAS_PER_BLOB as f64 * 1e9);
    }

    #[test]
    fn larger_epochs_cost_less_per_event() {
        let g = 100_000u64;
        let c64  = cost_per_event_usd(64,  200.0, g, 10.0, 1.0, 2000.0);
        let c512 = cost_per_event_usd(512, 200.0, g, 10.0, 1.0, 2000.0);
        assert!(c64 > c512 && c512 > 0.0);
        let want = (g as f64 * 10e9 + BLOB_GAS_PER_BLOB as f64 * 1e9) / 1e18 * 2000.0 / 512.0;
        assert!((c512 - want).abs() < 1e-12);
    }

    #[test]
    fn commit_latency_formula() {
        assert!((expected_commit_latency_s(512, 0, 1000.0, 1.0) - 1.512).abs() < 1e-9);
        assert!((expected_commit_latency_s(512, 256, 1000.0, 1.0) - 1.256).abs() < 1e-9);
        assert_eq!(expected_commit_latency_s(512, 600, 1000.0, 1.0), 1.0);
    }
}
