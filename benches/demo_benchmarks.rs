//! Live-demo benchmark harness. Real loops against real localhost sockets and
//! real crypto — no synthetic data. Run with: `cargo bench`.
//!
//! The measurement logic lives in `syntriass_overlay::benchmarks` so it can use
//! the crate's crypto dependencies (ml-kem / ml-dsa) for the ML-KEM-only
//! projection; this file is just the `harness = false` entry point.

fn main() {
    syntriass_overlay::benchmarks::run_all();
}
