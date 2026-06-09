//! Vector/matrix stress harness — C-DAC OpenBLAS-ARM (SVE) interaction.
//!
//! Compares the cost of the SYNTRIASS ~47 us quantum-safe PSK EncryptedFallback
//! control-plane extraction (measured in `tests/defense_scenario_tests.rs` /
//! `tests/chaos_orchestration.rs`) against an SVE-accelerated dense GEMM run on
//! the CDAC-SSDG/hpc-containers `math_libraries/Openblas_arm.sif` OpenBLAS build.
//!
//! Build + run inside the C-DAC OpenBLAS-ARM Singularity container (exact
//! repository-specified runtime directives):
//!
//!   singularity shell math_libraries/Openblas_arm.sif
//!   export LD_LIBRARY_PATH=/home/user/openblas/lib/:$LD_LIBRARY_PATH
//!   rustc -O --cfg openblas \
//!         -L /home/user/openblas/lib/ -l openblas \
//!         benchmarks/nsm_compliance_report/vector_matrix_stress.rs -o vms
//!   ./vms
//!
//! Host fallback (no OpenBLAS / not in the container): a naive triple-loop GEMM
//! stands in for the BLAS path so the harness still builds and runs:
//!
//!   rustc -O benchmarks/nsm_compliance_report/vector_matrix_stress.rs -o vms
//!
//! This is a standalone program (compiled with `rustc`, not `cargo`), exactly as
//! the C-DAC container workflow expects.

use std::time::Instant;

const N: usize = 256; // 256x256 f64 GEMM
/// Measured SYNTRIASS control-plane Garrison->EncryptedFallback decision+derive
/// (release build); see the committed BENCHMARKS.md / defense-scenario tests.
const FALLBACK_DERIVE_US: f64 = 47.0;

#[cfg(openblas)]
#[allow(non_camel_case_types)]
mod blas {
    use std::os::raw::{c_double, c_int};
    pub const CBLAS_ROW_MAJOR: c_int = 101;
    pub const CBLAS_NO_TRANS: c_int = 111;
    extern "C" {
        // ARM-SVE-optimized OpenBLAS from the C-DAC container.
        pub fn cblas_dgemm(
            layout: c_int,
            transa: c_int,
            transb: c_int,
            m: c_int,
            n: c_int,
            k: c_int,
            alpha: c_double,
            a: *const c_double,
            lda: c_int,
            b: *const c_double,
            ldb: c_int,
            beta: c_double,
            c: *mut c_double,
            ldc: c_int,
        );
    }
}

fn naive_gemm(a: &[f64], b: &[f64], c: &mut [f64]) {
    for i in 0..N {
        for k in 0..N {
            let aik = a[i * N + k];
            for j in 0..N {
                c[i * N + j] += aik * b[k * N + j];
            }
        }
    }
}

fn run_gemm(a: &[f64], b: &[f64], c: &mut [f64]) -> &'static str {
    #[cfg(openblas)]
    {
        use blas::*;
        unsafe {
            cblas_dgemm(
                CBLAS_ROW_MAJOR, CBLAS_NO_TRANS, CBLAS_NO_TRANS,
                N as i32, N as i32, N as i32,
                1.0, a.as_ptr(), N as i32, b.as_ptr(), N as i32,
                0.0, c.as_mut_ptr(), N as i32,
            );
        }
        return "openblas-sve (cblas_dgemm)";
    }
    #[cfg(not(openblas))]
    {
        naive_gemm(a, b, c);
        "host-fallback (naive triple loop)"
    }
}

fn main() {
    let a: Vec<f64> = (0..N * N).map(|i| (i % 7) as f64 * 0.5 + 1.0).collect();
    let b: Vec<f64> = (0..N * N).map(|i| (i % 5) as f64 * 0.25 + 0.5).collect();
    let mut c = vec![0.0f64; N * N];

    // Warm up + time the SVE vector workload.
    let _ = run_gemm(&a, &b, &mut c);
    c.iter_mut().for_each(|x| *x = 0.0);

    let iters = 20;
    let t = Instant::now();
    let mut backend = "";
    for _ in 0..iters {
        c.iter_mut().for_each(|x| *x = 0.0);
        backend = run_gemm(&a, &b, &mut c);
    }
    let per_gemm_us = t.elapsed().as_secs_f64() * 1e6 / iters as f64;
    let flop = 2.0 * (N as f64).powi(3);
    let gflops = flop / (per_gemm_us * 1e3); // FLOP / ns

    let checksum: f64 = c.iter().sum();

    println!("== C-DAC OpenBLAS-ARM (SVE) vector/matrix stress ==");
    println!("backend                 : {backend}");
    println!("GEMM size               : {N}x{N} f64");
    println!("per-GEMM latency        : {per_gemm_us:.1} us  ({gflops:.2} GFLOP/s)");
    println!("checksum                : {checksum:.3}");
    println!("PSK fallback derive     : {FALLBACK_DERIVE_US:.1} us (control-plane, measured)");
    println!(
        "fallback / GEMM ratio   : {:.4}  (the ~47 us fallback is {:.1}x the cost of one SVE GEMM)",
        FALLBACK_DERIVE_US / per_gemm_us,
        FALLBACK_DERIVE_US / per_gemm_us
    );
    println!(
        "NOTE: GFLOP/s and the ratio reflect the active backend above; the SVE \
         figure requires the OpenBLAS-ARM .sif on A64FX/Grace/Altra hardware."
    );
}
