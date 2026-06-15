//! Build script.
//!
//! Only does work for the optional `cdac-accel` feature: it compiles the C-DAC
//! ParaS SYCL offload bridge (`src/accelerator/cdac_sycl_bridge.cpp`) in
//! host-fallback mode via `cc`/g++ and links it into the crate. The real SYCL
//! object is produced out-of-band by `parascc` (see the header); set
//! `CDAC_SYCL_LIB`/link flags to use it instead. With the feature off this build
//! script is a no-op, so the default workspace build is unchanged.

fn main() {
    if std::env::var_os("CARGO_FEATURE_CDAC_ACCEL").is_none() {
        return;
    }

    println!("cargo:rerun-if-changed=src/accelerator/cdac_sycl_bridge.cpp");
    println!("cargo:rerun-if-changed=include/cdac_sycl_bridge.h");

    let mut build = cc::Build::new();
    build
        .cpp(true)
        .std("c++17")
        .file("src/accelerator/cdac_sycl_bridge.cpp")
        .include("include");

    // Opt into the real SYCL path when a SYCL toolchain is requested.
    if std::env::var_os("CDAC_ENABLE_SYCL").is_some() {
        build.define("CDAC_ENABLE_SYCL", None);
    }

    build.compile("cdac_sycl_bridge");
}
