//! Prometheus telemetry for the kernel-native control plane.
//!
//! The map reader is intentionally narrow: once the aya loader is wired in,
//! only `read_ebpf_atomic_telemetry_maps` needs to learn how to read pinned eBPF
//! maps. The HTTP surface and metric names remain stable.

use axum::{http::header, response::IntoResponse, routing::get, Router};
use once_cell::sync::Lazy;
use prometheus::{Encoder, IntCounter, IntGauge, Registry, TextEncoder};
use std::net::SocketAddr;

static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);
static ACTIVE_SESSIONS: Lazy<IntGauge> = Lazy::new(|| {
    IntGauge::new(
        "syntriass_kernel_active_sessions",
        "Active kernel-native Syntriass sessions.",
    )
    .expect("static metric definition is valid")
});
static BYPASS_ATTEMPTS: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new(
        "syntriass_kernel_bypass_attempts_total",
        "Plaintext bypass attempts blocked by the kernel-native interposer.",
    )
    .expect("static metric definition is valid")
});
static REGISTER: Lazy<()> = Lazy::new(|| {
    REGISTRY
        .register(Box::new(ACTIVE_SESSIONS.clone()))
        .expect("active sessions metric is unique");
    REGISTRY
        .register(Box::new(BYPASS_ATTEMPTS.clone()))
        .expect("bypass attempts metric is unique");
});

#[derive(Debug, Clone, Copy, Default)]
pub struct KernelTelemetry {
    pub active_sessions: i64,
    pub bypass_attempts: u64,
}

pub fn read_ebpf_atomic_telemetry_maps() -> KernelTelemetry {
    KernelTelemetry::default()
}

pub fn render_kernel_prometheus_metrics() -> Result<String, prometheus::Error> {
    Lazy::force(&REGISTER);
    let counters = read_ebpf_atomic_telemetry_maps();
    ACTIVE_SESSIONS.set(counters.active_sessions);
    BYPASS_ATTEMPTS.inc_by(counters.bypass_attempts);

    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    encoder.encode(&REGISTRY.gather(), &mut buffer)?;
    Ok(String::from_utf8_lossy(&buffer).into_owned())
}

pub async fn start_metrics_server(
    bind_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Router::new().route("/metrics", get(metrics));
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn metrics() -> impl IntoResponse {
    match render_kernel_prometheus_metrics() {
        Ok(body) => (
            axum::http::StatusCode::OK,
            [(header::CONTENT_TYPE, prometheus::TEXT_FORMAT)],
            body,
        ),
        Err(_) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "metrics unavailable\n".to_string(),
        ),
    }
}
