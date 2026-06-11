//! Per-file-descriptor session state. No crypto math here; this is the state
//! machine and the buffers that make a byte stream behave like a framed channel.
//!
//! The handshake now carries a runtime-negotiated suite. Initiator state and the
//! established session are trait objects, so the active cipher suite is dynamic.

#[cfg(target_os = "linux")]
use crate::crypto;
use crate::crypto::fallback::FallbackInitiator;
use crate::crypto::{CipherSuite, InitiatorState, SessionKeys};
use libc::c_int;
use once_cell::sync::Lazy;
use prometheus::{Encoder, Histogram, HistogramOpts, IntCounter, IntGauge, Registry, TextEncoder};
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::mem;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(target_os = "linux")]
use std::thread;
#[cfg(target_os = "linux")]
use std::time::Duration;
use std::time::Instant;
use zeroize::Zeroize;

pub const MAX_WIRE_RX_BUFFER: usize = 16 * 1024 * 1024;
pub const MAX_WRITE_BACKLOG: usize = 16 * 1024 * 1024;
pub const MAX_PLAIN_RX_BUFFER: usize = 16 * 1024 * 1024;
#[cfg(target_os = "linux")]
const CONFIG_DIR: &str = "/etc/syntriass";
#[cfg(target_os = "linux")]
const IDENTITY_FILE: &str = "identity.toml";
#[cfg(target_os = "linux")]
const POLICY_FILE: &str = "policy.toml";
#[cfg(target_os = "linux")]
const CONFIG_RELOAD_RETRY: Duration = Duration::from_secs(5);

static CONFIG_EPOCH: AtomicU64 = AtomicU64::new(1);

struct RuntimeMetrics {
    registry: Registry,
    active_sessions: IntGauge,
    handshake_latency: Histogram,
    blocked_bypass_attempts: IntCounter,
    config_epoch_reloads: IntCounter,
    fallback_activations: IntCounter,
    downgrade_attacks_detected: IntCounter,
}

static RUNTIME_METRICS: Lazy<RuntimeMetrics> = Lazy::new(|| {
    let registry = Registry::new();
    let active_sessions = IntGauge::new(
        "syntriass_active_sessions_total",
        "Active authenticated Syntriass tunnels currently tracked.",
    )
    .expect("static Prometheus gauge definition is valid");
    let handshake_latency = Histogram::with_opts(
        HistogramOpts::new(
            "syntriass_handshake_latency_seconds",
            "Authenticated X25519 plus ML-KEM handshake latency in seconds.",
        )
        .buckets(vec![
            0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
        ]),
    )
    .expect("static Prometheus histogram definition is valid");
    let blocked_bypass_attempts = IntCounter::new(
        "syntriass_blocked_bypass_attempts_total",
        "Fail-closed bypass attempts through unsupported stream-socket syscalls.",
    )
    .expect("static Prometheus counter definition is valid");
    let config_epoch_reloads = IntCounter::new(
        "syntriass_config_epoch_reloads_total",
        "Successful cryptographic configuration epoch reloads.",
    )
    .expect("static Prometheus counter definition is valid");
    let fallback_activations = IntCounter::new(
        "syntriass_fallback_activations_total",
        "Authenticated PSK EncryptedFallback sessions established (degraded mode).",
    )
    .expect("static Prometheus counter definition is valid");
    let downgrade_attacks_detected = IntCounter::new(
        "syntriass_downgrade_attacks_detected_total",
        "Detected downgrade/tamper attempts on the negotiation path (fail-closed).",
    )
    .expect("static Prometheus counter definition is valid");

    registry
        .register(Box::new(active_sessions.clone()))
        .expect("active sessions metric registration is unique");
    registry
        .register(Box::new(handshake_latency.clone()))
        .expect("handshake latency metric registration is unique");
    registry
        .register(Box::new(blocked_bypass_attempts.clone()))
        .expect("blocked bypass metric registration is unique");
    registry
        .register(Box::new(config_epoch_reloads.clone()))
        .expect("config reload metric registration is unique");
    registry
        .register(Box::new(fallback_activations.clone()))
        .expect("fallback activations metric registration is unique");
    registry
        .register(Box::new(downgrade_attacks_detected.clone()))
        .expect("downgrade attacks metric registration is unique");

    RuntimeMetrics {
        registry,
        active_sessions,
        handshake_latency,
        blocked_bypass_attempts,
        config_epoch_reloads,
        fallback_activations,
        downgrade_attacks_detected,
    }
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferError {
    LimitExceeded,
}

/// Handshake phase for a tracked socket.
pub enum FdPhase {
    /// connect(2) succeeded; we are the initiator. We hold the boxed initiator
    /// state for the suite we proposed until ServerHello arrives.
    InitiatorAwaitingServerHello(Box<dyn InitiatorState>),
    /// Degraded posture: we sent a FallbackHello and await FallbackFinished.
    InitiatorAwaitingFallbackFinished(FallbackInitiator),
    /// We accepted on this fd and expect a ClientHello (or, if our own posture is
    /// degraded, a FallbackHello) first.
    ResponderAwaitingClientHello,
    /// Key agreement complete; application data flows encrypted.
    Active(SessionKeys),
    /// Terminal: framing/crypto/negotiation failure. Fail closed.
    Failed,
}

/// All mutable state for one socket fd.
pub struct FdState {
    pub phase: FdPhase,
    /// Process that established or adopted this fd state. After `fork()`, the
    /// child inherits this value but has a different live PID, so inherited
    /// sessions can fail closed before any duplicated nonce counter is used.
    pub owner_pid: c_int,
    /// Suite this process is configured to use (policy-pinned at startup).
    pub policy_suite: CipherSuite,
    /// Cryptographic config epoch used to establish this session.
    pub config_epoch: u64,
    /// Bytes framed and waiting to go out on the real socket.
    pub tx_backlog: Vec<u8>,
    /// Raw bytes pulled off the wire, awaiting frame reassembly.
    pub rx_wire: Vec<u8>,
    /// Decrypted plaintext ready to hand back to the application.
    pub rx_plain: Vec<u8>,
    handshake_started: Option<Instant>,
    counted_active: bool,
}

impl FdState {
    pub fn responder(policy_suite: CipherSuite) -> Self {
        Self {
            phase: FdPhase::ResponderAwaitingClientHello,
            owner_pid: current_pid(),
            policy_suite,
            config_epoch: current_config_epoch(),
            tx_backlog: Vec::new(),
            rx_wire: Vec::new(),
            rx_plain: Vec::new(),
            handshake_started: Some(Instant::now()),
            counted_active: false,
        }
    }

    pub fn initiator(
        policy_suite: CipherSuite,
        state: Box<dyn InitiatorState>,
        client_hello_frame: Vec<u8>,
    ) -> Self {
        Self {
            phase: FdPhase::InitiatorAwaitingServerHello(state),
            owner_pid: current_pid(),
            policy_suite,
            config_epoch: current_config_epoch(),
            tx_backlog: client_hello_frame,
            rx_wire: Vec::new(),
            rx_plain: Vec::new(),
            handshake_started: Some(Instant::now()),
            counted_active: false,
        }
    }

    /// Degraded-posture initiator: we sent a FallbackHello and hold the fallback
    /// state until the authenticated FallbackFinished arrives.
    pub fn fallback_initiator(
        policy_suite: CipherSuite,
        state: FallbackInitiator,
        fallback_hello_frame: Vec<u8>,
    ) -> Self {
        Self {
            phase: FdPhase::InitiatorAwaitingFallbackFinished(state),
            owner_pid: current_pid(),
            policy_suite,
            config_epoch: current_config_epoch(),
            tx_backlog: fallback_hello_frame,
            rx_wire: Vec::new(),
            rx_plain: Vec::new(),
            handshake_started: Some(Instant::now()),
            counted_active: false,
        }
    }

    pub fn failed(policy_suite: CipherSuite) -> Self {
        Self {
            phase: FdPhase::Failed,
            owner_pid: current_pid(),
            policy_suite,
            config_epoch: current_config_epoch(),
            tx_backlog: Vec::new(),
            rx_wire: Vec::new(),
            rx_plain: Vec::new(),
            handshake_started: None,
            counted_active: false,
        }
    }

    pub fn append_tx(&mut self, bytes: &[u8]) -> Result<(), BufferError> {
        append_bounded(&mut self.tx_backlog, bytes, MAX_WRITE_BACKLOG)
    }

    pub fn append_rx_wire(&mut self, bytes: &[u8]) -> Result<(), BufferError> {
        append_bounded(&mut self.rx_wire, bytes, MAX_WIRE_RX_BUFFER)
    }

    pub fn append_rx_plain(&mut self, bytes: &[u8]) -> Result<(), BufferError> {
        append_bounded(&mut self.rx_plain, bytes, MAX_PLAIN_RX_BUFFER)
    }

    pub fn fail_closed(&mut self) {
        if self.counted_active {
            RUNTIME_METRICS.active_sessions.dec();
            self.counted_active = false;
        }
        self.tx_backlog.zeroize();
        self.rx_wire.zeroize();
        self.rx_plain.zeroize();
        self.tx_backlog.clear();
        self.rx_wire.clear();
        self.rx_plain.clear();
        self.phase = FdPhase::Failed;
    }

    pub fn activate(&mut self, keys: SessionKeys) {
        if !self.counted_active {
            RUNTIME_METRICS.active_sessions.inc();
            self.counted_active = true;
        }
        if let Some(started) = self.handshake_started.take() {
            RUNTIME_METRICS
                .handshake_latency
                .observe(started.elapsed().as_secs_f64());
        }
        self.phase = FdPhase::Active(keys);
    }

    pub fn fail_if_stale_idle_config(&mut self) -> bool {
        if self.config_epoch == current_config_epoch() {
            return false;
        }
        if self.is_idle_for_config_reload() {
            self.fail_closed();
            self.config_epoch = current_config_epoch();
            return true;
        }
        false
    }

    fn is_idle_for_config_reload(&self) -> bool {
        self.tx_backlog.is_empty() && self.rx_wire.is_empty() && self.rx_plain.is_empty()
    }
}

pub fn current_pid() -> c_int {
    // SAFETY: getpid takes no arguments, touches no memory, and cannot fail.
    unsafe { libc::getpid() }
}

pub fn current_config_epoch() -> u64 {
    CONFIG_EPOCH.load(Ordering::Acquire)
}

pub fn record_blocked_bypass_attempt() {
    RUNTIME_METRICS.blocked_bypass_attempts.inc();
}

pub fn record_config_epoch_reload() {
    RUNTIME_METRICS.config_epoch_reloads.inc();
}

/// An authenticated PSK fallback session was established (degraded mode).
pub fn record_fallback_activation() {
    RUNTIME_METRICS.fallback_activations.inc();
}

/// A downgrade / tamper attempt was detected on the negotiation path. Increments
/// the :9090 counter and logs a high-severity line; the caller then fails closed.
pub fn record_downgrade_attack(detail: &str) {
    RUNTIME_METRICS.downgrade_attacks_detected.inc();
    eprintln!("syntriass: SECURITY ALERT: downgrade attempt detected: {detail} (failing closed)");
}

pub fn render_prometheus_metrics() -> Result<String, prometheus::Error> {
    let metrics = RUNTIME_METRICS.registry.gather();
    let encoder = TextEncoder::new();
    let mut output = Vec::new();
    encoder.encode(&metrics, &mut output)?;
    Ok(String::from_utf8_lossy(&output).into_owned())
}

#[cfg(target_os = "linux")]
fn advance_config_epoch() -> u64 {
    CONFIG_EPOCH.fetch_add(1, Ordering::AcqRel) + 1
}

impl Drop for FdState {
    fn drop(&mut self) {
        if self.counted_active {
            RUNTIME_METRICS.active_sessions.dec();
            self.counted_active = false;
        }
        self.tx_backlog.zeroize();
        self.rx_wire.zeroize();
        self.rx_plain.zeroize();
    }
}

fn append_bounded(buf: &mut Vec<u8>, bytes: &[u8], limit: usize) -> Result<(), BufferError> {
    if bytes.len() > limit.saturating_sub(buf.len()) {
        return Err(BufferError::LimitExceeded);
    }
    buf.extend_from_slice(bytes);
    Ok(())
}

/// Global fd -> state registry.
///
/// The outer `Mutex<HashMap>` is the *global registry lock*: it guards only map
/// operations (insert / lookup-and-clone / remove) and is never held across a
/// blocking syscall. Each fd owns its own `Arc<Mutex<FdState>>`; callers clone
/// the `Arc` out under the short global lock, release it, then take the per-fd
/// lock for the blocking I/O. This keeps connections independent and lets a
/// `close` remove an fd while another thread is mid-I/O on it: removing the map
/// entry only drops the registry's `Arc` reference, so the in-flight thread's
/// clone keeps the `FdState` (and its zeroizing `Drop`) alive until it finishes.
pub static REGISTRY: Lazy<Mutex<HashMap<i32, Arc<Mutex<FdState>>>>> = Lazy::new(|| {
    start_config_hot_reloader();
    Mutex::new(HashMap::new())
});

#[cfg(target_os = "linux")]
pub fn start_config_hot_reloader() {
    START_RELOADER.call_once(|| {
        if let Err(e) = thread::Builder::new()
            .name("syntriass-config-reloader".to_string())
            .spawn(config_reloader_loop)
        {
            eprintln!("syntriass: failed to start config reloader: {e}");
        }
    });
}

#[cfg(not(target_os = "linux"))]
pub fn start_config_hot_reloader() {}

#[cfg(target_os = "linux")]
static START_RELOADER: std::sync::Once = std::sync::Once::new();

#[cfg(target_os = "linux")]
fn retire_idle_sessions_for_new_config(epoch: u64) {
    let states = match REGISTRY.lock() {
        Ok(registry) => registry.values().cloned().collect::<Vec<_>>(),
        Err(_) => {
            eprintln!("syntriass: config reload could not lock fd registry");
            return;
        }
    };
    for state in states {
        if let Ok(mut guard) = state.try_lock() {
            if guard.config_epoch != epoch && guard.is_idle_for_config_reload() {
                guard.fail_closed();
                guard.config_epoch = epoch;
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn handle_config_change() {
    match crypto::reload_runtime_config() {
        Ok(()) => {
            let epoch = advance_config_epoch();
            record_config_epoch_reload();
            retire_idle_sessions_for_new_config(epoch);
            eprintln!("syntriass: reloaded cryptographic config epoch {epoch}");
        }
        Err(e) => {
            eprintln!("syntriass: failed to reload cryptographic config: {e:?}");
        }
    }
}

#[cfg(target_os = "linux")]
fn config_reloader_loop() {
    loop {
        match watch_config_dir_once() {
            Ok(()) => {}
            Err(e) => {
                eprintln!("syntriass: config watcher unavailable: {e}");
                thread::sleep(CONFIG_RELOAD_RETRY);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn watch_config_dir_once() -> io::Result<()> {
    // SAFETY: inotify_init1 takes only a flag word and returns a new fd or -1.
    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let result = watch_config_dir_fd(fd);
    // SAFETY: `fd` was created above, is owned solely by this function, and is
    // closed exactly once here.
    unsafe {
        raw_close(fd);
    }
    result
}

#[cfg(target_os = "linux")]
fn watch_config_dir_fd(fd: c_int) -> io::Result<()> {
    let path = std::ffi::CString::new(CONFIG_DIR)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid config path"))?;
    let mask = libc::IN_CLOSE_WRITE | libc::IN_MODIFY | libc::IN_MOVED_TO;
    // SAFETY: `path` is a live NUL-terminated CString and `fd` is the caller's
    // valid inotify descriptor; the kernel only reads the path bytes.
    let wd = unsafe { libc::inotify_add_watch(fd, path.as_ptr(), mask) };
    if wd < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut buf = [0u8; 4096];
    loop {
        // SAFETY: `buf` is a live 4096-byte local and `len` is its exact size;
        // the kernel writes at most `len` bytes into it.
        let n = unsafe { raw_read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "inotify fd closed",
            ));
        }
        let mut offset = 0usize;
        let total = n as usize;
        while offset + mem::size_of::<libc::inotify_event>() <= total {
            // SAFETY: the loop condition guarantees at least size_of::<inotify_event>()
            // readable bytes at `offset` inside `buf`. `read_unaligned` copies the
            // header out by value, so no reference is formed to potentially
            // misaligned memory ([u8; 4096] has alignment 1; the kernel aligns
            // successive events, but the buffer base itself carries no guarantee —
            // taking `&*cast` here would be UB on a misaligned base).
            let event = unsafe {
                std::ptr::read_unaligned(buf[offset..].as_ptr().cast::<libc::inotify_event>())
            };
            let name_start = offset + mem::size_of::<libc::inotify_event>();
            let name_end = name_start.saturating_add(event.len as usize);
            if name_end > total {
                break;
            }
            if is_relevant_config_event(event.mask, &buf[name_start..name_end]) {
                handle_config_change();
            }
            offset = name_end;
        }
    }
}

/// Raw `read(2)` via `syscall`, bypassing the interposed libc `read` (the
/// overlay's own LD_PRELOAD hook must not recurse into this watcher).
///
/// # Safety
/// `buf` must be valid for writes of `len` bytes and `fd` must be a readable
/// descriptor owned by the caller.
#[cfg(target_os = "linux")]
unsafe fn raw_read(fd: c_int, buf: *mut libc::c_void, len: usize) -> isize {
    libc::syscall(libc::SYS_read, fd, buf, len) as isize
}

/// Raw `close(2)` via `syscall`, bypassing the interposed libc `close`.
///
/// # Safety
/// `fd` must be owned by the caller and not used again after this call.
#[cfg(target_os = "linux")]
unsafe fn raw_close(fd: c_int) {
    libc::syscall(libc::SYS_close, fd);
}

#[cfg(target_os = "linux")]
fn is_relevant_config_event(mask: u32, raw_name: &[u8]) -> bool {
    if mask & (libc::IN_CLOSE_WRITE | libc::IN_MODIFY | libc::IN_MOVED_TO) == 0 {
        return false;
    }
    let end = raw_name
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(raw_name.len());
    std::str::from_utf8(&raw_name[..end])
        .is_ok_and(|name| name == IDENTITY_FILE || name == POLICY_FILE)
}
