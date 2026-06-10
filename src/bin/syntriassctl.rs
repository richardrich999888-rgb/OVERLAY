use serde::Serialize;
use std::{env, net::IpAddr};
use syntriass_overlay::{
    policy::{
        engine::PolicyEngine,
        maps::{PolicyAction, PolicyEntry},
    },
    session::{monotonic_expiry_after, SessionEntry, SessionManager, SessionState},
};

#[derive(Serialize)]
struct CliResponse<T: Serialize> {
    status: &'static str,
    result: T,
}

#[derive(Serialize)]
struct CliError {
    status: &'static str,
    error: String,
}

fn main() {
    if let Err(e) = run() {
        let body = serde_json::to_string(&CliError {
            status: "error",
            error: e,
        })
        .unwrap_or_else(|_| "{\"status\":\"error\",\"error\":\"serialization\"}".to_string());
        eprintln!("{body}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() < 2 {
        return Err(usage());
    }

    match args[0].as_str() {
        "policy" => run_policy(&args[1..]),
        "session" => run_session(&args[1..]),
        _ => Err(usage()),
    }
}

fn run_policy(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err(usage());
    }
    match args[0].as_str() {
        "add" => {
            let cmd = parse_policy_target(&args[1..])?;
            let action = if has_flag(&args[1..], "--allow") {
                PolicyAction::Allow
            } else if has_flag(&args[1..], "--deny") {
                PolicyAction::Deny
            } else {
                return Err("policy add requires --allow or --deny".to_string());
            };
            let mut engine = linux_engine()?;
            let entry = engine.add(cmd.cgroup_id, cmd.ip, cmd.port, action)?;
            print_json(&CliResponse {
                status: "ok",
                result: entry,
            })
        }
        "remove" | "delete" => {
            let cmd = parse_policy_target(&args[1..])?;
            let mut engine = linux_engine()?;
            let entry = engine.remove(cmd.cgroup_id, cmd.ip, cmd.port)?;
            print_json(&CliResponse {
                status: "ok",
                result: entry,
            })
        }
        "list" => {
            let mut engine = linux_engine()?;
            let entries: Vec<PolicyEntry> = engine.list()?;
            print_json(&CliResponse {
                status: "ok",
                result: entries,
            })
        }
        _ => Err(usage()),
    }
}

fn run_session(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err(usage());
    }
    match args[0].as_str() {
        "establish" => {
            let socket_cookie = parse_value(&args[1..], "--socket-cookie")?
                .parse::<u64>()
                .map_err(|e| format!("invalid --socket-cookie: {e}"))?;
            let ttl_secs = parse_optional_value(&args[1..], "--ttl-secs")
                .unwrap_or_else(|| "60".to_string())
                .parse::<u64>()
                .map_err(|e| format!("invalid --ttl-secs: {e}"))?;
            let suite =
                syntriass_overlay::kernel_native::configured_suite().map_err(|e| e.to_string())?;
            let session_id =
                syntriass_overlay::session::run_authenticated_pqc_session(socket_cookie, suite)
                    .map_err(|e| format!("PQC handshake failed: {e:?}"))?;
            let mut manager = linux_session_manager()?;
            let entry = manager.insert_state(
                socket_cookie,
                session_id,
                SessionState::PqcEstablished,
                monotonic_expiry_after(std::time::Duration::from_secs(ttl_secs)),
            )?;
            print_json(&CliResponse {
                status: "ok",
                result: entry,
            })
        }
        "remove" | "delete" => {
            let socket_cookie = parse_value(&args[1..], "--socket-cookie")?
                .parse::<u64>()
                .map_err(|e| format!("invalid --socket-cookie: {e}"))?;
            let mut manager = linux_session_manager()?;
            let entry = manager.remove(socket_cookie)?;
            print_json(&CliResponse {
                status: "ok",
                result: entry,
            })
        }
        "list" => {
            let mut manager = linux_session_manager()?;
            let entries: Vec<SessionEntry> = manager.list()?;
            print_json(&CliResponse {
                status: "ok",
                result: entries,
            })
        }
        _ => Err(usage()),
    }
}

#[cfg(target_os = "linux")]
fn linux_engine(
) -> Result<PolicyEngine<syntriass_overlay::policy::engine::linux::BpfPolicyStore>, String> {
    let pin_dir =
        env::var("SYNTRIASS_MAP_PIN_PATH").unwrap_or_else(|_| "/sys/fs/bpf/syntriass".to_string());
    let store = syntriass_overlay::policy::engine::linux::BpfPolicyStore::open_pinned(
        &std::path::PathBuf::from(pin_dir),
    )?;
    Ok(PolicyEngine::new(store))
}

#[cfg(not(target_os = "linux"))]
fn linux_engine(
) -> Result<PolicyEngine<syntriass_overlay::policy::engine::MemoryPolicyStore>, String> {
    Err("syntriassctl policy commands require Linux and pinned POLICY_MAP".to_string())
}

#[cfg(target_os = "linux")]
fn linux_session_manager(
) -> Result<SessionManager<syntriass_overlay::session::linux::BpfSessionStore>, String> {
    let pin_dir =
        env::var("SYNTRIASS_MAP_PIN_PATH").unwrap_or_else(|_| "/sys/fs/bpf/syntriass".to_string());
    let store = syntriass_overlay::session::linux::BpfSessionStore::open_pinned(
        &std::path::PathBuf::from(pin_dir),
    )?;
    Ok(SessionManager::new(store))
}

#[cfg(not(target_os = "linux"))]
fn linux_session_manager(
) -> Result<SessionManager<syntriass_overlay::session::MemorySessionStore>, String> {
    Err("syntriassctl session commands require Linux and pinned SESSION_MAP".to_string())
}

struct PolicyTarget {
    cgroup_id: u64,
    ip: IpAddr,
    port: u16,
}

fn parse_policy_target(args: &[String]) -> Result<PolicyTarget, String> {
    let cgroup_id = parse_value(args, "--cgroup-id")?
        .parse::<u64>()
        .map_err(|e| format!("invalid --cgroup-id: {e}"))?;
    let ip = parse_value(args, "--ip")?
        .parse::<IpAddr>()
        .map_err(|e| format!("invalid --ip: {e}"))?;
    let port = parse_value(args, "--port")?
        .parse::<u16>()
        .map_err(|e| format!("invalid --port: {e}"))?;
    Ok(PolicyTarget {
        cgroup_id,
        ip,
        port,
    })
}

fn parse_value(args: &[String], flag: &str) -> Result<String, String> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].clone())
        .ok_or_else(|| format!("missing {flag}"))
}

fn parse_optional_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].clone())
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|arg| arg == flag)
}

fn print_json<T: Serialize>(value: &T) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string(value).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn usage() -> String {
    "usage: syntriassctl policy add --cgroup-id N --ip ADDR --port PORT (--allow|--deny) | syntriassctl policy remove --cgroup-id N --ip ADDR --port PORT | syntriassctl policy list | syntriassctl session establish --socket-cookie COOKIE [--ttl-secs N] | syntriassctl session remove --socket-cookie COOKIE | syntriassctl session list".to_string()
}
