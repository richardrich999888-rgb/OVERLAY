# SYNTRIASS Phase 2 Enforcement Demo

Build eBPF and daemon on a Linux cgroup v2 host:

```bash
cd ebpf
cargo +nightly build --release --target bpfel-unknown-none -Z build-std=core
cd ..
sudo SYNTRIASS_EBPF_OBJECT=ebpf/target/bpfel-unknown-none/release/syntriass-ebpf \
  SYNTRIASS_CGROUP_PATH=/sys/fs/cgroup \
  SYNTRIASS_MAP_PIN_PATH=/sys/fs/bpf/syntriass \
  cargo run --bin daemon
```

Allow one destination:

```bash
sudo cargo run --bin syntriassctl -- policy add \
  --cgroup-id 123 --ip 10.1.1.50 --port 5432 --allow
```

Deny one destination:

```bash
sudo cargo run --bin syntriassctl -- policy add \
  --cgroup-id 123 --ip 10.1.1.51 --port 5432 --deny
```

Clients:

```bash
CGO_ENABLED=0 go build -o /tmp/static_go_client ./examples/static_go_client
cargo build --manifest-path examples/static_rust_client/Cargo.toml --release
python3 examples/python_client/client.py 10.1.1.51 5432
```

Expected denied case:

```text
connect fails with EPERM
audit action=deny reason=policy_deny|no_policy
```

Expected allowed case:

```text
connect succeeds
audit action=allow reason=policy_allow
```

Phase 3 packet-capture validation:

```bash
SYNTRIASS_MAP_PIN_PATH=/sys/fs/bpf/syntriass \
  bash scripts/phase3_pcap_validate.sh eth0 123 10.1.1.50 5432 SOCKET_COOKIE_FROM_AUDIT
```
