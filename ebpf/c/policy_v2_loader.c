// SPDX-License-Identifier: GPL-2.0
//
// Loader + userspace policy distributor for the Policy Engine v2 object model.
//
//   policy_v2_loader <attach-cgroup> <run_ms> <schedule> <probe-cgroup> [expired-cgroup]
//
// Loads policy_v2.bpf.o, attaches the cgroup/connect4 program to <attach-cgroup>
// (the cgroup2 mount root, so every child cgroup is covered), then distributes
// structured `struct syntriass_policy` objects from userspace into policy_table
// and measures:
//   * UPDATE latency  — time to push a full policy object (bpf_map_update_elem);
//   * LOOKUP latency   — kernel-side policy resolution + decision, taken from the
//                        kernel's own per-program run-time accounting
//                        (BPF_STATS_RUN_TIME) averaged over the real connects;
//   * MEMORY overhead  — value_size and capacity from the map info.
//
// Policy distribution:
//   <probe-cgroup>    gets a FullPqc policy at load; the schedule rewrites its
//                     posture (full structured-object rewrites, timed).
//   <expired-cgroup>  (optional) gets a FullPqc policy whose expiry is already in
//                     the past, so the kernel must fail it closed (REASON_EXPIRED).
//   any other cgroup  has NO policy object -> map-miss fail-closed (REASON_NO_POLICY).
//
// Cgroup ids: bpf_get_current_cgroup_id() returns the cgroupfs directory inode,
// so a cgroup id is the stat() inode of its directory.

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MODE_FULL_PQC 0u
#define MODE_FAIL_CLOSED 2u

struct syntriass_policy {
    unsigned long long policy_id;
    unsigned long long cgroup_id;
    unsigned long long expiry_ns;
    unsigned char peer_identity_hash[32];
    unsigned int interface_id;
    unsigned int posture;
    unsigned int priority;
    unsigned char fallback_allowed;
    unsigned char audit_enabled;
    unsigned char _pad[2];
};

struct policy_event {
    unsigned long long policy_id, cgroup_id;
    unsigned int pid, daddr;
    unsigned short dport, posture, decision, reason;
    unsigned int level, _evpad;
};

static int g_pol_fd = -1, g_sess_fd = -1;

static const char *level_str(unsigned l) {
    switch (l) {
    case 0: return "global";
    case 1: return "node";
    case 2: return "app";
    case 3: return "session";
    default: return "?";
    }
}

static long now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000 + t.tv_nsec / 1000;
}
static long now_ms(void) { return now_us() / 1000; }

// cgroup id == inode number of the cgroupfs directory.
static unsigned long long cgid_of(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return (unsigned long long)st.st_ino;
}

static const char *reason_str(unsigned r) {
    switch (r) {
    case 0: return "ok";
    case 1: return "no-policy";
    case 2: return "expired";
    case 3: return "failclosed-posture";
    default: return "?";
    }
}

static int on_event(void *c, void *data, size_t sz) {
    (void)c;
    if (sz < sizeof(struct policy_event)) return 0;
    struct policy_event *e = data;
    char ip[INET_ADDRSTRLEN];
    struct in_addr a = {.s_addr = e->daddr};
    inet_ntop(AF_INET, &a, ip, sizeof(ip));
    printf("EVT pol=%llu cg=%llu pid=%u dst=%s:%u posture=%u decision=%s reason=%s level=%s\n",
           e->policy_id, e->cgroup_id, e->pid, ip, e->dport, e->posture,
           e->decision ? "DENY" : "ALLOW", reason_str(e->reason), level_str(e->level));
    fflush(stdout);
    return 0;
}

// Build a full policy object and push it; returns the update latency in us.
// expiry_ns: 0 = never; any non-zero in the past forces REASON_EXPIRED.
static long push_policy_ex(unsigned long long cgid, unsigned posture,
                           unsigned long long policy_id, unsigned long long expiry_ns) {
    struct syntriass_policy p;
    memset(&p, 0, sizeof(p));
    p.policy_id = policy_id;
    p.cgroup_id = cgid;
    p.expiry_ns = expiry_ns;
    p.posture = posture;
    p.priority = 100;
    p.fallback_allowed = 1;
    p.audit_enabled = 1;
    long t = now_us();
    int rc = bpf_map_update_elem(g_pol_fd, &cgid, &p, BPF_ANY);
    long us = now_us() - t;
    if (rc) fprintf(stderr, "policy push failed cg=%llu rc=%d\n", cgid, rc);
    return us;
}

// Bench mode: attach ONLY the lookup-only program and report its run-time
// accounting, isolating the policy lookup + decision cost.
//   policy_v2_loader bench <attach-cgroup> <probe-cgroup> <run_ms>
static int run_bench(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "usage: bench <attach> <probe> <run_ms>\n"); return 1; }
    const char *cg = argv[2];
    unsigned long long probe_cgid = cgid_of(argv[3]);
    int run_ms = atoi(argv[4]);

    struct bpf_object *obj = bpf_object__open_file("policy_v2.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) { fprintf(stderr, "bench load fail\n"); return 2; }
    g_pol_fd = bpf_object__find_map_fd_by_name(obj, "policy_table");
    struct bpf_program *p =
        bpf_object__find_program_by_name(obj, "syntriass_policy_lookup_bench");
    int prog_fd = bpf_program__fd(p);
    int stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);
    int cgfd = open(cg, O_RDONLY | O_DIRECTORY);
    if (cgfd < 0) { perror("open cgroup"); return 3; }
    struct bpf_link *link = bpf_program__attach_cgroup(p, cgfd);
    if (!link) { fprintf(stderr, "bench attach fail\n"); return 4; }

    push_policy_ex(probe_cgid, MODE_FULL_PQC, 0xD0001, 0);
    fprintf(stderr, "READY\n"); fflush(stderr);

    long start = now_ms();
    while (now_ms() < start + run_ms) usleep(20000);

    struct bpf_prog_info pinfo;
    unsigned int plen = sizeof(pinfo);
    memset(&pinfo, 0, sizeof(pinfo));
    if (bpf_prog_get_info_by_fd(prog_fd, &pinfo, &plen) == 0 && pinfo.run_cnt > 0) {
        printf("BENCHSTATS run_cnt=%llu run_time_ns=%llu avg_ns=%.1f\n",
               (unsigned long long)pinfo.run_cnt, (unsigned long long)pinfo.run_time_ns,
               (double)pinfo.run_time_ns / (double)pinfo.run_cnt);
    } else {
        printf("BENCHSTATS unavailable\n");
    }
    fflush(stdout);
    if (stats_fd >= 0) close(stats_fd);
    bpf_link__destroy(link);
    close(cgfd);
    bpf_object__close(obj);
    return 0;
}

// Build a full policy object with explicit priority/expiry, push it to a given
// map fd at a given key, return the update latency in us.
static long push_to(int fd, const void *key, unsigned posture, unsigned prio,
                    unsigned long long policy_id, unsigned long long expiry_ns) {
    struct syntriass_policy p;
    memset(&p, 0, sizeof(p));
    p.policy_id = policy_id;
    p.expiry_ns = expiry_ns;
    p.posture = posture;
    p.priority = prio;
    p.fallback_allowed = 1;
    p.audit_enabled = 1;
    long t = now_us();
    int rc = bpf_map_update_elem(fd, key, &p, BPF_ANY);
    long us = now_us() - t;
    if (rc) fprintf(stderr, "level push failed rc=%d\n", rc);
    return us;
}

// 127.0.0.1 network-order address, matching ctx->user_ip4 in the kernel.
#define LOOPBACK_BE 0x0100007fULL

// Apply a level spec ("L:posture:prio:exp" tokens, space/comma separated) to the
// four level maps; missing levels are cleared. Returns the max push latency (us)
// across applied entries — the userspace->kernel propagation cost (the change is
// live on the very next connect, since the kernel reads map state per packet).
static long apply_spec(int g_fd, int n_fd, int s_fd, unsigned long long probe_cgid,
                       unsigned long long flowkey, const char *spec) {
    // clear all four levels first
    struct syntriass_policy zero;
    memset(&zero, 0, sizeof(zero));
    unsigned int z = 0;
    bpf_map_update_elem(g_fd, &z, &zero, BPF_ANY);
    bpf_map_update_elem(n_fd, &z, &zero, BPF_ANY);
    bpf_map_delete_elem(g_pol_fd, &probe_cgid);
    bpf_map_delete_elem(s_fd, &flowkey);

    long maxus = 0;
    char buf[512];
    snprintf(buf, sizeof(buf), "%s", spec);
    for (char *tok = strtok(buf, " ,"); tok; tok = strtok(NULL, " ,")) {
        unsigned lvl, posture, prio, exp;
        if (sscanf(tok, "%u:%u:%u:%u", &lvl, &posture, &prio, &exp) != 4) continue;
        unsigned long long expiry = exp ? 1ULL : 0ULL; // 1ns => already expired
        unsigned long long pid = 0x10000ULL + lvl * 0x1000 + prio; // nonzero id
        long us = 0;
        switch (lvl) {
        case 0: us = push_to(g_fd, &z, posture, prio, pid, expiry); break;
        case 1: us = push_to(n_fd, &z, posture, prio, pid, expiry); break;
        case 2: us = push_to(g_pol_fd, &probe_cgid, posture, prio, pid, expiry); break;
        case 3: us = push_to(s_fd, &flowkey, posture, prio, pid, expiry); break;
        default: continue;
        }
        if (us > maxus) maxus = us;
    }
    return maxus;
}

// Hierarchical correctness run: apply a level spec, attach the hierarchical
// program, hold for run_ms (one connect from the script lands in this window),
// stream the decision.
//   hier <attach-cgroup> <probe-cgroup> <session-dport> <run_ms> <spec>
static int run_hier(int argc, char **argv) {
    if (argc < 7) { fprintf(stderr, "usage: hier <attach> <probe> <sport> <run_ms> <spec>\n"); return 1; }
    const char *cg = argv[2];
    unsigned long long probe_cgid = cgid_of(argv[3]);
    unsigned sport = (unsigned)atoi(argv[4]);
    int run_ms = atoi(argv[5]);
    const char *spec = argv[6];
    unsigned long long flowkey = (LOOPBACK_BE << 16) | sport;

    struct bpf_object *obj = bpf_object__open_file("policy_v2.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) { fprintf(stderr, "hier load fail\n"); return 2; }
    g_pol_fd = bpf_object__find_map_fd_by_name(obj, "policy_table");
    g_sess_fd = bpf_object__find_map_fd_by_name(obj, "session_state");
    int ev_fd = bpf_object__find_map_fd_by_name(obj, "events");
    int g_fd = bpf_object__find_map_fd_by_name(obj, "global_policy");
    int n_fd = bpf_object__find_map_fd_by_name(obj, "node_policy");
    int s_fd = bpf_object__find_map_fd_by_name(obj, "session_policy");

    struct bpf_program *p = bpf_object__find_program_by_name(obj, "syntriass_policy_hier");
    int cgfd = open(cg, O_RDONLY | O_DIRECTORY);
    if (cgfd < 0) { perror("open cgroup"); return 3; }
    struct bpf_link *link = bpf_program__attach_cgroup(p, cgfd);
    if (!link) { fprintf(stderr, "hier attach fail\n"); return 4; }
    struct ring_buffer *rb = ring_buffer__new(ev_fd, on_event, NULL, NULL);

    long propus = apply_spec(g_fd, n_fd, s_fd, probe_cgid, flowkey, spec);
    printf("HIER spec=[%s] prop_us=%ld sport=%u\n", spec, propus, sport);
    fflush(stdout);
    fprintf(stderr, "READY\n"); fflush(stderr);

    long start = now_ms();
    while (now_ms() < start + run_ms) ring_buffer__poll(rb, 50);

    ring_buffer__free(rb);
    bpf_link__destroy(link);
    close(cgfd);
    bpf_object__close(obj);
    return 0;
}

// Hierarchical resolution-latency bench: populate ALL FOUR levels (so every
// lookup executes), attach the lookup-only hierarchical program, hold while the
// script bursts connects, report the kernel run-time accounting.
//   hierbench <attach-cgroup> <probe-cgroup> <session-dport> <run_ms>
static int run_hierbench(int argc, char **argv) {
    if (argc < 6) { fprintf(stderr, "usage: hierbench <attach> <probe> <sport> <run_ms>\n"); return 1; }
    const char *cg = argv[2];
    unsigned long long probe_cgid = cgid_of(argv[3]);
    unsigned sport = (unsigned)atoi(argv[4]);
    int run_ms = atoi(argv[5]);
    unsigned long long flowkey = (LOOPBACK_BE << 16) | sport;

    struct bpf_object *obj = bpf_object__open_file("policy_v2.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) { fprintf(stderr, "hierbench load fail\n"); return 2; }
    g_pol_fd = bpf_object__find_map_fd_by_name(obj, "policy_table");
    int g_fd = bpf_object__find_map_fd_by_name(obj, "global_policy");
    int n_fd = bpf_object__find_map_fd_by_name(obj, "node_policy");
    int s_fd = bpf_object__find_map_fd_by_name(obj, "session_policy");
    struct bpf_program *p =
        bpf_object__find_program_by_name(obj, "syntriass_policy_hier_bench");
    int prog_fd = bpf_program__fd(p);
    int stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);
    int cgfd = open(cg, O_RDONLY | O_DIRECTORY);
    if (cgfd < 0) { perror("open cgroup"); return 3; }
    struct bpf_link *link = bpf_program__attach_cgroup(p, cgfd);
    if (!link) { fprintf(stderr, "hierbench attach fail\n"); return 4; }

    // All four levels populated; session is the highest-priority FullPqc winner
    // so the burst connects ALLOW and every lookup is exercised.
    apply_spec(g_fd, n_fd, s_fd, probe_cgid, flowkey,
               "0:0:10:0 1:0:20:0 2:2:30:0 3:0:200:0");
    fprintf(stderr, "READY\n"); fflush(stderr);

    long start = now_ms();
    while (now_ms() < start + run_ms) usleep(20000);

    struct bpf_prog_info pinfo;
    unsigned int plen = sizeof(pinfo);
    memset(&pinfo, 0, sizeof(pinfo));
    if (bpf_prog_get_info_by_fd(prog_fd, &pinfo, &plen) == 0 && pinfo.run_cnt > 0) {
        printf("HIERBENCHSTATS run_cnt=%llu run_time_ns=%llu avg_ns=%.1f\n",
               (unsigned long long)pinfo.run_cnt, (unsigned long long)pinfo.run_time_ns,
               (double)pinfo.run_time_ns / (double)pinfo.run_cnt);
    } else {
        printf("HIERBENCHSTATS unavailable\n");
    }
    fflush(stdout);
    if (stats_fd >= 0) close(stats_fd);
    bpf_link__destroy(link);
    close(cgfd);
    bpf_object__close(obj);
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "bench") == 0) return run_bench(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "hier") == 0) return run_hier(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "hierbench") == 0) return run_hierbench(argc, argv);
    if (argc < 5) {
        fprintf(stderr,
                "usage: %s <attach-cgroup> <run_ms> <schedule> <probe-cgroup> [expired-cgroup]\n",
                argv[0]);
        return 1;
    }
    const char *cg = argv[1];
    int run_ms = atoi(argv[2]);
    FILE *sched = fopen(argv[3], "r");
    unsigned long long probe_cgid = cgid_of(argv[4]);
    unsigned long long expired_cgid = (argc > 5) ? cgid_of(argv[5]) : 0;

    struct bpf_object *obj = bpf_object__open_file("policy_v2.bpf.o", NULL);
    if (!obj) { fprintf(stderr, "open fail\n"); return 2; }
    if (bpf_object__load(obj)) { fprintf(stderr, "load fail\n"); return 3; }
    g_pol_fd = bpf_object__find_map_fd_by_name(obj, "policy_table");
    g_sess_fd = bpf_object__find_map_fd_by_name(obj, "session_state");
    int ev_fd = bpf_object__find_map_fd_by_name(obj, "events");

    struct bpf_program *p = bpf_object__find_program_by_name(obj, "syntriass_policy_v2");
    int prog_fd = bpf_program__fd(p);
    int stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);
    if (stats_fd < 0) fprintf(stderr, "warn: bpf_enable_stats failed errno=%d\n", errno);

    int cgfd = open(cg, O_RDONLY | O_DIRECTORY);
    if (cgfd < 0) { perror("open cgroup"); return 4; }
    struct bpf_link *link = bpf_program__attach_cgroup(p, cgfd);
    if (!link) { fprintf(stderr, "attach fail\n"); return 5; }
    struct ring_buffer *rb = ring_buffer__new(ev_fd, on_event, NULL, NULL);

    printf("CGID probe=%llu expired=%llu\n", probe_cgid, expired_cgid);

    // ---- memory overhead: structured value size + table capacity ----
    struct bpf_map_info minfo;
    unsigned int ilen = sizeof(minfo);
    memset(&minfo, 0, sizeof(minfo));
    if (bpf_map_get_info_by_fd(g_pol_fd, &minfo, &ilen) == 0) {
        printf("MEM policy_value_bytes=%u key_bytes=%u capacity=%u table_value_bytes=%llu\n",
               minfo.value_size, minfo.key_size, minfo.max_entries,
               (unsigned long long)minfo.value_size * minfo.max_entries);
    }
    printf("STRUCT sizeof_policy=%zu\n", sizeof(struct syntriass_policy));

    // ---- distribute the initial structured policy objects ----
    long u0 = push_policy_ex(probe_cgid, MODE_FULL_PQC, 0xA0001, 0);
    printf("UPD cg=probe posture=%u us=%ld\n", MODE_FULL_PQC, u0);
    if (expired_cgid) {
        // expiry_ns=1 ns is always < bpf_ktime_get_ns() -> already expired.
        push_policy_ex(expired_cgid, MODE_FULL_PQC, 0xC0001, 1);
        printf("UPD cg=expired posture=%u expiry=past\n", MODE_FULL_PQC);
    }
    fflush(stdout);

    fprintf(stderr, "READY\n"); fflush(stderr);

    // Parse schedule "<at_ms> <posture>".
    long at[64]; unsigned int md[64]; int n = 0;
    if (sched) {
        while (n < 64 && fscanf(sched, "%ld %u", &at[n], &md[n]) == 2) n++;
        fclose(sched);
    }

    long start = now_ms(), deadline = start + run_ms;
    int next = 0;
    long upd_sum = u0, upd_cnt = 1, upd_max = u0;
    while (now_ms() < deadline) {
        long el = now_ms() - start;
        while (next < n && el >= at[next]) {
            long us = push_policy_ex(probe_cgid, md[next], 0xA0001, 0);
            printf("UPD cg=probe posture=%u us=%ld\n", md[next], us);
            fflush(stdout);
            upd_sum += us; upd_cnt++;
            if (us > upd_max) upd_max = us;
            next++;
        }
        ring_buffer__poll(rb, 50);
    }

    // ---- session_state count (kernel -> userspace distribution) ----
    unsigned long long key = 0, nkey; unsigned long sessions = 0;
    int more = (bpf_map_get_next_key(g_sess_fd, NULL, &key) == 0);
    while (more) {
        sessions++;
        more = (bpf_map_get_next_key(g_sess_fd, &key, &nkey) == 0);
        key = nkey;
    }
    printf("SESS %lu\n", sessions);
    printf("UPDSTATS count=%ld avg_us=%.2f max_us=%ld\n", upd_cnt,
           (double)upd_sum / (double)upd_cnt, upd_max);

    // ---- kernel-measured average program run time (policy lookup + decision) ----
    struct bpf_prog_info pinfo;
    unsigned int plen = sizeof(pinfo);
    memset(&pinfo, 0, sizeof(pinfo));
    if (bpf_prog_get_info_by_fd(prog_fd, &pinfo, &plen) == 0 && pinfo.run_cnt > 0) {
        printf("RUNSTATS run_cnt=%llu run_time_ns=%llu avg_ns=%.1f\n",
               (unsigned long long)pinfo.run_cnt, (unsigned long long)pinfo.run_time_ns,
               (double)pinfo.run_time_ns / (double)pinfo.run_cnt);
    } else {
        printf("RUNSTATS unavailable (BPF_STATS_RUN_TIME not active)\n");
    }
    fflush(stdout);

    if (stats_fd >= 0) close(stats_fd);
    ring_buffer__free(rb);
    bpf_link__destroy(link);
    close(cgfd);
    bpf_object__close(obj);
    return 0;
}
