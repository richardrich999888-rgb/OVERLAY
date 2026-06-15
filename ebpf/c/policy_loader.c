// SPDX-License-Identifier: GPL-2.0
//
// Loader + userspace<->kernel synchroniser for the Syntriass policy/state layer.
//
//   policy_loader <cgroup-dir> <run_ms> <mode_script>
//
// Loads policy.bpf.o, attaches to the cgroup, pins the maps' fds, then:
//   - reads newline mode commands from <mode_script> on a schedule encoded as
//     "<at_ms> <mode>" lines (e.g. "0 0", "500 2"), pushing the operation_mode
//     map and timing each update (posture distribution + map-update latency);
//   - streams decision events from the ring buffer;
//   - dumps the session_state map at exit (kernel->userspace distribution).
//
// Prints "READY", one "EVT ..." per decision, "UPD mode=<m> us=<latency>" per
// posture push, and "SESS <n>" with the live session count at the end.

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct policy_event {
    unsigned int pid, daddr;
    unsigned short dport, mode, decision, _pad;
};

static int g_mode_fd = -1, g_sess_fd = -1;

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static long now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000 + t.tv_nsec / 1000;
}

static int on_event(void *c, void *data, size_t sz) {
    (void)c;
    if (sz < sizeof(struct policy_event)) return 0;
    struct policy_event *e = data;
    char ip[INET_ADDRSTRLEN];
    struct in_addr a = {.s_addr = e->daddr};
    inet_ntop(AF_INET, &a, ip, sizeof(ip));
    printf("EVT pid=%u dst=%s:%u mode=%u decision=%s\n", e->pid, ip, e->dport, e->mode,
           e->decision ? "DENY" : "ALLOW");
    fflush(stdout);
    return 0;
}

static void set_mode(unsigned int mode) {
    unsigned int k = 0;
    long t = now_us();
    bpf_map_update_elem(g_mode_fd, &k, &mode, BPF_ANY);
    long us = now_us() - t;
    printf("UPD mode=%u us=%ld\n", mode, us);
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <cgroup> <run_ms> <schedule-file>\n", argv[0]);
        return 1;
    }
    const char *cg = argv[1];
    int run_ms = atoi(argv[2]);
    FILE *sched = fopen(argv[3], "r");

    struct bpf_object *obj = bpf_object__open_file("policy.bpf.o", NULL);
    if (!obj) { fprintf(stderr, "open fail\n"); return 2; }
    if (bpf_object__load(obj)) { fprintf(stderr, "load fail\n"); return 3; }
    g_mode_fd = bpf_object__find_map_fd_by_name(obj, "operation_mode");
    g_sess_fd = bpf_object__find_map_fd_by_name(obj, "session_state");
    int ev_fd = bpf_object__find_map_fd_by_name(obj, "events");

    struct bpf_program *p = bpf_object__find_program_by_name(obj, "syntriass_policy");
    int cgfd = open(cg, O_RDONLY | O_DIRECTORY);
    if (cgfd < 0) { perror("open cgroup"); return 4; }
    struct bpf_link *link = bpf_program__attach_cgroup(p, cgfd);
    if (!link) { fprintf(stderr, "attach fail\n"); return 5; }
    struct ring_buffer *rb = ring_buffer__new(ev_fd, on_event, NULL, NULL);

    // Default posture before any schedule: FullPqc (0).
    set_mode(0);
    fprintf(stderr, "READY\n"); fflush(stderr);

    // Parse schedule entries "<at_ms> <mode>".
    long at[64]; unsigned int md[64]; int n = 0;
    if (sched) {
        while (n < 64 && fscanf(sched, "%ld %u", &at[n], &md[n]) == 2) n++;
        fclose(sched);
    }

    long start = now_ms(), deadline = start + run_ms;
    int next = 0;
    while (now_ms() < deadline) {
        long el = now_ms() - start;
        while (next < n && el >= at[next]) { set_mode(md[next]); next++; }
        ring_buffer__poll(rb, 50);
    }

    // Dump the live session_state count (kernel -> userspace distribution).
    unsigned long long key = 0, nkey; unsigned long sessions = 0;
    int more = (bpf_map_get_next_key(g_sess_fd, NULL, &key) == 0);
    while (more) {
        sessions++;
        more = (bpf_map_get_next_key(g_sess_fd, &key, &nkey) == 0);
        key = nkey;
    }
    printf("SESS %lu\n", sessions);
    fflush(stdout);

    ring_buffer__free(rb);
    bpf_link__destroy(link);
    close(cgfd);
    bpf_object__close(obj);
    return 0;
}
