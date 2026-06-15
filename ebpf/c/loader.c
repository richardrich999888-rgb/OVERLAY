// SPDX-License-Identifier: GPL-2.0
//
// libbpf loader for the Syntriass universal-interception data plane.
//
// Loads `connect4.bpf.o`, attaches it to a cgroup v2 directory, and streams the
// per-connection events out of the ring buffer. Optionally programs the
// enforcement policy (a blocked destination port). This is the reference loader
// used by `scripts/ebpf_coverage_validate.sh`; a production deployment would use
// the same libbpf calls (or the Aya/Rust equivalent in `ebpf/src/`).
//
//   ./loader <cgroup-dir> [run_ms] [block_port]
//
// Prints "READY" to stderr once attached; one "EVT ..." line per connection to
// stdout; a final "SUMMARY events=<n>" line.

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct conn_event {
    unsigned int pid;
    unsigned int uid;
    unsigned int daddr;
    unsigned short dport;
    unsigned short action;
    char comm[16];
};

static unsigned long g_count = 0;

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static int on_event(void *ctx, void *data, size_t sz) {
    (void)ctx;
    if (sz < sizeof(struct conn_event))
        return 0;
    struct conn_event *e = data;
    char ip[INET_ADDRSTRLEN];
    struct in_addr a = {.s_addr = e->daddr};
    inet_ntop(AF_INET, &a, ip, sizeof(ip));
    printf("EVT comm=%s pid=%u uid=%u dst=%s:%u action=%s\n", e->comm, e->pid,
           e->uid, ip, e->dport, e->action ? "DENY" : "ALLOW");
    fflush(stdout);
    g_count++;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <cgroup-dir> [run_ms] [block_port]\n", argv[0]);
        return 1;
    }
    const char *cgroup = argv[1];
    int run_ms = argc > 2 ? atoi(argv[2]) : 4000;
    unsigned short block_port = argc > 3 ? (unsigned short)atoi(argv[3]) : 0;

    struct bpf_object *obj = bpf_object__open_file("connect4.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "open_file failed\n");
        return 2;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "load failed (verifier rejected or missing privilege)\n");
        return 3;
    }

    // Program the enforcement policy before attaching.
    int cfg_fd = bpf_object__find_map_fd_by_name(obj, "config");
    if (cfg_fd >= 0) {
        unsigned int k = 0;
        bpf_map_update_elem(cfg_fd, &k, &block_port, BPF_ANY);
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "syntriass_connect4");
    int cgfd = open(cgroup, O_RDONLY | O_DIRECTORY);
    if (cgfd < 0) {
        perror("open cgroup");
        return 4;
    }
    struct bpf_link *link = bpf_program__attach_cgroup(prog, cgfd);
    if (!link) {
        fprintf(stderr, "attach_cgroup failed\n");
        return 5;
    }

    int mfd = bpf_object__find_map_fd_by_name(obj, "events");
    struct ring_buffer *rb = ring_buffer__new(mfd, on_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "ring_buffer__new failed\n");
        return 6;
    }

    fprintf(stderr, "READY block_port=%u\n", block_port);
    fflush(stderr);

    long deadline = now_ms() + run_ms;
    while (now_ms() < deadline)
        ring_buffer__poll(rb, 100);

    printf("SUMMARY events=%lu\n", g_count);
    fflush(stdout);

    ring_buffer__free(rb);
    bpf_link__destroy(link);
    close(cgfd);
    bpf_object__close(obj);
    return 0;
}
