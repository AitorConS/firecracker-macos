// SPDX-License-Identifier: Apache-2.0
// dns-recovery regression. Real libslirp (with the production interception
// macros), the real socket gate and its forked authority process, real Unix
// proxy channels and real loopback UDP services. One scenario per process,
// because a failed gate is a terminal state by design.
//
// Contract under test:
//  * ephemeral mapping: a dead channel is detached after MAX_FAULTS reads and
//    the guest re-creates it with its next datagram; the gate stays healthy.
//  * persistent forwarding listener (SS_HOSTFWD, so_expire == 0): a dead
//    channel is replaced in place, keeping the libslirp socket, and later
//    clients work; if that is impossible, repeated, or over budget, the gate
//    fails explicitly (hvf_gate_check != 0). Never a silent disappearance,
//    never a busy loop, never an unbounded wait.
#ifndef GATE_SOURCE
#define GATE_SOURCE "socket_gate.c"
#endif
#include "slirp.h"
#include GATE_SOURCE
#include <libproc.h>
#include <sys/proc_info.h>
#include <signal.h>
#include <stdio.h>
#ifndef MAX_RECOVERIES
#define MAX_RECOVERIES 8 /* control build: the constant only exists when patched */
#define RECOVERY_COUNT(fd) 0U
#else
#define RECOVERY_COUNT(fd) ((unsigned)client_recoveries[fd])
#endif

static void report_injected(void);
#define CHECK(c, ...) do { if (!(c)) { printf("FAIL %s:%d: ", __func__, __LINE__); printf(__VA_ARGS__); printf("\n"); fflush(stdout); exit(1); } } while (0)
#define GUEST_PORT 9001

static Slirp *vm;
static const uint8_t guest_mac[6] = {2, 1, 2, 3, 4, 5};
static uint16_t listen_port, echo_port, dns_port, deny_port;
static int echo_fd = -1, dns_fd = -1, deny_fd = -1;
static struct hvf_endpoint listener_rules[1], egress_rules[1];
static struct hvf_security policy_rules;

/* ---- guest side: frames emitted by libslirp ---- */
struct frame { uint32_t src, dst; uint16_t sport, dport, len; uint8_t data[1400]; };
static struct frame frames[8192];
static unsigned nframes, icmp_frames, dropped_frames;
static ssize_t output(const void *buf, size_t len, void *opaque)
{
    (void)opaque; const uint8_t *p = buf;
    if (len >= 34 && p[12] == 8 && p[13] == 0) {
        unsigned ihl = (p[14] & 15) * 4; uint8_t proto = p[23];
        if (proto == 1) icmp_frames++;
        if (proto == 17 && len >= 14 + ihl + 8) {
            if (nframes == sizeof(frames) / sizeof(frames[0])) { dropped_frames++; return len; }
            struct frame *f = &frames[nframes++]; const uint8_t *u = p + 14 + ihl;
            memcpy(&f->src, p + 26, 4); memcpy(&f->dst, p + 30, 4);
            f->sport = (uint16_t)(u[0] << 8 | u[1]); f->dport = (uint16_t)(u[2] << 8 | u[3]);
            unsigned ul = (unsigned)(u[4] << 8 | u[5]); f->len = (uint16_t)(ul >= 8 ? ul - 8 : 0);
            if (f->len > sizeof(f->data) || 14 + ihl + 8 + f->len > len) { f->len = 0; dropped_frames++; }
            memcpy(f->data, u + 8, f->len);
        }
    }
    return (ssize_t)len;
}
static int64_t clock_ns(void *o) { (void)o; struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (int64_t)t.tv_sec * 1000000000 + t.tv_nsec; }
static double seconds(void) { return (double)clock_ns(NULL) / 1e9; }
static void notify(void *o) { (void)o; }
static void socket_noop(slirp_os_socket fd, void *o) { (void)fd; (void)o; }

/* ---- host side services ---- */
struct dns_held { struct sockaddr_in peer; uint8_t packet[512]; ssize_t n; };
static struct dns_held dns_held[512];
static unsigned nheld, hold_every, dns_answered, echo_answered, denied_received;
static void services(void)
{
    uint8_t b[2048]; struct sockaddr_in peer; socklen_t pl;
    for (;;) { pl = sizeof(peer); ssize_t n = recvfrom(echo_fd, b, sizeof(b), MSG_DONTWAIT, (void *)&peer, &pl); if (n < 0) break;
        (void)sendto(echo_fd, b, (size_t)n, 0, (void *)&peer, pl); echo_answered++; }
    for (;;) { pl = sizeof(peer); ssize_t n = recvfrom(dns_fd, b, sizeof(b), MSG_DONTWAIT, (void *)&peer, &pl); if (n < 12) break;
        unsigned id = (unsigned)(b[0] << 8 | b[1]);
        if (hold_every && id % hold_every == 0 && nheld < 512 && n <= 508) { dns_held[nheld].peer = peer; memcpy(dns_held[nheld].packet, b, (size_t)n); dns_held[nheld].n = n; nheld++; continue; }
        b[2] = 0x81; b[3] = 0x80; memcpy(b + n, "ANS!", 4);
        (void)sendto(dns_fd, b, (size_t)n + 4, 0, (void *)&peer, pl); dns_answered++; }
    for (;;) { if (recv(deny_fd, b, sizeof(b), MSG_DONTWAIT) < 0) break; denied_received++; }
}
static void release_held(void)
{
    for (unsigned i = 0; i < nheld; i++) {
        uint8_t *b = dns_held[i].packet; b[2] = 0x81; b[3] = 0x80; memcpy(b + dns_held[i].n, "ANS!", 4);
        (void)sendto(dns_fd, b, (size_t)dns_held[i].n + 4, 0, (void *)&dns_held[i].peer, sizeof(dns_held[i].peer)); dns_answered++;
    }
    nheld = 0;
}

/* ---- the broker's poll loop, reduced ---- */
static struct pollfd pfd[4096];
static unsigned npfd;
static int add_poll(slirp_os_socket fd, int ev, void *o)
{
    (void)o; short e = 0; if (ev & SLIRP_POLL_IN) e |= POLLIN; if (ev & SLIRP_POLL_OUT) e |= POLLOUT; if (ev & SLIRP_POLL_PRI) e |= POLLPRI;
    CHECK(npfd < 4096, "poll table"); pfd[npfd] = (struct pollfd){fd, e, 0}; return (int)npfd++;
}
static int get_revents(int i, void *o)
{
    (void)o; short r = pfd[i].revents;
    return ((r & POLLIN) ? SLIRP_POLL_IN : 0) | ((r & POLLOUT) ? SLIRP_POLL_OUT : 0) | ((r & POLLPRI) ? SLIRP_POLL_PRI : 0) | ((r & POLLERR) ? SLIRP_POLL_ERR : 0) | ((r & POLLHUP) ? SLIRP_POLL_HUP : 0);
}
static unsigned wakeups_on(int fd)
{
    unsigned hits = 0; for (unsigned i = 0; i < npfd; i++) if (pfd[i].fd == fd && (pfd[i].revents & (POLLIN | POLLHUP | POLLERR))) hits++;
    return hits;
}
static void spin(int timeout_ms)
{
    npfd = 0; uint32_t t = (uint32_t)timeout_ms; slirp_pollfds_fill_socket(vm, &t, add_poll, NULL);
    int n = poll(pfd, npfd, timeout_ms); slirp_pollfds_poll(vm, n < 0, get_revents, NULL);
    services();
}

/* ---- helpers ---- */
static struct socket *find_listener(void)
{
    for (struct socket *so = vm->udb.so_next; so != &vm->udb; so = so->so_next) if (so->so_state & SS_HOSTFWD) return so;
    return NULL;
}
static struct socket *find_mapping(uint16_t guest_port)
{
    for (struct socket *so = vm->udb.so_next; so != &vm->udb; so = so->so_next)
        if (!(so->so_state & SS_HOSTFWD) && so->so_lport == htons(guest_port)) return so;
    return NULL;
}
static unsigned udb_count(void) { unsigned n = 0; for (struct socket *so = vm->udb.so_next; so != &vm->udb; so = so->so_next) n++; return n; }
static int open_fds(void) { int n = 0; for (int fd = 0; fd < MAX_FD; fd++) if (fcntl(fd, F_GETFD) >= 0) n++; return n; }
static int authority_fds(void)
{
    int size = proc_pidinfo(authority_pid, PROC_PIDLISTFDS, 0, NULL, 0); if (size <= 0) return -1;
    struct proc_fdinfo *b = malloc((size_t)size); CHECK(b, "malloc");
    size = proc_pidinfo(authority_pid, PROC_PIDLISTFDS, 0, b, size); free(b);
    return size < 0 ? -1 : size / (int)PROC_PIDLISTFD_SIZE;
}
static struct sockaddr_in loopback(uint16_t port) { struct sockaddr_in a = {.sin_len = sizeof(a), .sin_family = AF_INET, .sin_port = htons(port)}; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); return a; }
static int bound_udp(uint16_t *port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0); CHECK(fd >= 0, "socket"); struct sockaddr_in a = loopback(0);
    CHECK(!bind(fd, (void *)&a, sizeof(a)), "bind"); socklen_t l = sizeof(a); CHECK(!getsockname(fd, (void *)&a, &l), "getsockname");
    *port = ntohs(a.sin_port); nonblock(fd); return fd;
}
static void fill(uint8_t *d, size_t n, unsigned tag) { for (size_t k = 0; k < n; k++) d[k] = (uint8_t)((tag * 131 + k * 29 + (k >> 8)) & 0xff); }
static int frame_since(unsigned start, uint16_t sport, uint16_t dport, const uint8_t *d, size_t n)
{
    for (unsigned i = start; i < nframes; i++)
        if (frames[i].sport == sport && frames[i].dport == dport && frames[i].len == n && !memcmp(frames[i].data, d, n)) return 1;
    return 0;
}
static uint16_t ip_checksum(const uint8_t *h, size_t n)
{
    uint32_t s = 0; for (size_t i = 0; i + 1 < n; i += 2) s += (uint32_t)(h[i] << 8 | h[i + 1]);
    while (s >> 16) s = (s & 0xffff) + (s >> 16); return (uint16_t)~s;
}
static void guest_udp(uint16_t sport, const char *dst, uint16_t dport, const uint8_t *d, size_t n)
{
    static uint16_t ident; uint8_t f[1600] = {0x52, 0x55, 10, 0, 2, 2};
    CHECK(n <= 1400, "payload"); memcpy(f + 6, guest_mac, 6); f[12] = 8;
    uint8_t *ip = f + 14; size_t total = 20 + 8 + n;
    ip[0] = 0x45; ip[2] = (uint8_t)(total >> 8); ip[3] = (uint8_t)total; ip[4] = (uint8_t)(++ident >> 8); ip[5] = (uint8_t)ident; ip[8] = 64; ip[9] = 17;
    inet_pton(AF_INET, "10.0.2.15", ip + 12); inet_pton(AF_INET, dst, ip + 16);
    uint16_t c = ip_checksum(ip, 20); ip[10] = (uint8_t)(c >> 8); ip[11] = (uint8_t)c;
    uint8_t *u = ip + 20; u[0] = (uint8_t)(sport >> 8); u[1] = (uint8_t)sport; u[2] = (uint8_t)(dport >> 8); u[3] = (uint8_t)dport;
    u[4] = (uint8_t)((8 + n) >> 8); u[5] = (uint8_t)(8 + n); memcpy(u + 8, d, n);
    slirp_input(vm, f, (int)(14 + total));
}
/* Host client -> forwarding listener -> guest, then guest -> same client. Both
 * directions compared byte by byte; returns 1 only if both arrive in time. */
static int roundtrip(int client, unsigned tag, size_t n)
{
    uint8_t d[1400], r[1400], got[1600]; fill(d, n, tag); for (size_t k = 0; k < n; k++) r[k] = d[k] ^ 0x5a;
    struct sockaddr_in me; socklen_t ml = sizeof(me); CHECK(!getsockname(client, (void *)&me, &ml), "client name");
    struct sockaddr_in to = loopback(listen_port); unsigned start = nframes;
    if (sendto(client, d, n, 0, (void *)&to, sizeof(to)) != (ssize_t)n) return 0;
    double deadline = seconds() + 2; int seen = 0;
    while (!(seen = frame_since(start, ntohs(me.sin_port), GUEST_PORT, d, n)) && seconds() < deadline) spin(2);
    if (!seen) return 0;
    guest_udp(GUEST_PORT, "10.0.2.2", ntohs(me.sin_port), r, n);
    deadline = seconds() + 2;
    while (seconds() < deadline) {
        spin(2); struct sockaddr_in from; socklen_t fl = sizeof(from);
        ssize_t k = recvfrom(client, got, sizeof(got), MSG_DONTWAIT, (void *)&from, &fl);
        if (k == (ssize_t)n && !memcmp(got, r, n) && from.sin_port == htons(listen_port)) return 1;
    }
    return 0;
}
static int new_client(void) { uint16_t ignored; return bound_udp(&ignored); }

static void setup(void)
{
    signal(SIGPIPE, SIG_IGN); setvbuf(stdout, NULL, _IOLBF, 0); atexit(report_injected);
    echo_fd = bound_udp(&echo_port); dns_fd = bound_udp(&dns_port); deny_fd = bound_udp(&deny_port);
    { int probe = bound_udp(&listen_port); close(probe); }
    uint8_t lo[4] = {127, 0, 0, 1};
    listener_rules[0] = (struct hvf_endpoint){.udp = 1, .port = listen_port}; memcpy(listener_rules[0].address, lo, 4);
    egress_rules[0] = (struct hvf_endpoint){.udp = 1, .port = echo_port}; memcpy(egress_rules[0].address, lo, 4);
    policy_rules = (struct hvf_security){.egress_count = 1, .listener_count = 1, .dns_port = dns_port, .egress = egress_rules, .listeners = listener_rules};
    memcpy(policy_rules.dns_address, lo, 4);
    hvf_policy_set(&policy_rules);
    CHECK(!hvf_gate_start(), "authority start errno=%d", errno);
    SlirpConfig cfg = {.version = 6, .in_enabled = true, .if_mtu = 1500, .if_mru = 1500};
    inet_pton(AF_INET, "10.0.2.0", &cfg.vnetwork); inet_pton(AF_INET, "255.255.255.0", &cfg.vnetmask);
    inet_pton(AF_INET, "10.0.2.2", &cfg.vhost); inet_pton(AF_INET, "10.0.2.15", &cfg.vdhcp_start); inet_pton(AF_INET, "10.0.2.3", &cfg.vnameserver);
    static const SlirpCb cb = {.send_packet = output, .clock_get_ns = clock_ns, .notify = notify, .register_poll_socket = socket_noop, .unregister_poll_socket = socket_noop};
    vm = slirp_new(&cfg, &cb, NULL); CHECK(vm, "slirp_new");
    struct in_addr guest; inet_pton(AF_INET, "10.0.2.15", &guest); arp_table_add(vm, guest.s_addr, guest_mac);
    struct in_addr host; inet_pton(AF_INET, "127.0.0.1", &host);
    CHECK(!slirp_add_hostfwd(vm, 1, host, listen_port, guest, GUEST_PORT), "hostfwd errno=%d", errno);
    struct socket *so = find_listener(); CHECK(so && so->so_expire == 0 && hvf_gate_is_udp(so->s), "listener shape");
    /* libslirp's curtime only advances in its poll; the broker polls before any
     * guest frame, so do the same or the first mapping gets a stale expiry. */
    spin(0);
}
/* Break a proxy channel the way the field reports show it: a receive half that
 * stays readable and yields zero bytes forever. Returns the poll iterations
 * until `done` holds, bounded so a regression cannot hang the test. */
static unsigned injected_breaks;
static void report_injected(void) { printf("INJECTED breaks=%u\n", injected_breaks); }
static unsigned break_until(int fd, int (*done)(void *), void *arg, unsigned bound)
{
    CHECK(!shutdown(fd, SHUT_RD), "shutdown errno=%d", errno); injected_breaks++;
    unsigned iterations = 0;
    while (!done(arg) && iterations < bound) { spin(0); iterations++; }
    return iterations;
}
struct watch { struct socket *so; int fd; uint32_t token; };
static int listener_changed(void *p)
{
    struct watch *w = p; return find_listener() != w->so || client_tokens[w->fd] != w->token || hvf_gate_check() != 0;
}
static int recovered_state(struct watch *w)
{
    return find_listener() == w->so && w->so->s == w->fd && client_tokens[w->fd] && client_tokens[w->fd] != w->token && hvf_gate_check() == 0;
}
static unsigned idle_wakeups(int fd, unsigned rounds) { unsigned hits = 0; for (unsigned i = 0; i < rounds; i++) { spin(2); hits += wakeups_on(fd); } return hits; }

/* ---- scenarios ---- */
static int scenario_isolated(void)
{
    struct socket *so = find_listener(); int fd = so->s; uint32_t token = client_tokens[fd];
    int c = new_client(); CHECK(roundtrip(c, 1, 64), "baseline roundtrip");
    int saved = dup(fd); int inj[2]; CHECK(!socketpair(AF_UNIX, SOCK_DGRAM, 0, inj), "socketpair");
    CHECK(dup2(inj[0], fd) == fd, "interpose"); close(inj[0]); nonblock(fd);
    struct datagram good = {.magic = UDP_MAGIC, .address = loopback(40000)}; unsigned delivered = 0;
    for (unsigned round = 0; round < 8; round++) {
        for (unsigned i = 0; i + 1 < MAX_FAULTS; i++) {
            struct datagram bad = good;
            switch ((round + i) % 4) {
            case 0: CHECK(send(inj[1], "", 0, 0) == 0, "empty"); break;
            case 1: CHECK(send(inj[1], "short", 5, 0) == 5, "short"); break;
            case 2: bad.magic = 0; CHECK(send(inj[1], &bad, sizeof(bad), 0) == sizeof(bad), "magic"); break;
            default: bad.address.sin_family = AF_UNIX; CHECK(send(inj[1], &bad, sizeof(bad), 0) == sizeof(bad), "family"); break;
            }
            spin(0);
        }
        struct pollfd p = {fd, POLLIN, 0}; CHECK(poll(&p, 1, 0) == 0, "fault datagrams not consumed");
        uint8_t wire[sizeof(good) + 32]; uint8_t payload[32]; fill(payload, sizeof(payload), 100 + round);
        memcpy(wire, &good, sizeof(good)); memcpy(wire + sizeof(good), payload, sizeof(payload));
        unsigned start = nframes; CHECK(send(inj[1], wire, sizeof(wire), 0) == (ssize_t)sizeof(wire), "valid");
        spin(0);
        CHECK(frame_since(start, 40000, GUEST_PORT, payload, sizeof(payload)), "valid envelope after 15 faults not delivered (round %u)", round);
        delivered++;
        CHECK(find_listener() == so && client_tokens[fd] == token && client_faults[fd] == 0 && hvf_gate_check() == 0, "isolated faults changed state");
    }
    CHECK(dup2(saved, fd) == fd, "restore"); close(saved); close(inj[1]);
    CHECK(roundtrip(c, 2, 512), "roundtrip after restoring real channel");
    CHECK(icmp_frames == 0, "icmp=%u", icmp_frames);
    printf("RESULT scenario=isolated rounds=8 faults_per_round=%d valid_after=%u icmp=%u token_unchanged=1 gate_check=%d\n", MAX_FAULTS - 1, delivered, icmp_frames, hvf_gate_check());
    return 0;
}
static int scenario_recover(void)
{
    struct socket *so = find_listener(); int fd = so->s;
    int early = new_client(); CHECK(roundtrip(early, 1, 64) && roundtrip(early, 2, 1024), "baseline roundtrip");
    int fds = open_fds(), auth = authority_fds(); unsigned udb = udb_count();
    struct watch w = {so, fd, client_tokens[fd]}; double t0 = seconds();
    unsigned iterations = break_until(fd, listener_changed, &w, MAX_FAULTS * 8);
    double took = seconds() - t0;
    printf("OBSERVED listener_present=%d gate_check=%d token_before=%u token_after=%u iterations=%u\n", find_listener() == so, hvf_gate_check(), w.token, client_tokens[fd], iterations);
    CHECK(find_listener() == so, "forwarding listener disappeared after %u reads (gate_check=%d)", iterations, hvf_gate_check());
    CHECK(recovered_state(&w), "listener not recovered in place");
    CHECK(iterations <= MAX_FAULTS, "recovery took %u reads", iterations);
    CHECK(so->so_expire == 0 && (so->so_state & SS_HOSTFWD) && udb_count() == udb, "listener shape changed");
    unsigned idle = idle_wakeups(fd, 50);
    CHECK(idle == 0, "busy loop: %u wakeups on idle recovered listener", idle);
    unsigned ok = 0, total = 0; size_t sizes[] = {1, 64, 512, 1024};
    ok += roundtrip(early, 10, 128); total++;
    for (unsigned c = 0; c < 8; c++) { int client = new_client(); for (unsigned s = 0; s < 4; s++) { ok += roundtrip(client, 20 + c * 4 + s, sizes[s]); total++; } close(client); }
    CHECK(ok == total, "later clients %u/%u", ok, total);
    unsigned deny_before = denied_received; uint8_t x[16]; fill(x, sizeof(x), 7); guest_udp(GUEST_PORT, "10.0.2.2", deny_port, x, sizeof(x));
    for (unsigned i = 0; i < 100; i++) spin(2);
    CHECK(denied_received == deny_before, "unauthorized destination reached after recovery");
    CHECK(open_fds() == fds && authority_fds() == auth, "descriptor leak client %d->%d authority %d->%d", fds, open_fds(), auth, authority_fds());
    CHECK(icmp_frames == 0 && dropped_frames == 0, "icmp=%u dropped=%u", icmp_frames, dropped_frames);
    printf("RESULT scenario=recover reads_to_recover=%u recover_seconds=%.4f idle_wakeups=%u later_roundtrips=%u/%u unauthorized_delivered=0 client_fds=%d authority_fds=%d icmp=%u recoveries=%u\n",
           iterations, took, idle, ok, total, fds, auth, icmp_frames, RECOVERY_COUNT(fd));
    close(early); return 0;
}
static int gone_or_failed(void *p) { struct watch *w = p; return find_listener() != w->so || hvf_gate_check() != 0; }
/* The replacement fails again before it carries a single datagram: that is the
 * same transient that broke the original (the replacement also travels by
 * SCM_RIGHTS), so it is recovered again within the consecutive budget, and the
 * listener then serves later clients. */
static int scenario_repeat(void)
{
    struct socket *so = find_listener(); int fd = so->s; int c = new_client(); CHECK(roundtrip(c, 1, 64), "baseline");
    struct watch w = {so, fd, client_tokens[fd]}; double t0 = seconds();
    unsigned first = break_until(fd, listener_changed, &w, MAX_FAULTS * 8);
    printf("OBSERVED after_first listener_present=%d gate_check=%d token_changed=%d reads=%u\n", find_listener() == so, hvf_gate_check(), client_tokens[fd] != w.token, first);
    CHECK(find_listener() == so, "listener disappeared after first failure (gate_check=%d)", hvf_gate_check());
    CHECK(recovered_state(&w), "first failure not recovered");
    struct watch w2 = {so, fd, client_tokens[fd]};
    unsigned second = break_until(fd, listener_changed, &w2, MAX_FAULTS * 8);
    double took = seconds() - t0;
    printf("OBSERVED after_second listener_present=%d gate_check=%d reads=%u\n", find_listener() == so, hvf_gate_check(), second);
    CHECK(second <= MAX_FAULTS && took < 5, "second failure took %u reads %.2fs", second, took);
    CHECK(recovered_state(&w2), "failure during recovery not recovered within budget (present=%d gate=%d)", find_listener() == so, hvf_gate_check());
    unsigned idle = idle_wakeups(fd, 50); CHECK(idle == 0, "busy loop: %u idle wakeups", idle);
    int later = new_client(); unsigned ok = roundtrip(later, 2, 512) + roundtrip(c, 3, 64);
    CHECK(ok == 2, "clients after repeated recovery %u/2", ok);
    printf("RESULT scenario=repeat first_reads=%u second_reads=%u later_roundtrips=%u/2 idle_wakeups=%u gate_check=%d seconds=%.4f icmp=%u\n", first, second, ok, idle, hvf_gate_check(), took, icmp_frames);
    return 0;
}
/* A permanent fault: every replacement dies before carrying a datagram. After
 * MAX_RECOVERIES consecutive replacements the gate fails explicitly. */
static int scenario_budget(void)
{
    struct socket *so = find_listener(); int fd = so->s; int c = new_client(); CHECK(roundtrip(c, 1, 64), "baseline");
    unsigned recoveries = 0, total_reads = 0; double t0 = seconds();
    for (unsigned k = 0; k <= MAX_RECOVERIES; k++) {
        struct watch w = {so, fd, client_tokens[fd]};
        unsigned reads = break_until(fd, listener_changed, &w, MAX_FAULTS * 8); total_reads += reads;
        CHECK(reads <= MAX_FAULTS, "break %u took %u reads", k, reads);
        if (hvf_gate_check() != 0) { CHECK(k == MAX_RECOVERIES, "failed after only %u consecutive recoveries", recoveries); break; }
        CHECK(find_listener() == so, "listener disappeared silently at break %u (gate_check=0)", k);
        CHECK(recovered_state(&w), "break %u not recovered", k); recoveries++;
    }
    double took = seconds() - t0;
    CHECK(recoveries == MAX_RECOVERIES && hvf_gate_check() != 0 && find_listener() == NULL, "budget: recoveries=%u gate=%d", recoveries, hvf_gate_check());
    CHECK(took < 5, "took %.2fs", took);
    printf("RESULT scenario=budget consecutive_recoveries=%u total_reads=%u final_gate_check=%d listener_present=0 seconds=%.4f icmp=%u\n", recoveries, total_reads, hvf_gate_check(), took, icmp_frames);
    return 0;
}
/* Isolated breaks separated by real traffic never exhaust the budget. */
static int scenario_alternating(void)
{
    struct socket *so = find_listener(); int fd = so->s; int c = new_client(); CHECK(roundtrip(c, 1, 64), "baseline");
    unsigned cycles = 2 * MAX_RECOVERIES + 2, ok = 0; double t0 = seconds();
    for (unsigned k = 0; k < cycles; k++) {
        struct watch w = {so, fd, client_tokens[fd]};
        unsigned reads = break_until(fd, listener_changed, &w, MAX_FAULTS * 8);
        CHECK(reads <= MAX_FAULTS, "cycle %u took %u reads", k, reads);
        CHECK(find_listener() == so, "listener disappeared at cycle %u (gate_check=%d)", k, hvf_gate_check());
        CHECK(recovered_state(&w), "cycle %u not recovered (gate=%d)", k, hvf_gate_check());
        ok += roundtrip(c, 100 + k, 256);
    }
    CHECK(ok == cycles && hvf_gate_check() == 0 && RECOVERY_COUNT(fd) >= cycles, "alternating ok=%u/%u gate=%d recoveries=%u", ok, cycles, hvf_gate_check(), RECOVERY_COUNT(fd));
    printf("RESULT scenario=alternating cycles=%u roundtrips=%u/%u lifetime_recoveries=%u gate_check=%d seconds=%.4f icmp=%u\n", cycles, ok, cycles, RECOVERY_COUNT(fd), hvf_gate_check(), seconds() - t0, icmp_frames);
    return 0;
}
struct mapping_watch { uint16_t port; struct socket *so; };
static int mapping_gone(void *p) { struct mapping_watch *m = p; return find_mapping(m->port) != m->so; }
static int echo_roundtrip(uint16_t sport, unsigned tag)
{
    uint8_t d[200]; fill(d, sizeof(d), tag); unsigned start = nframes; guest_udp(sport, "10.0.2.2", echo_port, d, sizeof(d));
    double deadline = seconds() + 2;
    while (seconds() < deadline) { spin(2); if (frame_since(start, echo_port, sport, d, sizeof(d))) return 1; }
    return 0;
}
static int scenario_ephemeral(void)
{
    const uint16_t sport = 40001;
    if (!echo_roundtrip(sport, 1)) {
        struct socket *m = find_mapping(sport);
        printf("DEBUG echo_answered=%u nframes=%u mapping=%p icmp=%u", echo_answered, nframes, (void *)m, icmp_frames);
        if (m) printf(" fport=%u faddr=%08x expire=%u", ntohs(m->so_fport), ntohl(m->so_faddr.s_addr), m->so_expire);
        for (unsigned i = nframes > 4 ? nframes - 4 : 0; i < nframes; i++) printf(" [%u:%08x->%08x %u->%u len=%u]", i, ntohl(frames[i].src), ntohl(frames[i].dst), frames[i].sport, frames[i].dport, frames[i].len);
        printf("\n");
        CHECK(0, "first echo");
    }
    struct socket *mapping = find_mapping(sport); CHECK(mapping && mapping->so_expire, "ephemeral mapping shape");
    int listener_fd = find_listener()->s; uint32_t listener_token = client_tokens[listener_fd];
    struct mapping_watch m = {sport, mapping}; unsigned reads = break_until(mapping->s, mapping_gone, &m, MAX_FAULTS * 8);
    CHECK(find_mapping(sport) == NULL, "dead ephemeral mapping kept after %u reads", reads);
    CHECK(reads <= MAX_FAULTS && hvf_gate_check() == 0, "reads=%u gate=%d", reads, hvf_gate_check());
    CHECK(find_listener() && client_tokens[listener_fd] == listener_token, "listener touched by ephemeral failure");
    CHECK(echo_roundtrip(sport, 2) && find_mapping(sport), "guest could not re-create the mapping");
    int c = new_client(); CHECK(roundtrip(c, 3, 256), "listener after ephemeral failure");
    CHECK(icmp_frames == 0, "icmp=%u", icmp_frames);
    printf("RESULT scenario=ephemeral reads_to_detach=%u recreated=1 gate_check=%d listener_untouched=1 icmp=%u\n", reads, hvf_gate_check(), icmp_frames);
    return 0;
}
static int dns_query(uint16_t id, uint8_t *q)
{
    int n = 12; memset(q, 0, 12); q[0] = (uint8_t)(id >> 8); q[1] = (uint8_t)id; q[2] = 1; q[5] = 1;
    n += snprintf((char *)q + n + 1, 32, "q%05u", id) + 1; q[12] = 6; q[n++] = 4; memcpy(q + n, "test", 4); n += 4; q[n++] = 0;
    q[n++] = 0; q[n++] = 1; q[n++] = 0; q[n++] = 1; return n;
}
static int dns_answer_seen(unsigned start, uint16_t id)
{
    uint8_t q[64]; int n = dns_query(id, q); q[2] = 0x81; q[3] = 0x80; memcpy(q + n, "ANS!", 4);
    return frame_since(start, 53, (uint16_t)(20000 + id), q, (size_t)n + 4);
}
static int scenario_pressure(void)
{
    const unsigned queries = 1200; hold_every = 12; /* 100 queries stay pending until the end */
    struct socket *so = find_listener(); int fd = so->s; int c = new_client(); CHECK(roundtrip(c, 1, 64), "baseline");
    /* The authority closes everything it inherits; with only the listener's
     * slot (two descriptors) open, the rest is its fixed base. */
    int auth_base = authority_fds() - 2; CHECK(auth_base > 0, "authority fds");
    int peak_auth = 0, peak_udb = 0; unsigned start = nframes, break_at = queries / 2, reads = 0; uint32_t token = client_tokens[fd];
    int broke_listener = 0, present_after_break = 0;
    for (unsigned id = 1; id <= queries; id++) {
        uint8_t q[64]; int n = dns_query((uint16_t)id, q); guest_udp((uint16_t)(20000 + id), "10.0.2.3", 53, q, (size_t)n);
        if (id % 8 == 0) for (unsigned s = 0; s < 4; s++) spin(1);
        int a = authority_fds(); if (a > peak_auth) peak_auth = a; if ((int)udb_count() > peak_udb) peak_udb = (int)udb_count();
        if (id == break_at) {
            struct watch w = {so, fd, token}; reads = break_until(fd, listener_changed, &w, MAX_FAULTS * 8); broke_listener = 1;
            present_after_break = find_listener() == so && hvf_gate_check() == 0 && client_tokens[fd] != token;
        }
    }
    for (unsigned s = 0; s < 200; s++) spin(2);
    unsigned pending_before_release = nheld; release_held();
    for (unsigned s = 0; s < 300; s++) spin(2);
    unsigned answered = 0, held_answered = 0, held_total = 0;
    for (unsigned id = 1; id <= queries; id++) { int seen = dns_answer_seen(start, (uint16_t)id); answered += seen; if (id % hold_every == 0) { held_total++; held_answered += seen; } }
    printf("OBSERVED dns_answered_to_guest=%u/%u pending_answered=%u/%u pending_held=%u peak_authority_fds=%d peak_udp_sockets=%d listener_reads=%u listener_ok_after_break=%d\n",
           answered, queries, held_answered, held_total, pending_before_release, peak_auth, peak_udb, reads, present_after_break);
    CHECK(broke_listener && held_total == 100 && pending_before_release == 100, "workload shape");
    CHECK(peak_auth >= auth_base + 2 * MAX_UDP, "pool never reached saturation: peak authority fds %d base %d", peak_auth, auth_base);
    CHECK(held_answered == held_total, "pending DNS queries lost under pressure: %u/%u", held_answered, held_total);
    CHECK(answered == queries, "DNS answers %u/%u", answered, queries);
    CHECK(present_after_break, "listener not recovered under pool pressure (present=%d gate=%d)", find_listener() == so, hvf_gate_check());
    CHECK(find_listener() == so && roundtrip(c, 2, 512), "listener unusable after pressure");
    CHECK(icmp_frames == 0 && dropped_frames == 0, "icmp=%u dropped=%u", icmp_frames, dropped_frames);
    printf("RESULT scenario=pressure queries=%u answered=%u pending=%u pending_answered=%u peak_authority_fds=%d pool_slots=%d peak_udp_sockets=%d listener_reads=%u icmp=%u\n",
           queries, answered, held_total, held_answered, peak_auth, (peak_auth - auth_base) / 2, peak_udb, reads, icmp_frames);
    return 0;
}
static int scenario_authority_down(void)
{
    struct socket *so = find_listener(); int fd = so->s; int c = new_client(); CHECK(roundtrip(c, 1, 64), "baseline");
    CHECK(!kill(authority_pid, SIGKILL), "kill authority");
    struct watch w = {so, fd, client_tokens[fd]}; double t0 = seconds();
    unsigned reads = break_until(fd, gone_or_failed, &w, MAX_FAULTS * 8); double took = seconds() - t0;
    CHECK(hvf_gate_check() != 0, "dead authority not reported");
    CHECK(reads <= MAX_FAULTS && took < 5, "reads=%u took=%.2f", reads, took);
    printf("RESULT scenario=authority-down reads=%u seconds=%.4f gate_check=%d listener_present=%d\n", reads, took, hvf_gate_check(), find_listener() == so);
    return 0;
}
int main(int argc, char **argv)
{
    CHECK(argc == 2, "usage: scenario");
    setup();
    if (!strcmp(argv[1], "isolated")) return scenario_isolated();
    if (!strcmp(argv[1], "recover")) return scenario_recover();
    if (!strcmp(argv[1], "repeat")) return scenario_repeat();
    if (!strcmp(argv[1], "budget")) return scenario_budget();
    if (!strcmp(argv[1], "alternating")) return scenario_alternating();
    if (!strcmp(argv[1], "ephemeral")) return scenario_ephemeral();
    if (!strcmp(argv[1], "pressure")) return scenario_pressure();
    if (!strcmp(argv[1], "authority-down")) return scenario_authority_down();
    CHECK(0, "unknown scenario %s", argv[1]);
}
