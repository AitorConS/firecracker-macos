// SPDX-License-Identifier: Apache-2.0
// Descriptor lifetime regression. Real libslirp, real host sockets, synthetic
// guest frames: many short TCP connections and DNS-style UDP rotation must not
// consume a descriptor per exchange.
#include "slirp.h"
#include "../../src/hvf-vmm/native/socket_gate.c"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>

#define GUEST 0x0a00020fU
#define GATEWAY 0x0a000202U
static const uint8_t guest_mac[6] = {0x02, 0x12, 0x34, 0x56, 0x78, 0x90};
static const uint8_t slirp_mac[6] = {0x52, 0x55, 0x0a, 0x00, 0x02, 0x02};

static int64_t virtual_ms = 1000;
static int64_t clock_ns(void *p) { (void)p; return virtual_ms * 1000000; }
static void notify(void *p) { (void)p; }
static void register_fd(slirp_os_socket fd, void *p) { (void)fd; (void)p; }

static uint8_t frames[256][2048];
static unsigned frame_len[256], frames_queued;
static ssize_t output(const void *data, size_t len, void *opaque) {
    (void)opaque;
    if (frames_queued < 256 && len <= sizeof(frames[0])) {
        memcpy(frames[frames_queued], data, len);
        frame_len[frames_queued++] = (unsigned)len;
    }
    return (ssize_t)len;
}

static struct pollfd polls[1024];
static unsigned npoll;
static int add_poll(slirp_os_socket fd, int events, void *o) {
    (void)o;
    assert(npoll < 1024);
    short ev = 0;
    if (events & SLIRP_POLL_IN) ev |= POLLIN;
    if (events & SLIRP_POLL_OUT) ev |= POLLOUT;
    if (events & SLIRP_POLL_PRI) ev |= POLLPRI;
    polls[npoll] = (struct pollfd){fd, ev, 0};
    return (int)npoll++;
}
static int poll_events(int i, void *o) {
    (void)o;
    short r = polls[i].revents;
    return ((r & POLLIN) ? SLIRP_POLL_IN : 0) | ((r & POLLOUT) ? SLIRP_POLL_OUT : 0) |
           ((r & POLLPRI) ? SLIRP_POLL_PRI : 0) | ((r & POLLERR) ? SLIRP_POLL_ERR : 0) |
           ((r & POLLHUP) ? SLIRP_POLL_HUP : 0);
}

static unsigned open_descriptors(void) {
    unsigned n = 0;
    for (int fd = 0; fd < 4096; fd++)
        if (fcntl(fd, F_GETFD) != -1) n++;
    return n;
}

static void report_states(Slirp *s, const char *label) {
    unsigned total = 0, with_fd = 0, nofdref = 0, states[16] = {0};
    for (struct socket *so = s->tcb.so_next; so != &s->tcb; so = so->so_next) {
        total++;
        if (have_valid_socket(so->s)) with_fd++;
        if (so->so_state & SS_NOFDREF) nofdref++;
        struct tcpcb *tp = sototcpcb(so);
        if (tp && tp->t_state >= 0 && tp->t_state < 16) states[tp->t_state]++;
    }
    printf("STATES %s sockets=%u with_fd=%u nofdref=%u", label, total, with_fd, nofdref);
    for (unsigned i = 0; i < 16; i++)
        if (states[i]) printf(" t_state%u=%u", i, states[i]);
    printf("\n");
}

static uint16_t checksum(const uint8_t *data, size_t len, uint32_t sum) {
    for (size_t i = 0; i + 1 < len; i += 2) sum += (uint32_t)((data[i] << 8) | data[i + 1]);
    if (len & 1) sum += (uint32_t)(data[len - 1] << 8);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return htons((uint16_t)~sum);
}

struct conn {
    uint16_t sport, dport;
    uint32_t snd_nxt, rcv_nxt;
    int established, fin_seen, fin_acked, reset;
    size_t received;
};

// Minimal guest side: enough of TCP to open, exchange and close cleanly.
static void guest_send(Slirp *s, struct conn *c, uint8_t flags, const void *payload, size_t len) {
    uint8_t frame[2048];
    memset(frame, 0, sizeof(frame));
    memcpy(frame, slirp_mac, 6);
    memcpy(frame + 6, guest_mac, 6);
    frame[12] = 0x08;
    uint8_t *ip = frame + 14, *tcp = ip + 20;
    size_t total = 40 + len;
    ip[0] = 0x45;
    ip[2] = (uint8_t)(total >> 8);
    ip[3] = (uint8_t)total;
    ip[4] = (uint8_t)(c->sport >> 8);
    ip[5] = (uint8_t)c->sport;
    ip[6] = 0x40;
    ip[8] = 64;
    ip[9] = IPPROTO_TCP;
    uint32_t src = htonl(GUEST), dst = htonl(GATEWAY);
    memcpy(ip + 12, &src, 4);
    memcpy(ip + 16, &dst, 4);
    uint16_t sum = checksum(ip, 20, 0);
    memcpy(ip + 10, &sum, 2);
    uint16_t sport = htons(c->sport), dport = htons(c->dport);
    memcpy(tcp, &sport, 2);
    memcpy(tcp + 2, &dport, 2);
    uint32_t seq = htonl(c->snd_nxt), ack = htonl(c->rcv_nxt);
    memcpy(tcp + 4, &seq, 4);
    memcpy(tcp + 8, &ack, 4);
    tcp[12] = 5 << 4;
    tcp[13] = flags;
    tcp[14] = 0xff;
    tcp[15] = 0xff;
    if (len) memcpy(tcp + 20, payload, len);
    uint32_t pseudo = (GUEST >> 16) + (GUEST & 0xffff) + (GATEWAY >> 16) + (GATEWAY & 0xffff) +
                      IPPROTO_TCP + (uint32_t)(20 + len);
    uint16_t tsum = checksum(tcp, 20 + len, pseudo);
    memcpy(tcp + 16, &tsum, 2);
    if (flags & (TH_SYN | TH_FIN)) c->snd_nxt++;
    c->snd_nxt += len;
    slirp_input(s, frame, (int)(14 + total));
}

static void guest_receive(Slirp *s, struct conn *c, const uint8_t *frame, unsigned len) {
    if (len < 54 || frame[12] != 0x08 || frame[13] != 0x00) return;
    const uint8_t *ip = frame + 14;
    if (ip[9] != IPPROTO_TCP) return;
    unsigned ihl = (ip[0] & 0xf) * 4;
    const uint8_t *tcp = ip + ihl;
    unsigned iplen = (unsigned)((ip[2] << 8) | ip[3]);
    unsigned offset = (tcp[12] >> 4) * 4;
    uint16_t dport;
    uint32_t raw_seq;
    memcpy(&dport, tcp + 2, sizeof(dport));
    memcpy(&raw_seq, tcp + 4, sizeof(raw_seq));
    if (ntohs(dport) != c->sport) return;
    uint32_t seq = ntohl(raw_seq);
    uint8_t flags = tcp[13];
    unsigned payload = iplen > ihl + offset ? iplen - ihl - offset : 0;
    if (flags & TH_RST) { c->reset = 1; return; }
    if ((flags & TH_SYN) && (flags & TH_ACK)) {
        c->rcv_nxt = seq + 1;
        c->established = 1;
        guest_send(s, c, TH_ACK, NULL, 0);
        return;
    }
    if (seq != c->rcv_nxt) { guest_send(s, c, TH_ACK, NULL, 0); return; }
    if (payload) {
        c->received += payload;
        c->rcv_nxt += payload;
    }
    if (flags & TH_FIN) {
        c->rcv_nxt++;
        c->fin_seen = 1;
    }
    if (payload || (flags & TH_FIN)) guest_send(s, c, TH_ACK, NULL, 0);
    if (c->fin_seen && !c->fin_acked) {
        c->fin_acked = 1;
        guest_send(s, c, TH_FIN | TH_ACK, NULL, 0);
    }
}

static void pump(Slirp *s, struct conn *c, int64_t advance) {
    npoll = 0;
    uint32_t timeout = 0;
    slirp_pollfds_fill_socket(s, &timeout, add_poll, NULL);
    int n = poll(polls, npoll, 1);
    slirp_pollfds_poll(s, n < 0, poll_events, NULL);
    virtual_ms += advance;
    unsigned queued = frames_queued;
    frames_queued = 0;
    for (unsigned i = 0; i < queued; i++)
        if (c) guest_receive(s, c, frames[i], frame_len[i]);
}

static int server_fd;
static void *server(void *arg) {
    (void)arg;
    for (;;) {
        int client = accept(server_fd, NULL, NULL);
        if (client < 0) { if (errno == EINTR) continue; return NULL; }
        char request[512];
        (void)recv(client, request, sizeof(request), 0);
        static const char reply[] =
            "HTTP/1.0 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world";
        (void)send(client, reply, sizeof(reply) - 1, 0);
        close(client);
    }
}

int main(int argc, char **argv) {
    unsigned connections = argc > 1 ? (unsigned)atoi(argv[1]) : 64;
    unsigned queries = argc > 2 ? (unsigned)atoi(argv[2]) : 64;
    signal(SIGPIPE, SIG_IGN);
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(server_fd >= 0);
    int one = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in address = {.sin_len = sizeof(address), .sin_family = AF_INET};
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(!bind(server_fd, (void *)&address, sizeof(address)));
    assert(!listen(server_fd, 64));
    socklen_t length = sizeof(address);
    assert(!getsockname(server_fd, (void *)&address, &length));
    uint16_t port = ntohs(address.sin_port);
    pthread_t thread;
    assert(!pthread_create(&thread, NULL, server, NULL));

    struct hvf_security policy = {.development = 1};
    hvf_policy_set(&policy);
    SlirpConfig cfg = {.version = 6, .in_enabled = true, .if_mtu = 1500, .if_mru = 1500};
    inet_pton(AF_INET, "10.0.2.0", &cfg.vnetwork);
    inet_pton(AF_INET, "255.255.255.0", &cfg.vnetmask);
    inet_pton(AF_INET, "10.0.2.2", &cfg.vhost);
    inet_pton(AF_INET, "10.0.2.3", &cfg.vnameserver);
    SlirpCb cb = {.send_packet = output, .clock_get_ns = clock_ns, .notify = notify,
                  .register_poll_socket = register_fd, .unregister_poll_socket = register_fd};
    Slirp *s = slirp_new(&cfg, &cb, NULL);
    assert(s);
    arp_table_add(s, htonl(GUEST), (uint8_t *)guest_mac);

    unsigned baseline = open_descriptors(), tcp_peak = baseline, udp_peak = baseline, completed = 0;
    for (unsigned i = 0; i < connections; i++) {
        struct conn c = {.sport = (uint16_t)(20000 + i), .dport = port, .snd_nxt = 1000 + i * 4096};
        guest_send(s, &c, TH_SYN, NULL, 0);
        static const char request[] = "GET /probe HTTP/1.0\r\nConnection: close\r\n\r\n";
        int sent = 0;
        for (int step = 0; step < 400 && !(c.fin_seen && c.fin_acked); step++) {
            pump(s, &c, 4);
            if (c.established && !sent) {
                sent = 1;
                guest_send(s, &c, TH_PUSH | TH_ACK, request, sizeof(request) - 1);
            }
            if (c.reset) break;
        }
        for (int step = 0; step < 20; step++) pump(s, &c, 4);
        if (c.received >= 11 && !c.reset) completed++;
        unsigned current = open_descriptors();
        if (getenv("HVF_FD_DUMP")) printf("STEP %u fds=%u\n", i, current);
        if (current > tcp_peak) tcp_peak = current;
    }
    report_states(s, "after-tcp-loop");
    if (getenv("HVF_FD_DUMP")) {
        printf("FDS");
        for (int fd = 0; fd < 4096; fd++) {
            if (fcntl(fd, F_GETFD) == -1) continue;
            struct sockaddr_storage local = {0}, remote = {0};
            socklen_t ll = sizeof(local), rl = sizeof(remote);
            int lok = !getsockname(fd, (void *)&local, &ll), rok = !getpeername(fd, (void *)&remote, &rl);
            printf(" %d:%s%s", fd, lok ? "L" : "-", rok ? "R" : "-");
            if (lok && local.ss_family == AF_INET)
                printf("(%u)", ntohs(((struct sockaddr_in *)&local)->sin_port));
        }
        printf("\n");
    }
    // Give the stack every chance to retire closed connections: 2MSL is counted
    // in 500 ms slow ticks, so advance the virtual clock well beyond it.
    for (int step = 0; step < 200; step++) pump(s, NULL, 600);
    unsigned after_tcp = open_descriptors();
    report_states(s, "after-drain");

    // DNS-style rotation: a new source port per query, as a stub resolver does.
    unsigned answered = 0, refused = 0;
    for (unsigned i = 0; i < queries; i++) {
        struct socket *so = socreate(s, IPPROTO_UDP);
        if (udp_attach(so, AF_INET) < 0) { refused++; sofree(so); continue; }
        answered++;
        so->so_lfamily = so->so_ffamily = AF_INET;
        so->so_laddr.s_addr = htonl(GUEST);
        so->so_faddr = cfg.vnameserver;
        so->so_lport = htons((uint16_t)(40000 + i));
        so->so_fport = htons(53);
        so->so_expire = (unsigned)virtual_ms + 10000;
        unsigned current = open_descriptors();
        if (current > udp_peak) udp_peak = current;
    }
    for (int step = 0; step < 200; step++) pump(s, NULL, 600);
    unsigned after_udp = open_descriptors();

    printf("RESULT baseline=%u completed=%u/%u tcp_peak=%u after_tcp=%u udp_attached=%u "
           "udp_refused=%u udp_peak=%u after_udp=%u\n",
           baseline, completed, connections, tcp_peak, after_tcp, answered, refused, udp_peak,
           after_udp);
    int leaked_tcp = (int)after_tcp - (int)baseline, leaked_udp = (int)after_udp - (int)after_tcp;
    int held = (int)tcp_peak - (int)baseline;
    printf("LEAK tcp=%d udp=%d tcp_peak_over_baseline=%d\n", leaked_tcp, leaked_udp, held);
    if (completed != connections) { printf("FAIL incomplete exchanges\n"); return 1; }
    if (leaked_tcp > 4) { printf("FAIL tcp descriptors retained\n"); return 1; }
    if (leaked_udp > 4) { printf("FAIL udp descriptors retained\n"); return 1; }
    // Sequential exchanges must not each hold a host descriptor until the
    // guest-side 2MSL expires: peak usage would then scale with the rate.
    if (held > 8) { printf("FAIL descriptors held per finished exchange\n"); return 1; }
    printf("PASS\n");
    return 0;
}
