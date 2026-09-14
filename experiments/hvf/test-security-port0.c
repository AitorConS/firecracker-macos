// SPDX-License-Identifier: Apache-2.0
// Durable RPC/port0 + listener/DNS authorization regression.
// Uses the real authority (hvf_gate_*) with Seatbelt installed, no RPC mocks.
#include "policy.h"
#include "socket_gate.h"
#include "seatbelt.h"
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

int hvf_policy_bind(int, const struct sockaddr *, socklen_t);
int hvf_policy_socket(int, int, int);
int hvf_policy_dns(struct in_addr *, uint16_t *);

static struct sockaddr_in addr(unsigned port) {
    struct sockaddr_in a = {.sin_len = sizeof(a), .sin_family = AF_INET, .sin_port = htons(port)};
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return a;
}
static int host(struct sockaddr_in *a) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);
    assert(!bind(fd, (void *)a, sizeof(*a)));
    socklen_t n = sizeof(*a);
    assert(!getsockname(fd, (void *)a, &n));
    return fd;
}
static int free_port(void) {
    struct sockaddr_in t = addr(0);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);
    assert(!bind(fd, (void *)&t, sizeof(t)));
    socklen_t n = sizeof(t);
    assert(!getsockname(fd, (void *)&t, &n));
    unsigned port = ntohs(t.sin_port);
    close(fd);
    return (int)port;
}
static void check(int cond, const char *msg) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s (errno=%d %s)\n", msg, errno, strerror(errno));
        _exit(1);
    }
}

int main(int argc, char **argv) {
    int wildcard = argc == 2 && !strcmp(argv[1], "--wildcard");
    struct sockaddr_in allowed = addr(0), forbidden = addr(0), peer = addr(0), dns = addr(0);
    int yes = host(&allowed), no = host(&forbidden), other = host(&peer), dnssock = host(&dns);
    int udp_listen_port = free_port();
    int tcp_listen_port = free_port();
    struct sockaddr_in listen_addr = addr((unsigned)udp_listen_port);
    struct sockaddr_in tcp_listen_addr = addr((unsigned)tcp_listen_port);

    struct hvf_endpoint egress = {.udp = 1, .address = {127, 0, 0, 1}, .port = ntohs(allowed.sin_port)};
    struct hvf_endpoint listeners[2] = {
        {.udp = 1, .address = {127, 0, 0, 1}, .port = (uint16_t)udp_listen_port},
        {.udp = 0, .address = {127, 0, 0, 1}, .port = (uint16_t)tcp_listen_port},
    };
    if (wildcard) {
        memset(listeners[0].address, 0, 4);
        memset(listeners[1].address, 0, 4);
        listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        tcp_listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    struct hvf_security policy = {
        .egress_count = 1, .egress = &egress,
        .listener_count = 2, .listeners = listeners,
        .dns_address = {127, 0, 0, 1}, .dns_port = ntohs(dns.sin_port),
    };
    hvf_policy_set(&policy);
    if (wildcard) {
        // The parent remains a host-side client; only this broker child is
        // deny-all sandboxed. Authority installs its own Seatbelt profile.
        pid_t child = fork();
        check(child >= 0, "fork sandbox probe");
        if (!child) {
        check(!hvf_gate_start(), "sandbox gate start");
        check(!hvf_sandbox_install("(version 1)(deny default)"), "broker Seatbelt");
        int raw = socket(AF_INET, SOCK_STREAM, 0);
        check(raw >= 0, "raw socket");
        check(bind(raw, (void *)&tcp_listen_addr, sizeof(tcp_listen_addr)) < 0 && errno == EPERM, "raw wildcard bind denied");
        close(raw);
        int gated = socket(AF_INET, SOCK_STREAM, 0);
        check(gated >= 0 && !hvf_gate_tcp(gated, &tcp_listen_addr, 1), "sandbox wildcard TCP gate");
        int udp_gated = hvf_gate_udp();
        check(udp_gated >= 0 && !hvf_gate_bind(udp_gated, &listen_addr), "sandbox wildcard UDP gate");
        check(!hvf_policy_allows(SOCK_STREAM, &tcp_listen_addr, 0), "listener is not egress");
        check(!hvf_policy_allows(SOCK_DGRAM, &listen_addr, 0), "UDP listener is not egress");
        hvf_gate_close(udp_gated); close(udp_gated); close(gated);
        _exit(0);
        }
        int status;
        check(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status), "sandbox probe exit");
        // Authority notices parent exit within its 10ms poll loop.
        usleep(50000);
    }

    check(!hvf_gate_start(), "gate start");

    // 1. Ephemeral bind must stay useful but not become an unrestricted listener.
    int proxy = hvf_gate_udp();
    check(proxy >= 0, "ephemeral proxy");
    struct sockaddr_in local = addr(0);
    check(!hvf_gate_bind(proxy, &local), "ephemeral bind port0");
    socklen_t n = sizeof(local);
    check(!hvf_gate_name(proxy, (void *)&local, &n) && local.sin_port, "ephemeral name");
    check(sendto(no, "X", 1, 0, (void *)&local, sizeof(local)) == 1, "unsolicited send");
    struct pollfd f = {proxy, POLLIN, 0};
    int unsolicited = poll(&f, 1, 250);
    char c = 0;
    if (unsolicited) {
        // Dropped fix would deliver here; drain to keep later checks deterministic.
        (void)hvf_gate_recv(proxy, &c, 1, 0, NULL, NULL);
        fprintf(stderr, "FAIL: unsolicited datagram from denied peer delivered\n");
        _exit(1);
    }
    // Authorized roundtrip through the same ephemeral socket.
    check(hvf_gate_send(proxy, "A", 1, 0, (void *)&allowed, sizeof(allowed)) == 1, "egress send");
    struct pollfd h = {yes, POLLIN, 0};
    check(poll(&h, 1, 1000) == 1, "host receives egress");
    struct sockaddr_in back;
    n = sizeof(back);
    check(recvfrom(yes, &c, 1, 0, (void *)&back, &n) == 1 && c == 'A', "egress payload");
    check(sendto(yes, "R", 1, 0, (void *)&back, n) == 1, "host reply");
    f.revents = 0;
    check(poll(&f, 1, 1000) == 1, "ephemeral receives authorized reply");
    check(hvf_gate_recv(proxy, &c, 1, 0, NULL, NULL) == 1 && c == 'R', "reply payload");
    // Source port0 must not authorize arbitrary egress.
    check(hvf_gate_send(proxy, "D", 1, 0, (void *)&forbidden, sizeof(forbidden)) == 1, "denied send local");
    h = (struct pollfd){no, POLLIN, 0};
    check(poll(&h, 1, 250) == 0, "denied egress dropped");
    puts("ephemeral_no_unsolicited=PASS authorized_roundtrip=PASS denied_egress=PASS");

    // 2. UDP listener exactness: wrong port/address denied, exact useful.
    int ul = hvf_gate_udp();
    check(ul >= 0, "listener proxy");
    struct sockaddr_in wrong = listen_addr;
    wrong.sin_port = htons((uint16_t)(udp_listen_port == 1 ? 2 : 1));
    check(hvf_gate_bind(ul, &wrong) && errno == EPERM, "udp wrong port denied");
    struct sockaddr_in wrongaddr = listen_addr;
    wrongaddr.sin_addr.s_addr = htonl(0x7f000002);
    check(hvf_gate_bind(ul, &wrongaddr) && errno == EPERM, "udp wrong address denied");
    wrongaddr.sin_addr.s_addr = wildcard ? htonl(INADDR_LOOPBACK) : htonl(INADDR_ANY);
    check(hvf_gate_bind(ul, &wrongaddr) && errno == EPERM, "wildcard and concrete grants are distinct");
    check(!hvf_gate_bind(ul, &listen_addr), "udp exact listener bind");
    struct sockaddr_in listener_target = listen_addr;
    listener_target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    check(sendto(other, "L", 1, 0, (void *)&listener_target, sizeof(listener_target)) == 1, "send to listener");
    f = (struct pollfd){ul, POLLIN, 0};
    check(poll(&f, 1, 1000) == 1, "listener receives");
    struct sockaddr_in src;
    n = sizeof(src);
    check(hvf_gate_recv(ul, &c, 1, 0, (void *)&src, &n) == 1 && c == 'L', "listener payload");
    // Reply to the observed peer is allowed even though it has no egress rule.
    check(hvf_gate_send(ul, "M", 1, 0, (void *)&src, n) == 1, "listener reply queued");
    // Give the authority a moment to forward, then confirm on the raw socket.
    struct pollfd q = {other, POLLIN, 0};
    check(poll(&q, 1, 1000) == 1, "listener reply arrives");
    check(recvfrom(other, &c, 1, 0, NULL, NULL) == 1 && c == 'M', "listener reply payload");
    puts("udp_listener_exact=PASS udp_wrong_denied=PASS listener_reply=PASS");

    // 3. TCP port0 / listener discipline through the policy wrapper.
    struct sockaddr_in tcp0 = addr(0);
    int tcp_fd = hvf_policy_socket(AF_INET, SOCK_STREAM, 0);
    check(tcp_fd >= 0, "tcp socket");
    check(hvf_policy_bind(tcp_fd, (void *)&tcp0, sizeof(tcp0)) && errno == EPERM, "tcp port0 denied");
    close(tcp_fd);
    int tcp_l = socket(AF_INET, SOCK_STREAM, 0);
    check(tcp_l >= 0, "raw tcp for listener bind");
    // Direct gate TCP listener exact + wrong-port cases use the gate API.
    check(hvf_gate_tcp(tcp_l, &tcp_listen_addr, 1) == 0, "tcp exact listener bind");
    int tcp_w = socket(AF_INET, SOCK_STREAM, 0);
    check(tcp_w >= 0, "raw tcp wrong");
    struct sockaddr_in tcp_wrong = tcp_listen_addr;
    tcp_wrong.sin_port = htons((uint16_t)(tcp_listen_port == 1 ? 2 : 1));
    check(hvf_gate_tcp(tcp_w, &tcp_wrong, 1) && errno == EPERM, "tcp wrong port denied");
    tcp_wrong = tcp_listen_addr;
    tcp_wrong.sin_addr.s_addr = wildcard ? htonl(INADDR_LOOPBACK) : htonl(INADDR_ANY);
    check(hvf_gate_tcp(tcp_w, &tcp_wrong, 1) && errno == EPERM, "tcp wildcard and concrete distinct");
    check(hvf_gate_tcp(tcp_w, &tcp_listen_addr, 0) && errno == EPERM, "tcp listener not egress");
    close(tcp_w);
    puts("tcp_port0_denied=PASS tcp_listener_exact=PASS tcp_wrong_denied=PASS");

    // 4. DNS explicit, no implicit port 53, byte order, alias not implicit.
    struct in_addr dns_addr;
    uint16_t dns_port = 0;
    check(hvf_policy_dns(&dns_addr, &dns_port) == 1, "dns explicit present");
    check(dns_port == dns.sin_port, "dns byte order network");
    struct sockaddr_in dns_ep = {.sin_len = sizeof(dns_ep), .sin_family = AF_INET, .sin_port = dns_port};
    dns_ep.sin_addr = dns_addr;
    check(hvf_policy_allows(SOCK_DGRAM, &dns_ep, 0), "dns udp allowed");
    check(hvf_policy_allows(SOCK_STREAM, &dns_ep, 0), "dns tcp allowed");
    struct sockaddr_in implicit = addr(53);
    int implicit_ok = 0;
    // implicit 127.0.0.1:53 must be denied unless it happens to equal the explicit DNS port.
    if (ntohs(dns.sin_port) != 53)
        implicit_ok = !hvf_policy_allows(SOCK_DGRAM, &implicit, 0);
    else
        implicit_ok = 1;
    check(implicit_ok, "dns implicit 53 denied");
    struct sockaddr_in alias = {.sin_len = sizeof(alias), .sin_family = AF_INET, .sin_port = dns.sin_port};
    alias.sin_addr.s_addr = htonl(0x0a000202); // 10.0.2.2 guest alias is not an implicit host grant
    check(!hvf_policy_allows(SOCK_DGRAM, &alias, 0), "alias not implicit");
    puts("dns_explicit=PASS dns_byteorder=PASS dns_no_implicit=PASS alias_denied=PASS");

    hvf_gate_close(proxy);
    close(proxy);
    hvf_gate_close(ul);
    close(ul);
    close(tcp_l);
    close(yes);
    close(no);
    close(other);
    close(dnssock);
    puts(wildcard ? "WILDCARD_LISTENERS: PASS" : "PORT0_DURABLE: PASS");
    return 0;
}
