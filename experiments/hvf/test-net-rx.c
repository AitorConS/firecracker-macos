// SPDX-License-Identifier: Apache-2.0
// Exercise the production HVF RX path without starting a VM or broker.
#include <assert.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../../src/hvf-vmm/native/net.c"

#define TEST_RAM_SIZE (1 << 20)
#define RX_RING 0x10000
#define RX_DATA 0x30000

static uint8_t *guest_memory;
static net_receive_fn deliver;

hv_return_t hv_gic_set_spi(uint32_t intid, bool level) {
    assert(intid == 36);
    (void)level;
    return HV_SUCCESS;
}
int net_backend_open(const struct hvf_options *options, net_receive_fn receive_frame) {
    (void)options;
    deliver = receive_frame;
    return 0;
}
int net_backend_send(const void *data, size_t size) {
    (void)data;
    (void)size;
    assert(0 && "RX test must not send");
    return 0;
}
void net_backend_poll(void) {}
void net_backend_close(void) { deliver = NULL; }

static uint16_t *available(void) { return (uint16_t *)(guest_memory + RX_RING + 4096); }
static uint16_t *completed(void) { return (uint16_t *)(guest_memory + RX_RING + 8192); }
static struct desc *descriptors(void) { return (struct desc *)(guest_memory + RX_RING); }

static void reset_device(uint64_t byte_rate) {
    if (guest_memory) {
        net_close();
        free(guest_memory);
    }
    guest_memory = calloc(1, TEST_RAM_SIZE);
    assert(guest_memory);
    struct hvf_options options = {
        .network_enabled = 1,
        .network_bytes_per_second = byte_rate,
    };
    assert(net_init(guest_memory, TEST_RAM_SIZE, &options) == 0);
    uint64_t value = 4;
    assert(net_mmio(BAR + 18, 1, 1, &value));
    value = (BASE + RX_RING) >> 12;
    assert(net_mmio(BAR + 8, 4, 1, &value));
}

static void queue_rx(unsigned head) {
    uint16_t *a = available();
    a[2 + (a[1] % QSZ)] = head;
    a[1]++;
}

static void expect_zero_header_and_payload(const uint8_t *actual,
                                           const uint8_t *payload, size_t len) {
    for (unsigned i = 0; i < 10; i++) assert(actual[i] == 0);
    assert(memcmp(actual + 10, payload, len) == 0);
}

static void expect_rejected_in_child(const uint8_t *payload, size_t len) {
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        (void)deliver(payload, len, NULL);
        _exit(0);
    }
    int status_code;
    assert(waitpid(child, &status_code, 0) == child);
    assert(WIFEXITED(status_code) && WEXITSTATUS(status_code) == 2);
}

int main(void) {
    static uint8_t max_payload[65526];
    for (size_t i = 0; i < sizeof(max_payload); i++)
        max_payload[i] = (uint8_t)(i * 37 + 11);

    reset_device(0);
    uint8_t small[14];
    for (unsigned i = 0; i < sizeof(small); i++) small[i] = (uint8_t)(i + 1);
    errno = 0;
    assert(deliver(small, sizeof(small), NULL) == -1 && errno == EAGAIN);
    assert(completed()[1] == 0); // Empty ring: broker retains its frame.

    // Descriptor boundaries cut through the ten-byte header and first payload byte.
    uint8_t *output = guest_memory + RX_DATA;
    memset(output, 0xa5, 64);
    descriptors()[0] = (struct desc){BASE + RX_DATA, 7, 3, 1};
    descriptors()[1] = (struct desc){BASE + RX_DATA + 7, 4, 3, 2};
    descriptors()[2] = (struct desc){BASE + RX_DATA + 11, 20, 2, 0};
    queue_rx(0);
    assert(deliver(small, sizeof(small), NULL) == (ssize_t)sizeof(small));
    expect_zero_header_and_payload(output, small, sizeof(small));
    assert(output[24] == 0xa5 && output[30] == 0xa5);
    assert(completed()[1] == 1 && get(completed() + 2, 4) == 0 &&
           get(completed() + 4, 4) == 24);

    reset_device(0);
    output = guest_memory + RX_DATA;
    memset(output, 0xa5, 65536);
    descriptors()[0] = (struct desc){BASE + RX_DATA, 65536, 2, 0};
    queue_rx(0);
    assert(deliver(max_payload, sizeof(max_payload), NULL) == (ssize_t)sizeof(max_payload));
    expect_zero_header_and_payload(output, max_payload, sizeof(max_payload));
    assert(completed()[1] == 1 && get(completed() + 4, 4) == 65536);

    // A following short frame must not copy stale bytes from the prior stack frame.
    output = guest_memory + RX_DATA + 65536;
    memset(output, 0xa5, 64);
    descriptors()[1] = (struct desc){BASE + RX_DATA + 65536, 64, 2, 0};
    queue_rx(1);
    assert(deliver(small, sizeof(small), NULL) == (ssize_t)sizeof(small));
    expect_zero_header_and_payload(output, small, sizeof(small));
    assert(output[24] == 0xa5 && completed()[1] == 2);

    // Existing malformed/too-small capacity paths terminate the VMM with code 2.
    reset_device(0);
    descriptors()[0] = (struct desc){BASE + RX_DATA, 23, 2, 0};
    queue_rx(0);
    expect_rejected_in_child(small, sizeof(small));
    expect_rejected_in_child(max_payload, sizeof(max_payload) + 1);
    assert(completed()[1] == 0); // Child failures cannot complete the parent ring.

    // A quota denial returns EAGAIN without consuming the available descriptor.
    reset_device(1 << 20);
    descriptors()[0] = (struct desc){BASE + RX_DATA, 64, 2, 0};
    queue_rx(0);
    network_budget.bytes = 0;
    network_budget.last = budget_now() + 1000000000ULL; // Keep refill out of this assertion.
    errno = 0;
    assert(deliver(small, sizeof(small), NULL) == -1 && errno == EAGAIN);
    assert(completed()[1] == 0 && available()[1] == 1);

    net_close();
    free(guest_memory);
    puts("PASS virtio-net RX: header, payload, scatter, bounds and EAGAIN");
    return 0;
}
