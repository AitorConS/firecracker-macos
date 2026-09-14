// SPDX-License-Identifier: Apache-2.0
// The TCP reassembly queue stores a struct qlink immediately before tcpiphdr.
// Keep the slirp_input() reserve aligned for that pointer-bearing structure.
#include "slirp.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

int main(void)
{
    const size_t overhead = sizeof(struct qlink) + sizeof(struct tcpiphdr) -
                            sizeof(struct ip) - sizeof(struct tcphdr);
    const size_t ip_offset = TCPIPHDR_DELTA + 2 + ETH_HLEN;
    const size_t qlink_offset = ip_offset - overhead;
    const size_t tcpiphdr_offset = qlink_offset + sizeof(struct qlink);

    assert(TCPIPHDR_DELTA >= overhead);
    assert((qlink_offset % _Alignof(struct qlink)) == 0);
    assert((tcpiphdr_offset % _Alignof(struct tcpiphdr)) == 0);
    assert(((TCPIPHDR_DELTA + 2 + ETH_HLEN) % _Alignof(struct ip6)) == 0);

    printf("libslirp TCP reassembly qlink alignment: PASS (delta=%d qlink_offset=%zu)\n",
           TCPIPHDR_DELTA, qlink_offset);
    return 0;
}
