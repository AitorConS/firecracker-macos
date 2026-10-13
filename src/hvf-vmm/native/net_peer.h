// SPDX-License-Identifier: Apache-2.0
// Direct VM-to-VM Ethernet channels (see peer_proto.h). Called by the
// supervisor and vCPU exits with the device I/O lock held.
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
typedef ssize_t (*net_peer_receive_fn)(const void *,size_t,void *);
// Takes the VMM end of the broker's peer channel; -1 leaves peers disabled.
void net_peer_open(int channel,const uint8_t mac[6],net_peer_receive_fn deliver);
// 1 sent (or dropped by a stalled peer), 0 peer busy: retain the descriptor,
// -1 not a peer destination: use the switch.
int net_peer_send(const uint8_t *frame,size_t len);
// Services the channel and delivers peer frames; returns frames moved.
int net_peer_poll(void);
void net_peer_close(void);
// TX frames, RX frames, TX bytes, RX bytes, invalid RX drops, stalled TX drops, peers.
void net_peer_metrics(uint64_t out[7]);
// The switch's IPv4 source contract (ethernetConn.validSource in jerboad).
int net_frame_source_valid(const uint8_t *frame,size_t len,const uint8_t mac[6],const uint8_t ip[4]);
