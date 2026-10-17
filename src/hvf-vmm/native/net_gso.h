// SPDX-License-Identifier: Apache-2.0
// virtio-net offloads at the edges that cannot take them: TCPv4 segmentation
// of TSO frames and completion of partial checksums. Pure functions over
// caller buffers; no allocation and no device state.
#pragma once
#include <stddef.h>
#include <stdint.h>
#define VNET_HDR 10u
#define VNET_F_NEEDS_CSUM 1u
#define VNET_F_DATA_VALID 2u
#define VNET_GSO_NONE 0u
#define VNET_GSO_TCPV4 1u
struct vnet_hdr {uint8_t flags,gso_type;uint16_t hdr_len,gso_size,csum_start,csum_offset;};
void vnet_hdr_decode(const uint8_t in[VNET_HDR],struct vnet_hdr *h);
void vnet_hdr_encode(uint8_t out[VNET_HDR],const struct vnet_hdr *h);
// Completes a NEEDS_CSUM frame in place. 0 on success, -1 if the offsets do not fit.
int vnet_complete_csum(uint8_t *frame,size_t len,const struct vnet_hdr *h);
// Number of segments a TCPv4 TSO frame splits into, or -1 if it is not a
// well-formed IPv4/TCP frame with a usable gso_size.
int vnet_gso_count(const uint8_t *frame,size_t len,const struct vnet_hdr *h);
// Turns a TCPv4 TSO frame into one oversized IPv4 packet: total length and
// header checksum cover the whole frame; the TCP checksum stays partial.
int vnet_gso_whole(uint8_t *frame,size_t len,const struct vnet_hdr *h);
// Describes an oversized IPv4/TCP packet with a partial TCP checksum as a TSO
// frame of mtu-sized IP packets. 0 on success, -1 if it is not one.
int vnet_gso_describe(const uint8_t *frame,size_t len,unsigned mtu,struct vnet_hdr *h);
// Writes segment index (0-based) of a TCPv4 TSO frame to out (capacity cap)
// with complete IPv4 and TCP checksums. Returns its length, or -1.
long vnet_gso_segment(const uint8_t *frame,size_t len,const struct vnet_hdr *h,unsigned index,uint8_t *out,size_t cap);
