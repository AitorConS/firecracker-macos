// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "hvf.h"
#include <stddef.h>
#include <stdint.h>
int net_init(void *ram,size_t size,const struct hvf_options *options);
int net_mmio(uint64_t addr,unsigned size,int write,uint64_t *v);
void net_poll(void);
int net_pending_tx(void);
void net_close(void);
void net_metrics(uint64_t out[6]);

int net_forget_guest_memory(void);

#include "snapshot_io.h"
void net_snapshot(struct snapshot_io *s);

void net_queue_depths(uint64_t out[2]);
