// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "hvf.h"
#include <stddef.h>
#include <stdint.h>
int net_init(void *ram,size_t size,const struct hvf_options *options);
int net_mmio(uint64_t addr,unsigned size,int write,uint64_t *v);
void net_poll(void);
void net_close(void);
