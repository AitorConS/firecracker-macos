// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stdint.h>
#include <stddef.h>
void input_init(void *,size_t,int);
int input_mmio(uint64_t,unsigned,int,uint64_t *);
int input_power_button(void);
