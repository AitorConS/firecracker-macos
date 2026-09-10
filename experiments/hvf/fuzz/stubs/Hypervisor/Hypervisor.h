// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stdint.h>
#define HV_SUCCESS 0
static inline int hv_gic_set_spi(uint32_t irq,int level){(void)irq;(void)level;return 0;}
