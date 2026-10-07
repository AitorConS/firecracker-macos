// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "hvf.h"
#include <pthread.h>
/* Global device I/O lock (probe.c): MMIO exits, polling, device state. */
extern pthread_mutex_t io_lock;
int devices_init(void *ram, size_t size, const char *disk,const struct hvf_options *options);
int devices_mmio(uint64_t addr, unsigned size, int write, uint64_t *value);
int devices_exit_status(void);
void devices_stop(void);
void devices_close(void);
void devices_poll(void);
int devices_pending(void);
void devices_metrics(uint64_t out[4]);

#include "snapshot_io.h"
void devices_snapshot(struct snapshot_io *s);

uint64_t devices_queue_depth(void);
