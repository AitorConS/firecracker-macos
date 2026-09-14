// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <sys/types.h>
#include "hvf.h"
typedef ssize_t (*net_receive_fn)(const void *,size_t,void *);
int net_backend_open(const struct hvf_options *,net_receive_fn);
void net_backend_send(const void *,size_t);
void net_backend_poll(void);
void net_backend_close(void);
int net_backend_pid(void);
void net_backend_pause(int paused, uint64_t operation);
int net_backend_pause_ready(uint64_t operation);
void net_backend_health(void);
int net_backend_pending_rx(void);
void slirp_backend_pause(int paused);

// Internal broker transport, also exercised by the stack fuzzer.
int slirp_backend_open(const struct hvf_options *,net_receive_fn);
void slirp_backend_send(const void *,size_t);
void slirp_backend_poll(void);
void slirp_backend_close(void);

void net_backend_metrics(uint64_t out[7]);
