// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <sys/types.h>
#include "hvf.h"
typedef ssize_t (*net_receive_fn)(const void *,size_t,void *);
int net_backend_open(const struct hvf_options *,net_receive_fn);
// Returns 0 when the broker socket or the bounded IPC queue is full; the caller
// retains the VirtIO descriptor and retries the frame.
int net_backend_send(const void *,size_t);
void net_backend_poll(void);
void net_backend_close(void);
int net_backend_pid(void);
void net_backend_pause(int paused, uint64_t operation);
int net_backend_pause_ready(uint64_t operation);
void net_backend_health(void);
int net_backend_pending_rx(void);
// Descriptor the VMM may sleep on for guest RX, or -1 to sleep for its poll interval.
int net_backend_wait_fd(void);
void slirp_backend_pause(int paused);

// Internal broker transport, also exercised by the stack fuzzer.
int slirp_backend_open(const struct hvf_options *,net_receive_fn);
void slirp_backend_send(const void *,size_t);
void slirp_backend_poll(void);
void slirp_backend_close(void);

void net_backend_metrics(uint64_t out[7]);

// Sleeps up to sleep_us, waking on supervisor, broker or wake_fd input.
void net_backend_wait(int control_fd,int running,int wake_fd,unsigned sleep_us);
