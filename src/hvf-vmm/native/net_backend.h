// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <sys/types.h>
#include "hvf.h"
typedef ssize_t (*net_receive_fn)(const void *,size_t,void *);
int net_backend_open(const struct hvf_options *,net_receive_fn);
void net_backend_send(const void *,size_t);
void net_backend_poll(void);
void net_backend_close(void);
