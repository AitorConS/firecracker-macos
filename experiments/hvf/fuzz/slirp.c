// SPDX-License-Identifier: Apache-2.0
// Exercise the vendored stack with the same mandatory socket-policy wrappers.
#include "net_backend.h"
#include <stddef.h>
#include <stdint.h>
static ssize_t discard(const void *data,size_t size,void *opaque){(void)data;(void)opaque;return size;}
int LLVMFuzzerTestOneInput(const uint8_t *data,size_t size){
    if(size>65536)return 0;
    static const struct hvf_security deny_all={0};
    const struct hvf_options options={.security=&deny_all};
    if(slirp_backend_open(&options,discard))return 0;
    slirp_backend_send(data,size);
    slirp_backend_poll();
    slirp_backend_close();return 0;
}
