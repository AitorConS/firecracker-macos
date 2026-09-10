// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stdint.h>
struct hvf_drive { int32_t fd; uint32_t read_only; };
struct hvf_firmware { const char *name; const uint8_t *data; uint32_t len; };
struct hvf_forward { uint32_t udp; uint8_t host_addr[4],guest_addr[4]; uint16_t host_port,guest_port; };
struct hvf_options {
    uint32_t cpus, memory_mib, timeout_ms, trace;
    uint32_t drive_count, firmware_count, forward_count, network_enabled;
    uint32_t power_button;
    int32_t ready_fd;
    uint8_t mac[6];
    const struct hvf_drive *drives;
    const struct hvf_firmware *firmware;
    const struct hvf_forward *forwards;
};
int hvf_run(const char *ram_path,uint64_t entry,const char *disk,const struct hvf_options *options);
