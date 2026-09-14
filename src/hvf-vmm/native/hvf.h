// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stdint.h>
struct hvf_drive { int32_t fd; uint32_t read_only; };
struct hvf_firmware { const char *name; const uint8_t *data; uint32_t len; };
struct hvf_forward { uint32_t udp; uint8_t host_addr[4],guest_addr[4]; uint16_t host_port,guest_port; };
struct hvf_endpoint { uint32_t udp; uint8_t address[4]; uint16_t port; };
struct hvf_security {
    uint32_t development,egress_count,listener_count;
    uint8_t dns_address[4];uint16_t dns_port;
    const struct hvf_endpoint *egress,*listeners;
    const char *vmm_profile,*broker_profile;
};
struct hvf_options {
    uint32_t cpus, memory_mib, timeout_ms, trace;
    uint32_t drive_count, firmware_count, forward_count, network_enabled;
    uint32_t power_button;
    int32_t ready_fd;
    uint8_t mac[6];
    const struct hvf_drive *drives;
    const struct hvf_firmware *firmware;
    const struct hvf_forward *forwards;
    const struct hvf_security *security;
    const char *snapshot_dir;
    const char *stream_path;
    uint32_t restore;
    uint64_t cpu_seconds;
    uint64_t disk_bytes_per_second,disk_operations_per_second,network_bytes_per_second,network_packets_per_second;
};
int hvf_run(const char *ram_path,uint64_t entry,const char *disk,const struct hvf_options *options);
