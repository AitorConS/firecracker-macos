// SPDX-License-Identifier: Apache-2.0
//! Host process counters; unavailable samples are omitted, never reported as zero.
use serde_json::{Value, json};
use std::time::Instant;

pub(super) struct Metrics {
    started: Instant,
    pub requests: u64,
    pub transitions: u64,
    entered: Instant,
    state: &'static str,
    residence: std::collections::BTreeMap<&'static str, f64>,
}
impl Metrics {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            requests: 0,
            transitions: 0,
            entered: Instant::now(),
            state: "not_started",
            residence: Default::default(),
        }
    }
    pub fn enter(&mut self, state: &'static str) {
        *self.residence.entry(self.state).or_default() += self.entered.elapsed().as_secs_f64();
        self.state = state;
        self.entered = Instant::now();
    }
    pub fn sample(
        &self,
        child: Option<u32>,
        broker: Option<u32>,
        connections: usize,
        rejected: u64,
    ) -> Value {
        let mut value = json!({
            "uptime_seconds": self.started.elapsed().as_secs_f64(),
            "http_requests_total": self.requests,
            "state_transitions_total": self.transitions,
            "http_connections": connections,
            "http_rejected_connections_total": rejected,
        });
        let elapsed = self.entered.elapsed().as_secs_f64();
        value["state_duration_seconds"] = json!(elapsed);
        for (state, total) in &self.residence {
            value[format!("state_{state}_seconds_total")] =
                json!(total + if *state == self.state { elapsed } else { 0.0 });
        }
        value[format!("state_{}_seconds_total", self.state)] =
            json!(self.residence.get(self.state).copied().unwrap_or(0.0) + elapsed);
        for (name, pid) in [
            ("supervisor", Some(std::process::id())),
            ("vmm", child),
            ("broker", broker),
        ] {
            if let Some(pid) = pid
                && let Some(info) = process(pid)
            {
                value[format!("{name}_resident_bytes")] = json!(info.pti_resident_size);
                value[format!("{name}_cpu_user_ticks_total")] = json!(info.pti_total_user);
                value[format!("{name}_cpu_system_ticks_total")] = json!(info.pti_total_system);
            }
        }
        value
    }
}
fn process(pid: u32) -> Option<libc::proc_taskinfo> {
    let mut info = std::mem::MaybeUninit::<libc::proc_taskinfo>::uninit();
    let size = std::mem::size_of::<libc::proc_taskinfo>() as i32;
    // SAFETY: the buffer is writable for size bytes; only initialized on a full result.
    let n = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTASKINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if n == size {
        Some(unsafe { info.assume_init() })
    } else {
        None
    }
}

const NATIVE_NAMES: [&str; 26] = [
    "vcpu_0_exits_total",
    "vcpu_1_exits_total",
    "vcpu_2_exits_total",
    "vcpu_3_exits_total",
    "block_requests_total",
    "block_read_bytes_total",
    "block_write_bytes_total",
    "block_errors_total",
    "net_tx_packets_total",
    "net_rx_packets_total",
    "net_tx_bytes_total",
    "net_rx_bytes_total",
    "net_rx_dropped_packets_total",
    "net_rx_dropped_bytes_total",
    "broker_pid",
    "block_pending_requests",
    "net_pending_tx_packets",
    "net_available_rx_buffers",
    "net_ipc_readable_bytes",
    "net_ipc_deferred_rx_bytes",
    "net_ipc_tx_dropped_packets_total",
    "net_ipc_tx_dropped_bytes_total",
    "net_ipc_rx_dropped_packets_total",
    "net_ipc_rx_dropped_bytes_total",
    "net_broker_metrics_dropped_samples_total",
    "native_metrics_dropped_samples_total",
];
pub(super) struct NativeMetrics {
    socket: std::os::unix::net::UnixDatagram,
    sample: Option<[u64; 26]>,
    sampled: Instant,
}
impl NativeMetrics {
    pub fn new(socket: std::os::unix::net::UnixDatagram) -> Self {
        Self {
            socket,
            sample: None,
            sampled: Instant::now(),
        }
    }
    pub fn poll(&mut self) {
        // The extra byte detects oversized/truncated datagrams.
        let mut bytes = [0u8; 217];
        for _ in 0..8 {
            match self.socket.recv(&mut bytes) {
                Ok(216) if bytes[..8] == *b"HVFM\x02\x1a\0\0" => {
                    let mut values = [0; 26];
                    for (i, value) in values.iter_mut().enumerate() {
                        *value =
                            u64::from_le_bytes(bytes[8 + i * 8..16 + i * 8].try_into().unwrap());
                    }
                    self.sample = Some(values);
                    self.sampled = Instant::now();
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    }
    pub fn broker_pid(&self) -> Option<u32> {
        self.sample
            .and_then(|values| u32::try_from(values[14]).ok())
            .filter(|pid| *pid > 1)
    }
    pub fn merge(&self, target: &mut Value) {
        if let Some(values) = self.sample {
            for (name, value) in NATIVE_NAMES.into_iter().zip(values) {
                if name == "net_ipc_readable_bytes" && value == u64::MAX {
                    continue;
                }
                target[name] = json!(value);
            }
            target["native_sample_age_seconds"] = json!(self.sampled.elapsed().as_secs_f64());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn telemetry_rejects_bad_size_and_version() {
        let (tx, rx) = std::os::unix::net::UnixDatagram::pair().unwrap();
        rx.set_nonblocking(true).unwrap();
        let mut metrics = NativeMetrics::new(rx);
        let mut packet = [0; 216];
        packet[..8].copy_from_slice(b"HVFM\x02\x1a\0\0");
        packet[8..16].copy_from_slice(&42u64.to_le_bytes());
        tx.send(&packet[..127]).unwrap();
        let mut oversized = packet.to_vec();
        oversized.push(0);
        tx.send(&oversized).unwrap();
        packet[4] = 3;
        tx.send(&packet).unwrap();
        metrics.poll();
        let mut value = json!({});
        metrics.merge(&mut value);
        assert!(value.as_object().unwrap().is_empty());
        packet[4] = 2;
        tx.send(&packet).unwrap();
        metrics.poll();
        metrics.merge(&mut value);
        assert_eq!(value["vcpu_0_exits_total"], 42);
    }
}
