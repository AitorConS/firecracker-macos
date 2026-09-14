// SPDX-License-Identifier: Apache-2.0
//! Hard file/descriptor ceilings and externally sampled group CPU/RSS.
use crate::Result;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
#[repr(C)]
struct Timebase {
    numer: u32,
    denom: u32,
}
unsafe extern "C" {
    fn mach_timebase_info(info: *mut Timebase) -> i32;
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Limits {
    pub version: u32,
    pub open_files: u64,
    pub file_size_bytes: u64,
    pub cpu_seconds: u64,
    pub rss_mib: u64,
    pub nice: i32,
    pub disk_bytes_per_second: u64,
    pub disk_operations_per_second: u64,
    pub network_bytes_per_second: u64,
    pub network_packets_per_second: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            version: 1,
            open_files: 1024,
            file_size_bytes: 16 << 30,
            cpu_seconds: 86400,
            rss_mib: 3072,
            nice: 5,
            disk_bytes_per_second: 256 << 20,
            disk_operations_per_second: 20000,
            network_bytes_per_second: 64 << 20,
            network_packets_per_second: 100000,
        }
    }
}
impl Limits {
    pub fn validate(&self) -> Result<()> {
        if !(1 << 20..=1 << 40).contains(&self.disk_bytes_per_second)
            || !(1..=1000000).contains(&self.disk_operations_per_second)
            || !(1 << 20..=1 << 40).contains(&self.network_bytes_per_second)
            || !(1..=1000000).contains(&self.network_packets_per_second)
        {
            return Err(
                "I/O limits require 1 MiB/s..1 TiB/s and 1..1000000 operations or packets/s".into(),
            );
        }
        if self.version != 1
            || !(64..=4096).contains(&self.open_files)
            || !(1 << 20..=1 << 40).contains(&self.file_size_bytes)
            || !(1..=31536000).contains(&self.cpu_seconds)
            || !(64..=16384).contains(&self.rss_mib)
            || !(0..=19).contains(&self.nice)
        {
            return Err("invalid limits v1: open_files 64..4096, file_size_bytes 1 MiB..1 TiB, cpu_seconds 1..31536000, rss_mib 64..16384, nice 0..19".into());
        }
        Ok(())
    }
    pub fn apply(&self) -> Result<()> {
        self.validate()?;
        let mut cpu = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // Finite RLIMIT_CPU stalls HVF on the validated host. Preserve inherited
        // restrictions and reject this setup; never silently remove a host limit.
        if unsafe { libc::getrlimit(libc::RLIMIT_CPU, &mut cpu) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if cpu.rlim_cur != libc::RLIM_INFINITY {
            return Err("HVF_UNSUPPORTED_INHERITED_CPU_LIMIT: finite RLIMIT_CPU is incompatible with this backend; use limits.cpu_seconds with the supervisor".into());
        }
        for (resource, value) in [
            (libc::RLIMIT_NOFILE, self.open_files),
            (libc::RLIMIT_FSIZE, self.file_size_bytes),
            (libc::RLIMIT_CORE, 0),
        ] {
            let limit = libc::rlimit {
                rlim_cur: value,
                rlim_max: value,
            };
            // SAFETY: valid immutable rlimit; only lowers ceilings in the VMM child.
            if unsafe { libc::setrlimit(resource, &limit) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        // SAFETY: changes only this process; descendants inherit the priority.
        if unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, self.nice) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
}
pub(crate) fn process(pid: u32) -> Option<libc::proc_taskinfo> {
    let mut info = std::mem::MaybeUninit::<libc::proc_taskinfo>::uninit();
    let size = std::mem::size_of::<libc::proc_taskinfo>() as i32;
    // SAFETY: writable buffer, initialized only when libproc returns its full size.
    if unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTASKINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    } == size
    {
        Some(unsafe { info.assume_init() })
    } else {
        None
    }
}
pub(crate) struct Watchdog {
    next: Instant,
    budget: u64,
    cpu_budget: u64,
    ticks: std::collections::BTreeMap<i32, u64>,
    pub cpu_ns: u64,
    pub rss_bytes: u64,
    pub samples: u64,
}
impl Watchdog {
    pub fn new(limits: &Limits) -> Self {
        Self {
            next: Instant::now(),
            budget: limits.rss_mib << 20,
            cpu_budget: limits.cpu_seconds * 1_000_000_000,
            ticks: Default::default(),
            cpu_ns: 0,
            rss_bytes: 0,
            samples: 0,
        }
    }
    // The supervisor holds an unreaped group leader Child while calling this.
    // Kernel group enumeration includes broker and authority; telemetry is untrusted.
    pub fn poll(&mut self, leader: u32) -> Option<String> {
        if Instant::now() < self.next {
            return None;
        }
        self.next = Instant::now() + Duration::from_millis(100);
        let mut pids = [0i32; 32];
        let size = std::mem::size_of_val(&pids) as i32;
        // PROC_PGRP_ONLY=2 is the public macOS 26 sys/proc_info.h selector.
        let n = unsafe { libc::proc_listpids(2, leader, pids.as_mut_ptr().cast(), size) };
        if n < 0 || n >= size || n % 4 != 0 {
            return Some(
                "RESOURCE_MONITOR_UNAVAILABLE: process group enumeration failed or overflowed"
                    .into(),
            );
        }
        let mut rss = 0u64;
        let mut ticks = std::collections::BTreeMap::new();
        let mut delta = 0u64;
        let mut timebase = Timebase { numer: 0, denom: 0 };
        if unsafe { mach_timebase_info(&mut timebase) } != 0 || timebase.denom == 0 {
            return Some("RESOURCE_MONITOR_UNAVAILABLE: clock conversion failed".into());
        }
        for &pid in &pids[..n as usize / 4] {
            if pid <= 0 {
                continue;
            }
            if let Some(info) = process(pid as u32) {
                rss = rss.saturating_add(info.pti_resident_size);
                let current = info.pti_total_user.saturating_add(info.pti_total_system);
                let previous = self.ticks.get(&pid).copied().unwrap_or(0);
                delta = delta.saturating_add(if current >= previous {
                    current - previous
                } else {
                    current
                });
                ticks.insert(pid, current);
            }
        }
        self.ticks = ticks;
        self.cpu_ns = self.cpu_ns.saturating_add(
            (u128::from(delta) * u128::from(timebase.numer) / u128::from(timebase.denom))
                .min(u128::from(u64::MAX)) as u64,
        );
        self.rss_bytes = rss;
        self.samples += 1;
        if self.cpu_ns >= self.cpu_budget {
            return Some(format!(
                "CPU_LIMIT_EXCEEDED: accumulated sampled group CPU {} ns; budget {} ns (reactive 100 ms sampling)",
                self.cpu_ns, self.cpu_budget
            ));
        }
        (rss>self.budget).then(||format!("RSS_LIMIT_EXCEEDED: process group uses {rss} bytes; budget {} bytes (reactive 100 ms sampling)",self.budget))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unsafe_limits() {
        let mut limits = Limits::default();
        limits.validate().unwrap();
        limits.nice = -1;
        assert!(limits.validate().is_err());
        limits.nice = 5;
        limits.open_files = 63;
        assert!(limits.validate().is_err());
        assert!(serde_json::from_str::<Limits>(r#"{"unexpected":1}"#).is_err());
    }
}
