// SPDX-License-Identifier: Apache-2.0
//! Versioned, explicit permissions. Wildcard binds are listeners only, never destinations.
use crate::Result;
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::net::Ipv4Addr;
use std::path::Path;

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Mode {
    #[default]
    Hardened,
    Development,
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Protocol {
    Tcp,
    Udp,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub(crate) struct Endpoint {
    pub protocol: Protocol,
    pub address: Ipv4Addr,
    pub port: u16,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Resolver {
    pub address: Ipv4Addr,
    pub port: u16,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Security {
    pub version: u32,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub egress: Vec<Endpoint>,
    #[serde(default)]
    pub listeners: Vec<Endpoint>,
    pub dns: Option<Resolver>,
    #[serde(default)]
    pub unix_stream: Option<std::path::PathBuf>,
}
impl Default for Security {
    fn default() -> Self {
        Self {
            version: 1,
            mode: Mode::Hardened,
            egress: Vec::new(),
            listeners: Vec::new(),
            dns: None,
            unix_stream: None,
        }
    }
}
fn endpoint(address: Ipv4Addr, port: u16) -> Result<()> {
    if port == 0 || address.octets()[0] == 0 || address.octets()[0] >= 224 {
        return Err(
            "security endpoints require a concrete unicast IPv4 address and nonzero port".into(),
        );
    }
    Ok(())
}
impl Security {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err("unsupported security version".into());
        }
        for (list, listener) in [(&self.egress, false), (&self.listeners, true)] {
            if list.len() > 64 {
                return Err("at most 64 security endpoints per list".into());
            }
            let mut seen = std::collections::BTreeSet::new();
            for rule in list {
                // INADDR_ANY is an explicit bind capability, not a wildcard
                // destination or a match for every concrete listener address.
                if !(listener && rule.address.is_unspecified() && rule.port != 0) {
                    endpoint(rule.address, rule.port)?;
                }
                if !seen.insert(rule) {
                    return Err("duplicate security endpoint".into());
                }
            }
        }
        if let Some(dns) = &self.dns {
            endpoint(dns.address, dns.port)?;
        }
        if self.mode == Mode::Development
            && (!self.egress.is_empty() || !self.listeners.is_empty() || self.dns.is_some())
        {
            return Err("development mode cannot imply enforcement of permission lists".into());
        }
        Ok(())
    }
    pub fn permits_listener(&self, protocol: &str, address: Ipv4Addr, port: u16) -> bool {
        self.mode == Mode::Development
            || self.listeners.iter().any(|r| {
                r.address == address
                    && r.port == port
                    && match r.protocol {
                        Protocol::Tcp => protocol == "tcp",
                        Protocol::Udp => protocol == "udp",
                    }
            })
    }
}
#[repr(C)]
pub(crate) struct NativeEndpoint {
    udp: u32,
    address: [u8; 4],
    port: u16,
}
#[repr(C)]
pub(crate) struct NativeSecurity {
    development: u32,
    egress_count: u32,
    listener_count: u32,
    dns_address: [u8; 4],
    dns_port: u16,
    egress: *const NativeEndpoint,
    listeners: *const NativeEndpoint,
    vmm_profile: *const std::ffi::c_char,
    broker_profile: *const std::ffi::c_char,
}
pub(crate) struct Policy {
    pub native: NativeSecurity,
    _egress: Vec<NativeEndpoint>,
    _listeners: Vec<NativeEndpoint>,
    _vmm: CString,
    _broker: CString,
}
fn quoted_path(path: &Path) -> Result<String> {
    let path = std::fs::canonicalize(path)?;
    let value = path.to_str().ok_or("security paths must be UTF-8")?;
    if value.chars().any(char::is_control) {
        return Err("security paths may not contain control characters".into());
    }
    Ok(serde_json::to_string(value)?)
}
impl Policy {
    pub fn new(config: &Security, work: &Path, _drives: &[crate::Drive]) -> Result<Self> {
        config.validate()?;
        // The VMM operates on already-open disk descriptors and its private
        // work root. It never reopens host disk paths by name after the
        // sandbox is installed, so no literal grants are issued: re-canonicalizing
        // a mutable disk path here would re-authorize a replacement target.
        let vmm = format!(
            "(version 1)(deny default)(allow file-read* file-write* (subpath {}))",
            quoted_path(work)?
        );
        let broker = if let Some(path) = &config.unix_stream {
            let parent = path.parent().ok_or("missing socket parent")?;
            use std::os::unix::fs::MetadataExt;
            let metadata = std::fs::metadata(parent)?;
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
                return Err("Unix stream socket parent must be owned and private (0700)".into());
            }
            let resolved =
                std::fs::canonicalize(parent)?.join(path.file_name().ok_or("missing socket name")?);
            let literal = serde_json::to_string(resolved.to_str().ok_or("invalid socket path")?)?;
            format!(
                "(version 1)(deny default)(allow file-read-metadata (literal {literal}))(allow network-outbound (remote unix-socket (path {literal})))"
            )
        } else {
            "(version 1)(deny default)".to_string()
        };
        let make = |rules: &[Endpoint]| {
            rules
                .iter()
                .map(|r| NativeEndpoint {
                    udp: (r.protocol == Protocol::Udp).into(),
                    address: r.address.octets(),
                    port: r.port,
                })
                .collect::<Vec<_>>()
        };
        let egress = make(&config.egress);
        let listeners = make(&config.listeners);
        let vmm = CString::new(vmm)?;
        let broker = CString::new(broker)?;
        let native = NativeSecurity {
            development: (config.mode == Mode::Development).into(),
            egress_count: egress.len() as u32,
            listener_count: listeners.len() as u32,
            dns_address: config
                .dns
                .as_ref()
                .map(|d| d.address.octets())
                .unwrap_or([0; 4]),
            dns_port: config.dns.as_ref().map(|d| d.port).unwrap_or(0),
            egress: egress.as_ptr(),
            listeners: listeners.as_ptr(),
            vmm_profile: vmm.as_ptr(),
            broker_profile: broker.as_ptr(),
        };
        Ok(Self {
            native,
            _egress: egress,
            _listeners: listeners,
            _vmm: vmm,
            _broker: broker,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_denies_and_development_is_explicit() {
        let policy = Security::default();
        policy.validate().unwrap();
        assert!(!policy.permits_listener("tcp", Ipv4Addr::LOCALHOST, 80));
        let mut dev = policy;
        dev.mode = Mode::Development;
        assert!(dev.permits_listener("tcp", Ipv4Addr::LOCALHOST, 80));
        dev.egress.push(Endpoint {
            protocol: Protocol::Tcp,
            address: Ipv4Addr::LOCALHOST,
            port: 80,
        });
        assert!(dev.validate().is_err());
    }
    #[test]
    fn wildcard_is_only_an_exact_listener_bind() {
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            let mut policy = Security::default();
            policy.listeners.push(Endpoint {
                protocol,
                address: Ipv4Addr::UNSPECIFIED,
                port: 8080,
            });
            policy.validate().unwrap();
            let proto = if protocol == Protocol::Tcp {
                "tcp"
            } else {
                "udp"
            };
            assert!(policy.permits_listener(proto, Ipv4Addr::UNSPECIFIED, 8080));
            assert!(!policy.permits_listener(proto, Ipv4Addr::LOCALHOST, 8080));
            assert!(!policy.permits_listener(proto, Ipv4Addr::UNSPECIFIED, 8081));
            assert!(!policy.permits_listener(
                if proto == "tcp" { "udp" } else { "tcp" },
                Ipv4Addr::UNSPECIFIED,
                8080
            ));
            policy.egress = policy.listeners.clone();
            assert!(policy.validate().is_err());
            policy.egress.clear();
            policy.dns = Some(Resolver {
                address: Ipv4Addr::UNSPECIFIED,
                port: 53,
            });
            assert!(policy.validate().is_err());
            policy.dns = None;
            for address in ["0.0.0.1", "224.0.0.1", "255.255.255.255"] {
                policy.listeners[0].address = address.parse().unwrap();
                assert!(policy.validate().is_err());
            }
            policy.listeners[0].address = Ipv4Addr::UNSPECIFIED;
            policy.listeners[0].port = 0;
            assert!(policy.validate().is_err());
            policy.listeners[0].port = 8080;
            policy.listeners[0].address = Ipv4Addr::LOCALHOST;
            policy.validate().unwrap();
            assert!(policy.permits_listener(proto, Ipv4Addr::LOCALHOST, 8080));
            assert!(!policy.permits_listener(proto, Ipv4Addr::UNSPECIFIED, 8080));
        }
    }
    #[test]
    fn rejects_wildcards_versions_and_duplicates() {
        let mut policy = Security {
            version: 2,
            ..Security::default()
        };
        assert!(policy.validate().is_err());
        policy.version = 1;
        policy.egress.push(Endpoint {
            protocol: Protocol::Tcp,
            address: Ipv4Addr::UNSPECIFIED,
            port: 80,
        });
        assert!(policy.validate().is_err());
        policy.egress[0].address = Ipv4Addr::LOCALHOST;
        policy.egress.push(policy.egress[0].clone());
        assert!(policy.validate().is_err());
    }
}
