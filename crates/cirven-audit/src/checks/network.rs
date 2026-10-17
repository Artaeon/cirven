//! Listening TCP sockets and the boot-time firewall.

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use cirven_core::{Finding, Severity};

use super::Context;
use crate::report::Report;
use cirven_core::Host;

#[derive(Debug, Clone)]
pub struct Listener {
    pub addr: IpAddr,
    pub port: u16,
    pub inode: u64,
    /// Command line of the owning process, when it is ours to read.
    pub process: Option<String>,
}

impl Listener {
    /// Bound to every interface, so reachable from any network the machine joins.
    pub fn exposed(&self) -> bool {
        self.addr.is_unspecified()
    }
}

/// Parse `/proc/net/tcp` or `/proc/net/tcp6`, keeping sockets in LISTEN state.
pub fn parse_proc_tcp(text: &str, v6: bool) -> Vec<Listener> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 || f[3] != "0A" {
                return None;
            }
            let (addr, port) = f[1].split_once(':')?;
            let addr = if v6 {
                parse_v6(addr)?
            } else {
                IpAddr::V4(parse_v4(addr)?)
            };
            Some(Listener {
                addr,
                port: u16::from_str_radix(port, 16).ok()?,
                inode: f[9].parse().ok()?,
                process: None,
            })
        })
        .collect()
}

/// The kernel prints each 32-bit word in host (little-endian) byte order.
fn parse_v4(hex: &str) -> Option<Ipv4Addr> {
    Some(Ipv4Addr::from(
        u32::from_str_radix(hex, 16).ok()?.to_le_bytes(),
    ))
}

fn parse_v6(hex: &str) -> Option<IpAddr> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let word = u32::from_str_radix(&hex[i * 8..i * 8 + 8], 16).ok()?;
        bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    let addr = Ipv6Addr::from(bytes);
    Some(match addr.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(addr),
    })
}

/// Socket inode to command line, for every process whose fds we may read.
fn socket_owners(host: &Host) -> HashMap<u64, String> {
    let mut owners = HashMap::new();
    for pid in host.pids() {
        let Ok(fds) = fs::read_dir(pid.join("fd")) else {
            continue;
        };
        let mut cmdline = None;
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let target = target.to_string_lossy();
            let Some(inode) = target
                .strip_prefix("socket:[")
                .and_then(|t| t.strip_suffix(']'))
                .and_then(|t| t.parse::<u64>().ok())
            else {
                continue;
            };
            let cmd = cmdline.get_or_insert_with(|| {
                let raw = fs::read(pid.join("cmdline")).unwrap_or_default();
                let text = String::from_utf8_lossy(&raw).replace('\0', " ");
                text.trim().chars().take(80).collect::<String>()
            });
            owners.insert(inode, cmd.clone());
        }
    }
    owners
}

pub fn listeners(host: &Host) -> Vec<Listener> {
    let mut all = Vec::new();
    for (file, v6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        if let Some(text) = host.read_sys(file) {
            all.extend(parse_proc_tcp(&text, v6));
        }
    }
    let owners = socket_owners(host);
    for l in &mut all {
        l.process = owners.get(&l.inode).cloned();
    }
    all
}

/// The firewall that starts at boot, if any. Its rules need root to read.
pub fn firewall(host: &Host) -> Option<&'static str> {
    let ufw_on = host
        .read_sys("/etc/ufw/ufw.conf")
        .is_some_and(|c| c.lines().any(|l| l.trim() == "ENABLED=yes"));
    if ufw_on && host.unit_enabled("ufw.service") {
        return Some("ufw");
    }
    [
        ("nftables.service", "nftables"),
        ("firewalld.service", "firewalld"),
        ("iptables.service", "iptables"),
    ]
    .into_iter()
    .find(|(unit, _)| host.unit_enabled(unit))
    .map(|(_, name)| name)
}

pub fn check(_host: &Host, ctx: &Context, report: &mut Report) {
    // One finding per port and owner: dual-stack servers bind both 0.0.0.0 and ::.
    let mut exposed: Vec<&Listener> = Vec::new();
    for l in ctx.listeners.iter().filter(|l| l.exposed()) {
        if !exposed
            .iter()
            .any(|e| e.port == l.port && e.process == l.process)
        {
            exposed.push(l);
        }
    }
    exposed.sort_by_key(|l| l.port);

    match ctx.firewall {
        Some(name) => report.pass(format!(
            "firewall enabled at boot ({name}); rules need root to inspect"
        )),
        None => {
            let mut f = Finding::new(
                "net.no-firewall",
                if exposed.is_empty() {
                    Severity::Medium
                } else {
                    Severity::High
                },
                "no firewall enabled at boot",
            )
            .remedy("ufw default deny incoming && systemctl enable --now ufw");
            if !exposed.is_empty() {
                f = f.path("every service below is reachable from any network you join");
            }
            report.find(f);
        }
    }

    if exposed.is_empty() {
        report.pass("no tcp services listening on all interfaces");
    }
    for l in exposed {
        let process = l
            .process
            .as_deref()
            .unwrap_or("owner not visible without root");
        let serves_files = process.contains("http.server") || process.contains("SimpleHTTPServer");
        let mut severity = if ctx.firewall.is_some() {
            Severity::Low
        } else {
            Severity::Medium
        };
        if serves_files {
            severity = if ctx.firewall.is_some() {
                Severity::Medium
            } else {
                Severity::High
            };
        }
        let mut f = Finding::new(
            "net.exposed-listener",
            severity,
            format!("tcp port {} open on all interfaces", l.port),
        )
        .at(format!("{} · {process}", sock(l)))
        .remedy("bind it to 127.0.0.1, or stop it if unused");
        if serves_files {
            f = f.path("a dev file server: anyone on the same network can browse and download the directory");
        } else if ctx.firewall.is_some() {
            f = f.path("reachable unless the firewall blocks this port");
        }
        report.find(f);
    }
}

fn sock(l: &Listener) -> String {
    match l.addr {
        IpAddr::V4(a) => format!("{a}:{}", l.port),
        IpAddr::V6(a) => format!("[{a}]:{}", l.port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 3600007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   975        0 4809 1 0 100 0 0 10 5
   1: 00000000:113C 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 331610 1 0 100 0 0 10 0
   2: 0100007F:1F40 0100007F:9C40 01 00000000:00000000 00:00000000 00000000  1000        0 0 1 0 100 0 0 10 0
";
    const TCP6: &str = "  sl  local_address remote_address st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 900 1 0 100 0 0 10 0
   1: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 901 1 0 100 0 0 10 0
";

    #[test]
    fn parses_ipv4_listeners_only() {
        let l = parse_proc_tcp(TCP, false);
        assert_eq!(l.len(), 2, "established socket must be skipped");
        assert_eq!(l[0].addr, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 54)));
        assert_eq!(l[0].port, 53);
        assert!(!l[0].exposed());
        assert_eq!(l[1].port, 4412);
        assert_eq!(l[1].inode, 331610);
        assert!(l[1].exposed());
    }

    #[test]
    fn parses_ipv6_any_and_loopback() {
        let l = parse_proc_tcp(TCP6, true);
        assert_eq!(l[0].port, 22);
        assert!(l[0].exposed());
        assert_eq!(l[1].addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(l[1].port, 631);
    }

    fn ctx(firewall: Option<&'static str>, process: &str) -> Context {
        Context {
            listeners: vec![Listener {
                addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                port: 4412,
                inode: 1,
                process: Some(process.into()),
            }],
            firewall,
            ..Context::default()
        }
    }

    #[test]
    fn file_server_without_firewall_is_high() {
        let host = Host::at("/nonexistent", "home/u");
        let mut r = Report::default();
        check(&host, &ctx(None, "python3 -m http.server 4412"), &mut r);
        assert!(r.findings.iter().all(|f| f.severity == Severity::High));
        assert_eq!(r.findings.len(), 2);
    }

    #[test]
    fn firewall_lowers_exposure() {
        let host = Host::at("/nonexistent", "home/u");
        let mut r = Report::default();
        check(&host, &ctx(Some("ufw"), "node server.js"), &mut r);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].severity, Severity::Low);
    }

    #[test]
    fn detects_ufw_from_config_and_unit() {
        let dir = tempfile::tempdir().unwrap();
        let host = Host::at(dir.path(), "home/u");
        assert_eq!(firewall(&host), None);
        fs::create_dir_all(host.sys("/etc/ufw")).unwrap();
        fs::write(host.sys("/etc/ufw/ufw.conf"), "ENABLED=yes\n").unwrap();
        assert_eq!(firewall(&host), None, "config alone is not enough");
        let wants = host.sys("/etc/systemd/system/multi-user.target.wants");
        fs::create_dir_all(&wants).unwrap();
        std::os::unix::fs::symlink(
            "/usr/lib/systemd/system/ufw.service",
            wants.join("ufw.service"),
        )
        .unwrap();
        assert_eq!(firewall(&host), Some("ufw"));
    }
}
