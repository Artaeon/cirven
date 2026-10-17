//! Kernel hardening sysctls a desktop can enable without breaking anything.

use cirven_core::{Finding, Severity};

use super::Context;
use crate::report::Report;
use cirven_core::Host;

pub struct Sysctl {
    pub key: &'static str,
    /// Smallest acceptable value; the recommended one when it is not met.
    pub min: i64,
    pub severity: Severity,
    pub why: &'static str,
}

/// Every entry here is safe on a workstation: harden applies these values.
pub const SYSCTLS: &[Sysctl] = &[
    Sysctl {
        key: "kernel.yama.ptrace_scope",
        min: 1,
        severity: Severity::Medium,
        why: "any process of yours can read the memory of every other: ssh-agent, password manager, browser",
    },
    Sysctl {
        key: "kernel.unprivileged_bpf_disabled",
        min: 1,
        severity: Severity::Medium,
        why: "unprivileged eBPF is a recurring source of local root exploits",
    },
    Sysctl {
        key: "fs.protected_symlinks",
        min: 1,
        severity: Severity::Medium,
        why: "symlink races in shared directories like /tmp become privilege escalation",
    },
    Sysctl {
        key: "fs.protected_hardlinks",
        min: 1,
        severity: Severity::Medium,
        why: "hardlinks to files you do not own enable privilege escalation",
    },
    Sysctl {
        key: "kernel.kptr_restrict",
        min: 1,
        severity: Severity::Low,
        why: "kernel addresses are visible, which makes kernel exploits reliable",
    },
    Sysctl {
        key: "kernel.dmesg_restrict",
        min: 1,
        severity: Severity::Low,
        why: "the kernel log leaks addresses and hardware details to any user",
    },
    Sysctl {
        key: "fs.protected_fifos",
        min: 1,
        severity: Severity::Low,
        why: "fifos in world-writable directories can be hijacked",
    },
    Sysctl {
        key: "fs.protected_regular",
        min: 1,
        severity: Severity::Low,
        why: "regular files in world-writable directories can be hijacked",
    },
    Sysctl {
        key: "kernel.perf_event_paranoid",
        min: 2,
        severity: Severity::Low,
        why: "unprivileged perf exposes kernel profiling data and attack surface",
    },
    Sysctl {
        key: "dev.tty.ldisc_autoload",
        min: 0,
        severity: Severity::Low,
        why: "unprivileged users can autoload old tty line disciplines with known bugs",
    },
    Sysctl {
        key: "net.ipv4.tcp_syncookies",
        min: 1,
        severity: Severity::Low,
        why: "syn floods can exhaust connections",
    },
];

/// Sysctls where lower is safer, with their maximum acceptable value.
const AT_MOST: &[(&str, i64)] = &[("dev.tty.ldisc_autoload", 0)];

pub fn read(host: &Host, key: &str) -> Option<i64> {
    host.read_sys(&format!("/proc/sys/{}", key.replace('.', "/")))?
        .trim()
        .parse()
        .ok()
}

/// Whether the current value of `s` is acceptable.
pub fn ok(s: &Sysctl, value: i64) -> bool {
    match AT_MOST.iter().find(|(k, _)| *k == s.key) {
        Some((_, max)) => value <= *max,
        None => value >= s.min,
    }
}

pub fn check(host: &Host, _ctx: &Context, report: &mut Report) {
    let mut good = 0;
    for s in SYSCTLS {
        let Some(value) = read(host, s.key) else {
            continue;
        };
        if ok(s, value) {
            good += 1;
            continue;
        }
        report.find(
            Finding::new(
                format!("sysctl.{}", s.key),
                s.severity,
                format!("{} = {value}", s.key),
            )
            .path(s.why)
            .remedy(format!("sysctl {}={}", s.key, s.min)),
        );
    }
    if good > 0 {
        report.pass(format!(
            "{good}/{} kernel hardening sysctls set",
            SYSCTLS.len()
        ));
    }
    // suid core dumps: 1 writes root-owned memory to dumps readable by the user.
    if read(host, "fs.suid_dumpable") == Some(1) {
        report.find(
            Finding::new(
                "sysctl.fs.suid_dumpable",
                Severity::Medium,
                "fs.suid_dumpable = 1",
            )
            .path("crashing setuid programs dump privileged memory where you can read it")
            .remedy("sysctl fs.suid_dumpable=0"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn set(host: &Host, key: &str, v: i64) {
        let p = host.sys(&format!("/proc/sys/{}", key.replace('.', "/")));
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, format!("{v}\n")).unwrap();
    }

    #[test]
    fn reports_weak_values_only() {
        let dir = tempfile::tempdir().unwrap();
        let host = Host::at(dir.path(), "home/u");
        set(&host, "kernel.yama.ptrace_scope", 0);
        set(&host, "kernel.kptr_restrict", 2);
        set(&host, "kernel.perf_event_paranoid", 1);
        set(&host, "dev.tty.ldisc_autoload", 1);
        set(&host, "fs.suid_dumpable", 2);
        let mut r = Report::default();
        check(&host, &Context::default(), &mut r);
        let ids: Vec<_> = r.findings.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "sysctl.kernel.yama.ptrace_scope",
                "sysctl.kernel.perf_event_paranoid",
                "sysctl.dev.tty.ldisc_autoload"
            ]
        );
        assert_eq!(
            r.findings[2].remedy.as_deref(),
            Some("sysctl dev.tty.ldisc_autoload=0")
        );
        assert_eq!(r.passed, ["1/11 kernel hardening sysctls set"]);
    }
}
