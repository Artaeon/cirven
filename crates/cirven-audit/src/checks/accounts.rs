//! Who can become root, and how easily.

use std::fs;

use cirven_core::{Finding, Severity};

use super::Context;
use crate::host::Host;
use crate::report::Report;

fn extra_root_accounts(host: &Host, report: &mut Report) {
    let Some(passwd) = host.read_sys("/etc/passwd") else {
        return;
    };
    let extra: Vec<&str> = passwd
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() > 3 && f[2] == "0" && f[0] != "root").then_some(f[0])
        })
        .collect();
    if extra.is_empty() {
        report.pass("root is the only uid 0 account");
    } else {
        report.find(
            Finding::new(
                "accounts.uid0",
                Severity::Critical,
                format!("extra uid 0 account: {}", extra.join(", ")),
            )
            .at("/etc/passwd")
            .path("a second root account is a classic backdoor")
            .remedy("remove the account unless you created it on purpose"),
        );
    }
}

fn shadow(host: &Host, report: &mut Report) {
    let path = host.sys("/etc/shadow");
    if host.mode(&path).is_some_and(|m| m & 0o004 != 0) {
        report.find(
            Finding::new(
                "accounts.shadow-readable",
                Severity::Critical,
                "/etc/shadow is world-readable",
            )
            .path("every user can copy the password hashes and crack them offline")
            .remedy("chmod 600 /etc/shadow"),
        );
    }
}

fn sudoers(host: &Host, report: &mut Report) {
    let mut files = vec![host.sys("/etc/sudoers")];
    let dir = host.sys("/etc/sudoers.d");
    let dir_readable = match fs::read_dir(&dir) {
        Ok(entries) => {
            let mut more: Vec<_> = entries.flatten().map(|e| e.path()).collect();
            more.sort();
            files.extend(more);
            true
        }
        Err(_) => !dir.exists(),
    };
    let mut read_any = false;
    for file in &files {
        let Ok(text) = host.read(file) else { continue };
        read_any = true;
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.starts_with('#') || !line.contains("NOPASSWD") {
                continue;
            }
            report.find(
                Finding::new(
                    "accounts.nopasswd",
                    Severity::Medium,
                    "passwordless sudo rule",
                )
                .at(format!("{}:{}", host.display(file), n + 1))
                .path("any process running as you can become root without asking")
                .remedy("drop NOPASSWD, or limit it to specific harmless commands"),
            );
        }
    }
    if !read_any || !dir_readable {
        report
            .skip("sudo rules: /etc/sudoers.d is readable only by root (run with sudo to include)");
    }
}

pub fn check(host: &Host, _ctx: &Context, report: &mut Report) {
    extra_root_accounts(host, report);
    shadow(host, report);
    sudoers(host, report);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn finds_backdoor_uid0_and_nopasswd() {
        let dir = tempfile::tempdir().unwrap();
        let host = Host::at(dir.path(), "home/u");
        fs::create_dir_all(host.sys("/etc/sudoers.d")).unwrap();
        fs::write(
            host.sys("/etc/passwd"),
            "root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/:/bin/sh\nu:x:1000:1000::/home/u:/bin/zsh\n",
        )
        .unwrap();
        fs::write(host.sys("/etc/shadow"), "root:!:1::::::\n").unwrap();
        fs::set_permissions(host.sys("/etc/shadow"), fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(
            host.sys("/etc/sudoers"),
            "# %wheel ALL=(ALL) NOPASSWD: ALL\n",
        )
        .unwrap();
        fs::write(
            host.sys("/etc/sudoers.d/10-u"),
            "u ALL=(ALL) NOPASSWD: ALL\n",
        )
        .unwrap();
        let mut r = Report::default();
        check(&host, &Context::default(), &mut r);
        let ids: Vec<_> = r.findings.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "accounts.uid0",
                "accounts.shadow-readable",
                "accounts.nopasswd"
            ]
        );
        assert_eq!(
            r.findings[2].location.as_deref(),
            Some("/etc/sudoers.d/10-u:1")
        );
        assert!(r.skipped.is_empty());
    }
}
