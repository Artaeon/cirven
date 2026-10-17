//! Turning audit findings into numbered, reviewable steps.

use std::path::PathBuf;

use cirven_audit::{Host, Report};
use cirven_core::Severity;

/// sysctl.d files load in name order and later ones win; `99-zz` sorts after
/// distribution files such as `99-sysctl.conf`, so our values survive boot.
pub const SYSCTL_DROPIN: &str = "/etc/sysctl.d/99-zz-cirven.conf";
pub const SSHD_DROPIN: &str = "/etc/ssh/sshd_config.d/10-cirven.conf";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Files you own: applied as your user.
    User,
    /// System files: applied as root.
    System,
    /// Needs a decision or interaction only you can make; printed, never run.
    Manual,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Chmod {
        path: PathBuf,
        mode: u32,
    },
    /// Settings merged into a file cirven owns. Existing lines for other keys stay.
    DropIn {
        path: PathBuf,
        settings: Vec<(String, String)>,
        sep: &'static str,
    },
    /// Also written to /proc/sys so the change takes effect without a reboot.
    Sysctl {
        settings: Vec<(String, i64)>,
    },
    Manual {
        command: String,
    },
}

#[derive(Debug, Clone)]
pub struct Step {
    pub scope: Scope,
    pub title: String,
    pub action: Action,
    pub findings: Vec<String>,
}

/// Resolve a path the way audit displays it (`~/x` or `/x`) back to the host.
fn resolve(host: &Host, shown: &str) -> PathBuf {
    match shown.strip_prefix("~/") {
        Some(rel) => host.home(rel),
        None if shown == "~" => host.home(""),
        None => host.sys(shown),
    }
}

/// sshd keyword for each ssh finding harden can fix with a drop-in.
const SSHD_FIXES: &[(&str, &str, &str)] = &[
    ("ssh.password-auth", "PasswordAuthentication", "no"),
    ("ssh.kbd-interactive", "KbdInteractiveAuthentication", "no"),
    ("ssh.root-login", "PermitRootLogin", "no"),
    ("ssh.empty-passwords", "PermitEmptyPasswords", "no"),
    ("ssh.x11-forwarding", "X11Forwarding", "no"),
];

/// Finding ids fixed by tightening a mode, with the mode to set.
const CHMOD_FIXES: &[(&str, u32)] = &[
    ("ssh.dir-perms", 0o700),
    ("ssh.key-perms", 0o600),
    ("desktop.gnupg-perms", 0o700),
    ("desktop.home-open", 0o700),
    ("secrets.credential-store", 0o600),
];

pub fn build(host: &Host, report: &Report) -> Vec<Step> {
    let mut steps = Vec::new();

    for f in &report.findings {
        let Some((_, mode)) = CHMOD_FIXES.iter().find(|(id, _)| *id == f.id) else {
            continue;
        };
        let Some(shown) = f.location.as_deref() else {
            continue;
        };
        let shown = shown.split(':').next().unwrap_or(shown);
        let path = resolve(host, shown);
        // A credential store finding is about plaintext; only a loose mode is ours to fix.
        if host.mode(&path).is_none_or(|m| m & 0o077 == 0) {
            continue;
        }
        steps.push(Step {
            scope: Scope::User,
            title: format!("chmod {mode:o} {shown}"),
            action: Action::Chmod { path, mode: *mode },
            findings: vec![f.id.clone()],
        });
    }

    let sysctls: Vec<(String, i64, String)> = report
        .findings
        .iter()
        .filter_map(|f| {
            let key = f.id.strip_prefix("sysctl.")?;
            Some((
                key.to_string(),
                cirven_audit::sysctl_target(key)?,
                f.id.clone(),
            ))
        })
        .collect();
    if !sysctls.is_empty() {
        steps.push(Step {
            scope: Scope::System,
            title: format!(
                "set {} in {SYSCTL_DROPIN} and live",
                sysctls
                    .iter()
                    .map(|(k, v, _)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            action: Action::Sysctl {
                settings: sysctls.iter().map(|(k, v, _)| (k.clone(), *v)).collect(),
            },
            findings: sysctls.into_iter().map(|(_, _, id)| id).collect(),
        });
    }

    // Only sshd findings that matter: a dormant sshd is reported as info and left alone.
    let sshd: Vec<(&str, &str, String)> = report
        .findings
        .iter()
        .filter(|f| f.severity > Severity::Info)
        .filter_map(|f| {
            let (_, key, value) = SSHD_FIXES.iter().find(|(id, _, _)| *id == f.id)?;
            Some((*key, *value, f.id.clone()))
        })
        .collect();
    if !sshd.is_empty() {
        let included = host.read_sys("/etc/ssh/sshd_config").is_some_and(|c| {
            c.lines()
                .any(|l| l.trim().starts_with("Include") && l.contains("sshd_config.d"))
        });
        let title = sshd
            .iter()
            .map(|(k, v, _)| format!("{k} {v}"))
            .collect::<Vec<_>>()
            .join(", ");
        let findings = sshd.iter().map(|(_, _, id)| id.clone()).collect();
        steps.push(if included {
            Step {
                scope: Scope::System,
                title: format!("sshd: {title} in {SSHD_DROPIN} (takes effect on sshd reload)"),
                action: Action::DropIn {
                    path: host.sys(SSHD_DROPIN),
                    settings: sshd.iter().map(|(k, v, _)| (k.to_string(), v.to_string())).collect(),
                    sep: " ",
                },
                findings,
            }
        } else {
            Step {
                scope: Scope::Manual,
                title: format!("sshd: {title}"),
                action: Action::Manual {
                    command: "sshd_config does not include sshd_config.d; edit /etc/ssh/sshd_config by hand".into(),
                },
                findings,
            }
        });
    }

    // Everything else with a remedy is advice: printed, never executed.
    let automated: Vec<String> = steps.iter().flat_map(|s| s.findings.clone()).collect();
    for f in &report.findings {
        if f.severity < Severity::Low || automated.contains(&f.id) || f.id.starts_with("sysctl.") {
            continue;
        }
        let Some(remedy) = &f.remedy else { continue };
        let title = match &f.location {
            Some(at) => format!("{} ({at})", f.title),
            None => f.title.clone(),
        };
        steps.push(Step {
            scope: Scope::Manual,
            title,
            action: Action::Manual {
                command: remedy.clone(),
            },
            findings: vec![f.id.clone()],
        });
    }
    steps
}

/// Parse `--apply` input: `all` or comma-separated step numbers (1-based).
pub fn select(spec: &str, steps: &[Step]) -> Result<Vec<usize>, String> {
    let runnable = |i: usize| steps[i].scope != Scope::Manual;
    if spec == "all" {
        return Ok((0..steps.len()).filter(|&i| runnable(i)).collect());
    }
    let mut picked = Vec::new();
    for part in spec.split(',') {
        let n: usize = part
            .trim()
            .parse()
            .map_err(|_| format!("not a step number: {part}"))?;
        if n == 0 || n > steps.len() {
            return Err(format!("no step {n}; the plan has {}", steps.len()));
        }
        if !runnable(n - 1) {
            return Err(format!("step {n} is manual; run its command yourself"));
        }
        if !picked.contains(&(n - 1)) {
            picked.push(n - 1);
        }
    }
    Ok(picked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cirven_core::Finding;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn fixture() -> (tempfile::TempDir, Host) {
        let dir = tempfile::tempdir().unwrap();
        let host = Host::at(dir.path(), "home/u");
        fs::create_dir_all(host.home(".ssh")).unwrap();
        fs::set_permissions(host.home(".ssh"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir_all(host.sys("/etc/ssh")).unwrap();
        fs::write(
            host.sys("/etc/ssh/sshd_config"),
            "Include /etc/ssh/sshd_config.d/*.conf\n",
        )
        .unwrap();
        (dir, host)
    }

    fn report(findings: Vec<Finding>) -> Report {
        Report {
            findings,
            ..Report::default()
        }
    }

    #[test]
    fn maps_findings_to_steps() {
        let (_d, host) = fixture();
        let r = report(vec![
            Finding::new("ssh.dir-perms", Severity::Medium, "x").at("~/.ssh"),
            Finding::new("sysctl.kernel.kptr_restrict", Severity::Low, "x"),
            Finding::new("sysctl.dev.tty.ldisc_autoload", Severity::Low, "x"),
            Finding::new("ssh.password-auth", Severity::High, "x"),
            Finding::new("ssh.key-no-passphrase", Severity::Medium, "key")
                .at("~/.ssh/id")
                .remedy("ssh-keygen -p"),
        ]);
        let steps = build(&host, &r);
        let scopes: Vec<_> = steps.iter().map(|s| s.scope).collect();
        assert_eq!(
            scopes,
            [Scope::User, Scope::System, Scope::System, Scope::Manual]
        );
        assert_eq!(
            steps[0].action,
            Action::Chmod {
                path: host.home(".ssh"),
                mode: 0o700
            }
        );
        assert_eq!(
            steps[1].action,
            Action::Sysctl {
                settings: vec![
                    ("kernel.kptr_restrict".into(), 1),
                    ("dev.tty.ldisc_autoload".into(), 0)
                ]
            }
        );
        assert!(
            matches!(&steps[2].action, Action::DropIn { settings, .. } if settings[0].0 == "PasswordAuthentication")
        );
        assert_eq!(
            steps[3].action,
            Action::Manual {
                command: "ssh-keygen -p".into()
            }
        );
    }

    #[test]
    fn dormant_sshd_is_left_alone() {
        let (_d, host) = fixture();
        let r = report(vec![
            Finding::new("ssh.password-auth", Severity::Info, "x").remedy("y"),
        ]);
        assert!(build(&host, &r).is_empty());
    }

    #[test]
    fn already_tight_modes_produce_no_step() {
        let (_d, host) = fixture();
        fs::set_permissions(host.home(".ssh"), fs::Permissions::from_mode(0o700)).unwrap();
        let r = report(vec![
            Finding::new("ssh.dir-perms", Severity::Medium, "x").at("~/.ssh"),
        ]);
        assert!(build(&host, &r).is_empty());
    }

    #[test]
    fn selection_rejects_manual_and_unknown_steps() {
        let (_d, host) = fixture();
        let r = report(vec![
            Finding::new("ssh.dir-perms", Severity::Medium, "x").at("~/.ssh"),
            Finding::new("boot.secure-boot", Severity::Medium, "x").remedy("sbctl"),
        ]);
        let steps = build(&host, &r);
        assert_eq!(select("all", &steps), Ok(vec![0]));
        assert_eq!(select("1,1", &steps), Ok(vec![0]));
        assert!(select("2", &steps).unwrap_err().contains("manual"));
        assert!(select("3", &steps).is_err());
        assert!(select("x", &steps).is_err());
    }
}
