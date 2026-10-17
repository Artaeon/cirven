//! The session itself: who can enter your home, and whether it locks when you walk away.

use std::fs;

use cirven_core::{Finding, Severity};

use super::Context;
use crate::report::Report;
use cirven_core::Host;

fn home_perms(host: &Host, report: &mut Report) {
    let home = host.home("");
    let Some(mode) = host.mode(&home) else { return };
    if mode & 0o005 != 0 {
        report.find(
            Finding::new(
                "desktop.home-open",
                Severity::Medium,
                format!("home directory is open to other users ({mode:o})"),
            )
            .at("~")
            .path("other accounts and services can read everything not explicitly locked down")
            .remedy("chmod 700 ~"),
        );
    } else {
        report.pass(format!("home directory closed to other users ({mode:o})"));
    }
    let gnupg = host.home(".gnupg");
    if host.mode(&gnupg).is_some_and(|m| m & 0o077 != 0) {
        report.find(
            Finding::new(
                "desktop.gnupg-perms",
                Severity::Medium,
                "~/.gnupg is accessible to other users",
            )
            .remedy("chmod 700 ~/.gnupg"),
        );
    }
}

fn running(host: &Host, comm: &str) -> bool {
    host.pids()
        .iter()
        .any(|p| fs::read_to_string(p.join("comm")).is_ok_and(|c| c.trim() == comm))
}

/// Omarchy's quickshell-based shell locks on idle itself, configured in
/// `~/.config/omarchy/shell.json` and defaulting to 300 seconds.
const OMARCHY_DEFAULT_LOCK: u64 = 300;

fn omarchy_lock(host: &Host, report: &mut Report) -> bool {
    let conf = host.home(".config/omarchy/shell.json");
    let Ok(text) = host.read(&conf) else {
        return false;
    };
    if !running(host, "quickshell") {
        return false;
    }
    let lock = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| v.get("idle")?.get("lock")?.as_u64())
        .unwrap_or(OMARCHY_DEFAULT_LOCK);
    if lock == 0 {
        report.find(
            Finding::new(
                "desktop.no-idle-lock",
                Severity::Medium,
                "omarchy shell never locks on idle",
            )
            .at(host.display(&conf))
            .path("an unlocked, unattended laptop is a logged-in shell for anyone nearby")
            .remedy("set idle.lock to e.g. 300 seconds"),
        );
    } else if lock > 900 {
        report.find(
            Finding::new(
                "desktop.slow-idle-lock",
                Severity::Low,
                format!("screen locks only after {} minutes idle", lock / 60),
            )
            .at(host.display(&conf))
            .remedy("set idle.lock to 300 seconds or less"),
        );
    } else {
        report.pass(format!("screen locks after {lock}s idle (omarchy shell)"));
    }
    true
}

fn screen_lock(host: &Host, report: &mut Report) {
    if !omarchy_lock(host, report) {
        hypridle_lock(host, report);
    }
}

fn hypridle_lock(host: &Host, report: &mut Report) {
    let conf = host.home(".config/hypr/hypridle.conf");
    let Ok(text) = host.read(&conf) else {
        if host.home(".config/hypr").exists() {
            report.find(
                Finding::new(
                    "desktop.no-idle-lock",
                    Severity::Medium,
                    "no idle lock configured",
                )
                .path("an unlocked, unattended laptop is a logged-in shell for anyone nearby")
                .remedy("configure hypridle with a lock listener"),
            );
        } else {
            report.skip("screen lock: only hyprland is supported so far");
        }
        return;
    };
    let locks = text.contains("lock_cmd")
        || text.contains("hyprlock")
        || text.contains("loginctl lock-session");
    let has_timeout = text.lines().any(|l| l.trim_start().starts_with("timeout"));
    if !locks || !has_timeout {
        report.find(
            Finding::new(
                "desktop.no-idle-lock",
                Severity::Medium,
                "hypridle does not lock the screen on idle",
            )
            .at(host.display(&conf))
            .remedy("add a listener with a timeout that runs loginctl lock-session"),
        );
    } else if !running(host, "hypridle") {
        report.find(
            Finding::new(
                "desktop.idle-not-running",
                Severity::Medium,
                "hypridle is configured but not running",
            )
            .path("the screen will not lock when you walk away")
            .remedy("start hypridle (exec-once in hyprland.conf)"),
        );
    } else {
        report.pass("screen locks on idle (hypridle)");
    }
}

pub fn check(host: &Host, _ctx: &Context, report: &mut Report) {
    home_perms(host, report);
    screen_lock(host, report);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fixture() -> (tempfile::TempDir, Host) {
        let dir = tempfile::tempdir().unwrap();
        let host = Host::at(dir.path(), "home/u");
        fs::create_dir_all(host.home(".config/hypr")).unwrap();
        fs::create_dir_all(host.sys("/proc")).unwrap();
        (dir, host)
    }

    #[test]
    fn open_home_is_flagged() {
        let (_d, host) = fixture();
        fs::set_permissions(host.home(""), fs::Permissions::from_mode(0o755)).unwrap();
        let mut r = Report::default();
        home_perms(&host, &mut r);
        assert_eq!(r.findings[0].id, "desktop.home-open");
        fs::set_permissions(host.home(""), fs::Permissions::from_mode(0o700)).unwrap();
        let mut r = Report::default();
        home_perms(&host, &mut r);
        assert!(r.findings.is_empty());
    }

    #[test]
    fn omarchy_shell_lock_takes_precedence() {
        let (_d, host) = fixture();
        fs::create_dir_all(host.home(".config/omarchy")).unwrap();
        fs::write(
            host.home(".config/omarchy/shell.json"),
            r#"{"idle": {"lock": 150}}"#,
        )
        .unwrap();
        fs::create_dir_all(host.sys("/proc/7")).unwrap();
        fs::write(host.sys("/proc/7/comm"), "quickshell\n").unwrap();
        let mut r = Report::default();
        screen_lock(&host, &mut r);
        assert!(r.findings.is_empty(), "{:?}", r.findings);
        assert_eq!(r.passed, ["screen locks after 150s idle (omarchy shell)"]);

        fs::write(
            host.home(".config/omarchy/shell.json"),
            r#"{"idle": {"lock": 0}}"#,
        )
        .unwrap();
        let mut r = Report::default();
        screen_lock(&host, &mut r);
        assert_eq!(r.findings[0].id, "desktop.no-idle-lock");

        fs::write(host.home(".config/omarchy/shell.json"), "{}").unwrap();
        let mut r = Report::default();
        screen_lock(&host, &mut r);
        assert_eq!(r.passed, ["screen locks after 300s idle (omarchy shell)"]);
    }

    #[test]
    fn idle_lock_must_be_configured_and_running() {
        let (_d, host) = fixture();
        let mut r = Report::default();
        screen_lock(&host, &mut r);
        assert_eq!(r.findings[0].id, "desktop.no-idle-lock");

        fs::write(
            host.home(".config/hypr/hypridle.conf"),
            "general {\n  lock_cmd = hyprlock\n}\nlistener {\n  timeout = 300\n  on-timeout = loginctl lock-session\n}\n",
        )
        .unwrap();
        let mut r = Report::default();
        screen_lock(&host, &mut r);
        assert_eq!(r.findings[0].id, "desktop.idle-not-running");

        fs::create_dir_all(host.sys("/proc/42")).unwrap();
        fs::write(host.sys("/proc/42/comm"), "hypridle\n").unwrap();
        let mut r = Report::default();
        screen_lock(&host, &mut r);
        assert!(r.findings.is_empty());
    }
}
