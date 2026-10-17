//! Whether the package manager has looked for updates recently.

use std::fs;
use std::time::{Duration, SystemTime};

use cirven_core::{Finding, Severity};

use super::Context;
use crate::host::Host;
use crate::report::Report;

const STALE_DAYS: u64 = 7;

/// Newest modification time among the pacman sync databases.
fn last_sync(host: &Host) -> Option<SystemTime> {
    fs::read_dir(host.sys("/var/lib/pacman/sync"))
        .ok()?
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".db"))
        .filter_map(|e| e.metadata().ok()?.modified().ok())
        .max()
}

pub fn days_since(then: SystemTime, now: SystemTime) -> u64 {
    now.duration_since(then).unwrap_or(Duration::ZERO).as_secs() / 86_400
}

pub fn check(host: &Host, _ctx: &Context, report: &mut Report) {
    if !host.sys("/var/lib/pacman").exists() {
        report.skip("package updates: only pacman is supported so far");
        return;
    }
    let Some(synced) = last_sync(host) else {
        report.skip("package updates: no sync databases found");
        return;
    };
    let days = days_since(synced, SystemTime::now());
    if days > STALE_DAYS {
        report.find(
            Finding::new(
                "packages.stale",
                Severity::Low,
                format!("package databases last synced {days} days ago"),
            )
            .path("security updates published since then are not installed")
            .remedy("sudo pacman -Syu"),
        );
    } else {
        report.pass(format!("package databases synced {days} days ago"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_whole_days_and_tolerates_clock_skew() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(30 * 86_400);
        assert_eq!(
            days_since(now - Duration::from_secs(8 * 86_400 + 5), now),
            8
        );
        assert_eq!(days_since(now + Duration::from_secs(60), now), 0);
    }

    #[test]
    fn fresh_sync_passes() {
        let dir = tempfile::tempdir().unwrap();
        let host = Host::at(dir.path(), "home/u");
        fs::create_dir_all(host.sys("/var/lib/pacman/sync")).unwrap();
        fs::write(host.sys("/var/lib/pacman/sync/core.db"), b"").unwrap();
        let mut r = Report::default();
        check(&host, &Context::default(), &mut r);
        assert!(r.findings.is_empty());
        assert_eq!(r.passed, ["package databases synced 0 days ago"]);
    }
}
