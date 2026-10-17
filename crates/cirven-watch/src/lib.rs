//! cirven watch: baseline every place malware writes to survive a reboot, alert on change.
//!
//! Watched persistence points:
//! - systemd units and timers, system and user
//! - xdg autostart, compositor exec lines (hyprland exec-once, sway exec)
//! - shell rc files, cron/at, ~/.ssh/authorized_keys, ssh ProxyCommand
//! - /etc/ld.so.preload and LD_PRELOAD in environment files
//! - pacman hooks, udev rules, PAM config, sudoers.d, kernel modules
//! - git hooks and core.hooksPath, editor plugin directories
//!
//! Mechanism: a hashed baseline of every point, compared on demand or in a
//! polling loop (`follow`). Only hashes and metadata are stored, never contents.
//! Planned: fanotify for live events with the writing process attached.
//!
//! Threat model: catches user-level persistence and poisoned install scripts.
//! A root attacker can stop watch first; tampering is logged and the baseline
//! can be verified from a clean boot.

pub mod baseline;
pub mod points;
pub mod suspicious;

use std::path::{Path, PathBuf};

use baseline::Change;
use cirven_core::{Error, Host, Module, Result, Status};
use clap::{Parser, Subcommand};

pub const MODULE: Module = Module {
    name: "watch",
    summary: "detect persistence: new units, autostarts, hooks",
    status: Status::Experimental,
};

/// Detect persistence: compare every autostart, service, hook and rc file
/// against a baseline. Reads only.
#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
    /// Watch a directory tree instead of the live system
    #[arg(long, hide = true, global = true)]
    root: Option<PathBuf>,
    /// Home directory inside --root
    #[arg(long, hide = true, global = true, default_value = "home/user")]
    home: String,
}

#[derive(Subcommand)]
enum Command {
    /// Record the current state as the baseline
    Baseline,
    /// Compare the current state with the baseline (default)
    Check,
    /// Accept the current state as the new baseline, after reviewing changes
    Accept,
    /// Keep checking and report every change as it happens
    Follow {
        /// Seconds between checks
        #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(2..))]
        interval: u64,
        /// Also send a desktop notification for each change
        #[arg(long)]
        notify: bool,
        /// Stop after this many checks (for testing)
        #[arg(long, hide = true)]
        ticks: Option<u64>,
    },
}

fn timestamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix:{secs}")
}

fn store(host: &Host, fixture: bool) -> PathBuf {
    cirven_core::state_dir(host, MODULE.name, fixture).join("baseline.json")
}

fn record(host: &Host, path: &Path, verb: &str) -> Result<u8> {
    let (base, _) = baseline::take(host, timestamp());
    baseline::save(path, &base)?;
    println!(
        "{verb} {} persistence points in {}",
        base.points.len(),
        path.display()
    );
    Ok(0)
}

/// Prints every change; exit code 1 if anything changed.
fn check(host: &Host, path: &Path) -> Result<u8> {
    let Some(old) = baseline::load(path) else {
        return Err(Error::Other(format!(
            "no baseline at {}; run: cirven watch baseline",
            path.display()
        )));
    };
    let (new, reasons) = baseline::take(host, timestamp());
    let changes = baseline::diff(&old, &new);
    println!(
        "cirven watch · {} points · baseline {}\n",
        new.points.len(),
        old.taken
    );
    if changes.is_empty() {
        println!("no changes.");
        return Ok(0);
    }
    let alerts = report(host, &changes, &reasons);
    println!(
        "\n{} changes, {alerts} suspicious. if they are yours: cirven watch accept",
        changes.len()
    );
    Ok(if alerts > 0 { 2 } else { 1 })
}

/// Readable text of a changed point, small enough to scan.
fn read_small(path: &Path) -> Option<String> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > 256 * 1024 {
        return None;
    }
    String::from_utf8(std::fs::read(path).ok()?).ok()
}

/// Prints the changes; returns how many look malicious.
fn report(
    host: &Host,
    changes: &[(Change, String)],
    reasons: &std::collections::BTreeMap<String, &'static str>,
) -> usize {
    let mut alerts = 0;
    for (change, shown) in changes {
        let lines = match change {
            Change::Removed => Vec::new(),
            _ => read_small(&baseline::resolve(host, shown))
                .map(|t| suspicious::scan(&t, 5))
                .unwrap_or_default(),
        };
        let alert = lines.iter().any(|l| l.alert.is_some());
        alerts += usize::from(alert);
        let tag = match (change, alert) {
            (_, true) => "[ALERT  ]",
            (Change::Added, _) => "[added  ]",
            (Change::Changed, _) => "[changed]",
            (Change::Removed, _) => "[removed]",
        };
        println!("{tag} {shown}");
        if let Some(why) = reasons.get(shown) {
            println!("          {why}");
        }
        for l in lines {
            match l.alert {
                Some(why) => println!("          {:>4}: {}   <- {why}", l.number, l.text),
                None => println!("          {:>4}: {}", l.number, l.text),
            }
        }
    }
    alerts
}

fn notify(title: &str, body: &str) {
    // Best effort: no notification daemon is not an error.
    let _ = std::process::Command::new("notify-send")
        .args(["--urgency=critical", "--app-name=cirven", title, body])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// Report drift from the baseline once, then every change since the last check.
fn follow(
    host: &Host,
    path: &Path,
    interval: u64,
    desktop: bool,
    ticks: Option<u64>,
) -> Result<u8> {
    let Some(base) = baseline::load(path) else {
        return Err(Error::Other(format!(
            "no baseline at {}; run: cirven watch baseline",
            path.display()
        )));
    };
    let (mut seen, reasons) = baseline::take(host, timestamp());
    println!(
        "following {} points every {interval}s · ctrl-c to stop",
        seen.points.len()
    );
    let drift = baseline::diff(&base, &seen);
    if !drift.is_empty() {
        println!("\nalready changed since the baseline:");
        report(host, &drift, &reasons);
    }
    let mut n = 0;
    while ticks.is_none_or(|t| n < t) {
        std::thread::sleep(std::time::Duration::from_secs(interval));
        n += 1;
        let (now, reasons) = baseline::take(host, timestamp());
        let changes = baseline::diff(&seen, &now);
        if !changes.is_empty() {
            println!("\n-- {} --", timestamp());
            let alerts = report(host, &changes, &reasons);
            if desktop {
                for (change, shown) in &changes {
                    let what = format!("{change:?}").to_lowercase();
                    let why = reasons.get(shown).copied().unwrap_or("persistence point");
                    let title = if alerts > 0 {
                        "cirven watch: suspicious change"
                    } else {
                        "cirven watch"
                    };
                    notify(title, &format!("{what}: {shown}\n{why}"));
                }
            }
        }
        seen = now;
    }
    Ok(0)
}

/// Entry point for `cirven watch`. Receives the arguments after the module name
/// and returns the process exit code.
pub fn run(args: &[String]) -> Result<u8> {
    let Some(args) = cirven_core::parse_args::<Args>(MODULE.name, args)? else {
        return Ok(0);
    };
    let host = match &args.root {
        Some(root) => Host::at(root, &args.home),
        None => Host::live(),
    };
    let path = store(&host, args.root.is_some());
    match args.command.unwrap_or(Command::Check) {
        Command::Baseline => record(&host, &path, "recorded"),
        Command::Accept => record(&host, &path, "accepted"),
        Command::Check => check(&host, &path),
        Command::Follow {
            interval,
            notify,
            ticks,
        } => follow(&host, &path, interval, notify, ticks),
    }
}
