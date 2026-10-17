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

use std::path::{Path, PathBuf};

use baseline::{Baseline, Change};
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
    report(&changes, &reasons, &new);
    println!(
        "\n{} changes. if they are yours: cirven watch accept",
        changes.len()
    );
    Ok(1)
}

fn report(
    changes: &[(Change, String)],
    reasons: &std::collections::BTreeMap<String, &'static str>,
    _new: &Baseline,
) {
    for (change, shown) in changes {
        let tag = match change {
            Change::Added => "[added  ]",
            Change::Changed => "[changed]",
            Change::Removed => "[removed]",
        };
        println!("{tag} {shown}");
        if let Some(why) = reasons.get(shown) {
            println!("          {why}");
        }
    }
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
    }
}
