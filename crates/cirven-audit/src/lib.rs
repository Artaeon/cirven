//! cirven audit: read the system, change nothing, report how an attacker would get in.
//!
//! Checks, grouped by area:
//! - network: listening sockets, firewall state, exposed services
//! - ssh: sshd config, authorized_keys, unencrypted private keys, agent forwarding
//! - secrets: tokens and keys in shell history, dotfiles, .env files, git configs
//! - disk: LUKS version and KDF, swap and hibernation encryption
//! - boot: secure boot, kernel cmdline, unsigned modules
//! - accounts: sudo rules, polkit, PAM stack
//! - updates: pending security updates, kernel age
//! - desktop: screen lock, autostart entries, world-readable home files
//!
//! Findings are ranked by the attack paths they open, not by checklist order.
//! Output: human or `--json`. The exit code reflects the highest severity:
//! 0 nothing above low, 1 medium, 2 high, 3 critical.
//!
//! Threat model: catches misconfigurations before an attacker does. It cannot
//! detect an attacker already on the machine; see `cirven-watch`.

mod checks;
pub mod host;
pub mod report;

use std::io::IsTerminal;
use std::path::PathBuf;

use cirven_core::{Error, Module, Result, Status};
use clap::Parser;

pub use host::Host;
pub use report::Report;

pub const MODULE: Module = Module {
    name: "audit",
    summary: "find weaknesses, rank them by real attack paths",
    status: Status::Experimental,
};

/// Find weaknesses, rank them by real attack paths. Changes nothing.
#[derive(Parser)]
struct Args {
    /// Print the report as JSON
    #[arg(long)]
    json: bool,
    /// Only print findings, not passed or skipped checks
    #[arg(long, short)]
    quiet: bool,
    /// Audit a directory tree instead of the live system
    #[arg(long, hide = true)]
    root: Option<PathBuf>,
    /// Home directory inside --root
    #[arg(long, hide = true, requires = "root", default_value = "home/user")]
    home: String,
}

/// Run every check against `host`. Reads only.
pub fn scan(host: &Host) -> Report {
    let mut report = Report {
        host: host
            .read_sys("/proc/sys/kernel/hostname")
            .map(|h| h.trim().to_string())
            .unwrap_or_else(|| "unknown".into()),
        ..Report::default()
    };
    let ctx = checks::Context::gather(host);
    checks::run_all(host, &ctx, &mut report);
    report.sort();
    report
}

/// Entry point for `cirven audit`. Receives the arguments after the module name
/// and returns the process exit code.
pub fn run(args: &[String]) -> Result<u8> {
    let Some(args) = cirven_core::parse_args::<Args>(MODULE.name, args)? else {
        return Ok(0);
    };
    let host = match &args.root {
        Some(root) => Host::at(root, &args.home),
        None => Host::live(),
    };
    let report = scan(&host);
    if args.json {
        let json =
            serde_json::to_string_pretty(&report).map_err(|e| Error::Other(e.to_string()))?;
        println!("{json}");
    } else {
        print!(
            "{}",
            report.render(std::io::stdout().is_terminal(), args.quiet)
        );
    }
    Ok(report.exit_code())
}
