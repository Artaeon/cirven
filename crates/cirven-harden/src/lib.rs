//! cirven harden: turn audit findings into fixes, with a plan, an apply step and a rollback.
//!
//! Design:
//! - every fix is a small declared change: a drop-in file, a sysctl, a mode bit
//! - drop-ins over edits, so upstream configs stay untouched
//! - files are snapshotted before change; rollback restores them byte for byte
//! - nothing restarts a service: sshd changes wait for your reload, and the
//!   firewall is only ever suggested, so a fix cannot cut off a remote session
//! - anything needing judgement (passphrases, secure boot, rotating secrets) is
//!   printed as a manual step and never executed
//! - private keys are never copied: a chmod snapshot stores only the old mode
//!
//! Threat model: closes the attack paths audit reports. A purged secret must
//! still be rotated at its issuer.

pub mod plan;

use std::io::IsTerminal;
use std::path::PathBuf;

use cirven_audit::Host;
use cirven_core::{Module, Result, Status};
use clap::Parser;
use plan::{Action, Scope, Step};

pub const MODULE: Module = Module {
    name: "harden",
    summary: "fix findings: preview, apply, roll back",
    status: Status::Experimental,
};

/// Fix audit findings. Without --apply it only prints the plan.
#[derive(Parser)]
struct Args {
    /// Audit a directory tree instead of the live system
    #[arg(long, hide = true)]
    root: Option<PathBuf>,
    /// Home directory inside --root
    #[arg(long, hide = true, requires = "root", default_value = "home/user")]
    home: String,
}

fn render(host_name: &str, steps: &[Step], color: bool) -> String {
    let dim = |s: &str| {
        if color {
            format!("\x1b[2m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    };
    let mut out = format!("cirven harden · plan for {host_name}\n\n");
    if steps.is_empty() {
        out.push_str("nothing to fix.\n");
        return out;
    }
    for (i, step) in steps.iter().enumerate() {
        let scope = match step.scope {
            Scope::User => "user  ",
            Scope::System => "system",
            Scope::Manual => "manual",
        };
        out.push_str(&format!("{:>2}  {scope}  {}\n", i + 1, step.title));
        match &step.action {
            Action::Manual { command } => {
                out.push_str(&format!("            {}\n", dim(&format!("-> {command}"))))
            }
            Action::DropIn {
                path,
                settings,
                sep,
            } => {
                for (k, v) in settings {
                    out.push_str(&format!(
                        "            {}\n",
                        dim(&format!("+ {k}{sep}{v}   ({})", path.display()))
                    ));
                }
            }
            _ => {}
        }
    }
    let runnable: Vec<String> = steps
        .iter()
        .enumerate()
        .filter(|(_, s)| s.scope != Scope::Manual)
        .map(|(i, _)| (i + 1).to_string())
        .collect();
    out.push_str("\nnothing has been changed.\n");
    if !runnable.is_empty() {
        out.push_str(&format!(
            "apply with: cirven harden --apply {}\n",
            runnable.join(",")
        ));
        if steps.iter().any(|s| s.scope == Scope::System) {
            out.push_str("system steps need root: sudo cirven harden --apply <n>\n");
        }
    }
    out
}

/// Entry point for `cirven harden`. Receives the arguments after the module name
/// and returns the process exit code.
pub fn run(args: &[String]) -> Result<u8> {
    let Some(args) = cirven_core::parse_args::<Args>(MODULE.name, args)? else {
        return Ok(0);
    };
    let host = match &args.root {
        Some(root) => Host::at(root, &args.home),
        None => Host::live(),
    };
    let report = cirven_audit::scan(&host);
    let steps = plan::build(&host, &report);
    print!(
        "{}",
        render(&report.host, &steps, std::io::stdout().is_terminal())
    );
    Ok(0)
}
