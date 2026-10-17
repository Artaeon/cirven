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

pub mod apply;
pub mod plan;

use std::io::IsTerminal;
use std::path::PathBuf;

use cirven_audit::Host;
use cirven_core::{Error, Module, Result, Status};
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
    /// Apply plan steps: comma-separated numbers, or "all"
    #[arg(long, value_name = "STEPS")]
    apply: Option<String>,
    /// Undo a previous run, restoring its snapshot
    #[arg(long, value_name = "SNAPSHOT", conflicts_with = "apply")]
    rollback: Option<String>,
    /// List snapshots of previous runs
    #[arg(long, conflicts_with_all = ["apply", "rollback"])]
    list: bool,
    /// Where snapshots are kept
    #[arg(long, hide = true)]
    state: Option<PathBuf>,
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
    let root = cirven_core::is_root();
    let state = args
        .state
        .clone()
        .unwrap_or_else(|| cirven_core::state_dir(&host, MODULE.name));

    if args.list {
        let snaps = apply::list(&state);
        if snaps.is_empty() {
            println!("no snapshots in {}", state.display());
        }
        for (id, rolled, steps) in snaps {
            let mark = if rolled { "  (rolled back)" } else { "" };
            println!("{id}{mark}");
            for s in steps {
                println!("    {s}");
            }
        }
        return Ok(0);
    }
    if let Some(id) = &args.rollback {
        let snap = apply::rollback(&state, id).map_err(Error::Other)?;
        println!("rolled back {} ({} steps):", snap.id, snap.steps.len());
        for s in snap.steps {
            println!("    {s}");
        }
        return Ok(0);
    }

    let report = cirven_audit::scan(&host);
    let steps = plan::build(&host, &report);
    let Some(spec) = &args.apply else {
        print!(
            "{}",
            render(&report.host, &steps, std::io::stdout().is_terminal())
        );
        return Ok(0);
    };

    let picked = plan::select(spec, &steps).map_err(Error::Other)?;
    if picked.is_empty() {
        println!("nothing to apply.");
        return Ok(0);
    }
    let chosen: Vec<&Step> = picked.iter().map(|&i| &steps[i]).collect();
    if args.root.is_none() && !root && chosen.iter().any(|s| s.scope == Scope::System) {
        let system: Vec<String> = picked
            .iter()
            .filter(|&&i| steps[i].scope == Scope::System)
            .map(|i| (i + 1).to_string())
            .collect();
        return Err(Error::Other(format!(
            "step {} changes system files; run: sudo cirven harden --apply {}",
            system.join(","),
            system.join(",")
        )));
    }
    let snap = apply::apply(&host, &chosen, &state).map_err(Error::Other)?;
    println!("snapshot {} saved in {}", snap.id, state.display());
    for s in &chosen {
        println!("applied: {}", s.title);
    }
    println!("undo with: cirven harden --rollback {}", snap.id);
    Ok(0)
}
