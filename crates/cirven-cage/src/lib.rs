//! cirven cage: give a process the project it works on and nothing else.
//!
//! Mechanism:
//! - landlock for filesystem rules, no root required
//! - a private network namespace when the profile has no network
//! - no_new_privs, so setuid binaries and sudo cannot escape
//! - profiles as plain text files that can be read and diffed
//!
//! Planned: per-host egress allowlists, seccomp filters.
//!
//! Primary use: AI coding agents, which run commands and can be steered by
//! prompt injection, and building untrusted packages.
//!
//! Threat model: contains a confused or hijacked tool. It does not stop kernel
//! exploits that escape the sandbox.

pub mod profile;
pub mod sandbox;

use std::os::unix::process::CommandExt;
use std::path::PathBuf;

use cirven_core::{Error, Host, Module, Result, Status};
use clap::Parser;

pub const MODULE: Module = Module {
    name: "cage",
    summary: "sandbox tools and AI agents to what they need",
    status: Status::Experimental,
};

/// Run a command confined to what it needs: by default the system read-only
/// and the current directory writable. Your home stays out of reach.
#[derive(Parser)]
#[command(trailing_var_arg = true)]
struct Args {
    /// Profile: default, offline, agent, or a file in ~/.config/cirven/cage/
    #[arg(long, short, default_value = "default")]
    profile: String,
    /// Extra path to allow reading (repeatable)
    #[arg(long, value_name = "PATH")]
    read: Vec<String>,
    /// Extra path to allow writing (repeatable)
    #[arg(long, value_name = "PATH")]
    write: Vec<String>,
    /// Cut all network access, whatever the profile says
    #[arg(long)]
    no_net: bool,
    /// List the built-in profiles
    #[arg(long)]
    list: bool,
    /// The command to run, after --
    command: Vec<String>,
}

/// Entry point for `cirven cage`. Receives the arguments after the module name.
/// On success it does not return: the process becomes the caged command.
pub fn run(args: &[String]) -> Result<u8> {
    let Some(args) = cirven_core::parse_args::<Args>(MODULE.name, args)? else {
        return Ok(0);
    };
    if args.list {
        for (name, what) in profile::BUILTIN {
            println!("{name:<8} {what}");
        }
        return Ok(0);
    }
    let Some((program, rest)) = args.command.split_first() else {
        return Err(Error::Other(
            "nothing to run. usage: cirven cage [--profile p] -- command [args]".into(),
        ));
    };
    let host = Host::live();
    let home = host.home("");
    let cwd = std::env::current_dir()?;
    let mut p =
        profile::load(&args.profile, &host.home(".config/cirven/cage")).map_err(Error::Other)?;
    p.read.extend(args.read);
    p.write.extend(args.write);
    if args.no_net {
        p.net = false;
    }
    let read: Vec<PathBuf> = p
        .read
        .iter()
        .map(|e| profile::expand(e, &home, &cwd))
        .collect();
    let write: Vec<PathBuf> = p
        .write
        .iter()
        .map(|e| profile::expand(e, &home, &cwd))
        .collect();

    eprintln!(
        "cage: profile {} · write {} · net {}",
        p.name,
        p.write
            .iter()
            .filter(|w| !w.starts_with('/'))
            .cloned()
            .collect::<Vec<_>>()
            .join(" "),
        if p.net { "on" } else { "off" }
    );
    if !p.net {
        sandbox::drop_network().map_err(Error::Other)?;
    }
    let status = sandbox::restrict(&read, &write).map_err(Error::Other)?;
    if status == landlock::RulesetStatus::PartiallyEnforced {
        eprintln!("cage: note: older kernel, some restrictions are not available");
    }
    let err = std::process::Command::new(program).args(rest).exec();
    Err(Error::Other(format!("{program}: {err}")))
}
