//! cirven lure: decoy credentials that are worthless except for the alarm they raise.
//!
//! Decoys: fake aws credentials, ssh keys, .env files, browser login stores,
//! placed next to the real ones. The user never touches them, so any access is
//! a signal with almost no false positives.
//!
//! Tripwires:
//! - status: access times. On a relatime mount the first read of a decoy is
//!   visible offline, with no daemon running
//! - watch: inotify reports opens as they happen, with the processes holding
//!   the file at that moment
//! - planned, use: decoy tokens that call home when tried elsewhere; needs a
//!   callback endpoint, self-hosted or cirven relay
//!
//! Threat model: exposes credential theft by infostealers, poisoned packages and
//! hijacked agents. It does not stop an attacker who reads only real secrets.

pub mod decoys;
pub mod plant;

use std::path::PathBuf;

use cirven_core::{Error, Host, Module, Result, Status};
use clap::{Parser, Subcommand};
use plant::State;

pub const MODULE: Module = Module {
    name: "lure",
    summary: "decoy credentials that alarm when touched",
    status: Status::Experimental,
};

/// Decoy credentials that are worthless except for the alarm they raise.
#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
    /// Use a directory tree instead of the live system
    #[arg(long, hide = true, global = true)]
    root: Option<PathBuf>,
    /// Home directory inside --root
    #[arg(long, hide = true, global = true, default_value = "home/user")]
    home: String,
}

#[derive(Subcommand)]
enum Command {
    /// Show where decoys would go (default; changes nothing)
    Plan,
    /// Create the decoys. Existing files are never overwritten
    Plant,
    /// Report whether any decoy was read, changed or removed
    Status,
    /// Delete the decoys that are still exactly as planted
    Remove,
}

/// Entry point for `cirven lure`. Receives the arguments after the module name
/// and returns the process exit code.
pub fn run(args: &[String]) -> Result<u8> {
    let Some(args) = cirven_core::parse_args::<Args>(MODULE.name, args)? else {
        return Ok(0);
    };
    let host = match &args.root {
        Some(root) => Host::at(root, &args.home),
        None => Host::live(),
    };
    let store =
        cirven_core::state_dir(&host, MODULE.name, args.root.is_some()).join("planted.json");
    let mut ledger = plant::load(&store);

    match args.command.unwrap_or(Command::Plan) {
        Command::Plan => {
            println!("cirven lure · plan\n");
            for (path, what, free) in plant::plan(&host, &ledger) {
                let mark = if ledger.planted.iter().any(|p| p.path == path) {
                    "planted"
                } else if free {
                    "free   "
                } else {
                    "exists "
                };
                println!("{mark}  {:<48} {what}", host.display(&path));
            }
            println!("\nnothing has been changed. plant with: cirven lure plant");
            if plant::atime_enabled(&host) == Some(false) {
                println!("note: home is mounted noatime, so `status` cannot see reads.");
            }
            Ok(0)
        }
        Command::Plant => {
            let new = plant::plant(&host, &mut ledger)?;
            plant::save(&store, &ledger)?;
            for p in &new {
                println!("planted  {:<48} {}", host.display(&p.path), p.what);
            }
            println!(
                "\n{} new decoys, {} total. never open them yourself.",
                new.len(),
                ledger.planted.len()
            );
            println!("check with: cirven lure status");
            Ok(0)
        }
        Command::Status => {
            if ledger.planted.is_empty() {
                println!("no decoys planted. see: cirven lure plan");
                return Ok(0);
            }
            let mut tripped = 0;
            for p in &ledger.planted {
                let (tag, note) = match plant::state(p) {
                    State::Untouched => ("[ok     ]", ""),
                    State::Read => ("[TRIPPED]", "read since planting"),
                    State::Modified => ("[TRIPPED]", "changed since planting"),
                    State::Gone => ("[TRIPPED]", "removed or moved"),
                };
                tripped += usize::from(!note.is_empty());
                println!("{tag} {:<48} {note}", host.display(&p.path));
            }
            if tripped > 0 {
                println!(
                    "\n{tripped} decoys touched. something read files it had no reason to read:"
                );
                println!(
                    "run cirven watch and cirven audit, and rotate real credentials stored nearby."
                );
                println!(
                    "(backup and indexing tools also read files; exclude the decoys from them.)"
                );
                return Ok(2);
            }
            if plant::atime_enabled(&host) == Some(false) {
                println!("\nnote: home is mounted noatime, so reads are not visible here.");
            }
            Ok(0)
        }
        Command::Remove => {
            let results = plant::remove(&mut ledger);
            plant::save(&store, &ledger)?;
            let mut failed = false;
            for (path, r) in results {
                match r {
                    Ok(()) => println!("removed  {}", host.display(&path)),
                    Err(e) => {
                        failed = true;
                        println!("kept     {}: {e}", host.display(&path));
                    }
                }
            }
            if failed {
                return Err(Error::Other("some decoys were left in place".into()));
            }
            Ok(0)
        }
    }
}
