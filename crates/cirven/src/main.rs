use std::process::ExitCode;

use cirven_core::Module;
use clap::{Args, Parser, Subcommand};

/// cirven systems: defense modules for linux developer workstations.
#[derive(Parser)]
#[command(name = "cirven", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List modules and their status
    Modules,
    /// Find weaknesses, rank them by real attack paths
    #[command(disable_help_flag = true)]
    Audit(Passthrough),
    /// Fix findings: preview, apply, roll back
    #[command(disable_help_flag = true)]
    Harden(Passthrough),
    /// Detect persistence: new units, autostarts, hooks
    #[command(disable_help_flag = true)]
    Watch(Passthrough),
    /// Decoy credentials that alarm when touched
    #[command(disable_help_flag = true)]
    Lure(Passthrough),
    /// Inspect AUR/npm/pip packages before install
    #[command(disable_help_flag = true)]
    Pkg(Passthrough),
    /// Sandbox tools and AI agents to what they need
    #[command(disable_help_flag = true)]
    Cage(Passthrough),
    /// Hardware key + password; unplug and it all locks
    #[command(disable_help_flag = true)]
    Key(Passthrough),
}

/// Arguments handed to the module unparsed; each module owns its own options.
#[derive(Args)]
struct Passthrough {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

const MODULES: &[&Module] = &[
    &cirven_audit::MODULE,
    &cirven_harden::MODULE,
    &cirven_watch::MODULE,
    &cirven_lure::MODULE,
    &cirven_pkg::MODULE,
    &cirven_cage::MODULE,
    &cirven_key::MODULE,
];

fn main() -> ExitCode {
    let result: cirven_core::Result<u8> = match Cli::parse().command {
        Command::Modules => {
            list();
            Ok(0)
        }
        Command::Audit(p) => cirven_audit::run(&p.args),
        Command::Harden(p) => cirven_harden::run(&p.args),
        Command::Watch(p) => cirven_watch::run(&p.args),
        Command::Lure(p) => cirven_lure::run(&p.args),
        Command::Pkg(p) => cirven_pkg::run(&p.args),
        Command::Cage(p) => cirven_cage::run(&p.args),
        Command::Key(p) => cirven_key::run(&p.args),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(e @ cirven_core::Error::Usage) => ExitCode::from(e.exit_code()),
        Err(e) => {
            eprintln!("cirven {e}");
            ExitCode::from(e.exit_code())
        }
    }
}

fn list() {
    for m in MODULES {
        println!("{:<8} {:<13} {}", m.name, m.status, m.summary);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
