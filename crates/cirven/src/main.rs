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
    Audit(Passthrough),
    /// Fix findings: preview, apply, roll back
    Harden(Passthrough),
}

/// Arguments handed to the module unparsed; each module owns its own options.
#[derive(Args)]
struct Passthrough {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

const MODULES: &[&Module] = &[&cirven_audit::MODULE, &cirven_harden::MODULE];

fn main() -> ExitCode {
    let result: cirven_core::Result<()> = match Cli::parse().command {
        Command::Modules => {
            list();
            Ok(())
        }
        Command::Audit(p) => cirven_audit::run(&p.args),
        Command::Harden(p) => cirven_harden::run(&p.args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("cirven {e}");
            ExitCode::from(e.exit_code())
        }
    }
}

fn list() {
    for m in MODULES {
        println!("{:<8} {:<8} {}", m.name, m.status, m.summary);
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
