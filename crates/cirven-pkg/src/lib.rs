//! cirven pkg: read what a package will run before it runs.
//!
//! Signals:
//! - sources: domain changes, non-upstream hosts, missing or skipped checksums
//! - scripts: network fetches, pipes to shells, base64 and eval, writes outside the package
//! - history: diff against the previous version, new maintainer, recent adoption
//! - npm/pip: install-time scripts, typosquat distance to popular names, binary blobs
//!
//! `cirven pkg wrap paru` checks every install through an AUR helper.
//!
//! Threat model: stops common supply-chain attacks. A patient attacker hiding
//! logic in compiled upstream code needs `cirven-cage` as a second layer.

pub mod pkgbuild;

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use cirven_core::{Error, Finding, Module, Result, Severity, Status};
use clap::{Parser, Subcommand};

pub const MODULE: Module = Module {
    name: "pkg",
    summary: "inspect AUR/npm/pip packages before install",
    status: Status::Experimental,
};

/// Inspect packages before they install. Static analysis only: nothing from
/// the package is ever executed.
#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check a package: a PKGBUILD file or a directory containing one
    Check {
        /// Path to a PKGBUILD or its directory
        target: String,
    },
}

/// 0 nothing above low, 1 medium, 2 high: do not install.
pub fn exit_code(findings: &[Finding]) -> u8 {
    match findings.iter().map(|f| f.severity).max() {
        Some(Severity::High | Severity::Critical) => 2,
        Some(Severity::Medium) => 1,
        _ => 0,
    }
}

pub fn render(name: &str, findings: &[Finding], color: bool) -> String {
    let paint = |code: &str, s: &str| {
        if color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    };
    let mut out = format!("cirven pkg · {name}\n\n");
    for f in findings {
        let (tag, code) = match f.severity {
            Severity::Critical | Severity::High => ("[high]", "31"),
            Severity::Medium => ("[med ]", "33"),
            Severity::Low => ("[low ]", "34"),
            Severity::Info => ("[info]", "2"),
        };
        out.push_str(&format!("{} {}\n", paint(code, tag), f.title));
        if let Some(at) = &f.location {
            out.push_str(&format!("       {}\n", paint("2", &format!("at   {at}"))));
        }
        if let Some(path) = &f.path {
            out.push_str(&format!("       {}\n", paint("2", &format!("     {path}"))));
        }
    }
    let verdict = match exit_code(findings) {
        2 => paint("31", "do not install"),
        1 => paint("33", "review before installing"),
        _ => paint("32", "no red flags found"),
    };
    if !findings.is_empty() {
        out.push('\n');
    }
    out.push_str(&format!("verdict: {verdict}\n"));
    out
}

/// A PKGBUILD path or directory, plus the install script it names.
fn local(target: &Path) -> Result<(String, Option<(String, String)>)> {
    let file = if target.is_dir() {
        target.join("PKGBUILD")
    } else {
        target.to_path_buf()
    };
    let text = std::fs::read_to_string(&file)?;
    let dir = file.parent().map(Path::to_path_buf).unwrap_or_default();
    let install = pkgbuild::parse(&text)
        .vars
        .get("install")
        .filter(|name| !name.is_empty() && !name.contains('/'))
        .and_then(|name| Some((name.clone(), std::fs::read_to_string(dir.join(name)).ok()?)));
    Ok((text, install))
}

/// Entry point for `cirven pkg`. Receives the arguments after the module name
/// and returns the process exit code.
pub fn run(args: &[String]) -> Result<u8> {
    let Some(args) = cirven_core::parse_args::<Args>(MODULE.name, args)? else {
        return Ok(0);
    };
    let color = std::io::stdout().is_terminal();
    match args.command {
        Command::Check { target } => {
            let path = PathBuf::from(&target);
            if !path.exists() {
                return Err(Error::Other(format!("{target}: no such file or directory")));
            }
            let (text, install) = local(&path)?;
            let findings = pkgbuild::analyse(
                &text,
                install.as_ref().map(|(n, t)| (n.as_str(), t.as_str())),
            );
            print!("{}", render(&target, &findings, color));
            Ok(exit_code(&findings))
        }
    }
}
