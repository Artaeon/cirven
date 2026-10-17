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

pub mod aur;
pub mod npm;
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
    /// Check a package: aur/<name>, npm/<name>, or a PKGBUILD file or directory
    Check {
        /// aur/<name>, npm/<name>, or a path to a PKGBUILD or its directory
        target: String,
    },
    /// Print a shell function that checks AUR packages before an AUR helper
    /// installs them. Load it with: eval "$(cirven pkg wrap paru)"
    Wrap {
        /// The AUR helper to wrap
        #[arg(value_parser = ["paru", "yay"])]
        helper: String,
    },
}

/// Exit code for "not an AUR package": the wrapper lets repo packages through.
pub const NOT_IN_AUR: u8 = 3;

/// A bash/zsh function shadowing the helper. Blocks on "do not install",
/// asks on "review", and passes repo packages and non-install commands through.
pub fn wrapper(helper: &str) -> String {
    format!(
        r#"# cirven: check AUR packages before {helper} installs them
{helper}() {{
  local arg rc install=0
  for arg in "$@"; do
    case "$arg" in
      -S*[sicglp]*) ;;
      -S*|--sync) install=1 ;;
    esac
  done
  if [ "$install" = 1 ]; then
    for arg in "$@"; do
      case "$arg" in -*) continue ;; esac
      cirven pkg check "aur/$arg"; rc=$?
      case "$rc" in
        0|{NOT_IN_AUR}) ;;
        1) printf 'cirven: install %s anyway? [y/N] ' "$arg"; read -r rc; [ "$rc" = y ] || return 1 ;;
        *) printf 'cirven: blocked %s. to override: command {helper} %s
' "$arg" "$*"; return 1 ;;
      esac
    done
  fi
  command {helper} "$@"
}}
"#
    )
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

/// Lines added since the last time this package was checked, if it was.
fn changes_since_last(state: &Path, base: &str, text: &str) -> Option<Vec<String>> {
    let path = state.join(format!("aur/{base}.PKGBUILD"));
    let before = std::fs::read_to_string(&path).ok();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
        let _ = std::fs::write(&path, text);
    }
    let before = before?;
    let old: std::collections::HashSet<&str> = before.lines().collect();
    Some(
        text.lines()
            .filter(|l| !l.trim().is_empty() && !old.contains(l))
            .map(|l| l.trim().to_string())
            .collect(),
    )
}

fn check_aur(name: &str, color: bool) -> Result<u8> {
    if !aur::valid_name(name) {
        return Err(Error::Other(format!("{name}: not a valid package name")));
    }
    let info = match aur::info(name) {
        Ok(info) => info,
        Err(e) if e.ends_with("not found in the AUR") => {
            eprintln!("cirven pkg: {name} is not in the AUR (a repo package?)");
            return Ok(NOT_IN_AUR);
        }
        Err(e) => return Err(Error::Other(e)),
    };
    let text = aur::file(&info.package_base, "PKGBUILD").map_err(Error::Other)?;
    let install = pkgbuild::parse(&text)
        .vars
        .get("install")
        .filter(|n| aur::valid_name(n))
        .and_then(|n| Some((n.clone(), aur::file(&info.package_base, n).ok()?)));
    let mut findings = aur::assess(&info, std::time::SystemTime::now());
    findings.extend(pkgbuild::analyse(
        &text,
        install.as_ref().map(|(n, t)| (n.as_str(), t.as_str())),
    ));
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));

    let label = format!(
        "aur/{} {} · maintainer {} · {} votes",
        info.name,
        info.version,
        info.maintainer.as_deref().unwrap_or("none"),
        info.num_votes
    );
    print!("{}", render(&label, &findings, color));
    let state = cirven_core::state_dir(&cirven_core::Host::live(), MODULE.name, false);
    match changes_since_last(&state, &info.package_base, &text) {
        Some(added) if !added.is_empty() => {
            println!("\nchanged since your last check:");
            for l in added.iter().take(20) {
                println!("  + {l}");
            }
        }
        Some(_) => println!("\nunchanged since your last check."),
        None => {}
    }
    Ok(exit_code(&findings))
}

/// Entry point for `cirven pkg`. Receives the arguments after the module name
/// and returns the process exit code.
pub fn run(args: &[String]) -> Result<u8> {
    let Some(args) = cirven_core::parse_args::<Args>(MODULE.name, args)? else {
        return Ok(0);
    };
    let color = std::io::stdout().is_terminal();
    match args.command {
        Command::Wrap { helper } => {
            print!("{}", wrapper(&helper));
            Ok(0)
        }
        Command::Check { target } => {
            if let Some(name) = target.strip_prefix("aur/") {
                return check_aur(name, color);
            }
            if let Some(name) = target.strip_prefix("npm/") {
                if !npm::valid_name(name) {
                    return Err(Error::Other(format!(
                        "{name}: not a valid npm package name"
                    )));
                }
                let doc = npm::fetch(name).map_err(Error::Other)?;
                let (label, findings) = npm::assess(name, &doc, std::time::SystemTime::now());
                print!("{}", render(&label, &findings, color));
                return Ok(exit_code(&findings));
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// Run the wrapper in bash with stub `cirven` and `paru` commands.
    fn run(cirven_rc: u8, args: &str) -> String {
        let script = format!(
            "cirven() {{ echo \"check $*\"; return {cirven_rc}; }}\nparu_real() {{ :; }}\n{}\nhash -p /bin/echo paru 2>/dev/null\nparu {args} </dev/null; echo \"rc=$?\"",
            wrapper("paru").replace("command paru", "echo ran paru")
        );
        let out = Command::new("bash").arg("-c").arg(script).output().unwrap();
        String::from_utf8(out.stdout).unwrap()
    }

    #[test]
    fn wrapper_gates_installs_only() {
        assert_eq!(
            run(0, "-S foo"),
            "check pkg check aur/foo\nran paru -S foo\nrc=0\n"
        );
        assert_eq!(
            run(NOT_IN_AUR, "-S firefox"),
            "check pkg check aur/firefox\nran paru -S firefox\nrc=0\n"
        );
        assert!(run(2, "-S evil").ends_with("rc=1\n"));
        assert!(run(1, "-S maybe").contains("anyway? [y/N]"));
        assert_eq!(
            run(2, "-Syu"),
            "ran paru -Syu\nrc=0\n",
            "upgrades are not gated"
        );
        assert_eq!(
            run(2, "-Ss term"),
            "ran paru -Ss term\nrc=0\n",
            "searches are not gated"
        );
    }
}
