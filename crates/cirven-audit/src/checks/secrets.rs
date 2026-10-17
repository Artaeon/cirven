//! Credentials lying around in plaintext. Matches are always masked: the
//! report says where a secret is, never what it is.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use cirven_core::{Finding, Severity};
use regex::Regex;

use super::Context;
use crate::report::Report;
use cirven_core::Host;

/// Token formats with a recognisable prefix: near-zero false positives.
static TOKENS: LazyLock<Vec<(&str, Regex)>> = LazyLock::new(|| {
    [
        (
            "github token",
            r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,})",
        ),
        ("gitlab token", r"\bglpat-[A-Za-z0-9_-]{20,}"),
        ("aws access key", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        ("anthropic api key", r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
        (
            "openai api key",
            r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}",
        ),
        ("slack token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
        ("stripe live key", r"\b[rs]k_live_[A-Za-z0-9]{20,}"),
        ("google api key", r"\bAIza[0-9A-Za-z_-]{35}"),
        ("npm token", r"\bnpm_[A-Za-z0-9]{36}\b"),
        ("private key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ]
    .into_iter()
    .map(|(name, re)| (name, Regex::new(re).expect("valid token regex")))
    .collect()
});

/// `TOKEN=…`, `--password …` and bearer headers typed into a shell.
static ASSIGNED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:\b[A-Z0-9_]*(?:PASSWORD|PASSWD|TOKEN|SECRET|API_?KEY)[A-Z0-9_]*=|--password[= ]|authorization:\s*(?:bearer|token)\s+)['"]?([^\s'"$][^\s'"]{7,})"#,
    )
    .expect("valid assignment regex")
});

const HISTORIES: &[&str] = &[
    ".bash_history",
    ".zsh_history",
    ".zhistory",
    ".local/share/fish/fish_history",
    ".python_history",
    ".node_repl_history",
    ".psql_history",
    ".mysql_history",
    ".sqlite_history",
    ".local/share/atuin/history.db",
];

/// Files whose whole purpose is storing a credential in plaintext.
const STORES: &[(&str, &str, &str)] = &[
    (
        ".git-credentials",
        "://",
        "git credential store keeps passwords in plaintext",
    ),
    (".netrc", "password", ".netrc holds plaintext passwords"),
    (".npmrc", "_authToken", ".npmrc holds an npm token"),
    (".pypirc", "password", ".pypirc holds a PyPI password"),
    (
        ".docker/config.json",
        "\"auth\":",
        "docker config holds registry credentials",
    ),
    (
        ".config/gh/hosts.yml",
        "oauth_token",
        "gh stores its token in a file, not the keyring",
    ),
    (
        ".aws/credentials",
        "aws_secret_access_key",
        "long-lived aws keys stored in plaintext",
    ),
];

const PROJECT_ROOTS: &[&str] = &[
    "Projects", "projects", "code", "src", "dev", "work", "repos", "git",
];
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    "vendor",
    ".venv",
    "venv",
    "dist",
    "build",
    ".cache",
    "__pycache__",
    ".next",
];
const MAX_FILE: u64 = 8 * 1024 * 1024;

#[derive(Debug, PartialEq)]
pub struct Hit {
    pub kind: &'static str,
    pub line: usize,
    pub masked: String,
}

/// `ghp_****`: enough to recognise which token it is, useless to an attacker.
/// Known formats keep their public prefix; anything else keeps two characters.
fn mask(secret: &str, prefixed: bool) -> String {
    let keep = match secret.find(['_', '-']) {
        Some(i) if prefixed && i < 8 => i + 1,
        _ => 2,
    };
    let keep = keep.min(secret.chars().count() / 2);
    let cut = secret
        .char_indices()
        .nth(keep)
        .map_or(secret.len(), |(i, _)| i);
    format!("{}****", &secret[..cut])
}

/// Values like `change-me` or `dev-secret` are templates, not credentials.
fn placeholder(value: &str) -> bool {
    let v = value.to_ascii_lowercase();
    [
        "change",
        "example",
        "placeholder",
        "dummy",
        "your",
        "xxxx",
        "replace",
        "todo",
        "<",
        "${",
    ]
    .iter()
    .any(|p| v.contains(p))
        || ["dev", "local", "test", "fake", "mock"]
            .iter()
            .any(|p| v.starts_with(p))
}

pub fn scan_text(text: &str, assignments: bool) -> Vec<Hit> {
    let mut hits = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let mut found = false;
        for (kind, re) in TOKENS.iter() {
            if let Some(m) = re.find(line) {
                hits.push(Hit {
                    kind,
                    line: n + 1,
                    masked: mask(m.as_str(), true),
                });
                found = true;
            }
        }
        if assignments
            && !found
            && let Some(c) = ASSIGNED.captures(line)
            && !placeholder(&c[1])
        {
            hits.push(Hit {
                kind: "password or token",
                line: n + 1,
                masked: mask(&c[1], false),
            });
        }
    }
    hits
}

fn read_capped(path: &Path) -> Option<String> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE {
        return None;
    }
    fs::read(path)
        .ok()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
}

/// One finding per file and kind, pointing at the first occurrence.
fn report_hits(
    host: &Host,
    path: &Path,
    hits: &[Hit],
    severity: Severity,
    remedy: &str,
    report: &mut Report,
) {
    let mut kinds: Vec<&str> = hits.iter().map(|h| h.kind).collect();
    kinds.dedup();
    kinds.sort();
    kinds.dedup();
    for kind in kinds {
        let of_kind: Vec<&Hit> = hits.iter().filter(|h| h.kind == kind).collect();
        let first = of_kind[0];
        let more = if of_kind.len() > 1 {
            format!(" (+{} more)", of_kind.len() - 1)
        } else {
            String::new()
        };
        report.find(
            Finding::new("secrets.plaintext", severity, format!("{kind} in plaintext ({}){more}", first.masked))
                .at(format!("{}:{}", host.display(path), first.line))
                .path("readable by every process running as you, and by anything that copies your dotfiles")
                .remedy(remedy),
        );
    }
}

fn histories(host: &Host, report: &mut Report) {
    let mut clean = 0;
    for rel in HISTORIES {
        let path = host.home(rel);
        let Some(text) = read_capped(&path) else {
            continue;
        };
        let hits = scan_text(&text, true);
        if hits.is_empty() {
            clean += 1;
            continue;
        }
        let severity = if hits.iter().any(|h| h.kind != "password or token") {
            Severity::High
        } else {
            Severity::Medium
        };
        report_hits(
            host,
            &path,
            &hits,
            severity,
            "rotate the secret, delete the line, and set HISTCONTROL=ignorespace to keep future ones out",
            report,
        );
    }
    if clean > 0 && !report.findings.iter().any(|f| f.id == "secrets.plaintext") {
        report.pass(format!("no secrets in {clean} shell histories"));
    }
}

/// File modes inside home only matter if other users can traverse home itself.
fn shared(host: &Host, path: &Path) -> bool {
    let home_open = host.mode(&host.home("")).is_some_and(|m| m & 0o001 != 0);
    home_open && host.mode(path).is_some_and(|m| m & 0o004 != 0)
}

fn stores(host: &Host, report: &mut Report) {
    for (rel, marker, title) in STORES {
        let path = host.home(rel);
        let Some(text) = read_capped(&path) else {
            continue;
        };
        if !text.contains(marker) {
            continue;
        }
        let shown = host.display(&path);
        let world = shared(host, &path);
        report.find(
            Finding::new(
                "secrets.credential-store",
                if world { Severity::High } else { Severity::Low },
                *title,
            )
            .at(&shown)
            .path(if world {
                "readable by other users on this machine"
            } else {
                "readable by every process running as you"
            })
            .remedy(if world {
                format!("chmod 600 {shown}; prefer a credential helper backed by the keyring")
            } else {
                "prefer a credential helper backed by the keyring or a hardware key".to_string()
            }),
        );
    }
}

fn env_files(host: &Host, report: &mut Report) {
    let mut found = Vec::new();
    for root in PROJECT_ROOTS {
        walk(&host.home(root), 0, &mut found);
    }
    found.sort();
    for path in found {
        let Some(text) = read_capped(&path) else {
            continue;
        };
        let hits = scan_text(&text, true);
        if hits.is_empty() {
            continue;
        }
        let world = shared(host, &path);
        report_hits(
            host,
            &path,
            &hits,
            if world {
                Severity::Medium
            } else {
                Severity::Low
            },
            if world {
                "chmod 600 the file; keep it out of git; prefer short-lived or scoped tokens"
            } else {
                "keep it out of git; prefer short-lived or scoped tokens"
            },
            report,
        );
    }
}

fn walk(dir: &Path, depth: u8, out: &mut Vec<PathBuf>) {
    if depth > 5 || out.len() > 500 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Ok(kind) = e.file_type() else { continue };
        if kind.is_dir() && !SKIP_DIRS.contains(&name.as_str()) {
            walk(&e.path(), depth + 1, out);
        } else if kind.is_file() && is_env_file(&name) {
            out.push(e.path());
        }
    }
}

fn is_env_file(name: &str) -> bool {
    (name == ".env" || name.starts_with(".env."))
        && !["example", "sample", "template", "dist", "defaults"]
            .iter()
            .any(|s| name.ends_with(s))
}

pub fn check(host: &Host, _ctx: &Context, report: &mut Report) {
    histories(host, report);
    stores(host, report);
    env_files(host, report);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    // Built at runtime so this file never contains a string that looks like a live token.
    fn gh() -> String {
        format!("ghp_{}", "a1B2".repeat(9))
    }

    #[test]
    fn finds_and_masks_tokens() {
        let text = format!("ls\ngit clone https://{}@github.com/x/y\n", gh());
        let hits = scan_text(&text, false);
        assert_eq!(
            hits,
            [Hit {
                kind: "github token",
                line: 2,
                masked: "ghp_****".into()
            }]
        );
    }

    #[test]
    fn finds_typed_passwords_but_not_variable_references() {
        let hits = scan_text(
            "export API_TOKEN=s3cr3tvalue99\nexport TOKEN=$(pass show x)\nmysql --password hunter2hunter2\n",
            true,
        );
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].line, 1);
        assert_eq!(hits[0].masked, "s3****");
        assert!(
            scan_text(
                "SECRET_KEY=change-me-in-prod\nAPI_KEY=dev-only-key-1\n",
                true
            )
            .is_empty()
        );
        assert_eq!(hits[1].line, 3);
        assert!(scan_text("export API_TOKEN=s3cr3tvalue99", false).is_empty());
    }

    #[test]
    fn mask_never_reveals_more_than_half() {
        assert_eq!(mask("abcd", false), "ab****");
        assert_eq!(mask("development-secret", false), "de****");
        assert_eq!(mask("sk-ant-api03-xxxxxxxx", true), "sk-****");
        assert_eq!(mask(&gh(), true), "ghp_****");
        assert_eq!(mask("äöüß", false), "äö****");
    }

    #[test]
    fn closed_home_makes_file_modes_irrelevant() {
        let dir = tempfile::tempdir().unwrap();
        let host = Host::at(dir.path(), "home/u");
        fs::create_dir_all(host.home("")).unwrap();
        fs::write(host.home(".netrc"), "machine x password y\n").unwrap();
        fs::set_permissions(host.home(".netrc"), fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(host.home(""), fs::Permissions::from_mode(0o700)).unwrap();
        let mut r = Report::default();
        stores(&host, &mut r);
        assert_eq!(r.findings[0].severity, Severity::Low);
        fs::set_permissions(host.home(""), fs::Permissions::from_mode(0o755)).unwrap();
        let mut r = Report::default();
        stores(&host, &mut r);
        assert_eq!(r.findings[0].severity, Severity::High);
    }

    #[test]
    fn env_file_names() {
        assert!(is_env_file(".env"));
        assert!(is_env_file(".env.production"));
        assert!(!is_env_file(".env.example"));
        assert!(!is_env_file("env"));
    }

    #[test]
    fn reports_history_store_and_env_files() {
        let dir = tempfile::tempdir().unwrap();
        let host = Host::at(dir.path(), "home/u");
        let proj = host.home("Projects/app");
        fs::create_dir_all(proj.join("node_modules/x")).unwrap();
        fs::set_permissions(host.home(""), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(
            host.home(".bash_history"),
            format!("echo hi\ncurl -H 'x' {}\n", gh()),
        )
        .unwrap();
        fs::write(host.home(".git-credentials"), "https://u:p@github.com\n").unwrap();
        fs::set_permissions(
            host.home(".git-credentials"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        fs::write(proj.join(".env"), "DB_PASSWORD=correcthorsebattery\n").unwrap();
        fs::set_permissions(proj.join(".env"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(proj.join(".env.example"), "DB_PASSWORD=changeme123\n").unwrap();
        fs::write(proj.join("node_modules/x/.env"), "API_KEY=ignoredignored\n").unwrap();

        let mut r = Report::default();
        check(&host, &Context::default(), &mut r);
        let got: Vec<_> = r
            .findings
            .iter()
            .map(|f| (f.severity, f.location.clone().unwrap()))
            .collect();
        assert_eq!(
            got,
            [
                (Severity::High, "~/.bash_history:2".to_string()),
                (Severity::High, "~/.git-credentials".to_string()),
                (Severity::Low, "~/Projects/app/.env:1".to_string()),
            ]
        );
        assert!(
            r.findings.iter().all(|f| !f.title.contains("a1B2")),
            "secret leaked into report"
        );
    }
}
