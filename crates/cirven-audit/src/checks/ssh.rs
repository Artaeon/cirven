//! The ssh server's effective configuration and the user's own keys.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use base64::Engine as _;
use cirven_core::{Finding, Severity};

use super::Context;
use crate::report::Report;
use cirven_core::Host;

const DROPIN: &str = "/etc/ssh/sshd_config.d/";

/// sshd keeps the first value it reads for a keyword, and `Include` splices
/// files in place. Settings inside `Match` blocks are conditional and ignored.
pub fn effective_sshd(host: &Host) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if let Some(text) = host.read_sys("/etc/ssh/sshd_config") {
        parse_sshd(host, &text, &mut out, 0);
    }
    out
}

/// Returns true once a `Match` block starts, which ends the global section.
fn parse_sshd(host: &Host, text: &str, out: &mut HashMap<String, String>, depth: u8) -> bool {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = match line.split_once(|c: char| c.is_whitespace() || c == '=') {
            Some((k, v)) => (
                k.to_ascii_lowercase(),
                v.trim_start_matches(['=', ' ', '\t']).trim(),
            ),
            None => continue,
        };
        match key.as_str() {
            "match" => return true,
            "include" if depth < 8 => {
                for pattern in value.split_whitespace() {
                    let pattern = if pattern.starts_with('/') {
                        pattern.to_string()
                    } else {
                        format!("/etc/ssh/{pattern}")
                    };
                    for file in glob(host, &pattern) {
                        if let Ok(inc) = host.read(&file)
                            && parse_sshd(host, &inc, out, depth + 1)
                        {
                            return true;
                        }
                    }
                }
            }
            _ => {
                out.entry(key).or_insert_with(|| value.to_ascii_lowercase());
            }
        }
    }
    false
}

/// Enough of glob(3) for sshd includes: one `*` in the final component.
fn glob(host: &Host, pattern: &str) -> Vec<std::path::PathBuf> {
    let (dir, name) = pattern.rsplit_once('/').unwrap_or(("", pattern));
    let Some((prefix, suffix)) = name.split_once('*') else {
        return vec![host.sys(pattern)];
    };
    let Ok(entries) = fs::read_dir(host.sys(dir)) else {
        return Vec::new();
    };
    let mut files: Vec<_> = entries
        .flatten()
        .filter(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.len() >= prefix.len() + suffix.len() && n.starts_with(prefix) && n.ends_with(suffix)
        })
        .map(|e| e.path())
        .collect();
    files.sort();
    files
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Reach {
    /// Not enabled and not listening: matters only if someone starts it.
    Dormant,
    /// Running, but only on loopback or specific addresses.
    Local,
    /// Running on every interface.
    Network,
}

fn reach(host: &Host, ctx: &Context, cfg: &HashMap<String, String>) -> Reach {
    let port: u16 = cfg.get("port").and_then(|p| p.parse().ok()).unwrap_or(22);
    let listening: Vec<_> = ctx.listeners.iter().filter(|l| l.port == port).collect();
    let enabled = ["sshd.service", "sshd.socket", "ssh.service", "ssh.socket"]
        .iter()
        .any(|u| host.unit_enabled(u));
    if listening.iter().any(|l| l.exposed()) {
        Reach::Network
    } else if !listening.is_empty() {
        Reach::Local
    } else if enabled {
        // Enabled but not up right now: assume the default, all interfaces.
        match cfg.get("listenaddress") {
            Some(a) if a.starts_with("127.") || a.starts_with("localhost") || a == "::1" => {
                Reach::Local
            }
            _ => Reach::Network,
        }
    } else {
        Reach::Dormant
    }
}

fn scaled(reach: Reach, on_network: Severity) -> Severity {
    match reach {
        Reach::Network => on_network,
        Reach::Local => Severity::Low,
        Reach::Dormant => Severity::Info,
    }
}

fn server(host: &Host, ctx: &Context, report: &mut Report) {
    if host.read_sys("/etc/ssh/sshd_config").is_none() {
        report.pass("sshd not installed");
        return;
    }
    let cfg = effective_sshd(host);
    let reach = reach(host, ctx, &cfg);
    let get = |k: &str, default: &str| cfg.get(k).cloned().unwrap_or_else(|| default.into());
    let note = |f: Finding| match reach {
        Reach::Dormant => f.path("sshd is not enabled; this applies the moment it is started"),
        Reach::Local => f.path("sshd listens only locally"),
        Reach::Network => f,
    };

    if reach == Reach::Dormant {
        report.pass("sshd not enabled");
    }
    if get("passwordauthentication", "yes") == "yes" {
        report.find(note(
            Finding::new(
                "ssh.password-auth",
                scaled(reach, Severity::High),
                "sshd accepts passwords",
            )
            .at("/etc/ssh/sshd_config")
            .path("network -> password guessing -> shell as any user with a weak password")
            .remedy(format!(
                "PasswordAuthentication no in {DROPIN}10-cirven.conf"
            )),
        ));
    } else {
        report.pass("sshd: password authentication off");
    }
    if get("kbdinteractiveauthentication", "yes") == "yes" {
        report.find(note(
            Finding::new(
                "ssh.kbd-interactive",
                scaled(reach, Severity::Medium),
                "sshd allows keyboard-interactive login (passwords via PAM)",
            )
            .remedy(format!(
                "KbdInteractiveAuthentication no in {DROPIN}10-cirven.conf"
            )),
        ));
    }
    if get("permitrootlogin", "prohibit-password") == "yes" {
        report.find(note(
            Finding::new(
                "ssh.root-login",
                scaled(reach, Severity::High),
                "sshd allows root to log in with a password",
            )
            .remedy(format!("PermitRootLogin no in {DROPIN}10-cirven.conf")),
        ));
    }
    if get("permitemptypasswords", "no") == "yes" {
        report.find(note(
            Finding::new(
                "ssh.empty-passwords",
                scaled(reach, Severity::Critical),
                "sshd accepts empty passwords",
            )
            .remedy(format!("PermitEmptyPasswords no in {DROPIN}10-cirven.conf")),
        ));
    }
    if get("x11forwarding", "no") == "yes" && reach != Reach::Dormant {
        report.find(
            Finding::new("ssh.x11-forwarding", Severity::Low, "sshd forwards X11")
                .remedy(format!("X11Forwarding no in {DROPIN}10-cirven.conf")),
        );
    }
}

/// Whether a private key is protected by a passphrase. `None` if unrecognised.
pub fn key_encrypted(text: &str) -> Option<bool> {
    if text.contains("BEGIN ENCRYPTED PRIVATE KEY") || text.contains("Proc-Type: 4,ENCRYPTED") {
        return Some(true);
    }
    if text.contains("BEGIN OPENSSH PRIVATE KEY") {
        let b64: String = text
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .map(str::trim)
            .collect();
        let raw = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
        let rest = raw.strip_prefix(b"openssh-key-v1\0")?;
        let len = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize;
        return Some(rest.get(4..4 + len)? != b"none");
    }
    if text.contains("PRIVATE KEY-----") {
        return Some(false);
    }
    None
}

fn user_keys(host: &Host, report: &mut Report) {
    let dir = host.home(".ssh");
    let Ok(entries) = fs::read_dir(&dir) else {
        report.pass("no ~/.ssh directory");
        return;
    };
    if host.mode(&dir).is_some_and(|m| m & 0o077 != 0) {
        report.find(
            Finding::new(
                "ssh.dir-perms",
                Severity::Medium,
                "~/.ssh is accessible to other users",
            )
            .at(host.display(&dir))
            .remedy("chmod 700 ~/.ssh"),
        );
    }
    let (mut keys, mut plain) = (0, 0);
    let mut paths: Vec<_> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        if !is_small_file(&path) || path.extension().is_some_and(|e| e == "pub") {
            continue;
        }
        let Ok(text) = host.read(&path) else { continue };
        let Some(encrypted) = key_encrypted(&text) else {
            continue;
        };
        keys += 1;
        let shown = host.display(&path);
        if host.mode(&path).is_some_and(|m| m & 0o077 != 0) {
            report.find(
                Finding::new(
                    "ssh.key-perms",
                    Severity::High,
                    "private key readable by other users",
                )
                .at(&shown)
                .remedy(format!("chmod 600 {shown}")),
            );
        }
        if !encrypted {
            plain += 1;
            report.find(
                Finding::new("ssh.key-no-passphrase", Severity::Medium, "ssh key has no passphrase")
                    .at(&shown)
                    .path("any process running as you, e.g. a poisoned package, can copy it and use it anywhere")
                    .remedy(format!("ssh-keygen -p -f {shown}, then load it into ssh-agent")),
            );
        }
    }
    if keys > 0 && plain == 0 {
        report.pass(format!("all {keys} ssh private keys have a passphrase"));
    }

    if let Ok(cfg) = host.read(&host.home(".ssh/config")) {
        let forwards = cfg.lines().any(|l| {
            let mut w = l.split_whitespace();
            w.next()
                .is_some_and(|k| k.eq_ignore_ascii_case("forwardagent"))
                && w.next().is_some_and(|v| v.eq_ignore_ascii_case("yes"))
        });
        if forwards {
            report.find(
                Finding::new(
                    "ssh.forward-agent",
                    Severity::Medium,
                    "ssh agent forwarding enabled",
                )
                .at("~/.ssh/config")
                .path("root on the remote host can use your keys while you are connected")
                .remedy("remove ForwardAgent yes; use ProxyJump instead"),
            );
        }
    }
}

fn is_small_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_file() && m.len() < 64 * 1024)
}

pub fn check(host: &Host, ctx: &Context, report: &mut Report) {
    server(host, ctx, report);
    user_keys(host, report);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fixture() -> (tempfile::TempDir, Host) {
        let dir = tempfile::tempdir().unwrap();
        let host = Host::at(dir.path(), "home/u");
        fs::create_dir_all(host.sys("/etc/ssh/sshd_config.d")).unwrap();
        fs::create_dir_all(host.home(".ssh")).unwrap();
        fs::set_permissions(host.home(".ssh"), fs::Permissions::from_mode(0o700)).unwrap();
        (dir, host)
    }

    fn openssh_key(cipher: &str) -> String {
        let mut raw = b"openssh-key-v1\0".to_vec();
        raw.extend((cipher.len() as u32).to_be_bytes());
        raw.extend(cipher.as_bytes());
        raw.extend([0u8; 32]);
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{b64}\n-----END OPENSSH PRIVATE KEY-----\n")
    }

    #[test]
    fn first_value_wins_and_includes_splice_in_place() {
        let (_d, host) = fixture();
        fs::write(
            host.sys("/etc/ssh/sshd_config"),
            "Include sshd_config.d/*.conf\nPasswordAuthentication yes\nPort 2222\nMatch User x\nPermitRootLogin yes\n",
        )
        .unwrap();
        fs::write(
            host.sys("/etc/ssh/sshd_config.d/50-a.conf"),
            "PasswordAuthentication no\n",
        )
        .unwrap();
        fs::write(
            host.sys("/etc/ssh/sshd_config.d/99-b.conf"),
            "PasswordAuthentication yes\nX11Forwarding=yes\n",
        )
        .unwrap();
        let cfg = effective_sshd(&host);
        assert_eq!(cfg["passwordauthentication"], "no");
        assert_eq!(cfg["x11forwarding"], "yes");
        assert_eq!(cfg["port"], "2222");
        assert!(
            !cfg.contains_key("permitrootlogin"),
            "Match block is conditional"
        );
    }

    #[test]
    fn dormant_sshd_is_informational() {
        let (_d, host) = fixture();
        fs::write(host.sys("/etc/ssh/sshd_config"), "").unwrap();
        let mut r = Report::default();
        check(&host, &Context::default(), &mut r);
        let pw = r
            .findings
            .iter()
            .find(|f| f.id == "ssh.password-auth")
            .unwrap();
        assert_eq!(pw.severity, Severity::Info);
        assert!(r.passed.iter().any(|p| p == "sshd not enabled"));
    }

    #[test]
    fn exposed_sshd_with_passwords_is_high() {
        let (_d, host) = fixture();
        fs::write(host.sys("/etc/ssh/sshd_config"), "").unwrap();
        let ctx = Context {
            listeners: vec![super::super::network::Listener {
                addr: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                port: 22,
                inode: 1,
                process: None,
            }],
            ..Context::default()
        };
        let mut r = Report::default();
        check(&host, &ctx, &mut r);
        let pw = r
            .findings
            .iter()
            .find(|f| f.id == "ssh.password-auth")
            .unwrap();
        assert_eq!(pw.severity, Severity::High);
    }

    #[test]
    fn recognises_key_encryption() {
        assert_eq!(key_encrypted(&openssh_key("none")), Some(false));
        assert_eq!(key_encrypted(&openssh_key("aes256-ctr")), Some(true));
        assert_eq!(
            key_encrypted("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n"),
            Some(true)
        );
        assert_eq!(
            key_encrypted("-----BEGIN RSA PRIVATE KEY-----\nMII\n"),
            Some(false)
        );
        assert_eq!(key_encrypted("ssh-ed25519 AAAA user@host"), None);
    }

    #[test]
    fn flags_plain_and_exposed_keys() {
        let (_d, host) = fixture();
        let key = host.home(".ssh/id_ed25519");
        fs::write(&key, openssh_key("none")).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(host.home(".ssh/id_ed25519.pub"), "ssh-ed25519 AAAA").unwrap();
        fs::write(host.home(".ssh/config"), "Host *\n  ForwardAgent yes\n").unwrap();
        let mut r = Report::default();
        user_keys(&host, &mut r);
        let ids: Vec<_> = r.findings.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "ssh.key-perms",
                "ssh.key-no-passphrase",
                "ssh.forward-agent"
            ]
        );
        assert_eq!(r.findings[0].location.as_deref(), Some("~/.ssh/id_ed25519"));
    }

    #[test]
    fn protected_keys_pass() {
        let (_d, host) = fixture();
        let key = host.home(".ssh/id_ed25519");
        fs::write(&key, openssh_key("aes256-ctr")).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let mut r = Report::default();
        user_keys(&host, &mut r);
        assert!(r.findings.is_empty());
        assert_eq!(r.passed, ["all 1 ssh private keys have a passphrase"]);
    }
}
