//! What a caged process may touch. Built-in profiles, and plain text files
//! in ~/.config/cirven/cage/<name>.profile that anyone can read and diff:
//!
//! ```text
//! # comment
//! read  ~/.gitconfig
//! write .
//! net   off
//! ```

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub struct Profile {
    pub name: String,
    /// Read and execute.
    pub read: Vec<String>,
    /// Read, write, create, delete.
    pub write: Vec<String>,
    pub net: bool,
}

/// What every program needs to start: libraries, config, devices, scratch space.
const SYSTEM_READ: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/etc",
    "/opt",
    "/run",
    "/proc",
    "/sys",
    "/var/lib",
    "/var/cache",
    "/dev",
];
const SYSTEM_WRITE: &[&str] = &[
    "/tmp",
    "/var/tmp",
    "/dev/null",
    "/dev/tty",
    "/dev/pts",
    "/dev/shm",
];

/// Tool installs and the config coding agents need, but no credentials.
const AGENT_READ: &[&str] = &[
    "~/.local/bin",
    "~/.local/share/mise",
    "~/.config/mise",
    "~/.gitconfig",
    "~/.config/git",
    "~/.nvm",
    "~/.bun",
    "~/.deno",
    "~/.rustup",
];
const AGENT_WRITE: &[&str] = &[
    "~/.claude",
    "~/.claude.json",
    "~/.codex",
    "~/.local/state/claude",
    "~/.local/share/claude",
    "~/.cache",
    "~/.npm",
    "~/.cargo",
    "~/.config/claude",
];

fn owned(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_string()).collect()
}

pub fn builtin(name: &str) -> Option<Profile> {
    let base = |name: &str, net: bool| Profile {
        name: name.into(),
        read: owned(SYSTEM_READ),
        write: [owned(SYSTEM_WRITE), vec![".".into()]].concat(),
        net,
    };
    match name {
        "default" => Some(base("default", true)),
        "offline" => Some(base("offline", false)),
        "agent" => {
            let mut p = base("agent", true);
            p.read.extend(owned(AGENT_READ));
            p.write.extend(owned(AGENT_WRITE));
            Some(p)
        }
        _ => None,
    }
}

pub const BUILTIN: &[(&str, &str)] = &[
    (
        "default",
        "system read-only, current directory writable, network on",
    ),
    ("offline", "like default, no network at all"),
    (
        "agent",
        "default plus the config and caches coding agents need; no ~/.ssh, ~/.aws, browsers",
    ),
];

pub fn parse(name: &str, text: &str) -> Result<Profile, String> {
    let mut p = Profile {
        name: name.into(),
        read: Vec::new(),
        write: Vec::new(),
        net: true,
    };
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once(char::is_whitespace)
            .map(|(k, v)| (k, v.trim()))
            .unwrap_or((line, ""));
        match key {
            "include" => {
                let base = builtin(value)
                    .ok_or_else(|| format!("line {}: unknown profile {value}", n + 1))?;
                p.read.extend(base.read);
                p.write.extend(base.write);
                p.net = base.net;
            }
            "read" if !value.is_empty() => p.read.push(value.into()),
            "write" if !value.is_empty() => p.write.push(value.into()),
            "net" => {
                p.net = match value {
                    "on" => true,
                    "off" => false,
                    _ => return Err(format!("line {}: net must be on or off", n + 1)),
                }
            }
            _ => {
                return Err(format!(
                    "line {}: expected include, read, write or net",
                    n + 1
                ));
            }
        }
    }
    Ok(p)
}

pub fn load(name: &str, config: &Path) -> Result<Profile, String> {
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(format!("{name}: not a valid profile name"));
    }
    let file = config.join(format!("{name}.profile"));
    match std::fs::read_to_string(&file) {
        Ok(text) => parse(name, &text).map_err(|e| format!("{}: {e}", file.display())),
        Err(_) => builtin(name)
            .ok_or_else(|| format!("no profile {name}: not built in, and no {}", file.display())),
    }
}

/// `~/x` to the home directory, `.` and relative paths to the working directory.
pub fn expand(entry: &str, home: &Path, cwd: &Path) -> PathBuf {
    if entry == "~" {
        home.to_path_buf()
    } else if let Some(rest) = entry.strip_prefix("~/") {
        home.join(rest)
    } else if entry.starts_with('/') {
        PathBuf::from(entry)
    } else {
        cwd.join(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_profile_never_exposes_credentials() {
        let p = builtin("agent").unwrap();
        for secret in [
            "~/.ssh",
            "~/.aws",
            "~/.gnupg",
            "~",
            "~/.config",
            "~/.mozilla",
        ] {
            assert!(!p.read.contains(&secret.to_string()), "{secret} readable");
            assert!(!p.write.contains(&secret.to_string()), "{secret} writable");
        }
        assert!(p.write.contains(&".".to_string()));
    }

    #[test]
    fn parses_profile_files() {
        let p = parse("x", "# build untrusted code\ninclude offline\nread ~/.gitconfig # git identity\nwrite ./out\n").unwrap();
        assert!(!p.net);
        assert!(p.read.contains(&"~/.gitconfig".to_string()));
        assert!(p.write.contains(&"./out".to_string()));
        assert!(parse("x", "net maybe").is_err());
        assert!(parse("x", "chmod 777 /").is_err());
    }

    #[test]
    fn expands_paths() {
        let (home, cwd) = (Path::new("/home/u"), Path::new("/home/u/proj"));
        assert_eq!(
            expand("~/.cache", home, cwd),
            PathBuf::from("/home/u/.cache")
        );
        assert_eq!(expand(".", home, cwd), PathBuf::from("/home/u/proj/."));
        assert_eq!(expand("/tmp", home, cwd), PathBuf::from("/tmp"));
    }

    #[test]
    fn rejects_path_like_names() {
        assert!(load("../../etc/passwd", Path::new("/nonexistent")).is_err());
        assert_eq!(
            load("agent", Path::new("/nonexistent")).unwrap().name,
            "agent"
        );
    }
}
