//! Where persistence lives on a Linux desktop, and why each place matters.

use std::fs;
use std::path::{Path, PathBuf};

use cirven_core::Host;

/// A watched location: a file, or a directory watched recursively.
pub struct Point {
    pub path: &'static str,
    pub why: &'static str,
}

/// Paths relative to the home directory.
pub const USER: &[Point] = &[
    Point {
        path: ".config/systemd/user",
        why: "user service: runs a program at every login",
    },
    Point {
        path: ".config/autostart",
        why: "xdg autostart: runs a program at every login",
    },
    Point {
        path: ".config/hypr",
        why: "compositor config: exec-once runs programs at login",
    },
    Point {
        path: ".config/uwsm",
        why: "session environment: can inject variables like LD_PRELOAD",
    },
    Point {
        path: ".config/environment.d",
        why: "session environment: can inject variables like LD_PRELOAD",
    },
    Point {
        path: ".bashrc",
        why: "runs in every new bash shell",
    },
    Point {
        path: ".bash_profile",
        why: "runs at every bash login",
    },
    Point {
        path: ".bash_logout",
        why: "runs whenever a bash login shell exits",
    },
    Point {
        path: ".profile",
        why: "runs at every login shell",
    },
    Point {
        path: ".zshrc",
        why: "runs in every new zsh shell",
    },
    Point {
        path: ".zshenv",
        why: "runs for every zsh, even scripts",
    },
    Point {
        path: ".zprofile",
        why: "runs at every zsh login",
    },
    Point {
        path: ".config/fish",
        why: "runs in every new fish shell",
    },
    Point {
        path: ".xprofile",
        why: "runs at every graphical login",
    },
    Point {
        path: ".xinitrc",
        why: "runs when X starts",
    },
    Point {
        path: ".pam_environment",
        why: "login environment: can inject LD_PRELOAD",
    },
    Point {
        path: ".ssh/authorized_keys",
        why: "grants ssh login to whoever holds the matching key",
    },
    Point {
        path: ".ssh/config",
        why: "ProxyCommand and LocalCommand run programs on every ssh",
    },
    Point {
        path: ".ssh/rc",
        why: "runs on every incoming ssh login",
    },
    Point {
        path: ".gitconfig",
        why: "core.hooksPath and core.fsmonitor run programs inside every repo",
    },
    Point {
        path: ".config/git",
        why: "core.hooksPath and core.fsmonitor run programs inside every repo",
    },
    Point {
        path: ".local/bin",
        why: "early on PATH: a new file here can shadow a real command",
    },
    Point {
        path: ".local/share/applications",
        why: "desktop entries: can hijack how files and links open",
    },
    Point {
        path: ".config/mimeapps.list",
        why: "decides which program opens files and links",
    },
];

/// Absolute system paths. Package-managed /usr is left to the package manager.
pub const SYSTEM: &[Point] = &[
    Point {
        path: "/etc/systemd/system",
        why: "system service: runs as root at boot",
    },
    Point {
        path: "/etc/systemd/user",
        why: "user service for every account",
    },
    Point {
        path: "/etc/ld.so.preload",
        why: "injects a library into every program on the system",
    },
    Point {
        path: "/etc/environment",
        why: "global environment: can inject LD_PRELOAD",
    },
    Point {
        path: "/etc/profile.d",
        why: "runs in every login shell of every user",
    },
    Point {
        path: "/etc/profile",
        why: "runs in every login shell of every user",
    },
    Point {
        path: "/etc/bash.bashrc",
        why: "runs in every bash shell of every user",
    },
    Point {
        path: "/etc/zsh",
        why: "runs in every zsh shell of every user",
    },
    Point {
        path: "/etc/xdg/autostart",
        why: "autostart for every graphical login",
    },
    Point {
        path: "/etc/pam.d",
        why: "decides how every login is authenticated",
    },
    Point {
        path: "/etc/sudoers",
        why: "decides who becomes root",
    },
    Point {
        path: "/etc/sudoers.d",
        why: "decides who becomes root",
    },
    Point {
        path: "/etc/passwd",
        why: "user accounts: a new uid 0 entry is a backdoor",
    },
    Point {
        path: "/etc/group",
        why: "group membership: wheel and docker mean root",
    },
    Point {
        path: "/etc/crontab",
        why: "scheduled commands run as root",
    },
    Point {
        path: "/etc/cron.d",
        why: "scheduled commands run as root",
    },
    Point {
        path: "/etc/cron.hourly",
        why: "scheduled commands run as root",
    },
    Point {
        path: "/etc/cron.daily",
        why: "scheduled commands run as root",
    },
    Point {
        path: "/var/spool/cron",
        why: "per-user scheduled commands",
    },
    Point {
        path: "/etc/udev/rules.d",
        why: "runs commands as root when devices appear",
    },
    Point {
        path: "/etc/pacman.d/hooks",
        why: "runs commands as root on every package transaction",
    },
    Point {
        path: "/etc/modules-load.d",
        why: "loads kernel modules at boot",
    },
    Point {
        path: "/etc/modprobe.d",
        why: "install directives run commands when modules load",
    },
    Point {
        path: "/etc/ssh/sshd_config",
        why: "decides who may log in over ssh",
    },
    Point {
        path: "/etc/ssh/sshd_config.d",
        why: "decides who may log in over ssh",
    },
    Point {
        path: "/etc/hosts",
        why: "redirects host names, e.g. to a phishing server",
    },
];

const MAX_DEPTH: u8 = 4;
const MAX_FILES: usize = 5_000;

/// Files under a point, with the reason inherited from the point.
/// Symlinks are listed, never followed: their target is what gets recorded.
pub fn expand(host: &Host) -> Vec<(PathBuf, &'static str)> {
    let mut out = Vec::new();
    for p in USER {
        collect(&host.home(p.path), p.why, 0, &mut out);
    }
    for p in SYSTEM {
        collect(&host.sys(p.path), p.why, 0, &mut out);
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out.dedup_by(|a, b| a.0 == b.0);
    out
}

fn collect(path: &Path, why: &'static str, depth: u8, out: &mut Vec<(PathBuf, &'static str)>) {
    if out.len() >= MAX_FILES {
        return;
    }
    let Ok(meta) = fs::symlink_metadata(path) else {
        return;
    };
    if meta.is_dir() && depth < MAX_DEPTH {
        match fs::read_dir(path) {
            Ok(entries) => {
                for e in entries.flatten() {
                    collect(&e.path(), why, depth + 1, out);
                }
            }
            // An unreadable directory is still worth recording: its mode and mtime.
            Err(_) => out.push((path.to_path_buf(), why)),
        }
    } else if !meta.is_dir() {
        out.push((path.to_path_buf(), why));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_directories_and_keeps_symlinks_unfollowed() {
        let dir = tempfile::tempdir().unwrap();
        let host = Host::at(dir.path(), "home/u");
        let units = host.home(".config/systemd/user/default.target.wants");
        fs::create_dir_all(&units).unwrap();
        fs::write(host.home(".config/systemd/user/a.service"), "[Service]\n").unwrap();
        std::os::unix::fs::symlink("../a.service", units.join("a.service")).unwrap();
        fs::write(host.home(".bashrc"), "alias ll='ls -l'\n").unwrap();
        fs::create_dir_all(host.sys("/etc")).unwrap();
        fs::write(host.sys("/etc/hosts"), "127.0.0.1 localhost\n").unwrap();

        let shown: Vec<String> = expand(&host).iter().map(|(p, _)| host.display(p)).collect();
        assert_eq!(
            shown,
            [
                "/etc/hosts",
                "~/.bashrc",
                "~/.config/systemd/user/a.service",
                "~/.config/systemd/user/default.target.wants/a.service",
            ]
        );
    }
}
