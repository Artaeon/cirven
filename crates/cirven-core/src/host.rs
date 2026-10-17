//! Read-only view of the machine being audited.
//!
//! Every path goes through `Host`, so tests can point it at a fixture tree
//! instead of `/`. Nothing in here writes.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub struct Host {
    root: PathBuf,
    home: PathBuf,
}

impl Host {
    /// The running system, audited as the current user.
    pub fn live() -> Host {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/root"));
        Host {
            root: PathBuf::from("/"),
            home,
        }
    }

    /// A fixture tree: `root` stands in for `/`, `home` is relative to it.
    pub fn at(root: impl Into<PathBuf>, home: &str) -> Host {
        let root = root.into();
        let home = root.join(home.trim_start_matches('/'));
        Host { root, home }
    }

    /// An absolute system path such as `/etc/ssh/sshd_config`.
    pub fn sys(&self, abs: &str) -> PathBuf {
        self.root.join(abs.trim_start_matches('/'))
    }

    /// A path relative to the user's home directory.
    pub fn home(&self, rel: &str) -> PathBuf {
        if rel.is_empty() {
            self.home.clone()
        } else {
            self.home.join(rel)
        }
    }

    pub fn read(&self, path: &Path) -> io::Result<String> {
        fs::read(path).map(|b| String::from_utf8_lossy(&b).into_owned())
    }

    pub fn read_sys(&self, abs: &str) -> Option<String> {
        self.read(&self.sys(abs)).ok()
    }

    /// Permission bits of a path, without following a final symlink.
    pub fn mode(&self, path: &Path) -> Option<u32> {
        fs::symlink_metadata(path)
            .ok()
            .map(|m| m.permissions().mode() & 0o7777)
    }

    /// Whether a systemd unit is enabled at boot, judged by its `.wants` links.
    pub fn unit_enabled(&self, unit: &str) -> bool {
        let Ok(dirs) = fs::read_dir(self.sys("/etc/systemd/system")) else {
            return false;
        };
        dirs.flatten().any(|d| {
            d.file_name().to_string_lossy().ends_with(".wants")
                && fs::symlink_metadata(d.path().join(unit)).is_ok()
        })
    }

    /// Process ids under `/proc`.
    pub fn pids(&self) -> Vec<PathBuf> {
        let Ok(entries) = fs::read_dir(self.sys("/proc")) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .bytes()
                    .all(|b| b.is_ascii_digit())
            })
            .map(|e| e.path())
            .collect()
    }

    /// How a path should be shown to the user: `~/…` for home, `/…` otherwise.
    pub fn display(&self, path: &Path) -> String {
        if let Ok(rest) = path.strip_prefix(&self.home) {
            return format!("~/{}", rest.display());
        }
        match path.strip_prefix(&self.root) {
            Ok(rest) => format!("/{}", rest.display()),
            Err(_) => path.display().to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_paths_into_fixture_root() {
        let host = Host::at("/tmp/fx", "home/u");
        assert_eq!(host.sys("/etc/passwd"), PathBuf::from("/tmp/fx/etc/passwd"));
        assert_eq!(host.home(".ssh"), PathBuf::from("/tmp/fx/home/u/.ssh"));
        assert_eq!(host.display(&host.home(".ssh/id")), "~/.ssh/id");
        assert_eq!(host.display(&host.sys("/etc/x")), "/etc/x");
    }
}
