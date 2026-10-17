//! Fingerprints of every persistence point, and the differences between two sets.
//!
//! Only hashes and metadata are stored, never contents: a baseline of shell rc
//! files must not become a second copy of the secrets people put in them.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use cirven_core::Host;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Print {
    File { sha256: String, mode: u32, uid: u32 },
    Link { target: String },
    /// Not readable by us: compare what the inode tells.
    Opaque { size: u64, mtime: i64, mode: u32, uid: u32 },
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Baseline {
    pub taken: String,
    /// Keyed by the path as shown to the user (`~/…` or `/…`).
    pub points: BTreeMap<String, Print>,
}

pub fn fingerprint(path: &Path) -> Option<Print> {
    let meta = fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() {
        let target = fs::read_link(path).ok()?;
        return Some(Print::Link { target: target.display().to_string() });
    }
    let mode = meta.permissions().mode() & 0o7777;
    match fs::read(path) {
        Ok(bytes) if meta.is_file() => Some(Print::File {
            sha256: hex(&Sha256::digest(&bytes)),
            mode,
            uid: meta.uid(),
        }),
        _ => Some(Print::Opaque { size: meta.len(), mtime: meta.mtime(), mode, uid: meta.uid() }),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn take(host: &Host, taken: String) -> (Baseline, BTreeMap<String, &'static str>) {
    let mut points = BTreeMap::new();
    let mut reasons = BTreeMap::new();
    for (path, why) in crate::points::expand(host) {
        if let Some(print) = fingerprint(&path) {
            let shown = host.display(&path);
            reasons.insert(shown.clone(), why);
            points.insert(shown, print);
        }
    }
    (Baseline { taken, points }, reasons)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Change {
    Added,
    Changed,
    Removed,
}

/// Every point that differs between `old` and `new`, in path order.
pub fn diff(old: &Baseline, new: &Baseline) -> Vec<(Change, String)> {
    let mut out = Vec::new();
    for (path, print) in &new.points {
        match old.points.get(path) {
            None => out.push((Change::Added, path.clone())),
            Some(before) if before != print => out.push((Change::Changed, path.clone())),
            _ => {}
        }
    }
    for path in old.points.keys() {
        if !new.points.contains_key(path) {
            out.push((Change::Removed, path.clone()));
        }
    }
    out.sort_by(|a, b| a.1.cmp(&b.1));
    out
}

pub fn load(path: &Path) -> Option<Baseline> {
    serde_json::from_str(&fs::read_to_string(path).ok()?).ok()
}

pub fn save(path: &Path, baseline: &Baseline) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, serde_json::to_string_pretty(baseline).map_err(std::io::Error::other)?)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    fs::rename(tmp, path)
}

/// Turn a shown path back into a real one, to read a changed file's lines.
pub fn resolve(host: &Host, shown: &str) -> PathBuf {
    match shown.strip_prefix("~/") {
        Some(rel) => host.home(rel),
        None => host.sys(shown),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_added_changed_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        let host = Host::at(dir.path(), "home/u");
        fs::create_dir_all(host.home(".config/autostart")).unwrap();
        fs::write(host.home(".bashrc"), "alias ll='ls -l'\n").unwrap();
        fs::write(host.home(".zshrc"), "setopt x\n").unwrap();
        let (before, _) = take(&host, "t0".into());

        fs::write(host.home(".bashrc"), "alias ll='ls -l'\nexport LD_PRELOAD=/tmp/x.so\n").unwrap();
        fs::remove_file(host.home(".zshrc")).unwrap();
        fs::write(host.home(".config/autostart/upd.desktop"), "[Desktop Entry]\nExec=/tmp/upd\n").unwrap();
        let (after, reasons) = take(&host, "t1".into());

        assert_eq!(
            diff(&before, &after),
            [
                (Change::Changed, "~/.bashrc".to_string()),
                (Change::Added, "~/.config/autostart/upd.desktop".to_string()),
                (Change::Removed, "~/.zshrc".to_string()),
            ]
        );
        assert_eq!(reasons["~/.bashrc"], "runs in every new bash shell");
        assert!(diff(&after, &after).is_empty());
    }

    #[test]
    fn mode_changes_count() {
        let dir = tempfile::tempdir().unwrap();
        let host = Host::at(dir.path(), "home/u");
        fs::create_dir_all(host.home(".ssh")).unwrap();
        fs::write(host.home(".ssh/authorized_keys"), "ssh-ed25519 AAAA me\n").unwrap();
        let (before, _) = take(&host, "t0".into());
        fs::set_permissions(host.home(".ssh/authorized_keys"), fs::Permissions::from_mode(0o666)).unwrap();
        let (after, _) = take(&host, "t1".into());
        assert_eq!(diff(&before, &after).len(), 1);
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = Baseline { taken: "t".into(), ..Baseline::default() };
        b.points.insert("~/.bashrc".into(), Print::Link { target: "x".into() });
        let path = dir.path().join("state/baseline.json");
        save(&path, &b).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.points, b.points);
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
