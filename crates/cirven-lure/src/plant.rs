//! Planting decoys, noticing when they are touched, and removing them again.
//!
//! The offline tripwire is the access time: on a `relatime` mount the first
//! read after a write moves atime past mtime. cirven never reads a decoy
//! after planting it, so that move means someone else did.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use cirven_core::Host;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::decoys::{DECOYS, Random};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Planted {
    pub path: PathBuf,
    pub what: String,
    pub sha256: String,
    /// Modification time right after writing, in nanoseconds.
    pub mtime_ns: i128,
    /// Directories created for this decoy, deepest last.
    pub created_dirs: Vec<PathBuf>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Ledger {
    pub planted: Vec<Planted>,
}

pub fn load(path: &Path) -> Ledger {
    fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

pub fn save(path: &Path, ledger: &Ledger) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    let tmp = path.with_extension("tmp");
    fs::write(
        &tmp,
        serde_json::to_string_pretty(ledger).map_err(std::io::Error::other)?,
    )?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    fs::rename(tmp, path)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn ns(secs: i64, nsec: i64) -> i128 {
    i128::from(secs) * 1_000_000_000 + i128::from(nsec)
}

/// Decoy paths that are free to use. Existing files are never touched.
pub fn plan(host: &Host, ledger: &Ledger) -> Vec<(PathBuf, &'static str, bool)> {
    DECOYS
        .iter()
        .map(|d| {
            let path = host.home(d.path);
            let ours = ledger.planted.iter().any(|p| p.path == path);
            let free = !ours && fs::symlink_metadata(&path).is_err();
            (path, d.what, free)
        })
        .collect()
}

/// Create missing parents one level at a time, remembering which were new.
fn make_dirs(dir: &Path, stop: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut missing = Vec::new();
    let mut cur = dir;
    while !cur.exists() && cur != stop {
        missing.push(cur.to_path_buf());
        cur = cur.parent().unwrap_or(stop);
    }
    missing.reverse();
    for d in &missing {
        fs::create_dir(d)?;
        fs::set_permissions(d, fs::Permissions::from_mode(0o700))?;
    }
    Ok(missing)
}

pub fn plant(host: &Host, ledger: &mut Ledger) -> std::io::Result<Vec<Planted>> {
    let mut random = Random::new()?;
    let mut new = Vec::new();
    for decoy in DECOYS {
        let path = host.home(decoy.path);
        if ledger.planted.iter().any(|p| p.path == path) || fs::symlink_metadata(&path).is_ok() {
            continue;
        }
        let created_dirs = make_dirs(
            path.parent().expect("decoys live in a directory"),
            &host.home(""),
        )?;
        let body = (decoy.make)(&mut random);
        // create_new: never follow a symlink or replace a file that appeared meanwhile.
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(&body)?;
        file.sync_all()?;
        drop(file);
        let meta = fs::metadata(&path)?;
        let planted = Planted {
            path,
            what: decoy.what.to_string(),
            sha256: hex(&Sha256::digest(&body)),
            mtime_ns: ns(meta.mtime(), meta.mtime_nsec()),
            created_dirs,
        };
        ledger.planted.push(planted.clone());
        new.push(planted);
    }
    Ok(new)
}

#[derive(Debug, PartialEq)]
pub enum State {
    Untouched,
    /// Read since planting (atime moved past mtime).
    Read,
    /// Rewritten, or its metadata changed.
    Modified,
    Gone,
}

/// Judged from metadata only: checking must not itself read the decoy.
pub fn state(p: &Planted) -> State {
    let Ok(meta) = fs::symlink_metadata(&p.path) else {
        return State::Gone;
    };
    let mtime = ns(meta.mtime(), meta.mtime_nsec());
    if mtime != p.mtime_ns || !meta.is_file() {
        return State::Modified;
    }
    if ns(meta.atime(), meta.atime_nsec()) > p.mtime_ns {
        return State::Read;
    }
    State::Untouched
}

/// Whether access times are recorded where the decoys live.
pub fn atime_enabled(host: &Host) -> Option<bool> {
    let mounts = host.read_sys("/proc/self/mounts")?;
    let home = host.home("");
    mounts
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() > 3 && home.starts_with(f[1]))
                .then(|| (f[1].len(), !f[3].split(',').any(|o| o == "noatime")))
        })
        .max_by_key(|(len, _)| *len)
        .map(|(_, enabled)| enabled)
}

/// Delete decoys that are still exactly as planted, and the directories made
/// for them if empty. Anything changed is left in place and reported.
pub fn remove(ledger: &mut Ledger) -> Vec<(PathBuf, Result<(), String>)> {
    let mut results = Vec::new();
    let mut keep = Vec::new();
    let mut dirs = Vec::new();
    for p in ledger.planted.drain(..) {
        let outcome = match fs::read(&p.path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
            Ok(body) if hex(&Sha256::digest(&body)) != p.sha256 => {
                Err("contents changed since planting; left in place".into())
            }
            Ok(_) => fs::remove_file(&p.path).map_err(|e| e.to_string()),
        };
        if outcome.is_ok() {
            dirs.extend(p.created_dirs.iter().cloned());
        } else {
            keep.push(p.clone());
        }
        results.push((p.path, outcome));
    }
    // Decoys can share a directory one of them created: only once all are
    // gone can it go, deepest first. remove_dir refuses non-empty ones.
    dirs.sort_by_key(|d| std::cmp::Reverse(d.components().count()));
    dirs.dedup();
    for dir in dirs {
        let _ = fs::remove_dir(dir);
    }
    ledger.planted = keep;
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, Host) {
        let dir = tempfile::tempdir().unwrap();
        let host = Host::at(dir.path(), "home/u");
        fs::create_dir_all(host.home(".ssh")).unwrap();
        fs::write(host.home(".ssh/id_ed25519_old"), "mine, do not touch").unwrap();
        (dir, host)
    }

    #[test]
    fn never_overwrites_existing_files() {
        let (_d, host) = fixture();
        let mut ledger = Ledger::default();
        let free: Vec<bool> = plan(&host, &ledger).iter().map(|(_, _, f)| *f).collect();
        assert_eq!(free, [true, false, true, true, true]);
        let planted = plant(&host, &mut ledger).unwrap();
        assert_eq!(planted.len(), 4);
        assert_eq!(
            fs::read_to_string(host.home(".ssh/id_ed25519_old")).unwrap(),
            "mine, do not touch"
        );
        assert_eq!(
            fs::metadata(host.home(".aws/credentials.bak"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(
            plant(&host, &mut ledger).unwrap().is_empty(),
            "planting twice adds nothing"
        );
    }

    #[test]
    fn detects_reads_changes_and_deletion() {
        let (_d, host) = fixture();
        let mut ledger = Ledger::default();
        plant(&host, &mut ledger).unwrap();
        let [aws, env, wallet, login] = &ledger.planted[..] else {
            panic!()
        };
        assert!(ledger.planted.iter().all(|p| state(p) == State::Untouched));

        // A read: atime moves past mtime.
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(5);
        fs::File::options()
            .write(true)
            .open(&aws.path)
            .unwrap()
            .set_times(fs::FileTimes::new().set_accessed(later))
            .unwrap();
        assert_eq!(state(aws), State::Read);
        fs::write(&env.path, "changed").unwrap();
        assert_eq!(state(env), State::Modified);
        fs::remove_file(&wallet.path).unwrap();
        assert_eq!(state(wallet), State::Gone);
        assert_eq!(state(login), State::Untouched);
    }

    #[test]
    fn removes_only_unchanged_decoys_and_their_new_dirs() {
        let (_d, host) = fixture();
        let mut ledger = Ledger::default();
        plant(&host, &mut ledger).unwrap();
        fs::write(&ledger.planted[1].path, "edited by the user").unwrap();
        let results = remove(&mut ledger);
        assert_eq!(results.iter().filter(|(_, r)| r.is_err()).count(), 1);
        assert!(!host.home(".aws").exists(), "created directory removed");
        assert!(host.home(".ssh").exists(), "pre-existing directory kept");
        assert!(
            host.home("backup/.env.production").exists(),
            "changed decoy kept"
        );
        assert_eq!(ledger.planted.len(), 1);
    }
}
