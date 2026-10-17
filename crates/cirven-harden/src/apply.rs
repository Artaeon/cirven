//! Applying steps behind a snapshot, and rolling a snapshot back.
//!
//! The snapshot is written before the first change, so even a crash halfway
//! through leaves a complete way back. A failed step rolls back the run.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use cirven_audit::Host;
use serde::{Deserialize, Serialize};

use crate::plan::{Action, SYSCTL_DROPIN, Step};

#[derive(Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: String,
    pub steps: Vec<String>,
    pub entries: Vec<Entry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Entry {
    /// Only the mode changes; the file's contents are never read or copied.
    Mode { path: PathBuf, mode: u32 },
    /// A file cirven writes. `before` is `None` if it did not exist.
    File {
        path: PathBuf,
        before: Option<String>,
        mode: Option<u32>,
    },
    /// A live kernel value under /proc/sys.
    Sysctl { path: PathBuf, before: String },
}

const HEADER: &str = "# managed by cirven harden. undo: cirven harden --rollback <id>";

/// Merge `settings` into an existing drop-in, keeping lines for other keys.
pub fn merge(before: Option<&str>, settings: &[(String, String)], sep: &str) -> String {
    let key_of = |line: &str| {
        line.split(|c: char| c.is_whitespace() || c == '=')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase()
    };
    let mut out = vec![HEADER.to_string()];
    for line in before.unwrap_or("").lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("# managed by cirven") {
            continue;
        }
        if !settings
            .iter()
            .any(|(k, _)| k.to_ascii_lowercase() == key_of(t))
        {
            out.push(line.to_string());
        }
    }
    out.extend(settings.iter().map(|(k, v)| format!("{k}{sep}{v}")));
    out.join("\n") + "\n"
}

fn sysctl_path(host: &Host, key: &str) -> PathBuf {
    host.sys(&format!("/proc/sys/{}", key.replace('.', "/")))
}

/// What a step will touch, recorded before anything changes.
fn record(host: &Host, step: &Step) -> io::Result<Vec<Entry>> {
    let file_entry = |path: &Path| -> io::Result<Entry> {
        let before = match fs::read_to_string(path) {
            Ok(s) => Some(s),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        Ok(Entry::File {
            path: path.to_path_buf(),
            before,
            mode: host.mode(path),
        })
    };
    Ok(match &step.action {
        Action::Chmod { path, .. } => {
            let meta = fs::symlink_metadata(path)?;
            if meta.file_type().is_symlink() {
                return Err(io::Error::other(format!(
                    "{} is a symlink; refusing to chmod",
                    path.display()
                )));
            }
            vec![Entry::Mode {
                path: path.clone(),
                mode: meta.permissions().mode() & 0o7777,
            }]
        }
        Action::DropIn { path, .. } => vec![file_entry(path)?],
        Action::Sysctl { settings } => {
            let mut entries = vec![file_entry(&host.sys(SYSCTL_DROPIN))?];
            for (key, _) in settings {
                let path = sysctl_path(host, key);
                entries.push(Entry::Sysctl {
                    before: fs::read_to_string(&path)?,
                    path,
                });
            }
            entries
        }
        Action::Manual { .. } => Vec::new(),
    })
}

/// Write via a temporary file and rename, so readers never see half a file.
fn write_atomic(path: &Path, content: &str, mode: u32) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("no parent directory"))?;
    if !parent.is_dir() {
        return Err(io::Error::other(format!(
            "{} does not exist",
            parent.display()
        )));
    }
    let tmp = path.with_extension("cirven-tmp");
    fs::write(&tmp, content)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    fs::rename(&tmp, path)
}

fn perform(host: &Host, step: &Step) -> io::Result<()> {
    match &step.action {
        Action::Chmod { path, mode } => {
            fs::set_permissions(path, fs::Permissions::from_mode(*mode))
        }
        Action::DropIn {
            path,
            settings,
            sep,
        } => {
            let before = fs::read_to_string(path).ok();
            write_atomic(path, &merge(before.as_deref(), settings, sep), 0o644)
        }
        Action::Sysctl { settings } => {
            let path = host.sys(SYSCTL_DROPIN);
            let before = fs::read_to_string(&path).ok();
            let pairs: Vec<(String, String)> = settings
                .iter()
                .map(|(k, v)| (k.clone(), v.to_string()))
                .collect();
            write_atomic(&path, &merge(before.as_deref(), &pairs, " = "), 0o644)?;
            for (key, value) in settings {
                fs::write(sysctl_path(host, key), format!("{value}\n"))?;
            }
            Ok(())
        }
        Action::Manual { .. } => Ok(()),
    }
}

/// Undo entries newest first. Keeps going past errors and reports them all.
pub fn restore(entries: &[Entry]) -> Vec<String> {
    let mut errors = Vec::new();
    for entry in entries.iter().rev() {
        let result = match entry {
            Entry::Mode { path, mode } => {
                fs::set_permissions(path, fs::Permissions::from_mode(*mode))
            }
            Entry::File {
                path,
                before: Some(content),
                mode,
            } => write_atomic(path, content, mode.unwrap_or(0o644)),
            Entry::File {
                path, before: None, ..
            } => match fs::remove_file(path) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                other => other,
            },
            Entry::Sysctl { path, before } => fs::write(path, before),
        };
        if let Err(e) = result {
            errors.push(format!("{}: {e}", entry_path(entry).display()));
        }
    }
    errors
}

fn entry_path(entry: &Entry) -> &Path {
    match entry {
        Entry::Mode { path, .. } | Entry::File { path, .. } | Entry::Sysctl { path, .. } => path,
    }
}

/// `20261017T143000Z`, sortable and safe as a file name.
pub fn timestamp(now: SystemTime) -> String {
    let secs = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

pub fn snapshot_path(state: &Path, id: &str) -> PathBuf {
    state.join(format!("{id}.json"))
}

/// Snapshot, then apply. On the first failure everything done so far is undone.
pub fn apply(host: &Host, steps: &[&Step], state: &Path) -> Result<Snapshot, String> {
    let mut entries = Vec::new();
    for step in steps {
        entries.extend(record(host, step).map_err(|e| format!("{}: {e}", step.title))?);
    }
    let snapshot = Snapshot {
        id: timestamp(SystemTime::now()),
        steps: steps.iter().map(|s| s.title.clone()).collect(),
        entries,
    };
    fs::create_dir_all(state).map_err(|e| format!("{}: {e}", state.display()))?;
    fs::set_permissions(state, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let json = serde_json::to_string_pretty(&snapshot).map_err(|e| e.to_string())?;
    write_atomic(&snapshot_path(state, &snapshot.id), &json, 0o600).map_err(|e| e.to_string())?;

    for step in steps {
        if let Err(e) = perform(host, step) {
            let undo = restore(&snapshot.entries);
            let mut msg = format!(
                "{}: {e}; all changes from this run were rolled back",
                step.title
            );
            if !undo.is_empty() {
                msg.push_str(&format!(" (with errors: {})", undo.join("; ")));
            }
            let _ = fs::remove_file(snapshot_path(state, &snapshot.id));
            return Err(msg);
        }
    }
    Ok(snapshot)
}

pub fn rollback(state: &Path, id: &str) -> Result<Snapshot, String> {
    let path = snapshot_path(state, id);
    let text = fs::read_to_string(&path).map_err(|e| format!("snapshot {id}: {e}"))?;
    let snapshot: Snapshot =
        serde_json::from_str(&text).map_err(|e| format!("snapshot {id}: {e}"))?;
    let errors = restore(&snapshot.entries);
    if !errors.is_empty() {
        return Err(format!("rollback incomplete: {}", errors.join("; ")));
    }
    fs::rename(&path, state.join(format!("{id}.rolled-back.json"))).map_err(|e| e.to_string())?;
    Ok(snapshot)
}

/// Snapshot ids with their steps, oldest first; rolled back ones are marked.
pub fn list(state: &Path) -> Vec<(String, bool, Vec<String>)> {
    let Ok(entries) = fs::read_dir(state) else {
        return Vec::new();
    };
    let mut out: Vec<_> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let (id, rolled) = match name.strip_suffix(".rolled-back.json") {
                Some(id) => (id.to_string(), true),
                None => (name.strip_suffix(".json")?.to_string(), false),
            };
            let snap: Snapshot = serde_json::from_str(&fs::read_to_string(e.path()).ok()?).ok()?;
            Some((id, rolled, snap.steps))
        })
        .collect();
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{SSHD_DROPIN, Scope};

    fn fixture() -> (tempfile::TempDir, Host) {
        let dir = tempfile::tempdir().unwrap();
        let host = Host::at(dir.path(), "home/u");
        fs::create_dir_all(host.home(".ssh")).unwrap();
        fs::set_permissions(host.home(".ssh"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir_all(host.sys("/etc/sysctl.d")).unwrap();
        fs::create_dir_all(host.sys("/etc/ssh/sshd_config.d")).unwrap();
        fs::create_dir_all(host.sys("/proc/sys/kernel")).unwrap();
        fs::write(host.sys("/proc/sys/kernel/kptr_restrict"), "0\n").unwrap();
        (dir, host)
    }

    fn steps(host: &Host) -> Vec<Step> {
        vec![
            Step {
                scope: Scope::User,
                title: "chmod".into(),
                action: Action::Chmod {
                    path: host.home(".ssh"),
                    mode: 0o700,
                },
                findings: vec![],
            },
            Step {
                scope: Scope::System,
                title: "sysctl".into(),
                action: Action::Sysctl {
                    settings: vec![("kernel.kptr_restrict".into(), 1)],
                },
                findings: vec![],
            },
            Step {
                scope: Scope::System,
                title: "sshd".into(),
                action: Action::DropIn {
                    path: host.sys(SSHD_DROPIN),
                    settings: vec![("PasswordAuthentication".into(), "no".into())],
                    sep: " ",
                },
                findings: vec![],
            },
        ]
    }

    #[test]
    fn merge_replaces_own_keys_and_keeps_others() {
        let merged = merge(
            Some(
                "# managed by cirven harden. undo: x\nX11Forwarding no\nPasswordAuthentication yes\n",
            ),
            &[("PasswordAuthentication".into(), "no".into())],
            " ",
        );
        assert_eq!(
            merged,
            format!("{HEADER}\nX11Forwarding no\nPasswordAuthentication no\n")
        );
    }

    #[test]
    fn timestamps_are_utc_civil_time() {
        assert_eq!(timestamp(UNIX_EPOCH), "19700101T000000Z");
        let t = UNIX_EPOCH + std::time::Duration::from_secs(1_792_160_000);
        assert_eq!(timestamp(t), "20261016T141320Z");
    }

    #[test]
    fn apply_then_rollback_restores_everything() {
        let (dir, host) = fixture();
        let state = dir.path().join("state");
        let steps = steps(&host);
        let refs: Vec<&Step> = steps.iter().collect();

        let snap = apply(&host, &refs, &state).unwrap();
        assert_eq!(host.mode(&host.home(".ssh")), Some(0o700));
        assert_eq!(
            fs::read_to_string(host.sys("/proc/sys/kernel/kptr_restrict")).unwrap(),
            "1\n"
        );
        assert!(
            fs::read_to_string(host.sys(SYSCTL_DROPIN))
                .unwrap()
                .contains("kernel.kptr_restrict = 1")
        );
        assert!(
            fs::read_to_string(host.sys(SSHD_DROPIN))
                .unwrap()
                .contains("PasswordAuthentication no")
        );
        assert_eq!(
            list(&state),
            [(
                snap.id.clone(),
                false,
                vec!["chmod".into(), "sysctl".into(), "sshd".into()]
            )]
        );

        rollback(&state, &snap.id).unwrap();
        assert_eq!(host.mode(&host.home(".ssh")), Some(0o755));
        assert_eq!(
            fs::read_to_string(host.sys("/proc/sys/kernel/kptr_restrict")).unwrap(),
            "0\n"
        );
        assert!(!host.sys(SYSCTL_DROPIN).exists());
        assert!(!host.sys(SSHD_DROPIN).exists());
        assert!(list(&state)[0].1, "snapshot marked rolled back");
    }

    #[test]
    fn failed_step_rolls_back_the_whole_run() {
        let (dir, host) = fixture();
        let mut steps = steps(&host);
        // The sshd drop-in directory vanishes: the third step must fail.
        fs::remove_dir(host.sys("/etc/ssh/sshd_config.d")).unwrap();
        steps.truncate(3);
        let refs: Vec<&Step> = steps.iter().collect();
        let err = apply(&host, &refs, &dir.path().join("state")).unwrap_err();
        assert!(err.contains("rolled back"), "{err}");
        assert_eq!(host.mode(&host.home(".ssh")), Some(0o755));
        assert_eq!(
            fs::read_to_string(host.sys("/proc/sys/kernel/kptr_restrict")).unwrap(),
            "0\n"
        );
        assert!(!host.sys(SYSCTL_DROPIN).exists());
        assert!(list(&dir.path().join("state")).is_empty());
    }

    #[test]
    fn refuses_to_chmod_through_symlinks() {
        let (_d, host) = fixture();
        std::os::unix::fs::symlink("/etc/passwd", host.home("link")).unwrap();
        let step = Step {
            scope: Scope::User,
            title: "chmod".into(),
            action: Action::Chmod {
                path: host.home("link"),
                mode: 0o600,
            },
            findings: vec![],
        };
        assert!(record(&host, &step).is_err());
    }
}
