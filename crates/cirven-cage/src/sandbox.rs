//! Applying a profile to the current process, right before exec.
//!
//! - network off: a new user and network namespace with nothing but a downed
//!   loopback; no TCP, no UDP, no DNS
//! - filesystem: Landlock, unprivileged and inherited by every child
//! - Landlock sets no_new_privs, so sudo and setuid binaries cannot escape

use std::fs;
use std::path::PathBuf;

use landlock::{
    ABI, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    path_beneath_rules,
};
use nix::sched::{CloneFlags, unshare};
use nix::unistd::{getgid, getuid};

/// Newest Landlock ABI we know; older kernels get what they support.
const ABI_TARGET: ABI = ABI::V5;

/// Cut all network access by moving into fresh user and network namespaces,
/// mapping our uid and gid to themselves so file ownership looks unchanged.
pub fn drop_network() -> Result<(), String> {
    let (uid, gid) = (getuid(), getgid());
    unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNET).map_err(|e| {
        format!(
            "cannot create a network namespace ({e}); unprivileged user namespaces may be disabled"
        )
    })?;
    fs::write("/proc/self/setgroups", "deny").map_err(|e| format!("setgroups: {e}"))?;
    fs::write("/proc/self/uid_map", format!("{uid} {uid} 1"))
        .map_err(|e| format!("uid_map: {e}"))?;
    fs::write("/proc/self/gid_map", format!("{gid} {gid} 1"))
        .map_err(|e| format!("gid_map: {e}"))?;
    Ok(())
}

/// Restrict the filesystem to `read` (read and execute) and `write` (full).
/// Missing paths are skipped. Fails rather than run unconfined.
pub fn restrict(read: &[PathBuf], write: &[PathBuf]) -> Result<RulesetStatus, String> {
    let existing = |list: &[PathBuf]| -> Vec<PathBuf> {
        list.iter().filter(|p| p.exists()).cloned().collect()
    };
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(ABI_TARGET))
        .and_then(|r| r.create())
        .and_then(|r| {
            r.add_rules(path_beneath_rules(
                existing(read),
                AccessFs::from_read(ABI_TARGET),
            ))
        })
        .and_then(|r| {
            r.add_rules(path_beneath_rules(
                existing(write),
                AccessFs::from_all(ABI_TARGET),
            ))
        })
        .and_then(|r| r.restrict_self())
        .map_err(|e| format!("landlock: {e}"))?;
    match status.ruleset {
        RulesetStatus::NotEnforced => {
            Err("landlock is not available in this kernel; refusing to run unconfined".into())
        }
        s => Ok(s),
    }
}
