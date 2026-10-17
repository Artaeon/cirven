//! cirven watch: baseline every place malware writes to survive a reboot, alert on change.
//!
//! Watched persistence points:
//! - systemd units and timers, system and user
//! - xdg autostart, compositor exec lines (hyprland exec-once, sway exec)
//! - shell rc files, cron/at, ~/.ssh/authorized_keys, ssh ProxyCommand
//! - /etc/ld.so.preload and LD_PRELOAD in environment files
//! - pacman hooks, udev rules, PAM config, sudoers.d, kernel modules
//! - git hooks and core.hooksPath, editor plugin directories
//!
//! Mechanism: fanotify for live events with the writing process attached, plus a
//! hashed baseline to catch changes made while watch was not running.
//!
//! Threat model: catches user-level persistence and poisoned install scripts.
//! A root attacker can stop watch first; tampering is logged and the baseline
//! can be verified from a clean boot.

use cirven_core::{Error, Module, Result, Status};

pub const MODULE: Module = Module {
    name: "watch",
    summary: "detect persistence: new units, autostarts, hooks",
    status: Status::Planned,
};

/// Entry point for `cirven watch`. Receives the arguments after the module name.
pub fn run(_args: &[String]) -> Result<()> {
    Err(Error::NotImplemented(&MODULE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_not_implemented() {
        assert!(matches!(run(&[]), Err(Error::NotImplemented(m)) if m.name == "watch"));
    }
}
