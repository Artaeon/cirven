//! cirven audit: read the system, change nothing, report how an attacker would get in.
//!
//! Checks, grouped by area:
//! - network: listening sockets, firewall state, exposed services
//! - ssh: sshd config, authorized_keys, unencrypted private keys, agent forwarding
//! - secrets: tokens and keys in shell history, dotfiles, .env files, git configs
//! - disk: LUKS version and KDF, swap and hibernation encryption
//! - boot: secure boot, kernel cmdline, unsigned modules
//! - accounts: sudo rules, polkit, PAM stack
//! - updates: pending security updates, kernel age
//! - desktop: screen lock, autostart entries, world-readable home files
//!
//! Findings are ranked by the attack paths they open, not by checklist order.
//! Output: human, `--json`, `--sarif`. The exit code reflects the highest severity.
//!
//! Threat model: catches misconfigurations before an attacker does. It cannot
//! detect an attacker already on the machine; see `cirven-watch`.

use cirven_core::{Error, Module, Result, Status};

pub const MODULE: Module = Module {
    name: "audit",
    summary: "find weaknesses, rank them by real attack paths",
    status: Status::Planned,
};

/// Entry point for `cirven audit`. Receives the arguments after the module name.
pub fn run(_args: &[String]) -> Result<()> {
    Err(Error::NotImplemented(&MODULE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_not_implemented() {
        assert!(matches!(run(&[]), Err(Error::NotImplemented(m)) if m.name == "audit"));
    }
}
