//! cirven harden: turn audit findings into fixes, with a plan, an apply step and a rollback.
//!
//! Design:
//! - every fix is a small declared change: a drop-in file, a sysctl, a mode bit
//! - drop-ins over edits, so upstream configs stay untouched
//! - files are snapshotted before change; rollback restores them byte for byte
//! - fixes that can lock the user out (ssh, firewall) apply behind a dead-man timer:
//!   without confirmation within 60s they roll back automatically
//! - profiles: `laptop`, `dev`, `paranoid`
//!
//! Threat model: closes the attack paths audit reports. A purged secret must
//! still be rotated at its issuer.

use cirven_core::{Error, Module, Result, Status};

pub const MODULE: Module = Module {
    name: "harden",
    summary: "fix findings: preview, apply, roll back",
    status: Status::Planned,
};

/// Entry point for `cirven harden`. Receives the arguments after the module name.
pub fn run(_args: &[String]) -> Result<()> {
    Err(Error::NotImplemented(&MODULE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_not_implemented() {
        assert!(matches!(run(&[]), Err(Error::NotImplemented(m)) if m.name == "harden"));
    }
}
