//! cirven pkg: read what a package will run before it runs.
//!
//! Signals:
//! - sources: domain changes, non-upstream hosts, missing or skipped checksums
//! - scripts: network fetches, pipes to shells, base64 and eval, writes outside the package
//! - history: diff against the previous version, new maintainer, recent adoption
//! - npm/pip: install-time scripts, typosquat distance to popular names, binary blobs
//!
//! `cirven pkg wrap paru` checks every install through an AUR helper.
//!
//! Threat model: stops common supply-chain attacks. A patient attacker hiding
//! logic in compiled upstream code needs `cirven-cage` as a second layer.

use cirven_core::{Error, Module, Result, Status};

pub const MODULE: Module = Module {
    name: "pkg",
    summary: "inspect AUR/npm/pip packages before install",
    status: Status::Planned,
};

/// Entry point for `cirven pkg`. Receives the arguments after the module name.
pub fn run(_args: &[String]) -> Result<()> {
    Err(Error::NotImplemented(&MODULE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_not_implemented() {
        assert!(matches!(run(&[]), Err(Error::NotImplemented(m)) if m.name == "pkg"));
    }
}
