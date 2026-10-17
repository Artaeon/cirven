//! cirven cage: give a process the project it works on and nothing else.
//!
//! Mechanism:
//! - landlock for filesystem rules, no root required
//! - user and mount namespaces to hide paths entirely
//! - seccomp to drop syscalls a profile never needs
//! - egress allowlist per profile; denied connections are logged
//! - profiles as plain text files that can be read and diffed
//!
//! Primary use: AI coding agents, which run commands and can be steered by
//! prompt injection, and building untrusted packages.
//!
//! Threat model: contains a confused or hijacked tool. It does not stop kernel
//! exploits that escape the sandbox.

use cirven_core::{Error, Module, Result, Status};

pub const MODULE: Module = Module {
    name: "cage",
    summary: "sandbox tools and AI agents to what they need",
    status: Status::Planned,
};

/// Entry point for `cirven cage`. Receives the arguments after the module name.
pub fn run(_args: &[String]) -> Result<()> {
    Err(Error::NotImplemented(&MODULE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_not_implemented() {
        assert!(matches!(run(&[]), Err(Error::NotImplemented(m)) if m.name == "cage"));
    }
}
