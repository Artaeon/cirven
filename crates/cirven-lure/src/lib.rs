//! cirven lure: decoy credentials that are worthless except for the alarm they raise.
//!
//! Decoys: fake aws credentials, ssh keys, .env files, browser login stores,
//! placed next to the real ones. The user never touches them, so any access is
//! a signal with almost no false positives.
//!
//! Two tripwires:
//! - read: fanotify reports which process opened a decoy; local and offline
//! - use: decoy tokens and URLs call home when tried elsewhere; needs a callback
//!   endpoint, self-hosted or cirven relay
//!
//! Threat model: exposes credential theft by infostealers, poisoned packages and
//! hijacked agents. It does not stop an attacker who reads only real secrets.

use cirven_core::{Error, Module, Result, Status};

pub const MODULE: Module = Module {
    name: "lure",
    summary: "decoy credentials that alarm when touched",
    status: Status::Planned,
};

/// Entry point for `cirven lure`. Receives the arguments after the module name
/// and returns the process exit code.
pub fn run(_args: &[String]) -> Result<u8> {
    Err(Error::NotImplemented(&MODULE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_not_implemented() {
        assert!(matches!(run(&[]), Err(Error::NotImplemented(m)) if m.name == "lure"));
    }
}
