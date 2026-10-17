//! cirven key: login and vaults need the key, the secret inside it and a password.
//!
//! Design:
//! - any FIDO2 key; the secret never leaves its secure element
//! - FIDO2 hmac-secret derives a per-vault value inside the key
//! - vault key = HKDF(hmac-secret || Argon2id(password)); neither half alone opens anything
//! - PAM module for local login, sudo and screen lock
//! - on udev removal: lock the screen, close vaults, zero key buffers (mlock'd, never swapped)
//! - no key files on flash storage: a USB stick can be copied, a secure element cannot
//!
//! Threat model: covers stolen laptops, stolen passwords, copied disks and
//! walk-away sessions. It does not stop malware running while the key is present
//! and a vault is open. Enroll a second key as backup.

use cirven_core::{Error, Module, Result, Status};

pub const MODULE: Module = Module {
    name: "key",
    summary: "hardware key + password; unplug and it all locks",
    status: Status::Planned,
};

/// Entry point for `cirven key`. Receives the arguments after the module name.
pub fn run(_args: &[String]) -> Result<()> {
    Err(Error::NotImplemented(&MODULE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_not_implemented() {
        assert!(matches!(run(&[]), Err(Error::NotImplemented(m)) if m.name == "key"));
    }
}
