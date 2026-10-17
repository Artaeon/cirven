//! Boot chain: secure boot, risky kernel parameters, a kernel waiting for reboot.

use cirven_core::{Finding, Severity};

use super::Context;
use crate::host::Host;
use crate::report::Report;

const EFI_GLOBAL: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";

/// Kernel parameters that switch off a protection, with what that costs.
const RISKY_CMDLINE: &[(&str, Severity, &str)] = &[
    (
        "mitigations=off",
        Severity::High,
        "cpu side-channel mitigations disabled",
    ),
    (
        "nokaslr",
        Severity::Medium,
        "kernel address randomisation disabled",
    ),
    (
        "nopti",
        Severity::Medium,
        "page table isolation (meltdown) disabled",
    ),
    (
        "spectre_v2=off",
        Severity::Medium,
        "spectre v2 mitigation disabled",
    ),
    (
        "module.sig_enforce=0",
        Severity::Low,
        "unsigned kernel modules allowed",
    ),
    (
        "selinux=0",
        Severity::Low,
        "selinux disabled on the command line",
    ),
];

/// An efivar is 4 attribute bytes followed by the value.
fn efivar(host: &Host, name: &str) -> Option<u8> {
    let path = host.sys(&format!("/sys/firmware/efi/efivars/{name}-{EFI_GLOBAL}"));
    std::fs::read(path).ok()?.get(4).copied()
}

fn secure_boot(host: &Host, report: &mut Report) {
    if !host.sys("/sys/firmware/efi").exists() {
        report.find(
            Finding::new(
                "boot.legacy-bios",
                Severity::Low,
                "booted in legacy BIOS mode",
            )
            .path("no secure boot possible: the boot chain cannot be verified")
            .remedy("switch the firmware to UEFI mode on the next reinstall"),
        );
        return;
    }
    match efivar(host, "SecureBoot") {
        Some(1) => report.pass("secure boot enabled"),
        Some(_) => {
            let setup = efivar(host, "SetupMode") == Some(1);
            report.find(
                Finding::new("boot.secure-boot", Severity::Medium, "secure boot disabled")
                    .path("a few minutes of physical access are enough to swap the bootloader or kernel and capture your disk password (evil maid)")
                    .remedy(if setup {
                        "firmware is in setup mode: sbctl create-keys && sbctl enroll-keys -m, then sign and enable"
                    } else {
                        "enroll your own keys with sbctl, sign the bootloader/UKI, then enable secure boot"
                    }),
            );
        }
        None => report.skip("secure boot state: efivar not readable"),
    }
}

fn cmdline(host: &Host, report: &mut Report) {
    let Some(line) = host.read_sys("/proc/cmdline") else {
        return;
    };
    let args: Vec<&str> = line.split_whitespace().collect();
    let mut risky = false;
    for (param, severity, title) in RISKY_CMDLINE {
        if args.contains(param) {
            risky = true;
            report.find(
                Finding::new("boot.cmdline", *severity, *title)
                    .at(format!("kernel parameter {param}"))
                    .remedy(format!("remove {param} from the bootloader entry")),
            );
        }
    }
    if !risky {
        report.pass("kernel command line keeps mitigations on");
    }
}

fn reboot_pending(host: &Host, report: &mut Report) {
    let Some(release) = host.read_sys("/proc/sys/kernel/osrelease") else {
        return;
    };
    let release = release.trim();
    if !host.sys("/usr/lib/modules").exists() {
        return;
    }
    if host.sys(&format!("/usr/lib/modules/{release}")).exists() {
        report.pass(format!("running the installed kernel ({release})"));
    } else {
        report.find(
            Finding::new(
                "boot.reboot-pending",
                Severity::Low,
                "running kernel is no longer installed",
            )
            .at(release)
            .path("security fixes in the updated kernel are not active until you reboot")
            .remedy("reboot"),
        );
    }
}

pub fn check(host: &Host, _ctx: &Context, report: &mut Report) {
    secure_boot(host, report);
    cmdline(host, report);
    reboot_pending(host, report);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture(secure: Option<u8>) -> (tempfile::TempDir, Host) {
        let dir = tempfile::tempdir().unwrap();
        let host = Host::at(dir.path(), "home/u");
        let vars = host.sys("/sys/firmware/efi/efivars");
        fs::create_dir_all(&vars).unwrap();
        if let Some(v) = secure {
            fs::write(
                vars.join(format!("SecureBoot-{EFI_GLOBAL}")),
                [6, 0, 0, 0, v],
            )
            .unwrap();
        }
        fs::create_dir_all(host.sys("/proc/sys/kernel")).unwrap();
        fs::create_dir_all(host.sys("/usr/lib/modules/6.1.0-new")).unwrap();
        (dir, host)
    }

    #[test]
    fn secure_boot_off_is_medium() {
        let (_d, host) = fixture(Some(0));
        let mut r = Report::default();
        secure_boot(&host, &mut r);
        assert_eq!(r.findings[0].id, "boot.secure-boot");
        assert_eq!(r.findings[0].severity, Severity::Medium);
    }

    #[test]
    fn secure_boot_on_passes() {
        let (_d, host) = fixture(Some(1));
        let mut r = Report::default();
        secure_boot(&host, &mut r);
        assert!(r.findings.is_empty());
    }

    #[test]
    fn flags_risky_parameters() {
        let (_d, host) = fixture(None);
        fs::write(
            host.sys("/proc/cmdline"),
            "root=/dev/x quiet mitigations=off nokaslr\n",
        )
        .unwrap();
        let mut r = Report::default();
        cmdline(&host, &mut r);
        let sev: Vec<_> = r.findings.iter().map(|f| f.severity).collect();
        assert_eq!(sev, [Severity::High, Severity::Medium]);
    }

    #[test]
    fn detects_pending_reboot() {
        let (_d, host) = fixture(None);
        fs::write(host.sys("/proc/sys/kernel/osrelease"), "6.1.0-old\n").unwrap();
        let mut r = Report::default();
        reboot_pending(&host, &mut r);
        assert_eq!(r.findings[0].id, "boot.reboot-pending");
        fs::write(host.sys("/proc/sys/kernel/osrelease"), "6.1.0-new\n").unwrap();
        let mut r = Report::default();
        reboot_pending(&host, &mut r);
        assert!(r.findings.is_empty());
    }
}
