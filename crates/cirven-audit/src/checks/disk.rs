//! Encryption at rest: root, home and swap.

use std::fs;

use cirven_core::{Finding, Severity};

use super::Context;
use crate::host::Host;
use crate::report::Report;

/// Device-mapper name for a mount source, if it is a dm device.
fn dm_node(host: &Host, source: &str) -> Option<String> {
    if let Some(node) = source
        .strip_prefix("/dev/")
        .filter(|n| n.starts_with("dm-"))
    {
        return Some(node.to_string());
    }
    let name = source.strip_prefix("/dev/mapper/")?;
    let blocks = fs::read_dir(host.sys("/sys/block")).ok()?;
    blocks.flatten().find_map(|b| {
        let node = b.file_name().to_string_lossy().into_owned();
        let dm_name = host.read_sys(&format!("/sys/block/{node}/dm/name"))?;
        (dm_name.trim() == name).then_some(node)
    })
}

/// `LUKS2`, `LUKS1` or `PLAIN` if the device is dm-crypt, looking through
/// stacked layers such as LVM on LUKS.
pub fn crypt_type(host: &Host, node: &str, depth: u8) -> Option<String> {
    if depth > 4 {
        return None;
    }
    let uuid = host.read_sys(&format!("/sys/block/{node}/dm/uuid"))?;
    if let Some(rest) = uuid.trim().strip_prefix("CRYPT-") {
        return rest.split('-').next().map(str::to_string);
    }
    let slaves = fs::read_dir(host.sys(&format!("/sys/block/{node}/slaves"))).ok()?;
    slaves.flatten().find_map(|s| {
        let slave = s.file_name().to_string_lossy().into_owned();
        slave
            .starts_with("dm-")
            .then(|| crypt_type(host, &slave, depth + 1))
            .flatten()
    })
}

fn mounts(host: &Host) -> Vec<(String, String, String)> {
    host.read_sys("/proc/self/mounts")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            Some((
                f.next()?.to_string(),
                f.next()?.to_string(),
                f.next()?.to_string(),
            ))
        })
        .collect()
}

/// Encryption of whatever is mounted at `point`: Some(type) or None if plain.
/// Returns Err when it cannot tell (not mounted, or a filesystem with its own crypto).
fn mount_crypt(host: &Host, point: &str) -> Result<Option<String>, ()> {
    let all = mounts(host);
    let (source, _, fstype) = all.iter().rev().find(|(_, p, _)| p == point).ok_or(())?;
    if fstype == "zfs" || fstype == "bcachefs" {
        return Err(());
    }
    Ok(dm_node(host, source).and_then(|n| crypt_type(host, &n, 0)))
}

fn volume(host: &Host, point: &str, label: &str, report: &mut Report) -> Option<bool> {
    match mount_crypt(host, point) {
        Ok(Some(t)) if t == "LUKS1" => {
            report.find(
                Finding::new("disk.luks1", Severity::Medium, format!("{label} on LUKS1"))
                    .at(point)
                    .path("LUKS1 derives keys with PBKDF2, which GPUs brute-force far faster than argon2id")
                    .remedy("cryptsetup convert --type luks2, then luksConvertKey --pbkdf argon2id"),
            );
            Some(true)
        }
        Ok(Some(t)) => {
            report.pass(format!("{label} encrypted ({t})"));
            Some(true)
        }
        Ok(None) => {
            report.find(
                Finding::new(
                    "disk.unencrypted",
                    Severity::High,
                    format!("{label} not encrypted"),
                )
                .at(point)
                .path("a lost or stolen laptop hands over ssh keys, tokens and browser sessions")
                .remedy("reinstall onto LUKS2, or encrypt in place with cryptsetup reencrypt"),
            );
            Some(false)
        }
        Err(()) => None,
    }
}

fn swap(host: &Host, root_encrypted: Option<bool>, report: &mut Report) {
    let swaps = host.read_sys("/proc/swaps").unwrap_or_default();
    let entries: Vec<(String, String)> = swaps
        .lines()
        .skip(1)
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            Some((f.next()?.to_string(), f.next()?.to_string()))
        })
        .collect();
    if entries.is_empty() {
        report.pass("no swap");
        return;
    }
    for (name, kind) in entries {
        let plain = if name.starts_with("/dev/zram") {
            false
        } else if kind == "file" {
            root_encrypted == Some(false)
        } else {
            dm_node(host, &name)
                .and_then(|n| crypt_type(host, &n, 0))
                .is_none()
        };
        if plain {
            report.find(
                Finding::new(
                    "disk.swap-unencrypted",
                    Severity::High,
                    "swap not encrypted",
                )
                .at(&name)
                .path(
                    "memory pages, including keys and passwords, are written to disk in plaintext",
                )
                .remedy("use zram, or put swap on dm-crypt"),
            );
        } else {
            report.pass(format!("swap protected ({name})"));
        }
    }
}

pub fn check(host: &Host, _ctx: &Context, report: &mut Report) {
    let root = volume(host, "/", "root filesystem", report);
    if root.is_none() {
        report.skip("root filesystem encryption: could not determine");
    }
    let home_separate = mounts(host).iter().any(|(_, p, _)| p == "/home");
    if home_separate {
        volume(host, "/home", "/home", report);
    }
    swap(host, root, report);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, Host) {
        let dir = tempfile::tempdir().unwrap();
        let host = Host::at(dir.path(), "home/u");
        fs::create_dir_all(host.sys("/proc/self")).unwrap();
        (dir, host)
    }

    fn dm(host: &Host, node: &str, name: &str, uuid: &str, slaves: &[&str]) {
        let base = host.sys(&format!("/sys/block/{node}"));
        fs::create_dir_all(base.join("dm")).unwrap();
        fs::create_dir_all(base.join("slaves")).unwrap();
        fs::write(base.join("dm/name"), format!("{name}\n")).unwrap();
        fs::write(base.join("dm/uuid"), format!("{uuid}\n")).unwrap();
        for s in slaves {
            fs::create_dir_all(base.join("slaves").join(s)).unwrap();
        }
    }

    #[test]
    fn luks2_root_and_zram_pass() {
        let (_d, host) = fixture();
        dm(&host, "dm-0", "root", "CRYPT-LUKS2-1ab3-root", &[]);
        fs::write(
            host.sys("/proc/self/mounts"),
            "/dev/mapper/root / btrfs rw 0 0\n",
        )
        .unwrap();
        fs::write(
            host.sys("/proc/swaps"),
            "Filename Type Size Used Priority\n/dev/zram0 partition 1 0 100\n",
        )
        .unwrap();
        let mut r = Report::default();
        check(&host, &Context::default(), &mut r);
        assert!(r.findings.is_empty(), "{:?}", r.findings);
        assert_eq!(
            r.passed,
            [
                "root filesystem encrypted (LUKS2)",
                "swap protected (/dev/zram0)"
            ]
        );
    }

    #[test]
    fn sees_luks_below_lvm() {
        let (_d, host) = fixture();
        dm(&host, "dm-0", "cryptlvm", "CRYPT-LUKS1-abc-cryptlvm", &[]);
        dm(&host, "dm-1", "vg-root", "LVM-xyz", &["dm-0"]);
        assert_eq!(crypt_type(&host, "dm-1", 0).as_deref(), Some("LUKS1"));
    }

    #[test]
    fn plain_root_and_partition_swap_are_high() {
        let (_d, host) = fixture();
        fs::write(
            host.sys("/proc/self/mounts"),
            "/dev/nvme0n1p2 / ext4 rw 0 0\n",
        )
        .unwrap();
        fs::write(
            host.sys("/proc/swaps"),
            "Filename Type Size Used Priority\n/dev/nvme0n1p3 partition 1 0 -2\n",
        )
        .unwrap();
        let mut r = Report::default();
        check(&host, &Context::default(), &mut r);
        let ids: Vec<_> = r
            .findings
            .iter()
            .map(|f| (f.id.as_str(), f.severity))
            .collect();
        assert_eq!(
            ids,
            [
                ("disk.unencrypted", Severity::High),
                ("disk.swap-unencrypted", Severity::High)
            ]
        );
    }
}
