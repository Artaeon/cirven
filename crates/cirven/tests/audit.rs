//! Runs the real binary against a fixture system and checks two promises:
//! the report finds what is there, and audit never changes a single byte.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

fn fixture(root: &Path) {
    let w = |rel: &str, body: &str| {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    };
    w("proc/sys/kernel/hostname", "fixture\n");
    w("proc/sys/kernel/yama/ptrace_scope", "0\n");
    w(
        "proc/net/tcp",
        "  sl  local rem st q q t t r uid t inode\n   0: 00000000:0016 00000000:0000 0A 0:0 0:0 0 0 0 900 1\n",
    );
    w("etc/ssh/sshd_config", "PasswordAuthentication yes\n");
    w("etc/passwd", "root:x:0:0::/root:/bin/sh\n");
    w("home/user/.bash_history", "ls\n");
    fs::set_permissions(root.join("home/user"), fs::Permissions::from_mode(0o700)).unwrap();
}

/// Path -> (mode, contents) for every file and directory under `root`.
fn snapshot(root: &Path) -> BTreeMap<String, (u32, Vec<u8>)> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in fs::read_dir(&dir).unwrap().flatten() {
            let meta = fs::symlink_metadata(e.path()).unwrap();
            let key = e.path().strip_prefix(root).unwrap().display().to_string();
            let body = if meta.is_file() {
                fs::read(e.path()).unwrap()
            } else {
                Vec::new()
            };
            out.insert(key, (meta.permissions().mode(), body));
            if meta.is_dir() {
                stack.push(e.path());
            }
        }
    }
    out
}

#[test]
fn audit_reports_findings_and_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    fixture(dir.path());
    let before = snapshot(dir.path());

    let out = Command::new(env!("CARGO_BIN_EXE_cirven"))
        .args(["audit", "--json", "--root"])
        .arg(dir.path())
        .output()
        .unwrap();

    assert_eq!(
        snapshot(dir.path()),
        before,
        "audit modified the audited tree"
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["host"], "fixture");
    let ids: Vec<&str> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"net.no-firewall"), "{ids:?}");
    assert!(ids.contains(&"ssh.password-auth"), "{ids:?}");
    assert!(ids.contains(&"sysctl.kernel.yama.ptrace_scope"), "{ids:?}");
    // sshd on 0.0.0.0:22 with passwords and no firewall: high, so exit code 2.
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn unknown_module_flag_is_a_usage_error() {
    let out = Command::new(env!("CARGO_BIN_EXE_cirven"))
        .args(["audit", "--definitely-not-a-flag"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}
