//! plan -> apply -> audit is clean -> rollback -> the tree is byte for byte what it was.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

fn fixture(root: &Path) {
    let w = |rel: &str, body: &str| {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    };
    w("proc/sys/kernel/hostname", "fixture\n");
    w("proc/sys/kernel/kptr_restrict", "0\n");
    w("proc/sys/kernel/yama/ptrace_scope", "0\n");
    w(
        "proc/net/tcp",
        "  sl  local rem st q q t t r uid t inode\n   0: 00000000:0016 00000000:0000 0A 0:0 0:0 0 0 0 900 1\n",
    );
    w(
        "etc/ssh/sshd_config",
        "Include /etc/ssh/sshd_config.d/*.conf\n",
    );
    fs::create_dir_all(root.join("etc/ssh/sshd_config.d")).unwrap();
    fs::create_dir_all(root.join("etc/sysctl.d")).unwrap();
    w("home/user/.ssh/known_hosts", "");
    fs::set_permissions(root.join("home/user"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(
        root.join("home/user/.ssh"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
}

fn snapshot(root: &Path) -> BTreeMap<String, (u32, Vec<u8>)> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in fs::read_dir(&dir).unwrap().flatten() {
            let key = e.path().strip_prefix(root).unwrap().display().to_string();
            // The snapshot store itself (in the fixture: var/lib/cirven) outlives a rollback.
            if key == "var" || key.starts_with("var/") {
                continue;
            }
            let meta = fs::symlink_metadata(e.path()).unwrap();
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

fn cirven(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cirven"))
        .args(args)
        .arg("--root")
        .arg(root)
        .output()
        .unwrap()
}

fn finding_ids(root: &Path) -> Vec<String> {
    let out = cirven(root, &["audit", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn plan_apply_rollback_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fixture(root);
    let before = snapshot(root);

    let plan = cirven(root, &["harden"]);
    let plan = String::from_utf8(plan.stdout).unwrap();
    assert!(plan.contains("nothing has been changed"), "{plan}");
    assert_eq!(snapshot(root), before, "the plan alone must not write");

    let applied = cirven(root, &["harden", "--apply", "all"]);
    let text = String::from_utf8(applied.stdout).unwrap();
    assert!(
        applied.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    let id = text
        .lines()
        .find_map(|l| l.strip_prefix("undo with: cirven harden --rollback "))
        .unwrap()
        .to_string();

    let ids = finding_ids(root);
    for fixed in [
        "ssh.dir-perms",
        "ssh.password-auth",
        "sysctl.kernel.kptr_restrict",
        "sysctl.kernel.yama.ptrace_scope",
    ] {
        assert!(
            !ids.contains(&fixed.to_string()),
            "{fixed} still reported: {ids:?}"
        );
    }
    assert!(
        ids.contains(&"net.no-firewall".to_string()),
        "firewall is never touched"
    );

    let rolled = cirven(root, &["harden", "--rollback", &id]);
    assert!(
        rolled.status.success(),
        "{}",
        String::from_utf8_lossy(&rolled.stderr)
    );
    assert_eq!(
        snapshot(root),
        before,
        "rollback must restore the exact previous state"
    );
}
