//! The cage keeps a command inside its project: files beside it are out of
//! reach, and without network only a downed loopback exists. Skips itself on
//! kernels without Landlock or without unprivileged user namespaces.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn landlock() -> bool {
    fs::read_to_string("/sys/kernel/security/lsm").is_ok_and(|l| l.contains("landlock"))
}

fn userns() -> bool {
    Command::new("unshare")
        .args(["-rn", "true"])
        .status()
        .is_ok_and(|s| s.success())
}

fn cage(cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cirven"))
        .arg("cage")
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap()
}

#[test]
fn files_outside_the_project_are_out_of_reach() {
    if !landlock() {
        eprintln!("skipped: landlock not enabled");
        return;
    }
    // Under target/, not /tmp: /tmp is writable in every profile.
    let base = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let (project, secrets) = (base.path().join("project"), base.path().join("secrets"));
    fs::create_dir_all(&project).unwrap();
    fs::create_dir_all(&secrets).unwrap();
    fs::write(project.join("code.rs"), "fn main() {}").unwrap();
    fs::write(secrets.join("token"), "hunter2").unwrap();

    let inside = cage(&project, &["--", "cat", "code.rs"]);
    assert!(
        inside.status.success(),
        "{}",
        String::from_utf8_lossy(&inside.stderr)
    );
    assert_eq!(inside.stdout, b"fn main() {}");

    let outside = cage(
        &project,
        &["--", "cat", secrets.join("token").to_str().unwrap()],
    );
    assert!(!outside.status.success());
    assert!(String::from_utf8_lossy(&outside.stderr).contains("Permission denied"));

    assert!(cage(&project, &["--", "touch", "new.txt"]).status.success());
    let escape = cage(
        &project,
        &["--", "touch", secrets.join("planted").to_str().unwrap()],
    );
    assert!(!escape.status.success());
    assert!(!secrets.join("planted").exists());

    let extra = cage(
        &project,
        &[
            "--read",
            secrets.to_str().unwrap(),
            "--",
            "cat",
            secrets.join("token").to_str().unwrap(),
        ],
    );
    assert!(extra.status.success(), "--read grants access");
}

#[test]
fn no_net_leaves_only_loopback() {
    if !landlock() || !userns() {
        eprintln!("skipped: landlock or unprivileged user namespaces unavailable");
        return;
    }
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let out = cage(dir.path(), &["--no-net", "--", "cat", "/proc/net/dev"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let ifaces: Vec<String> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .skip(2)
        .filter_map(|l| l.split(':').next().map(|i| i.trim().to_string()))
        .collect();
    assert_eq!(ifaces, ["lo"]);
}

#[test]
fn refuses_to_run_nothing() {
    let out = Command::new(env!("CARGO_BIN_EXE_cirven"))
        .arg("cage")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("nothing to run"));
}
