//! A planted autostart entry is caught, explained and flagged; accepting it clears the alarm.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn cirven(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cirven"))
        .args(args)
        .arg("--root")
        .arg(root)
        .output()
        .unwrap()
}

#[test]
fn catches_planted_autostart() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let home = root.join("home/user");
    fs::create_dir_all(home.join(".config/autostart")).unwrap();
    fs::write(home.join(".bashrc"), "alias ll='ls -l'\n").unwrap();

    assert!(cirven(root, &["watch", "baseline"]).status.success());
    let clean = cirven(root, &["watch"]);
    assert_eq!(clean.status.code(), Some(0));

    fs::write(
        home.join(".config/autostart/dbus-helper.desktop"),
        "[Desktop Entry]\nType=Application\nExec=/home/user/.cache/.x/run\n",
    )
    .unwrap();
    let caught = cirven(root, &["watch"]);
    let text = String::from_utf8(caught.stdout).unwrap();
    assert_eq!(caught.status.code(), Some(2), "{text}");
    assert!(
        text.contains("[ALERT  ] ~/.config/autostart/dbus-helper.desktop"),
        "{text}"
    );
    assert!(text.contains("runs a program at every login"), "{text}");
    assert!(text.contains("runs from a hidden directory"), "{text}");

    assert!(cirven(root, &["watch", "accept"]).status.success());
    assert_eq!(cirven(root, &["watch"]).status.code(), Some(0));
}

#[test]
fn follow_reports_drift_and_stops_after_ticks() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::create_dir_all(root.join("home/user")).unwrap();
    assert!(cirven(root, &["watch", "baseline"]).status.success());
    fs::write(
        root.join("home/user/.zshenv"),
        "export LD_PRELOAD=/tmp/x.so\n",
    )
    .unwrap();
    let out = cirven(
        root,
        &["watch", "follow", "--interval", "2", "--ticks", "1"],
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(out.status.success(), "{text}");
    assert!(
        text.contains("already changed since the baseline"),
        "{text}"
    );
    assert!(text.contains("[ALERT  ] ~/.zshenv"), "{text}");
}

#[test]
fn check_without_baseline_explains_what_to_do() {
    let dir = tempfile::tempdir().unwrap();
    let out = cirven(dir.path(), &["watch"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cirven watch baseline"));
}
