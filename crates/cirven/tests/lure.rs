//! Decoys are planted without touching real files, stay invisible to audit,
//! trip on a real read, and leave nothing behind when removed.

use std::collections::BTreeMap;
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

fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in fs::read_dir(&dir).unwrap().flatten() {
            let key = e.path().strip_prefix(root).unwrap().display().to_string();
            if key == "var" || key.starts_with("var/") {
                continue;
            }
            if e.file_type().unwrap().is_dir() {
                stack.push(e.path());
                out.insert(key, Vec::new());
            } else {
                out.insert(key, fs::read(e.path()).unwrap());
            }
        }
    }
    out
}

#[test]
fn plant_trip_remove() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let home = root.join("home/user");
    fs::create_dir_all(home.join(".ssh")).unwrap();
    fs::write(home.join(".ssh/config"), "Host *\n").unwrap();
    let before = tree(root);

    let planted = cirven(root, &["lure", "plant"]);
    assert!(
        planted.status.success(),
        "{}",
        String::from_utf8_lossy(&planted.stderr)
    );
    assert!(home.join(".aws/credentials.bak").exists());
    assert_eq!(
        fs::read_to_string(home.join(".ssh/config")).unwrap(),
        "Host *\n"
    );

    let audit = cirven(root, &["audit", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&audit.stdout).unwrap();
    let ids: Vec<&str> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap())
        .collect();
    assert!(
        !ids.contains(&"ssh.key-no-passphrase"),
        "decoy key must not look like a weak real key: {ids:?}"
    );

    assert_eq!(cirven(root, &["lure", "status"]).status.code(), Some(0));
    // A real read, the way a stealer would do it.
    let read = Command::new("cat")
        .arg(home.join(".aws/credentials.bak"))
        .output()
        .unwrap();
    assert!(read.status.success());
    let status = cirven(root, &["lure", "status"]);
    let text = String::from_utf8(status.stdout).unwrap();
    assert_eq!(status.status.code(), Some(2), "{text}");
    assert!(text.contains("[TRIPPED] ~/.aws/credentials.bak"), "{text}");

    assert!(cirven(root, &["lure", "remove"]).status.success());
    assert_eq!(tree(root), before, "remove must leave the tree as it was");
}
