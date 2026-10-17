//! Live tripwire: inotify reports every open of a decoy as it happens.
//!
//! inotify does not say who opened a file, so right after each event the fd
//! tables of all visible processes are searched for the decoy. A stealer that
//! reads and closes quickly can be gone by then; the event itself still counts.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use cirven_core::Host;
use inotify::{EventMask, Inotify, WatchMask};

use crate::plant::Planted;

/// Processes that have `path` open right now, as "pid command". Always the
/// real /proc: the file events are real even when the paths are a fixture.
pub fn openers(path: &Path) -> Vec<String> {
    Host::live()
        .pids()
        .into_iter()
        .filter(|pid| {
            fs::read_dir(pid.join("fd"))
                .into_iter()
                .flatten()
                .flatten()
                .any(|fd| fs::read_link(fd.path()).is_ok_and(|t| t == path))
        })
        .map(|pid| {
            let raw = fs::read(pid.join("cmdline")).unwrap_or_default();
            let cmd = String::from_utf8_lossy(&raw).replace('\0', " ");
            let id = pid
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            format!("{id} {}", cmd.trim())
        })
        .collect()
}

fn describe(mask: EventMask) -> &'static str {
    if mask.contains(EventMask::OPEN) || mask.contains(EventMask::ACCESS) {
        "read"
    } else if mask.contains(EventMask::MODIFY) || mask.contains(EventMask::ATTRIB) {
        "changed"
    } else if mask.contains(EventMask::DELETE_SELF) || mask.contains(EventMask::MOVE_SELF) {
        "removed or moved"
    } else {
        "touched"
    }
}

/// Block and report events until `max` have been seen (forever if `None`).
/// `alert` is called for each one with the decoy, what happened and who.
pub fn watch(
    decoys: &[Planted],
    max: Option<usize>,
    mut alert: impl FnMut(&Planted, &str, &[String]),
) -> std::io::Result<()> {
    let mut inotify = Inotify::init()?;
    let mask = WatchMask::OPEN
        | WatchMask::ACCESS
        | WatchMask::MODIFY
        | WatchMask::ATTRIB
        | WatchMask::DELETE_SELF
        | WatchMask::MOVE_SELF;
    let mut by_wd = HashMap::new();
    for d in decoys {
        if let Ok(wd) = inotify.watches().add(&d.path, mask) {
            by_wd.insert(wd, d);
        }
    }
    if by_wd.is_empty() {
        return Err(std::io::Error::other("no planted decoy could be watched"));
    }
    let mut seen = 0;
    let mut buffer = [0u8; 4096];
    loop {
        for event in inotify.read_events_blocking(&mut buffer)? {
            if event.mask.contains(EventMask::IGNORED) {
                continue;
            }
            let Some(decoy) = by_wd.get(&event.wd) else {
                continue;
            };
            let who = openers(&decoy.path);
            alert(decoy, describe(event.mask), &who);
            seen += 1;
            if max.is_some_and(|m| seen >= m) {
                return Ok(());
            }
        }
    }
}
