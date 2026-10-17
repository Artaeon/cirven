//! Fetching an AUR package for inspection, and what its metadata says.
//!
//! Only plain HTTPS GETs against aur.archlinux.org. Nothing is cloned or built.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cirven_core::{Finding, Severity};
use serde::Deserialize;

const AUR: &str = "https://aur.archlinux.org";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Info {
    pub name: String,
    pub package_base: String,
    pub version: String,
    pub maintainer: Option<String>,
    pub first_submitted: u64,
    pub last_modified: u64,
    pub num_votes: u64,
    pub out_of_date: Option<u64>,
}

#[derive(Deserialize)]
struct Rpc {
    results: Vec<Info>,
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "@._+-".contains(c))
        && !name.starts_with(['-', '.'])
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(15))
        .user_agent(concat!(
            "cirven/",
            env!("CARGO_PKG_VERSION"),
            " (+https://cirven.dev)"
        ))
        .https_only(true)
        .build()
}

pub(crate) fn get(url: &str) -> Result<String, String> {
    agent()
        .get(url)
        .call()
        .map_err(|e| format!("{url}: {e}"))?
        .into_string()
        .map_err(|e| format!("{url}: {e}"))
}

pub fn info(name: &str) -> Result<Info, String> {
    let body = get(&format!("{AUR}/rpc/v5/info?arg%5B%5D={name}"))?;
    let rpc: Rpc = serde_json::from_str(&body).map_err(|e| format!("aur rpc: {e}"))?;
    rpc.results
        .into_iter()
        .next()
        .ok_or_else(|| format!("{name}: not found in the AUR"))
}

/// A file from the package's git repository, at its current head.
pub fn file(base: &str, path: &str) -> Result<String, String> {
    get(&format!("{AUR}/cgit/aur.git/plain/{path}?h={base}"))
}

fn days_ago(epoch: u64, now: SystemTime) -> u64 {
    let now = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now.saturating_sub(epoch) / 86_400
}

/// What the package's history and ownership say about it.
pub fn assess(info: &Info, now: SystemTime) -> Vec<Finding> {
    let mut out = Vec::new();
    let age = days_ago(info.first_submitted, now);
    if age < 30 {
        out.push(
            Finding::new("pkg.new", Severity::Medium, format!("package first submitted {age} days ago"))
                .path("most malicious AUR packages are removed within days; new ones have no track record"),
        );
    }
    match &info.maintainer {
        None => out.push(
            Finding::new("pkg.orphan", Severity::Low, "package is orphaned")
                .path("anyone can adopt it and push a new PKGBUILD"),
        ),
        Some(m) => {
            let changed = days_ago(info.last_modified, now);
            if changed < 3 && info.num_votes < 10 {
                out.push(
                    Finding::new(
                        "pkg.fresh-change",
                        Severity::Low,
                        format!(
                            "changed {changed} days ago by {m}, {} votes",
                            info.num_votes
                        ),
                    )
                    .path("a recent change to a little-used package deserves a look at the diff"),
                );
            }
        }
    }
    if info.out_of_date.is_some() {
        out.push(Finding::new(
            "pkg.out-of-date",
            Severity::Info,
            "flagged out of date",
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(maintainer: Option<&str>, first: u64, last: u64, votes: u64) -> Info {
        Info {
            name: "x".into(),
            package_base: "x".into(),
            version: "1".into(),
            maintainer: maintainer.map(Into::into),
            first_submitted: first,
            last_modified: last,
            num_votes: votes,
            out_of_date: None,
        }
    }

    #[test]
    fn names_are_validated_before_they_reach_a_url() {
        assert!(valid_name("google-chrome"));
        assert!(valid_name("python-foo_bar+qt5"));
        assert!(!valid_name("x&arg[]=y"));
        assert!(!valid_name("../etc"));
        assert!(!valid_name(""));
    }

    #[test]
    fn new_orphaned_and_fresh_packages() {
        let now = UNIX_EPOCH + Duration::from_secs(400 * 86_400);
        let ids = |i: &Info| assess(i, now).into_iter().map(|f| f.id).collect::<Vec<_>>();
        assert_eq!(ids(&info(Some("m"), 0, 0, 500)), Vec::<String>::new());
        assert_eq!(
            ids(&info(Some("m"), 395 * 86_400, 399 * 86_400, 2)),
            ["pkg.new", "pkg.fresh-change"]
        );
        assert_eq!(ids(&info(None, 0, 0, 500)), ["pkg.orphan"]);
    }

    #[test]
    fn parses_rpc_response() {
        let body = r#"{"resultcount":1,"results":[{"Name":"yay","PackageBase":"yay","Version":"12.4.2-1","Maintainer":"jguer","FirstSubmitted":1475688004,"LastModified":1727000000,"NumVotes":2200,"OutOfDate":null,"Popularity":20.5}],"type":"multiinfo","version":5}"#;
        let rpc: Rpc = serde_json::from_str(body).unwrap();
        assert_eq!(rpc.results[0].package_base, "yay");
        assert_eq!(rpc.results[0].maintainer.as_deref(), Some("jguer"));
    }
}
