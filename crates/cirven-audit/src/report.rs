//! Collected results of a run and how they are printed.

use std::fmt::Write as _;

use cirven_core::{Finding, Severity};
use serde::Serialize;

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub host: String,
    pub findings: Vec<Finding>,
    pub passed: Vec<String>,
    pub skipped: Vec<String>,
}

impl Report {
    pub fn find(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn pass(&mut self, what: impl Into<String>) {
        self.passed.push(what.into());
    }

    pub fn skip(&mut self, what: impl Into<String>) {
        self.skipped.push(what.into());
    }

    pub fn worst(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    /// 0 when nothing above low was found, then 1 medium, 2 high, 3 critical.
    pub fn exit_code(&self) -> u8 {
        match self.worst() {
            Some(Severity::Critical) => 3,
            Some(Severity::High) => 2,
            Some(Severity::Medium) => 1,
            _ => 0,
        }
    }

    /// Most severe first; stable within a severity, so checks keep their order.
    pub fn sort(&mut self) {
        self.findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    }

    pub fn render(&self, color: bool, quiet: bool) -> String {
        let paint = |code: &str, s: &str| {
            if color {
                format!("\x1b[{code}m{s}\x1b[0m")
            } else {
                s.to_string()
            }
        };
        let mut out = String::new();
        let _ = writeln!(out, "cirven audit · {}\n", self.host);
        for f in &self.findings {
            let (tag, code) = match f.severity {
                Severity::Critical => ("[crit]", "1;31"),
                Severity::High => ("[high]", "31"),
                Severity::Medium => ("[med ]", "33"),
                Severity::Low => ("[low ]", "34"),
                Severity::Info => ("[info]", "2"),
            };
            let _ = writeln!(out, "{} {}", paint(code, tag), f.title);
            for (label, value) in [("at", &f.location), ("path", &f.path), ("fix", &f.remedy)] {
                if let Some(v) = value {
                    let _ = writeln!(out, "       {}", paint("2", &format!("{label:<5}{v}")));
                }
            }
        }
        if !quiet {
            for p in &self.passed {
                let _ = writeln!(out, "{} {p}", paint("32", "[ok  ]"));
            }
            for s in &self.skipped {
                let _ = writeln!(out, "{} {}", paint("2", "[skip]"), paint("2", s));
            }
        }
        let count = |s: Severity| self.findings.iter().filter(|f| f.severity == s).count();
        let parts: Vec<String> = [
            (Severity::Critical, "crit"),
            (Severity::High, "high"),
            (Severity::Medium, "med"),
            (Severity::Low, "low"),
            (Severity::Info, "info"),
        ]
        .into_iter()
        .filter(|(s, _)| count(*s) > 0)
        .map(|(s, name)| format!("{} {name}", count(s)))
        .collect();
        if !self.findings.is_empty()
            || (!quiet && !(self.passed.is_empty() && self.skipped.is_empty()))
        {
            out.push('\n');
        }
        let _ = writeln!(
            out,
            "{} findings{} · {} passed · {} skipped",
            self.findings.len(),
            if parts.is_empty() {
                String::new()
            } else {
                format!(" ({})", parts.join(", "))
            },
            self.passed.len(),
            self.skipped.len()
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_follows_worst_finding() {
        let mut r = Report::default();
        assert_eq!(r.exit_code(), 0);
        r.find(Finding::new("a", Severity::Low, "a"));
        assert_eq!(r.exit_code(), 0);
        r.find(Finding::new("b", Severity::High, "b"));
        r.find(Finding::new("c", Severity::Medium, "c"));
        assert_eq!(r.exit_code(), 2);
        r.sort();
        assert_eq!(r.findings[0].id, "b");
    }

    #[test]
    fn render_without_color_has_no_escapes() {
        let mut r = Report::default();
        r.find(Finding::new("a", Severity::High, "bad thing").remedy("fix it"));
        r.pass("good thing");
        let text = r.render(false, false);
        assert!(!text.contains('\x1b'));
        assert!(text.contains("[high] bad thing"));
        assert!(text.contains("fix  fix it"));
        assert!(text.contains("[ok  ] good thing"));
        assert!(text.contains("1 findings (1 high)"));
    }
}
