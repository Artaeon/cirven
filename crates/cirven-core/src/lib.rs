//! Shared types for all cirven modules: module metadata, findings, errors.

use std::fmt;

/// Static description of a module, shown by `cirven modules`.
#[derive(Debug)]
pub struct Module {
    pub name: &'static str,
    pub summary: &'static str,
    pub status: Status,
}

impl Module {
    /// Documentation page on cirven.dev.
    pub fn url(&self) -> String {
        format!("https://cirven.dev/modules/{}.html", self.name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Planned,
    Experimental,
    Stable,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Status::Planned => "planned",
            Status::Experimental => "experimental",
            Status::Stable => "stable",
        })
    }
}

/// Ordered so that the highest severity of a run can drive the exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "med",
            Severity::High => "high",
            Severity::Critical => "crit",
        })
    }
}

/// One result of a check: what is wrong, where, and why it matters.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Stable identifier, e.g. `ssh.password-auth`.
    pub id: String,
    pub severity: Severity,
    pub title: String,
    /// File, socket or setting the finding refers to.
    pub location: Option<String>,
    /// The attack path this finding opens.
    pub path: Option<String>,
}

#[derive(Debug)]
pub enum Error {
    NotImplemented(&'static Module),
    Io(std::io::Error),
}

impl Error {
    pub fn exit_code(&self) -> u8 {
        match self {
            Error::NotImplemented(_) => 64,
            Error::Io(_) => 74,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotImplemented(m) => write!(
                f,
                "{}: not implemented yet (status: {}). see {}",
                m.name,
                m.status,
                m.url()
            ),
            Error::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_by_impact() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::Low > Severity::Info);
        let worst = [Severity::Low, Severity::High, Severity::Medium]
            .into_iter()
            .max();
        assert_eq!(worst, Some(Severity::High));
    }

    #[test]
    fn module_url_points_to_site() {
        let m = Module {
            name: "audit",
            summary: "",
            status: Status::Planned,
        };
        assert_eq!(m.url(), "https://cirven.dev/modules/audit.html");
    }
}
