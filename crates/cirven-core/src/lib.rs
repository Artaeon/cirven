//! Shared types for all cirven modules: module metadata, findings, errors.

use std::fmt;

use serde::Serialize;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
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
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Stable identifier, e.g. `ssh.password-auth`. Other modules key on it.
    pub id: String,
    pub severity: Severity,
    pub title: String,
    /// File, socket or setting the finding refers to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// The attack path this finding opens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// What to do about it, in one line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remedy: Option<String>,
}

impl Finding {
    pub fn new(id: impl Into<String>, severity: Severity, title: impl Into<String>) -> Self {
        Finding {
            id: id.into(),
            severity,
            title: title.into(),
            location: None,
            path: None,
            remedy: None,
        }
    }

    pub fn at(mut self, location: impl Into<String>) -> Self {
        self.location = Some(location.into());
        self
    }

    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn remedy(mut self, remedy: impl Into<String>) -> Self {
        self.remedy = Some(remedy.into());
        self
    }
}

#[derive(Debug)]
pub enum Error {
    NotImplemented(&'static Module),
    /// Bad arguments; clap has already printed the details.
    Usage,
    Io(std::io::Error),
    Other(String),
}

impl Error {
    pub fn exit_code(&self) -> u8 {
        match self {
            Error::NotImplemented(_) => 64,
            Error::Usage => 2,
            Error::Io(_) => 74,
            Error::Other(_) => 1,
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
            Error::Usage => write!(f, "invalid arguments"),
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Other(msg) => f.write_str(msg),
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

/// Parse a module's own arguments. `Ok(None)` means help or version was
/// printed and the module should exit successfully without doing anything.
pub fn parse_args<T: clap::Parser>(module: &str, args: &[String]) -> Result<Option<T>> {
    let argv = std::iter::once(format!("cirven {module}")).chain(args.iter().cloned());
    match T::try_parse_from(argv) {
        Ok(parsed) => Ok(Some(parsed)),
        Err(e) => {
            let _ = e.print();
            if e.use_stderr() {
                Err(Error::Usage)
            } else {
                Ok(None)
            }
        }
    }
}

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
