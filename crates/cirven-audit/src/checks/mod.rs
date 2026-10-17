//! The checks. Each one reads the host and adds findings, passes or skips.

use crate::host::Host;
use crate::report::Report;

/// Facts several checks depend on, gathered once per run.
pub struct Context {}

impl Context {
    pub fn gather(_host: &Host) -> Context {
        Context {}
    }
}

pub fn run_all(_host: &Host, _ctx: &Context, _report: &mut Report) {}
