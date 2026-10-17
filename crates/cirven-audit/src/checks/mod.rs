//! The checks. Each one reads the host and adds findings, passes or skips.

pub mod network;

use crate::host::Host;
use crate::report::Report;

/// Facts several checks depend on, gathered once per run.
#[derive(Default)]
pub struct Context {
    pub listeners: Vec<network::Listener>,
    pub firewall: Option<&'static str>,
}

impl Context {
    pub fn gather(host: &Host) -> Context {
        Context {
            listeners: network::listeners(host),
            firewall: network::firewall(host),
        }
    }
}

pub fn run_all(host: &Host, ctx: &Context, report: &mut Report) {
    network::check(host, ctx, report);
}
