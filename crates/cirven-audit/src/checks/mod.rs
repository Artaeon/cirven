//! The checks. Each one reads the host and adds findings, passes or skips.

pub mod accounts;
pub mod boot;
pub mod desktop;
pub mod disk;
pub mod kernel;
pub mod network;
pub mod packages;
pub mod secrets;
pub mod ssh;

use crate::report::Report;
use std::collections::HashSet;
use std::path::PathBuf;

use cirven_core::Host;

/// Facts several checks depend on, gathered once per run.
#[derive(Default)]
pub struct Context {
    pub listeners: Vec<network::Listener>,
    pub firewall: Option<&'static str>,
    /// Decoys planted by cirven lure. Reading them would trip the alarm.
    pub decoys: HashSet<PathBuf>,
}

impl Context {
    pub fn gather(host: &Host) -> Context {
        Context {
            listeners: network::listeners(host),
            firewall: network::firewall(host),
            decoys: decoys(host),
        }
    }
}

/// Paths from lure's ledger. Only the ledger is read, never the decoys.
fn decoys(host: &Host) -> HashSet<PathBuf> {
    let ledger = cirven_core::state_dir(host, "lure").join("planted.json");
    let Some(json) = std::fs::read_to_string(ledger)
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
    else {
        return HashSet::new();
    };
    json["planted"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|p| p["path"].as_str().map(PathBuf::from))
        .collect()
}

pub fn run_all(host: &Host, ctx: &Context, report: &mut Report) {
    network::check(host, ctx, report);
    ssh::check(host, ctx, report);
    secrets::check(host, ctx, report);
    disk::check(host, ctx, report);
    boot::check(host, ctx, report);
    kernel::check(host, ctx, report);
    accounts::check(host, ctx, report);
    desktop::check(host, ctx, report);
    packages::check(host, ctx, report);
}
