//! Operator configuration (TOML).

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct Config {
    /// TCP bind for the group relay; empty string disables the service.
    pub group_bind: String,
    /// TCP bind for the mailbox; empty string disables the service.
    pub mailbox_bind: String,
    /// TCP bind for the call relay (voice/video rendezvous); empty disables it.
    pub call_bind: String,

    /// Exact source IPs allowed to connect. Empty = allow any.
    pub allow_ips: Vec<String>,
    /// Hard cap on concurrent connections (per service). Excess is dropped.
    pub max_connections: usize,
    /// Idle read timeout; a connection sending nothing for this long is closed.
    pub idle_timeout_secs: u64,

    /// Encrypted spool file (persistence across restarts).
    pub spool_path: String,
    /// How often to flush an encrypted snapshot to disk.
    pub snapshot_interval_secs: u64,

    /// Private mode: refuse to bind any non-loopback address, so the relay is
    /// reachable ONLY via a co-located Tor onion service (torrc `HiddenService`).
    /// In this mode the relay never observes a real client IP — every peer is
    /// 127.0.0.1 from the local Tor daemon. Default off (direct-TCP binds).
    pub private_mode: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            group_bind: "0.0.0.0:9910".into(),
            mailbox_bind: "0.0.0.0:9900".into(),
            call_bind: "0.0.0.0:9930".into(),
            allow_ips: Vec::new(),
            max_connections: 512,
            idle_timeout_secs: 90,
            spool_path: "umbra-relay.spool".into(),
            snapshot_interval_secs: 30,
            private_mode: false,
        }
    }
}

/// True if `bind` (host:port) resolves to a loopback-only address.
pub fn bind_is_loopback(bind: &str) -> bool {
    use std::net::ToSocketAddrs;
    match bind.to_socket_addrs() {
        Ok(addrs) => {
            let mut any = false;
            for a in addrs {
                any = true;
                if !a.ip().is_loopback() {
                    return false;
                }
            }
            any
        }
        Err(_) => false,
    }
}

impl Config {
    pub fn load(path: &str) -> Result<Self, String> {
        let s = std::fs::read_to_string(path).map_err(|e| format!("reading {path}: {e}"))?;
        toml::from_str(&s).map_err(|e| format!("parsing {path}: {e}"))
    }

    pub fn default_toml() -> String {
        let header = "# umbra-relay configuration.\n\
                      # An empty *_bind disables that service. allow_ips empty = allow any source.\n\
                      # private_mode = true refuses non-loopback binds so the relay is reachable\n\
                      # only via a co-located Tor onion service (it then never sees a client IP).\n\
                      # Client IPs are never logged in any mode.\n\n";
        format!("{header}{}", toml::to_string_pretty(&Self::default()).unwrap_or_default())
    }

    /// True if `ip` (a peer address's IP, as a string) may connect.
    pub fn ip_allowed(&self, ip: &str) -> bool {
        self.allow_ips.is_empty() || self.allow_ips.iter().any(|a| a == ip)
    }
}
