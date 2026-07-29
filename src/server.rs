//! Hardened TCP acceptor: source-IP allowlist, a hard concurrent-connection
//! cap, and an idle read timeout — then hand the socket to a core protocol
//! handler.
//!
//! Metadata discipline: client IP addresses are used *transiently* for the
//! allowlist check and then dropped. They are NEVER logged, counted per-source,
//! echoed in errors, or otherwise persisted — so neither the logs nor any other
//! client can be used to learn who is connecting. In `private_mode` the relay
//! binds loopback-only and is meant to sit behind a co-located Tor onion
//! service, so it never even observes a real client IP (every peer looks like
//! 127.0.0.1 from the local Tor daemon).

use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::config::Config;

/// A protocol handler for one accepted connection (e.g. the group relay or the
/// mailbox handler from `unichat-core`).
pub type Handler = Arc<dyn Fn(std::net::TcpStream) + Send + Sync>;

pub fn log(msg: &str) {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    eprintln!("[{t}] {msg}");
}

/// Bind and start accepting for one service. Binding happens synchronously (so
/// errors surface at startup); the accept loop runs on its own thread.
pub fn serve_tcp(
    name: &'static str,
    bind: String,
    handler: Handler,
    cfg: Config,
    active: Arc<AtomicUsize>,
) -> Result<(), String> {
    let listener = TcpListener::bind(&bind).map_err(|e| format!("{name}: bind {bind}: {e}"))?;
    let addr = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| bind.clone());
    log(&format!("{name} listening on {addr}"));

    thread::spawn(move || {
        for stream in listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            // Peer IP is used only for the allowlist decision, then dropped in
            // this scope. It is deliberately never logged or retained.
            let allowed = {
                let ip = stream
                    .peer_addr()
                    .map(|a| a.ip().to_string())
                    .unwrap_or_default();
                cfg.ip_allowed(&ip)
            };
            if !allowed {
                // No IP in the message — refusals are counted, not attributed.
                log(&format!("{name}: refused a connection (not allowlisted)"));
                continue;
            }
            if active.load(Ordering::Relaxed) >= cfg.max_connections {
                log(&format!("{name}: at capacity ({}), dropped a connection", cfg.max_connections));
                continue;
            }
            let _ = stream.set_read_timeout(Some(Duration::from_secs(cfg.idle_timeout_secs)));

            active.fetch_add(1, Ordering::Relaxed);
            let h = handler.clone();
            let a = active.clone();
            thread::spawn(move || {
                h(stream);
                a.fetch_sub(1, Ordering::Relaxed);
            });
        }
    });
    Ok(())
}
