//! Hardened TCP acceptor: source-IP allowlist, a hard concurrent-connection
//! cap, and an idle read timeout — then hand the socket to a core protocol
//! handler. Logs connection-level events only (never message contents).

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
            let ip = stream
                .peer_addr()
                .map(|a| a.ip().to_string())
                .unwrap_or_default();

            if !cfg.ip_allowed(&ip) {
                log(&format!("{name}: refused {ip} (not allowlisted)"));
                continue;
            }
            if active.load(Ordering::Relaxed) >= cfg.max_connections {
                log(&format!("{name}: at capacity ({}), dropping {ip}", cfg.max_connections));
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
