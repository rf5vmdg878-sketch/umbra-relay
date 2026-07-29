//! umbra-relay — a private, encrypted relay server for the Umbra secure
//! messenger. It runs the group-relay and mailbox store-and-forward services
//! (protocol-compatible with the app, reusing `unichat-core`'s handlers) with:
//!
//! - an **encrypted, persistent spool** (Argon2id + AES-256-GCM) so messages
//!   survive restarts and the on-disk data reveals nothing without the operator
//!   secret;
//! - **access control**: an operator passphrase to unlock the spool, a source-IP
//!   allowlist, a hard concurrent-connection cap, and idle read timeouts;
//! - **graceful shutdown** that flushes a final encrypted snapshot.
//!
//! The relay itself is untrusted with respect to *content* — clients seal
//! everything end-to-end — so it never holds any key that can read a message.
//! Run it behind a Tor onion service (torrc `HiddenService`, optionally with
//! client authorization) to also make it location-private and access-gated at
//! the transport.

mod config;
mod server;
mod spool;

use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

use unichat_core::groups::relay::GroupRelay;
use unichat_core::sync::mailbox::MailboxStore;

use config::Config;
use server::{log, serve_tcp, Handler};
use spool::SpoolCrypto;

fn die(msg: &str) -> ! {
    eprintln!("umbra-relay: {msg}");
    std::process::exit(2);
}

/// Print ready-to-paste torrc for exposing the loopback binds as onion services.
/// Clients then dial the `.onion` address; the relay only ever sees 127.0.0.1.
fn print_onion_guidance(cfg: &Config) {
    let port_of = |bind: &str| bind.rsplit(':').next().unwrap_or("").to_string();
    log("private_mode ON — bind loopback + front with a Tor onion service:");
    eprintln!("  # torrc — one HiddenServiceDir, one HiddenServicePort per service:");
    eprintln!("  HiddenServiceDir /var/lib/tor/umbra-relay/");
    for (label, bind) in [
        ("group", &cfg.group_bind),
        ("mailbox", &cfg.mailbox_bind),
        ("call", &cfg.call_bind),
    ] {
        if !bind.trim().is_empty() {
            let p = port_of(bind);
            eprintln!("  HiddenServicePort {p} {bind}   # {label}");
        }
    }
    eprintln!("  # (optional) HiddenServiceAuthorizeClient / client-auth for access gating.");
    eprintln!("  # Give clients the generated <HiddenServiceDir>/hostname (.onion).");
}

fn main() {
    unichat_core::integrity::enforce(); // refuse to run a tampered build
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--gen-config") {
        print!("{}", Config::default_toml());
        return;
    }
    let cfg_path = args
        .iter()
        .skip(1)
        .find(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or_else(|| "umbra-relay.toml".into());
    let cfg = Config::load(&cfg_path).unwrap_or_else(|e| {
        die(&format!(
            "{e}\n  create one with:  umbra-relay --gen-config > umbra-relay.toml"
        ))
    });

    // Private mode: the relay must be unreachable except via a co-located Tor
    // onion service, so it never sees a real client IP. Enforce loopback binds.
    if cfg.private_mode {
        for (svc, b) in [
            ("group_bind", &cfg.group_bind),
            ("mailbox_bind", &cfg.mailbox_bind),
            ("call_bind", &cfg.call_bind),
        ] {
            if !b.trim().is_empty() && !config::bind_is_loopback(b) {
                die(&format!(
                    "private_mode is on but {svc} = \"{b}\" is not loopback.\n  \
                     Bind each service to 127.0.0.1 and expose it as a Tor onion service."
                ));
            }
        }
        print_onion_guidance(&cfg);
    }

    // Operator secret unlocks the encrypted spool. From env for unattended use,
    // else prompted.
    let pass = match std::env::var("UMBRA_RELAY_PASSPHRASE") {
        Ok(p) => Zeroizing::new(p.into_bytes()),
        Err(_) => Zeroizing::new(
            rpassword::prompt_password("Operator passphrase: ")
                .unwrap_or_default()
                .into_bytes(),
        ),
    };
    if pass.is_empty() {
        die("empty operator passphrase; refusing to start");
    }

    let group = GroupRelay::new();
    let mailbox = MailboxStore::new();
    let spool_path = PathBuf::from(&cfg.spool_path);

    let crypto = if spool_path.exists() {
        match SpoolCrypto::open(&spool_path, &pass) {
            Ok((c, g, m)) => {
                group.restore_bytes(&g);
                mailbox.restore_bytes(&m);
                log(&format!(
                    "encrypted spool loaded ({} B group, {} B mailbox)",
                    g.len(),
                    m.len()
                ));
                c
            }
            Err(e) => die(&e),
        }
    } else {
        match SpoolCrypto::create(&pass) {
            Ok(c) => {
                log("initialized a new encrypted spool");
                c
            }
            Err(e) => die(&e),
        }
    };
    drop(pass);

    let crypto = Arc::new(crypto);
    let write_lock = Arc::new(Mutex::new(()));

    // One reusable snapshotter (periodic + on shutdown).
    let snapshot: Arc<dyn Fn() + Send + Sync> = {
        let group = group.clone();
        let mailbox = mailbox.clone();
        let crypto = crypto.clone();
        let path = spool_path.clone();
        let lock = write_lock.clone();
        Arc::new(move || {
            let _g = lock.lock().unwrap();
            if let Err(e) = crypto.write(&path, &group.snapshot_bytes(), &mailbox.snapshot_bytes()) {
                log(&format!("snapshot failed: {e}"));
            }
        })
    };

    let active = Arc::new(AtomicUsize::new(0));
    let mut started = 0;

    if !cfg.group_bind.trim().is_empty() {
        let g = group.clone();
        let h: Handler = Arc::new(move |s| {
            let _ = g.handle_connection(s);
        });
        match serve_tcp("group-relay", cfg.group_bind.clone(), h, cfg.clone(), active.clone()) {
            Ok(()) => started += 1,
            Err(e) => eprintln!("umbra-relay: {e}"),
        }
    }
    if !cfg.mailbox_bind.trim().is_empty() {
        let m = mailbox.clone();
        let h: Handler = Arc::new(move |s| {
            let _ = m.handle_connection(s);
        });
        match serve_tcp("mailbox", cfg.mailbox_bind.clone(), h, cfg.clone(), active.clone()) {
            Ok(()) => started += 1,
            Err(e) => eprintln!("umbra-relay: {e}"),
        }
    }
    if !cfg.call_bind.trim().is_empty() {
        // Voice/video call rendezvous: pairs two callers by call-id and pumps
        // opaque encrypted media between them. No persistence (calls are live).
        let cr = unichat_core::call::relay::CallRelay::new();
        let h: Handler = Arc::new(move |s| {
            let _ = cr.handle_connection(s);
        });
        match serve_tcp("call-relay", cfg.call_bind.clone(), h, cfg.clone(), active.clone()) {
            Ok(()) => started += 1,
            Err(e) => eprintln!("umbra-relay: {e}"),
        }
    }
    if started == 0 {
        die("no services enabled (set group_bind and/or mailbox_bind in the config)");
    }

    // Periodic encrypted snapshot.
    {
        let snapshot = snapshot.clone();
        let interval = cfg.snapshot_interval_secs.max(5);
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(interval));
            snapshot();
        });
    }

    // Graceful shutdown: flush a final snapshot on Ctrl-C.
    let (tx, rx) = std::sync::mpsc::channel();
    let _ = ctrlc::set_handler(move || {
        let _ = tx.send(());
    });
    if !cfg.allow_ips.is_empty() {
        log(&format!("source allowlist active ({} ips)", cfg.allow_ips.len()));
    }
    log("umbra-relay running (Ctrl-C to stop)");
    let _ = rx.recv();
    log("shutting down; writing final encrypted snapshot");
    snapshot();
    log("stopped");
}
