# umbra-relay

A **private, encrypted relay server** for the Umbra secure messenger. It runs the
two store-and-forward services the app talks to — the **group relay** and the
**mailbox** — using the messenger's own protocol code (`unichat-core`), so it's a
drop-in relay for existing clients with no client changes.

## What "private" and "encrypted" mean here

The relay is **untrusted with respect to content**: clients seal every message
end-to-end (post-quantum X-Wing + AES-256-GCM), so the server never holds a key
that can read a message, learn a group's contents, or (for mailboxes) learn who
sent one. On top of that this server adds:

- **Encrypted, persistent spool.** The stored (already-sealed) blobs are written
  to disk inside a second envelope: `Argon2id(operator passphrase)` →
  AES-256-GCM (via Microsoft SymCrypt). A stolen disk reveals nothing —
  not even the routing tags or message volumes — without the operator secret.
  Messages survive restarts.
- **Access control.** An operator passphrase is required to unlock the spool and
  start; a **source-IP allowlist**, a hard **concurrent-connection cap**, and an
  **idle read timeout** bound who can connect and cap resource use.
- **Graceful shutdown** flushes a final encrypted snapshot on Ctrl-C.
- **Runs great behind Tor.** Point a system-Tor `HiddenService` (optionally with
  **client authorization**) at the TCP bind to make the relay location-private
  and cryptographically access-gated at the transport — the app already dials
  `.onion` addresses. See below.

## Build

```powershell
$env:Path = "C:\Users\Admin\tools\mingw64\bin;$env:USERPROFILE\.cargo\bin;$env:Path"
cargo build --release
```

Depends on the messenger's shared core: clone the **umbra** repository alongside
this one (as `../umbra`), and provide its SymCrypt DLL (see umbra's vendor
README). Licensed MIT, Copyright (c) 2026 rf5vmdg878-sketch (see `LICENSE` and
`THIRD-PARTY-NOTICES.md`).

## Run

```powershell
# 1. Generate a config and edit it:
.\target\release\umbra-relay.exe --gen-config > umbra-relay.toml

# 2. Provide the operator secret (prompted, or via env for unattended start):
$env:UMBRA_RELAY_PASSPHRASE = "a strong operator passphrase"

# 3. Start:
.\target\release\umbra-relay.exe umbra-relay.toml
```

Point the app's relay/mailbox addresses at this server's `group_bind` /
`mailbox_bind` (e.g. in the GUI's Groups relay field and Mailbox address, or the
CLI `--via` / `--relay` flags).

## Configuration (`umbra-relay.toml`)

| Key | Meaning |
|---|---|
| `group_bind` / `mailbox_bind` | TCP address per service; empty string disables it |
| `allow_ips` | exact source IPs allowed to connect; empty = allow any |
| `max_connections` | hard cap on concurrent connections |
| `idle_timeout_secs` | close a connection that sends nothing for this long |
| `spool_path` | encrypted persistence file |
| `snapshot_interval_secs` | how often to flush an encrypted snapshot |

## Making it a private onion relay (recommended)

Install Tor and add to `torrc`:

```
HiddenServiceDir C:\Users\<you>\umbra-relay-hs\
HiddenServicePort 9910 127.0.0.1:9910   # group relay
HiddenServicePort 9900 127.0.0.1:9900   # mailbox
# Private access: only clients holding an authorized key may connect
HiddenServiceAuthorizeClient ... (v3 client auth via client_auth files)
```

Bind the relay to `127.0.0.1` in `umbra-relay.toml`, and hand the `.onion`
address (and, for a truly private relay, the client-auth key) to your users.

## Security notes

- The operator passphrase protects data **at rest** only; it is not an
  authentication secret for connecting clients. Restrict who can connect with
  `allow_ips` and/or onion client authorization.
- Deposits/posts are unauthenticated at the relay by design (content is sealed;
  non-members produce blobs real members simply discard). The connection cap +
  allowlist bound abuse; a proof-of-work / token admission layer is future work.
- Logs record connection-level events only — never message contents or sender
  identities.
