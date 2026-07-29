# Third-party notices

The original source code in this repository is Copyright (c) 2026
rf5vmdg878-sketch and licensed under the MIT License (see `LICENSE`). The notices
below cover third-party components, each under its own license and its own
authors' copyright.

- **Umbra messenger core** (`unichat-core`) — this relay is a companion to the
  Umbra secure messenger and depends on its shared core (the `umbra` repository)
  by path. Clone `umbra` alongside this repo (`../umbra`). Same author/MIT.
- **Microsoft SymCrypt** — FIPS-validated crypto (AES-256-GCM, Argon2id inputs,
  DRBG) used for the encrypted spool. MIT, Copyright (c) Microsoft Corporation.
  The prebuilt binary is not redistributed; see `umbra`'s vendor README.
- **Rust dependencies** fetched by Cargo — serde, toml, ctrlc, rpassword,
  zeroize, and (transitively) the RustCrypto / dalek crates — each under
  permissive (MIT / Apache-2.0 / BSD-3-Clause) terms.
