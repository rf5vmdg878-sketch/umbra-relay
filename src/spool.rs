//! Encrypted, persistent spool. The relay's stored blobs are already sealed by
//! clients; this adds a second layer so the on-disk spool (and its routing tags
//! + volumes) reveals nothing without the operator secret.
//!
//! Reuses the messenger's crypto core: Argon2id(operator passphrase) -> a
//! 256-bit key that AES-256-GCM-encrypts the combined group + mailbox snapshot.
//! The Argon2 derivation runs once at startup; snapshots reuse the derived key
//! with the spool's stored salt.
//!
//! File: `MAGIC(8) || salt(16) || m,t,p (12) || AES-256-GCM(nonce 0, aad=header)`.

use std::path::Path;

use unichat_core::crypto::aead::AeadKey;
use unichat_core::crypto::kdf::{argon2id_32, Argon2Params, SALT_SIZE};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"URLYSPL1";
const HEADER_LEN: usize = 8 + SALT_SIZE + 12; // 36

pub struct SpoolCrypto {
    key: AeadKey,
    salt: [u8; SALT_SIZE],
    params: Argon2Params,
}

fn derive(pass: &[u8], salt: &[u8; SALT_SIZE], params: Argon2Params) -> Result<AeadKey, String> {
    let key: Zeroizing<[u8; 32]> =
        argon2id_32(pass, salt, params).map_err(|e| format!("key derivation: {e}"))?;
    AeadKey::new(&key).map_err(|e| format!("cipher init: {e}"))
}

fn header(salt: &[u8; SALT_SIZE], p: &Argon2Params) -> Vec<u8> {
    let mut h = Vec::with_capacity(HEADER_LEN);
    h.extend_from_slice(MAGIC);
    h.extend_from_slice(salt);
    h.extend_from_slice(&p.m_cost_kib.to_le_bytes());
    h.extend_from_slice(&p.t_cost.to_le_bytes());
    h.extend_from_slice(&p.p_cost.to_le_bytes());
    h
}

impl SpoolCrypto {
    /// Fresh spool key for a brand-new relay (random salt, default parameters).
    pub fn create(passphrase: &[u8]) -> Result<Self, String> {
        let mut salt = [0u8; SALT_SIZE];
        unichat_core::crypto::random_bytes(&mut salt);
        let params = Argon2Params::default();
        Ok(Self {
            key: derive(passphrase, &salt, params)?,
            salt,
            params,
        })
    }

    /// Open an existing spool: derive the key from its stored salt/params and
    /// decrypt. Returns the crypto handle plus the (group, mailbox) snapshots.
    pub fn open(path: &Path, passphrase: &[u8]) -> Result<(Self, Vec<u8>, Vec<u8>), String> {
        let data = std::fs::read(path).map_err(|e| format!("reading spool: {e}"))?;
        if data.len() < HEADER_LEN + 16 || &data[..8] != MAGIC {
            return Err("not an umbra-relay spool (bad magic)".into());
        }
        let salt: [u8; SALT_SIZE] = data[8..8 + SALT_SIZE].try_into().unwrap();
        let params = Argon2Params {
            m_cost_kib: u32::from_le_bytes(data[24..28].try_into().unwrap()),
            t_cost: u32::from_le_bytes(data[28..32].try_into().unwrap()),
            p_cost: u32::from_le_bytes(data[32..36].try_into().unwrap()),
        };
        let key = derive(passphrase, &salt, params)?;
        let head = &data[..HEADER_LEN];
        let mut body = data[HEADER_LEN..].to_vec();
        key.open(0, head, &mut body)
            .map_err(|_| "wrong operator passphrase or corrupted spool".to_string())?;

        // plaintext = u32-le(group_len) || group || mailbox
        if body.len() < 4 {
            return Err("spool body truncated".into());
        }
        let glen = u32::from_le_bytes(body[0..4].try_into().unwrap()) as usize;
        if body.len() < 4 + glen {
            return Err("spool body length mismatch".into());
        }
        let group = body[4..4 + glen].to_vec();
        let mailbox = body[4 + glen..].to_vec();
        Ok((Self { key, salt, params }, group, mailbox))
    }

    /// Encrypt and atomically write a new snapshot.
    pub fn write(&self, path: &Path, group: &[u8], mailbox: &[u8]) -> Result<(), String> {
        let head = header(&self.salt, &self.params);
        let mut plaintext = Vec::with_capacity(4 + group.len() + mailbox.len());
        plaintext.extend_from_slice(&(group.len() as u32).to_le_bytes());
        plaintext.extend_from_slice(group);
        plaintext.extend_from_slice(mailbox);
        self.key.seal(0, &head, &mut plaintext); // appends tag; plaintext now ciphertext

        let mut out = head;
        out.extend_from_slice(&plaintext);

        let tmp = path.with_extension("spool.tmp");
        std::fs::write(&tmp, &out).map_err(|e| format!("writing spool: {e}"))?;
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
        std::fs::rename(&tmp, path).map_err(|e| format!("finalizing spool: {e}"))?;
        Ok(())
    }
}
