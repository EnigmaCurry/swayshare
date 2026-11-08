//! The persistent TLS identity presented to remote viewers.
//!
//! The key pair is generated once and kept, so the remote user sees the same
//! certificate fingerprint on every session and can pin or verify it. Only the
//! password is ephemeral.

use crate::paths;
use anyhow::{Context, Result, bail};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub struct Identity {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    /// SHA-256 over the certificate DER, formatted as colon-separated hex.
    pub fingerprint: String,
}

impl Identity {
    /// Load the stored identity, generating one on first run.
    pub fn ensure() -> Result<Self> {
        let dir = paths::data_dir()?.join("tls");
        paths::ensure_private_dir(&dir)?;
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");

        if !cert_path.exists() || !key_path.exists() {
            // Regenerate both together: a cert paired with a lost key is
            // useless, and a half-written pair would fail obscurely in wayvnc.
            generate(&cert_path, &key_path)?;
        }

        let pem = std::fs::read_to_string(&cert_path)
            .with_context(|| format!("reading {}", cert_path.display()))?;
        let fingerprint = fingerprint_from_pem(&pem)?;
        Ok(Self {
            cert_path,
            key_path,
            fingerprint,
        })
    }
}

fn generate(cert_path: &Path, key_path: &Path) -> Result<()> {
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_default();
    let mut names = vec!["swayshare".to_string()];
    if !hostname.is_empty() && hostname != "swayshare" {
        names.push(hostname);
    }

    let key = rcgen::generate_simple_self_signed(names)
        .context("generating a self-signed certificate")?;

    // The certificate is public; the key must never be.
    paths::write_atomic(cert_path, &key.cert.pem(), 0o644)?;
    paths::write_private(key_path, &key.signing_key.serialize_pem())?;
    Ok(())
}

/// Compute the DER fingerprint of the first certificate in a PEM bundle.
fn fingerprint_from_pem(pem: &str) -> Result<String> {
    let body: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END CERTIFICATE-----"))
        .map(|l| l.trim())
        .collect();
    if body.is_empty() {
        bail!("no CERTIFICATE block found in the stored PEM file");
    }
    let der = base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .context("decoding the certificate PEM body")?;
    let digest = Sha256::digest(&der);
    Ok(digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_matches_a_known_der() {
        // A PEM wrapper around three bytes, so the expected digest is just
        // SHA-256("abc") - the well-known test vector.
        let pem = "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n";
        let fp = fingerprint_from_pem(pem).unwrap();
        assert_eq!(
            fp.replace(':', "").to_lowercase(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn multiline_pem_bodies_are_joined() {
        let pem = "-----BEGIN CERTIFICATE-----\nYW\nJj\n-----END CERTIFICATE-----\n";
        assert_eq!(
            fingerprint_from_pem(pem).unwrap(),
            fingerprint_from_pem("-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n")
                .unwrap()
        );
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(fingerprint_from_pem("not a pem file").is_err());
        assert!(
            fingerprint_from_pem("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n")
                .is_err()
        );
    }

    #[test]
    fn generated_pair_is_readable_and_fingerprintable() {
        let dir = std::env::temp_dir().join(format!("swayshare-id-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        generate(&cert, &key).unwrap();

        let pem = std::fs::read_to_string(&cert).unwrap();
        assert!(pem.contains("BEGIN CERTIFICATE"));
        let fp = fingerprint_from_pem(&pem).unwrap();
        assert_eq!(fp.split(':').count(), 32);

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "private key must not be readable by others");

        std::fs::remove_dir_all(&dir).ok();
    }
}
