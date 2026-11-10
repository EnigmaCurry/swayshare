//! The persistent TLS identity presented to remote viewers.
//!
//! The key pair is generated once and kept, so the remote user sees the same
//! certificate fingerprint on every session and can pin or verify it. Only the
//! password is ephemeral.
//!
//! The certificate has to name the *address* the invitation advertises, not
//! just the hostname. Invitations always carry a bare IP - a helper cannot be
//! expected to share our DNS - and a strict client validates the certificate
//! against the address it dialled: wlvncc calls
//! `gnutls_x509_crt_check_hostname` and gtk-vnc does the equivalent, both of
//! which fail outright against a certificate holding only DNS names. So the
//! listen address is carried as an IP SAN.

use crate::paths;
use anyhow::{Context, Result, bail};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Records the SANs the stored certificate was issued for.
///
/// Reading them back from the certificate would mean parsing X.509; this file
/// is written beside it instead, so `ensure` can tell whether the address it
/// has been handed is already covered.
const NAMES_FILE: &str = "cert.names";

/// How many addresses the certificate remembers.
///
/// Addresses accumulate rather than replace, so an identity that has seen an
/// address once never has to change its fingerprint for that address again.
/// The cap stops an interface with a churning lease from growing the
/// certificate without bound; the stalest address is dropped first.
const MAX_REMEMBERED_IPS: usize = 8;

pub struct Identity {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    /// SHA-256 over the certificate DER, formatted as colon-separated hex.
    pub fingerprint: String,
}

impl Identity {
    /// Load the stored identity, generating one on first run.
    ///
    /// `listen_ip` is the address the invitation will advertise. If the stored
    /// certificate does not already cover it, a new pair is issued - which
    /// changes the fingerprint, so callers should say so where the user can
    /// see it. `None` keeps whatever the stored certificate covers, for the
    /// eager generation at daemon start where no session has been bound yet.
    pub fn ensure(listen_ip: Option<IpAddr>) -> Result<Self> {
        let dir = tls_dir()?;
        paths::ensure_private_dir(&dir)?;
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        let names_path = dir.join(NAMES_FILE);

        let have_pair = cert_path.exists() && key_path.exists();
        let stored = if have_pair {
            read_names(&names_path)
        } else {
            // Without a pair the recorded names describe nothing.
            Vec::new()
        };
        let wanted = desired_names(&stored, listen_ip);

        // Regenerate both together: a cert paired with a lost key is useless,
        // and a half-written pair would fail obscurely in wayvnc. Compare as a
        // set, not a sequence - `wanted` is in recency order, so alternating
        // between two tunnels reorders it without changing what it covers, and
        // reissuing for that would churn the fingerprint for no reason.
        if !have_pair || !covers_same(&wanted, &stored) {
            generate(&cert_path, &key_path, &wanted)?;
        }
        if wanted != stored {
            // Order carries the recency the cap evicts by, so persist it even
            // when the certificate itself was left alone.
            write_names(&names_path, &wanted)?;
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

    /// The stored certificate in PEM form, or `None` if there is not one yet.
    ///
    /// Deliberately never generates one, unlike [`Identity::ensure`]: a
    /// certificate handed to a helper before any session exists would be
    /// reissued the moment access is granted and an address has to be
    /// covered, leaving them holding a file that no longer verifies.
    pub fn stored_pem() -> Result<Option<String>> {
        let path = tls_dir()?.join("cert.pem");
        match std::fs::read_to_string(&path) {
            Ok(pem) => Ok(Some(pem)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }
}

fn tls_dir() -> Result<PathBuf> {
    Ok(paths::data_dir()?.join("tls"))
}

/// The SANs the certificate should carry, most recently used address first.
///
/// The DNS names are always present and always first; addresses follow, with
/// `listen_ip` promoted to the front so the cap drops the stalest one.
fn desired_names(stored: &[String], listen_ip: Option<IpAddr>) -> Vec<String> {
    let mut names = vec!["swayshare".to_string()];
    let hostname = hostname();
    if !hostname.is_empty() && hostname != "swayshare" {
        names.push(hostname);
    }

    let mut ips: Vec<IpAddr> = Vec::new();
    if let Some(ip) = listen_ip {
        ips.push(ip);
    }
    // A wildcard bind names no particular host, so it cannot be validated
    // against and is not worth spending a remembered slot on.
    ips.retain(|ip| !ip.is_unspecified());
    for ip in stored.iter().filter_map(|s| s.parse::<IpAddr>().ok()) {
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    ips.truncate(MAX_REMEMBERED_IPS);

    names.extend(ips.iter().map(|ip| ip.to_string()));
    names
}

/// Whether two SAN lists cover the same names, ignoring order.
fn covers_same(a: &[String], b: &[String]) -> bool {
    a.len() == b.len() && a.iter().all(|n| b.contains(n))
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_default()
}

fn read_names(path: &Path) -> Vec<String> {
    // A missing or unreadable record just means "nothing known", which
    // reissues the certificate - correct, and no worse than first run.
    std::fs::read_to_string(path)
        .map(|text| {
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn write_names(path: &Path, names: &[String]) -> Result<()> {
    let mut text = names.join("\n");
    text.push('\n');
    // Public, like the certificate it describes.
    paths::write_atomic(path, &text, 0o644)
}

fn generate(cert_path: &Path, key_path: &Path, names: &[String]) -> Result<()> {
    // rcgen reads each entry as an IP SAN if it parses as an address and a DNS
    // SAN otherwise, which is exactly the split we want.
    let key = rcgen::generate_simple_self_signed(names.to_vec())
        .context("generating a self-signed certificate")?;

    // The certificate is public; the key must never be.
    paths::write_atomic(cert_path, &key.cert.pem(), 0o644)?;
    paths::write_private(key_path, &key.signing_key.serialize_pem())?;
    Ok(())
}

/// Compute the DER fingerprint of the first certificate in a PEM bundle.
pub fn fingerprint_from_pem(pem: &str) -> Result<String> {
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
        generate(&cert, &key, &desired_names(&[], None)).unwrap();

        let pem = std::fs::read_to_string(&cert).unwrap();
        assert!(pem.contains("BEGIN CERTIFICATE"));
        let fp = fingerprint_from_pem(&pem).unwrap();
        assert_eq!(fp.split(':').count(), 32);

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "private key must not be readable by others");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_listen_address_becomes_a_name() {
        // The invitation advertises a bare IP, so the certificate has to carry
        // it or a strict client's hostname check fails.
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        let names = desired_names(&[], Some(ip));
        assert!(
            names.contains(&"192.0.2.10".to_string()),
            "the bound address must be a SAN: {names:?}"
        );
        assert!(names.contains(&"swayshare".to_string()));
    }

    #[test]
    fn ipv6_addresses_are_carried_too() {
        let ip: IpAddr = "fd00::10".parse().unwrap();
        let names = desired_names(&[], Some(ip));
        assert!(names.contains(&"fd00::10".to_string()), "{names:?}");
    }

    #[test]
    fn addresses_accumulate_so_a_known_one_never_reissues() {
        let first: IpAddr = "192.0.2.10".parse().unwrap();
        let second: IpAddr = "198.51.100.5".parse().unwrap();

        let after_first = desired_names(&[], Some(first));
        let after_second = desired_names(&after_first, Some(second));
        assert!(after_second.contains(&"192.0.2.10".to_string()));
        assert!(after_second.contains(&"198.51.100.5".to_string()));

        // Coming back to the first address must not change what is covered,
        // or the fingerprint would flap every time the tunnel changed.
        let back_to_first = desired_names(&after_second, Some(first));
        assert!(
            covers_same(&back_to_first, &after_second),
            "{back_to_first:?} should cover the same names as {after_second:?}"
        );
    }

    #[test]
    fn the_current_address_is_kept_when_the_cap_evicts() {
        // Fill every slot, then bind one more: the newest must survive.
        let stored: Vec<String> = (0..MAX_REMEMBERED_IPS)
            .map(|i| format!("192.0.2.{}", i + 1))
            .collect();
        let fresh: IpAddr = "198.51.100.5".parse().unwrap();
        let names = desired_names(&stored, Some(fresh));

        let ips: Vec<&String> = names
            .iter()
            .filter(|n| n.parse::<IpAddr>().is_ok())
            .collect();
        assert_eq!(
            ips.len(),
            MAX_REMEMBERED_IPS,
            "the cap must hold: {names:?}"
        );
        assert!(
            names.contains(&"198.51.100.5".to_string()),
            "the address being bound now must never be the one evicted: {names:?}"
        );
    }

    #[test]
    fn a_wildcard_bind_is_not_remembered() {
        // 0.0.0.0 names no host, so it cannot be validated against.
        for wildcard in ["0.0.0.0", "::"] {
            let ip: IpAddr = wildcard.parse().unwrap();
            let names = desired_names(&[], Some(ip));
            assert!(
                !names.contains(&wildcard.to_string()),
                "{wildcard} should not be a SAN: {names:?}"
            );
        }
    }

    #[test]
    fn reordering_alone_does_not_count_as_a_change() {
        let a = vec!["swayshare".to_string(), "192.0.2.1".to_string()];
        let b = vec!["192.0.2.1".to_string(), "swayshare".to_string()];
        assert!(covers_same(&a, &b));
        assert!(!covers_same(&a, &["swayshare".to_string()]));
    }
}
