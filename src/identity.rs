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
//!
//! Which addresses a stored certificate covers is read back out of the
//! certificate itself. The alternative - recording them in a file beside it -
//! has a failure mode this does not: the record and the certificate can
//! disagree, and then a perfectly good identity gets reissued because its
//! notes went missing.

use crate::paths;
use anyhow::{Context, Result, bail};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use x509_parser::prelude::*;

/// Left beside the certificate by earlier versions, which recorded the SANs
/// in a file rather than reading them from the certificate. Removed on sight
/// so it cannot be mistaken for something still consulted.
const STALE_NAMES_FILE: &str = "cert.names";

/// The name the certificate is handed to a helper under.
///
/// Matches what the invitation tells them to expect, which `cert.pem` - a
/// name shared by every certificate on their disk - would not.
const EXPORT_NAME: &str = "swayshare.pem";

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
        paths::remove_if_present(&dir.join(STALE_NAMES_FILE));

        // Both or neither: a certificate whose key is gone cannot be
        // presented, and a half-written pair fails obscurely inside wayvnc.
        let stored = if cert_path.exists() && key_path.exists() {
            std::fs::read_to_string(&cert_path).ok()
        } else {
            None
        };
        let covered = stored.as_deref().map(covered_addresses).unwrap_or_default();

        // An address the certificate does not name is the one thing worth
        // reissuing for, because that is what a strict client refuses over.
        // Notably absent from this decision: the DNS names. They are carried
        // for completeness, but renaming a machine must not rotate an
        // identity a helper has already pinned.
        let fresh = address_to_add(&covered, listen_ip);
        if stored.is_none() || fresh.is_some() {
            generate(&cert_path, &key_path, &desired_names(&covered, fresh))?;
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

    /// Write the certificate out under the name a recipient should see, and
    /// return the path, for handing to another application.
    ///
    /// Written afresh on every call rather than kept in step with the
    /// certificate: a copy left lying around would be handed over stale after
    /// a reissue, and a certificate that does not verify is the one outcome
    /// worth engineering against. Mode 0644 - it is public, and whatever the
    /// user drags it into has to be able to read it.
    pub fn export_pem() -> Result<PathBuf> {
        let pem = Self::stored_pem()?
            .context("there is no certificate yet - it is created when the daemon first runs")?;
        write_export(&tls_dir()?, &pem)
    }
}

/// Split from [`Identity::export_pem`] so the name and the mode - the two
/// things another application depends on - can be asserted without writing
/// into the real data directory.
fn write_export(dir: &Path, pem: &str) -> Result<PathBuf> {
    let path = dir.join(EXPORT_NAME);
    // 0644: the certificate is public, and whatever it is dragged into has to
    // be able to read it.
    paths::write_atomic(&path, pem, 0o644)?;
    Ok(path)
}

fn tls_dir() -> Result<PathBuf> {
    Ok(paths::data_dir()?.join("tls"))
}

/// The address that forces a reissue, if any.
///
/// Split out from [`Identity::ensure`] because it is the whole stability
/// contract: anything this returns `None` for keeps the existing fingerprint.
fn address_to_add(covered: &[IpAddr], listen_ip: Option<IpAddr>) -> Option<IpAddr> {
    // A wildcard bind names no particular host, so nothing can validate
    // against it and it is not worth reissuing for.
    listen_ip.filter(|ip| !ip.is_unspecified() && !covered.contains(ip))
}

/// The SANs the certificate should carry, most recently used address first.
///
/// DNS names come first and are always present; addresses follow, with
/// `fresh` promoted to the front so the cap drops the stalest one. rcgen reads
/// an entry that parses as an address as an IP SAN and anything else as a DNS
/// SAN, so one list expresses both.
fn desired_names(covered: &[IpAddr], fresh: Option<IpAddr>) -> Vec<String> {
    let mut names = vec!["swayshare".to_string()];
    let hostname = hostname();
    if !hostname.is_empty() && hostname != "swayshare" {
        names.push(hostname);
    }

    let mut ips: Vec<IpAddr> = Vec::new();
    ips.extend(fresh);
    for ip in covered {
        if !ips.contains(ip) {
            ips.push(*ip);
        }
    }
    ips.truncate(MAX_REMEMBERED_IPS);

    names.extend(ips.iter().map(|ip| ip.to_string()));
    names
}

/// The addresses a stored certificate already names.
///
/// Returned in the certificate's own SAN order, which is the order they were
/// written - most recently used first - so recency survives a round trip
/// without being recorded anywhere else.
///
/// A certificate we cannot parse reads as covering nothing, which reissues it.
/// That is the safe direction: the alternative is presenting a certificate
/// whose contents we could not confirm.
fn covered_addresses(pem: &str) -> Vec<IpAddr> {
    let Ok(der) = der_from_pem(pem) else {
        return Vec::new();
    };
    let Ok((_, cert)) = X509Certificate::from_der(&der) else {
        return Vec::new();
    };
    let Ok(Some(san)) = cert.subject_alternative_name() else {
        return Vec::new();
    };
    san.value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::IPAddress(octets) => ip_from_octets(octets),
            _ => None,
        })
        .collect()
}

/// An IP SAN is stored as raw network-order octets: 4 for v4, 16 for v6.
fn ip_from_octets(octets: &[u8]) -> Option<IpAddr> {
    match octets.len() {
        4 => Some(IpAddr::from(<[u8; 4]>::try_from(octets).ok()?)),
        16 => Some(IpAddr::from(<[u8; 16]>::try_from(octets).ok()?)),
        _ => None,
    }
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_default()
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

/// The DER bytes of the first certificate in a PEM bundle.
fn der_from_pem(pem: &str) -> Result<Vec<u8>> {
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
    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .context("decoding the certificate PEM body")
}

/// Compute the DER fingerprint of the first certificate in a PEM bundle.
pub fn fingerprint_from_pem(pem: &str) -> Result<String> {
    let digest = Sha256::digest(der_from_pem(pem)?);
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

    /// Generate a pair in a scratch directory and hand back the certificate.
    ///
    /// The directory is unique per call: these tests run concurrently, and a
    /// shared path means one removing it while another is still writing.
    fn generated_pem(names: &[String]) -> String {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("swayshare-id-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("cert.pem");
        generate(&cert, &dir.join("key.pem"), names).unwrap();
        let pem = std::fs::read_to_string(&cert).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        pem
    }

    #[test]
    fn addresses_survive_a_round_trip_through_the_certificate() {
        // The whole point of reading SANs back out of the certificate: what
        // went in has to come out, or every run would look like a new address
        // and reissue.
        for addr in ["192.0.2.10", "fd00::10"] {
            let ip: IpAddr = addr.parse().unwrap();
            let pem = generated_pem(&desired_names(&[], Some(ip)));
            assert_eq!(
                covered_addresses(&pem),
                vec![ip],
                "{addr} should be readable back out of its own certificate"
            );
        }
    }

    #[test]
    fn recency_order_survives_the_round_trip() {
        // The cap evicts the stalest address, so the order the certificate
        // names them in has to be the order they were last used.
        let first: IpAddr = "192.0.2.10".parse().unwrap();
        let second: IpAddr = "198.51.100.5".parse().unwrap();
        let pem = generated_pem(&desired_names(&[first], Some(second)));
        assert_eq!(covered_addresses(&pem), vec![second, first]);
    }

    #[test]
    fn a_covered_address_never_reissues() {
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        assert_eq!(address_to_add(&[ip], Some(ip)), None);
        // Still true when it is not the most recent of several.
        let other: IpAddr = "198.51.100.5".parse().unwrap();
        assert_eq!(address_to_add(&[other, ip], Some(ip)), None);
    }

    #[test]
    fn renaming_the_machine_does_not_reissue() {
        // The reissue decision must not look at DNS names at all: a cosmetic
        // rename rotating the identity would invalidate every copy of the
        // certificate a helper has already saved.
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        let pem = generated_pem(&[
            "swayshare".to_string(),
            "the-old-hostname".to_string(),
            ip.to_string(),
        ]);
        assert_eq!(
            address_to_add(&covered_addresses(&pem), Some(ip)),
            None,
            "a certificate naming a different hostname must still be kept"
        );
    }

    #[test]
    fn an_uncovered_address_does_reissue() {
        let known: IpAddr = "192.0.2.10".parse().unwrap();
        let fresh: IpAddr = "198.51.100.5".parse().unwrap();
        assert_eq!(address_to_add(&[known], Some(fresh)), Some(fresh));
        // Nothing stored yet, and nothing known: still has to be issued.
        assert_eq!(address_to_add(&[], Some(fresh)), Some(fresh));
    }

    #[test]
    fn addresses_accumulate_so_a_known_one_never_reissues() {
        let first: IpAddr = "192.0.2.10".parse().unwrap();
        let second: IpAddr = "198.51.100.5".parse().unwrap();

        let after_first = desired_names(&[], Some(first));
        let covered = covered_addresses(&generated_pem(&after_first));
        let after_second = desired_names(&covered, address_to_add(&covered, Some(second)));
        assert!(after_second.contains(&"192.0.2.10".to_string()));
        assert!(after_second.contains(&"198.51.100.5".to_string()));

        // Coming back to the first address must not reissue, or the
        // fingerprint would flap every time the tunnel changed.
        let both = covered_addresses(&generated_pem(&after_second));
        assert_eq!(address_to_add(&both, Some(first)), None);
        assert_eq!(address_to_add(&both, Some(second)), None);
    }

    #[test]
    fn the_current_address_is_kept_when_the_cap_evicts() {
        // Fill every slot, then bind one more: the newest must survive.
        let covered: Vec<IpAddr> = (0..MAX_REMEMBERED_IPS)
            .map(|i| format!("192.0.2.{}", i + 1).parse().unwrap())
            .collect();
        let fresh: IpAddr = "198.51.100.5".parse().unwrap();
        let names = desired_names(&covered, Some(fresh));

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
        // 0.0.0.0 names no host, so it cannot be validated against and must
        // not trigger a reissue either.
        for wildcard in ["0.0.0.0", "::"] {
            let ip: IpAddr = wildcard.parse().unwrap();
            assert_eq!(address_to_add(&[], Some(ip)), None);
            let names = desired_names(&[], address_to_add(&[], Some(ip)));
            assert!(
                !names.contains(&wildcard.to_string()),
                "{wildcard} should not be a SAN: {names:?}"
            );
        }
    }

    #[test]
    fn the_export_is_named_for_the_recipient_and_is_readable() {
        // Both halves matter to something outside this program: the name is
        // what the invitation tells the helper to expect, and the mode is
        // what lets the application it is dragged into open it.
        let dir = std::env::temp_dir().join(format!("swayshare-export-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pem = "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n";
        let path = write_export(&dir, pem).unwrap();

        assert_eq!(path.file_name().unwrap(), "swayshare.pem");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), pem);
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o644,
            "the receiving application must be able to read it"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_unparseable_certificate_is_treated_as_covering_nothing() {
        // The safe direction: reissue rather than present a certificate whose
        // contents we could not confirm.
        assert!(covered_addresses("not a pem file").is_empty());
        assert!(
            covered_addresses("-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n")
                .is_empty()
        );
    }
}
