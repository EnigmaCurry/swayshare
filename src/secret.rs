//! Session password generation.
//!
//! A fresh password is minted every time sharing is enabled and is never
//! written to the persistent config — only to the 0600 wayvnc config inside
//! the runtime directory, which is deleted when sharing stops.

use anyhow::{Context, Result};
use zeroize::Zeroize;

/// Crockford base32: no `I`, `L`, `O` or `U`, so a password read aloud or
/// retyped by the remote user has no ambiguous glyphs.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// 26 symbols over a 32-symbol alphabet is 130 bits of entropy.
const LEN: usize = 26;

/// A password that is zeroized on drop and never printed by accident.
///
/// `Debug`/`Display` deliberately redact; call [`Secret::expose`] at the one
/// place the plaintext is genuinely needed.
pub struct Secret(String);

impl Secret {
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; LEN];
        getrandom::fill(&mut bytes).context("reading from the system CSPRNG")?;
        // 256 is an exact multiple of 32, so the modulo mapping is uniform.
        let s: String = bytes
            .iter()
            .map(|b| ALPHABET[(*b % 32) as usize] as char)
            .collect();
        bytes.zeroize();
        Ok(Self(s))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl std::fmt::Display for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_has_expected_shape() {
        let s = Secret::generate().unwrap();
        assert_eq!(s.expose().len(), LEN);
        assert!(s.expose().bytes().all(|b| ALPHABET.contains(&b)));
    }

    #[test]
    fn passwords_are_distinct() {
        let a = Secret::generate().unwrap();
        let b = Secret::generate().unwrap();
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn debug_and_display_redact() {
        let s = Secret::generate().unwrap();
        assert!(!format!("{s:?}").contains(s.expose()));
        assert!(!format!("{s}").contains(s.expose()));
    }
}
