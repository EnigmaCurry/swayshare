//! Session password generation.
//!
//! A fresh password is minted every time someone connects and is never written
//! to the persistent config — only to the 0600 wayvnc config inside the
//! runtime directory, which is deleted when sharing stops. Because the owner
//! reads the password aloud to the connecting person over the phone, the
//! default form is a short word passphrase rather than a random string.

use anyhow::{Context, Result, bail};
use zeroize::Zeroize;

/// Crockford base32: no `I`, `L`, `O` or `U`, so a password read aloud or
/// retyped by the remote user has no ambiguous glyphs.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// 26 symbols over a 32-symbol alphabet is 130 bits of entropy.
const LEN: usize = 26;

/// The EFF short wordlist (v1): 1296 words, each at most five letters, chosen
/// for being easy to say and tell apart. Reading four of them down a phone
/// line is the intended way to hand over a session password.
///
/// Source: <https://www.eff.org/dice>, by the Electronic Frontier Foundation,
/// released under CC-BY 3.0. The single hyphenated entry (`yo-yo`) is the one
/// local edit, replaced so every word is plain lowercase letters.
const WORDLIST: &str = include_str!("wordlist.txt");

/// Words joined into one passphrase. Four words of 1296 is ~41 bits, which -
/// behind TLS, the address/interface gate, and rotation on every disconnect -
/// is a sensible floor for a secret a human reads aloud. Configurable upward.
pub const DEFAULT_WORDS: usize = 4;
/// Guard against a config that would make the secret trivial to guess.
const MIN_WORDS: usize = 3;
/// A plain space: it reads most naturally aloud and VNC passwords may contain
/// one. Every wordlist entry is pure letters, so words stay unambiguous.
const SEPARATOR: char = ' ';

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

    /// Build a passphrase of `words` words drawn from the embedded wordlist.
    ///
    /// Selection is uniform: a byte that would bias the modulo is rejected and
    /// redrawn, so every word is equally likely and the stated entropy holds.
    pub fn passphrase(words: usize) -> Result<Self> {
        if words < MIN_WORDS {
            bail!("a passphrase needs at least {MIN_WORDS} words");
        }
        let list: Vec<&str> = WORDLIST.lines().filter(|l| !l.is_empty()).collect();
        let n = list.len();
        // The list is a fixed asset; an empty or tiny one is a build mistake.
        assert!(n >= 1024, "wordlist is too small: {n} words");

        let mut chosen = Vec::with_capacity(words);
        for _ in 0..words {
            chosen.push(list[uniform_index(n)?]);
        }
        Ok(Self(chosen.join(&SEPARATOR.to_string())))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// A uniformly random index in `0..n`, by rejection sampling over a u32.
///
/// Drawing four bytes covers wordlists far larger than ours; values in the
/// short tail above the largest multiple of `n` are discarded so the modulo
/// does not favour the low indices.
fn uniform_index(n: usize) -> Result<usize> {
    assert!((1..=(1 << 24)).contains(&n));
    let span = n as u64;
    let limit = ((1u64 << 32) / span) * span;
    loop {
        let mut b = [0u8; 4];
        getrandom::fill(&mut b).context("reading from the system CSPRNG")?;
        let v = u32::from_le_bytes(b) as u64;
        if v < limit {
            return Ok((v % span) as usize);
        }
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
        // A passphrase must redact just the same - it is still a password.
        let p = Secret::passphrase(DEFAULT_WORDS).unwrap();
        assert!(!format!("{p:?}").contains(p.expose()));
        assert!(!format!("{p}").contains(p.expose()));
    }

    #[test]
    fn the_wordlist_is_the_full_distinct_eff_short_list() {
        let words: Vec<&str> = WORDLIST.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(words.len(), 1296, "the EFF short wordlist has 1296 words");
        let unique: std::collections::HashSet<&str> = words.iter().copied().collect();
        assert_eq!(unique.len(), 1296, "the words must all be distinct");
        assert!(
            words
                .iter()
                .all(|w| (1..=5).contains(&w.len()) && w.bytes().all(|b| b.is_ascii_lowercase())),
            "every word should be short, lowercase ascii for reading aloud"
        );
    }

    #[test]
    fn a_passphrase_has_the_requested_number_of_words() {
        for words in [MIN_WORDS, DEFAULT_WORDS, 8] {
            let p = Secret::passphrase(words).unwrap();
            let parts: Vec<&str> = p.expose().split(SEPARATOR).collect();
            assert_eq!(parts.len(), words, "got {:?}", p.expose());
            let list: std::collections::HashSet<&str> =
                WORDLIST.lines().filter(|l| !l.is_empty()).collect();
            assert!(
                parts.iter().all(|w| list.contains(w)),
                "every part must come from the wordlist: {:?}",
                p.expose()
            );
        }
    }

    #[test]
    fn too_few_words_is_refused() {
        assert!(Secret::passphrase(MIN_WORDS - 1).is_err());
    }

    #[test]
    fn passphrases_are_distinct() {
        // Not a guarantee, but a collision across fresh 41-bit secrets would
        // signal the generator is stuck.
        let a = Secret::passphrase(DEFAULT_WORDS).unwrap();
        let b = Secret::passphrase(DEFAULT_WORDS).unwrap();
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn uniform_index_stays_in_range() {
        for n in [3usize, 100, 1296] {
            for _ in 0..200 {
                assert!(uniform_index(n).unwrap() < n);
            }
        }
    }
}
