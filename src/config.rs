//! Persistent configuration: the peer list and a few policy knobs.
//!
//! Session passwords are never stored here. See [`crate::secret`].

use crate::paths;
use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const DEFAULT_PORT: u16 = 5900;
pub const DEFAULT_USERNAME: &str = "support";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub network: Network,
    #[serde(default)]
    pub security: Security,
    #[serde(default)]
    pub peers: Vec<Peer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Network {
    /// The interface access is confined to, e.g. `wg0`.
    ///
    /// This does two things. Its current address is what the gate binds to,
    /// resolved at every session start so a tunnel that comes and goes is
    /// picked up each time; and every connection must reach us over it, or it
    /// is refused whatever the peer's CIDR says.
    ///
    /// The second part is the one that matters. Binding an interface's
    /// *address* does not confine traffic to that interface: Linux uses the
    /// weak host model, so a packet addressed to the wg0 address is accepted
    /// arriving on any interface. Without the route check, a mistyped CIDR
    /// would be the only thing between the internet and wayvnc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// Explicit bind address, which takes precedence over `interface` for
    /// *binding* only.
    ///
    /// Setting both is meaningful: the gate binds `address` but still refuses
    /// anything that does not arrive over `interface`. Setting `address`
    /// alone turns the interface requirement off, which is weaker - the CIDR
    /// then stands alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<IpAddr>,
    #[serde(default = "default_port")]
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Security {
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Minutes after which a session self-revokes. 0 disables expiry.
    #[serde(default = "default_session_minutes")]
    pub default_session_minutes: u64,
    /// Username the remote peer authenticates with.
    #[serde(default = "default_username")]
    pub username: String,
    /// How many words make up the one-time password the owner reads aloud when
    /// someone connects. More words is harder to guess but longer to dictate.
    #[serde(default = "default_password_words")]
    pub password_words: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub name: String,
    pub cidr: IpNet,
}

fn default_port() -> u16 {
    DEFAULT_PORT
}
fn default_max_connections() -> usize {
    1
}
fn default_session_minutes() -> u64 {
    60
}
fn default_username() -> String {
    DEFAULT_USERNAME.to_string()
}
fn default_password_words() -> usize {
    crate::secret::DEFAULT_WORDS
}

impl Default for Network {
    fn default() -> Self {
        Self {
            interface: None,
            address: None,
            port: default_port(),
        }
    }
}

impl Default for Security {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            default_session_minutes: default_session_minutes(),
            username: default_username(),
            password_words: default_password_words(),
        }
    }
}

impl Config {
    /// Load the config, returning defaults when the file does not exist yet.
    pub fn load() -> Result<Self> {
        let path = paths::config_file()?;
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let cfg: Config =
                    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
                cfg.validate()?;
                Ok(cfg)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn save(&self) -> Result<()> {
        let path = paths::config_file()?;
        paths::ensure_private_dir(&paths::config_dir()?)?;
        let text = toml::to_string_pretty(self).context("serialising config")?;
        paths::write_atomic(&path, &text, 0o600)
    }

    fn validate(&self) -> Result<()> {
        if self.security.max_connections == 0 {
            bail!("security.max_connections must be at least 1");
        }
        if self.security.password_words < 3 {
            bail!("security.password_words must be at least 3");
        }
        let mut seen = std::collections::HashSet::new();
        for p in &self.peers {
            if !seen.insert(p.name.to_lowercase()) {
                bail!("duplicate peer name in config: {}", p.name);
            }
        }
        Ok(())
    }

    pub fn find_peer(&self, name: &str) -> Option<&Peer> {
        self.peers
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case(name))
    }

    /// Add a peer. Returns an error if the name is already taken.
    pub fn add_peer(&mut self, name: &str, cidr: IpNet) -> Result<()> {
        validate_peer_name(name)?;
        if self.find_peer(name).is_some() {
            bail!("peer '{name}' already exists");
        }
        self.peers.push(Peer {
            name: name.to_string(),
            cidr,
        });
        self.peers.sort_by_key(|p| p.name.to_lowercase());
        Ok(())
    }

    pub fn remove_peer(&mut self, name: &str) -> Result<Peer> {
        match self
            .peers
            .iter()
            .position(|p| p.name.eq_ignore_ascii_case(name))
        {
            Some(i) => Ok(self.peers.remove(i)),
            None => bail!("no such peer: {name}"),
        }
    }
}

fn validate_peer_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("peer name cannot be empty");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        bail!("peer name may only contain letters, digits, '-', '_' and '.'");
    }
    Ok(())
}

/// Accept both a bare address and a CIDR, treating the former as a host route.
///
/// Typing `10.0.0.3` and silently getting a whole subnet would be the worst
/// possible surprise here, so a bare address becomes an explicit /32 or /128.
pub fn parse_cidr(input: &str) -> Result<IpNet> {
    if let Ok(net) = input.parse::<IpNet>() {
        // `IpNet` accepts a host address with non-zero bits outside the prefix
        // (10.0.0.3/24); truncate so the stored range is unambiguous.
        return Ok(net.trunc());
    }
    if let Ok(ip) = input.parse::<IpAddr>() {
        return Ok(IpNet::from(ip));
    }
    bail!("'{input}' is not an IP address or CIDR range")
}

/// How broad a CIDR has to be before we refuse it without an explicit override.
///
/// Anything wider than a /24 (or /120 for IPv6) almost certainly is not "one
/// person", which is the unit of trust this tool is built around.
pub fn breadth_warning(cidr: &IpNet) -> Option<String> {
    let (len, host_len, refuse_below) = match cidr {
        IpNet::V4(n) => (n.prefix_len(), 32u8, 24u8),
        IpNet::V6(n) => (n.prefix_len(), 128u8, 120u8),
    };
    if len == host_len {
        return None;
    }
    let hosts = 2u128.saturating_pow((host_len - len) as u32);
    let severity = if len < refuse_below {
        "very broad"
    } else {
        "broad"
    };
    Some(format!(
        "{cidr} is a {severity} range covering {hosts} addresses; \
         anyone holding any of them could connect"
    ))
}

/// True when a CIDR is wide enough to require `--force`.
pub fn requires_force(cidr: &IpNet) -> bool {
    match cidr {
        IpNet::V4(n) => n.prefix_len() < 24,
        IpNet::V6(n) => n.prefix_len() < 120,
    }
}

/// Resolve the address the gate should bind to.
///
/// Fails rather than falling back to a wildcard bind: a misconfigured or
/// absent tunnel must not silently expose the gate on every interface.
pub fn resolve_listen_ip(net: &Network) -> Result<IpAddr> {
    if let Some(addr) = net.address {
        return Ok(addr);
    }
    let Some(iface) = net.interface.as_deref() else {
        bail!(
            "no bind address configured; set network.interface (e.g. \"wg0\") \
             or network.address in {}",
            paths::config_file()?.display()
        );
    };
    let addrs = if_addrs::get_if_addrs().context("enumerating network interfaces")?;
    let mut found: Vec<IpAddr> = addrs
        .iter()
        .filter(|i| i.name == iface)
        .map(|i| i.addr.ip())
        .filter(|ip| !ip.is_loopback())
        .collect();
    // Prefer IPv4: wireguard setups in the wild are predominantly v4, and a
    // link-local v6 address would not be reachable by the peer anyway.
    found.sort_by_key(|ip| match ip {
        IpAddr::V4(_) => 0,
        IpAddr::V6(v6) if !(v6.segments()[0] & 0xffc0 == 0xfe80) => 1,
        IpAddr::V6(_) => 2,
    });
    match found.first() {
        Some(ip) => Ok(*ip),
        None => bail!(
            "interface '{iface}' has no usable address - is the tunnel up? \
             swayshare will not bind elsewhere on its own"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_addresses_become_host_routes() {
        assert_eq!(
            parse_cidr("10.0.0.3").unwrap(),
            "10.0.0.3/32".parse::<IpNet>().unwrap()
        );
        assert_eq!(
            parse_cidr("fd00::3").unwrap(),
            "fd00::3/128".parse::<IpNet>().unwrap()
        );
    }

    #[test]
    fn cidrs_are_truncated_to_their_prefix() {
        // Otherwise "10.0.0.3/24" would read as one host but match 256.
        assert_eq!(
            parse_cidr("10.0.0.3/24").unwrap(),
            "10.0.0.0/24".parse::<IpNet>().unwrap()
        );
    }

    #[test]
    fn nonsense_cidrs_are_rejected() {
        assert!(parse_cidr("mike").is_err());
        assert!(parse_cidr("10.0.0.300/32").is_err());
        assert!(parse_cidr("10.0.0.3/33").is_err());
        assert!(parse_cidr("").is_err());
    }

    #[test]
    fn host_routes_do_not_warn() {
        assert!(breadth_warning(&"10.0.0.3/32".parse().unwrap()).is_none());
        assert!(breadth_warning(&"fd00::3/128".parse().unwrap()).is_none());
    }

    #[test]
    fn subnets_warn_and_wide_ones_need_force() {
        assert!(breadth_warning(&"10.0.0.0/24".parse().unwrap()).is_some());
        assert!(!requires_force(&"10.0.0.0/24".parse().unwrap()));
        assert!(requires_force(&"10.0.0.0/8".parse().unwrap()));
        assert!(requires_force(&"fd00::/64".parse().unwrap()));
    }

    #[test]
    fn peer_names_are_restricted() {
        assert!(validate_peer_name("mike").is_ok());
        assert!(validate_peer_name("mike-laptop.1").is_ok());
        assert!(validate_peer_name("").is_err());
        assert!(validate_peer_name("mike brown").is_err());
        assert!(validate_peer_name("../../etc/passwd").is_err());
    }

    #[test]
    fn peers_are_matched_case_insensitively_and_uniquely() {
        let mut c = Config::default();
        c.add_peer("Mike", "10.0.0.3/32".parse().unwrap()).unwrap();
        assert!(c.find_peer("mike").is_some());
        assert!(c.add_peer("mike", "10.0.0.9/32".parse().unwrap()).is_err());
        assert!(c.remove_peer("MIKE").is_ok());
        assert!(c.remove_peer("mike").is_err());
    }

    #[test]
    fn explicit_address_wins_over_interface() {
        let net = Network {
            interface: Some("definitely-not-an-interface".into()),
            address: Some("10.0.0.10".parse().unwrap()),
            port: 5900,
        };
        assert_eq!(
            resolve_listen_ip(&net).unwrap(),
            "10.0.0.10".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn address_and_interface_have_separate_jobs() {
        // `address` decides where to bind; `interface` decides what is let
        // in. Setting both is a legitimate combination - bind somewhere
        // specific, but still only accept traffic off the tunnel.
        let net = Network {
            interface: Some("wg0".into()),
            address: Some("0.0.0.0".parse().unwrap()),
            port: 5900,
        };
        assert_eq!(
            resolve_listen_ip(&net).unwrap(),
            "0.0.0.0".parse::<IpAddr>().unwrap(),
            "the explicit address wins for binding"
        );
        assert_eq!(
            net.interface.as_deref(),
            Some("wg0"),
            "...and the interface requirement is still there to be enforced"
        );
    }

    #[test]
    fn missing_interface_is_an_error_not_a_wildcard_bind() {
        let net = Network {
            interface: Some("definitely-not-an-interface".into()),
            address: None,
            port: 5900,
        };
        assert!(resolve_listen_ip(&net).is_err());
        let empty = Network {
            interface: None,
            address: None,
            port: 5900,
        };
        assert!(resolve_listen_ip(&empty).is_err());
    }

    #[test]
    fn config_round_trips_through_toml() {
        let mut c = Config::default();
        c.network.interface = Some("wg0".into());
        c.add_peer("mike", "10.0.0.3/32".parse().unwrap()).unwrap();
        c.add_peer("jane", "10.0.0.4/32".parse().unwrap()).unwrap();
        let text = toml::to_string_pretty(&c).unwrap();
        let back: Config = toml::from_str(&text).unwrap();
        assert_eq!(back.peers.len(), 2);
        assert_eq!(back.network.interface.as_deref(), Some("wg0"));
        assert_eq!(back.security.max_connections, 1);
    }
}
