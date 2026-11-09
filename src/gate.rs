//! The access gate: the only thing between the network and wayvnc.
//!
//! wayvnc listens on a Unix socket inside the private runtime directory and
//! has no network listener of its own. Everything that reaches it comes
//! through [`serve`], which admits a connection only when it satisfies every
//! part of the [`Policy`]: the source address is inside the authorised peer's
//! CIDR, it reaches us over the required network interface, and the
//! connection limit allows it.
//!
//! The admission decision is factored into the pure [`decide`] function so it
//! can be exercised directly by tests.

use anyhow::{Context, Result};
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::{mpsc, watch};

/// How long to keep trying to reach wayvnc's socket before giving up on one
/// connection. A password rotation restarts wayvnc, so the socket can be
/// briefly absent just as a new connection arrives; this rides over that gap
/// without the connection seeing an error.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const UPSTREAM_RETRY_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Source address is outside the authorised peer's range.
    DenyAddress,
    /// The peer does not reach us over the required interface.
    DenyInterface,
    /// Address is authorised but the connection limit is already reached.
    DenyLimit,
}

impl Decision {
    /// Short phrase for logs and notifications.
    pub fn reason(self) -> &'static str {
        match self {
            Decision::Allow => "allowed",
            Decision::DenyAddress => "address not authorised",
            Decision::DenyInterface => "not reachable over the required interface",
            Decision::DenyLimit => "connection limit reached",
        }
    }
}

/// Everything the gate checks a connection against.
///
/// Held together in one place so that adding a rule cannot accidentally
/// bypass the others.
#[derive(Debug, Clone)]
pub struct Policy {
    /// The authorised peer's address range.
    pub allow: IpNet,
    /// When set, a connection is admitted only if its source address routes
    /// back through this interface.
    ///
    /// This exists because binding to an interface's *address* is weaker than
    /// it looks: Linux uses the weak host model, so a packet addressed to the
    /// wg0 address is accepted on any interface. Without this check a
    /// mistyped CIDR would be the only thing between the internet and wayvnc.
    pub required_interface: Option<String>,
    pub max_connections: usize,
}

#[derive(Debug, Clone)]
pub enum GateEvent {
    Accepted {
        ip: IpAddr,
        active: usize,
    },
    Rejected {
        ip: IpAddr,
        decision: Decision,
    },
    Closed {
        ip: IpAddr,
        active: usize,
    },
    /// The accept loop died; the daemon treats this as a reason to fail closed.
    Failed {
        error: String,
    },
}

/// Collapse IPv4-mapped IPv6 addresses (`::ffff:10.0.0.3`) to plain IPv4.
///
/// A dual-stack listener reports IPv4 clients in the mapped form, which would
/// never match an IPv4 CIDR. Without this, a `10.0.0.3/32` rule would reject
/// the very peer it names - or, worse, a `::/0`-style rule would match
/// something the user never intended.
pub fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Decide whether to admit a connection. Pure, so it is directly testable.
///
/// `route` is the interface the peer's address currently routes through, as
/// determined by [`egress_interface`]; `None` means the kernel could not say.
pub fn decide(policy: &Policy, peer: IpAddr, route: Option<&str>, active: usize) -> Decision {
    if !policy.allow.contains(&normalize(peer)) {
        return Decision::DenyAddress;
    }
    if let Some(required) = policy.required_interface.as_deref() {
        // An unknown route is a denial, not a pass: if we cannot show the
        // peer is on the right interface, we must assume it is not.
        if route != Some(required) {
            return Decision::DenyInterface;
        }
    }
    if active >= policy.max_connections {
        return Decision::DenyLimit;
    }
    Decision::Allow
}

/// Name the interface that traffic to `peer` would leave by.
///
/// Connecting a UDP socket sends nothing; it just asks the kernel to run its
/// routing decision and pin the result, which `getsockname` then reveals as
/// the source address it chose. Mapping that address back to an interface
/// gives us the kernel's own answer - including any policy routing - without
/// parsing routing tables and, crucially, without privileges. `SO_BINDTODEVICE`
/// would be more direct but needs `CAP_NET_RAW`, which this program does not
/// want to hold.
///
/// Returns `None` when the address is unroutable or the local address does not
/// belong to any interface we can see; callers must treat that as a denial.
pub fn egress_interface(peer: IpAddr) -> Option<String> {
    let bind: SocketAddr = match peer {
        IpAddr::V4(_) => (std::net::Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(bind).ok()?;
    // Port 9 is discard; nothing is ever sent, so it only has to be non-zero.
    socket.connect(SocketAddr::new(peer, 9)).ok()?;
    let local = socket.local_addr().ok()?.ip();

    let addrs = if_addrs::get_if_addrs().ok()?;
    addrs
        .into_iter()
        .find(|i| i.addr.ip() == local)
        .map(|i| i.name)
}

/// Shared handle used to revoke a running gate.
///
/// Dropping the sender (or calling [`Revoker::revoke`]) wakes every forwarding
/// task, which drops its sockets immediately.
#[derive(Clone)]
pub struct Revoker(watch::Sender<bool>);

impl Revoker {
    pub fn new() -> (Self, watch::Receiver<bool>) {
        let (tx, rx) = watch::channel(false);
        (Self(tx), rx)
    }

    pub fn revoke(&self) {
        let _ = self.0.send(true);
    }
}

/// Run the accept loop until `cancel` fires.
///
/// The listener is owned by this task, so returning closes it - there is no
/// window in which a revoked session still has a bound port.
pub async fn serve(
    listener: TcpListener,
    policy: Policy,
    vnc_socket: PathBuf,
    events: mpsc::Sender<GateEvent>,
    mut cancel: watch::Receiver<bool>,
) {
    let active = Arc::new(AtomicUsize::new(0));

    loop {
        let accepted = tokio::select! {
            biased;
            _ = cancel.changed() => break,
            r = listener.accept() => r,
        };

        let (client, addr) = match accepted {
            Ok(pair) => pair,
            Err(e) => {
                // EMFILE and friends are transient; a broken listener is not.
                // Report and stop, letting the daemon fail closed.
                let _ = events
                    .send(GateEvent::Failed {
                        error: e.to_string(),
                    })
                    .await;
                break;
            }
        };

        let ip = normalize(addr.ip());
        let current = active.load(Ordering::SeqCst);
        // Recomputed per connection rather than cached: a tunnel can come up
        // or go down mid-session, and a stale answer would be the wrong one.
        let route = policy
            .required_interface
            .as_ref()
            .and_then(|_| egress_interface(ip));
        match decide(&policy, ip, route.as_deref(), current) {
            Decision::Allow => {}
            decision => {
                // Drop the socket without writing anything back: an
                // unauthorised scanner learns nothing about what is behind us.
                drop(client);
                let _ = events.send(GateEvent::Rejected { ip, decision }).await;
                continue;
            }
        }

        let active_now = active.fetch_add(1, Ordering::SeqCst) + 1;
        let _ = events
            .send(GateEvent::Accepted {
                ip,
                active: active_now,
            })
            .await;

        tokio::spawn(forward(
            client,
            addr,
            vnc_socket.clone(),
            Arc::clone(&active),
            events.clone(),
            cancel.clone(),
        ));
    }
}

/// Splice one admitted TCP connection onto wayvnc's Unix socket.
///
/// The VNC stream is forwarded verbatim, so wayvnc's own authentication and
/// TLS run end to end between the viewer and wayvnc; the gate cannot read the
/// session and holds no key material.
async fn forward(
    mut client: TcpStream,
    addr: SocketAddr,
    vnc_socket: PathBuf,
    active: Arc<AtomicUsize>,
    events: mpsc::Sender<GateEvent>,
    mut cancel: watch::Receiver<bool>,
) {
    let ip = normalize(addr.ip());
    // Interactive remote desktop: round-trip latency matters more than
    // coalescing small input events into full segments.
    let _ = client.set_nodelay(true);

    match connect_upstream(&vnc_socket, &mut cancel).await {
        Some(mut upstream) => {
            // No Nagle knob on Unix sockets; the TCP side above is the one
            // that needed it.
            tokio::select! {
                _ = copy_bidirectional(&mut client, &mut upstream) => {}
                _ = cancel.changed() => {
                    // Revocation is immediate: both halves are dropped here
                    // rather than waiting for either side to close.
                }
            }
        }
        None => {
            // wayvnc never came back (or the session is being revoked). Drop
            // just this connection rather than failing the whole session: a
            // genuine wayvnc crash is reported separately by its supervisor.
            eprintln!("swayshare: dropping {ip}: wayvnc socket was unreachable");
        }
    }

    let remaining = active.fetch_sub(1, Ordering::SeqCst).saturating_sub(1);
    let _ = events
        .send(GateEvent::Closed {
            ip,
            active: remaining,
        })
        .await;
}

/// Connect to wayvnc's socket, retrying briefly across a password rotation.
///
/// Returns `None` if the session is being revoked or wayvnc does not reappear
/// within [`UPSTREAM_CONNECT_TIMEOUT`]; either way this connection is dropped
/// rather than treated as a session-ending failure.
async fn connect_upstream(
    vnc_socket: &Path,
    cancel: &mut watch::Receiver<bool>,
) -> Option<UnixStream> {
    let deadline = tokio::time::Instant::now() + UPSTREAM_CONNECT_TIMEOUT;
    loop {
        if *cancel.borrow() {
            return None;
        }
        match UnixStream::connect(vnc_socket).await {
            Ok(stream) => return Some(stream),
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::select! {
                    _ = cancel.changed() => return None,
                    _ = tokio::time::sleep(UPSTREAM_RETRY_INTERVAL) => {}
                }
            }
            Err(_) => return None,
        }
    }
}

/// Bind the gate's listener, failing with an actionable message.
pub async fn bind(addr: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(addr).await.with_context(|| {
        format!(
            "binding {addr} - is the address present (is the tunnel up?) \
             and the port free?"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn policy(allow: &str) -> Policy {
        Policy {
            allow: allow.parse().unwrap(),
            required_interface: None,
            max_connections: 1,
        }
    }

    fn policy_on(allow: &str, interface: &str) -> Policy {
        Policy {
            required_interface: Some(interface.to_string()),
            ..policy(allow)
        }
    }

    #[test]
    fn authorised_host_is_admitted() {
        assert_eq!(
            decide(&policy("10.0.0.3/32"), ip("10.0.0.3"), None, 0),
            Decision::Allow
        );
    }

    #[test]
    fn neighbouring_host_is_refused() {
        let p = policy("10.0.0.3/32");
        assert_eq!(decide(&p, ip("10.0.0.4"), None, 0), Decision::DenyAddress);
        assert_eq!(decide(&p, ip("10.0.1.3"), None, 0), Decision::DenyAddress);
    }

    #[test]
    fn ipv4_mapped_source_matches_ipv4_rule() {
        // What a dual-stack listener actually reports for an IPv4 client.
        assert_eq!(normalize(ip("::ffff:10.0.0.3")), ip("10.0.0.3"));
        let p = policy("10.0.0.3/32");
        assert_eq!(decide(&p, ip("::ffff:10.0.0.3"), None, 0), Decision::Allow);
        assert_eq!(
            decide(&p, ip("::ffff:10.0.0.4"), None, 0),
            Decision::DenyAddress
        );
    }

    #[test]
    fn mapped_form_does_not_leak_across_families() {
        // An IPv6 rule must not be satisfied by an IPv4 client arriving mapped.
        assert_eq!(
            decide(&policy("::/0"), ip("::ffff:10.0.0.3"), None, 0),
            Decision::DenyAddress
        );
        // ...and a real IPv6 address is still matched normally.
        let p = policy("fd00::3/128");
        assert_eq!(decide(&p, ip("fd00::3"), None, 0), Decision::Allow);
        assert_eq!(decide(&p, ip("fd00::4"), None, 0), Decision::DenyAddress);
    }

    #[test]
    fn subnet_rules_match_their_members_only() {
        let p = policy("10.0.0.0/24");
        assert_eq!(decide(&p, ip("10.0.0.1"), None, 0), Decision::Allow);
        assert_eq!(decide(&p, ip("10.0.0.255"), None, 0), Decision::Allow);
        assert_eq!(decide(&p, ip("10.0.1.0"), None, 0), Decision::DenyAddress);
    }

    #[test]
    fn connection_limit_is_enforced_after_the_address_check() {
        let p = policy("10.0.0.3/32");
        // At the limit, an authorised peer is refused...
        assert_eq!(decide(&p, ip("10.0.0.3"), None, 1), Decision::DenyLimit);
        // ...and an unauthorised one is refused for the stronger reason.
        assert_eq!(decide(&p, ip("10.0.0.9"), None, 1), Decision::DenyAddress);
        let roomy = Policy {
            max_connections: 2,
            ..p
        };
        assert_eq!(decide(&roomy, ip("10.0.0.3"), None, 1), Decision::Allow);
    }

    #[test]
    fn loopback_is_not_implicitly_trusted() {
        assert_eq!(
            decide(&policy("10.0.0.3/32"), ip("127.0.0.1"), None, 0),
            Decision::DenyAddress
        );
    }

    // --- the interface requirement ---

    #[test]
    fn no_required_interface_means_the_route_is_ignored() {
        let p = policy("10.0.0.3/32");
        for route in [None, Some("eth0"), Some("wg0")] {
            assert_eq!(decide(&p, ip("10.0.0.3"), route, 0), Decision::Allow);
        }
    }

    #[test]
    fn the_right_interface_is_admitted_and_others_are_not() {
        let p = policy_on("10.0.0.3/32", "wg0");
        assert_eq!(decide(&p, ip("10.0.0.3"), Some("wg0"), 0), Decision::Allow);
        assert_eq!(
            decide(&p, ip("10.0.0.3"), Some("eth0"), 0),
            Decision::DenyInterface
        );
    }

    #[test]
    fn an_unknown_route_is_a_denial_not_a_pass() {
        // The whole point is to fail closed: if the kernel cannot tell us the
        // peer is on wg0, we must not assume it is.
        let p = policy_on("10.0.0.3/32", "wg0");
        assert_eq!(decide(&p, ip("10.0.0.3"), None, 0), Decision::DenyInterface);
    }

    #[test]
    fn the_interface_check_catches_an_over_broad_cidr() {
        // The reason this rule exists. A far-too-wide CIDR would admit this
        // address on its own; arriving over the wrong interface still does not.
        let p = policy_on("10.0.0.0/8", "wg0");
        assert_eq!(
            decide(&p, ip("10.1.2.3"), Some("eth0"), 0),
            Decision::DenyInterface
        );
        assert_eq!(decide(&p, ip("10.1.2.3"), Some("wg0"), 0), Decision::Allow);
    }

    #[test]
    fn interface_names_are_matched_exactly() {
        let p = policy_on("10.0.0.3/32", "wg0");
        for near_miss in ["wg", "wg00", "wg0:1", "WG0", " wg0"] {
            assert_eq!(
                decide(&p, ip("10.0.0.3"), Some(near_miss), 0),
                Decision::DenyInterface,
                "{near_miss:?} must not pass for wg0"
            );
        }
    }

    #[test]
    fn the_address_rule_still_wins_over_the_interface_rule() {
        // Right interface, wrong address: still refused, and reported as the
        // address failure because that is the more fundamental one.
        let p = policy_on("10.0.0.3/32", "wg0");
        assert_eq!(
            decide(&p, ip("10.0.0.9"), Some("wg0"), 0),
            Decision::DenyAddress
        );
    }

    #[test]
    fn every_denial_has_a_distinct_reason() {
        use std::collections::HashSet;
        let reasons: HashSet<&str> = [
            Decision::DenyAddress,
            Decision::DenyInterface,
            Decision::DenyLimit,
        ]
        .into_iter()
        .map(Decision::reason)
        .collect();
        assert_eq!(reasons.len(), 3, "the user should be told which rule bit");
    }

    // --- the kernel route lookup ---

    #[test]
    fn loopback_routes_over_the_loopback_interface() {
        // A real routing decision, which is portable enough to assert on:
        // 127.0.0.1 always leaves by the loopback device.
        assert_eq!(egress_interface(ip("127.0.0.1")).as_deref(), Some("lo"));
        assert_eq!(egress_interface(ip("::1")).as_deref(), Some("lo"));
    }

    #[test]
    fn a_non_loopback_address_does_not_route_over_loopback() {
        // Whatever the host's routing looks like, a public address must not
        // come back as "lo" - otherwise the check would be trivially passed.
        if let Some(name) = egress_interface(ip("198.51.100.1")) {
            assert_ne!(name, "lo");
        }
    }
}
