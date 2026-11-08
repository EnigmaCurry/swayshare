//! The access gate: the only thing between the network and wayvnc.
//!
//! wayvnc listens on a Unix socket inside the private runtime directory and
//! has no network listener of its own. Everything that reaches it comes
//! through [`serve`], which admits a connection only when its source address
//! falls inside the authorised peer's CIDR and the connection limit allows it.
//!
//! The admission decision is factored into the pure [`decide`] function so it
//! can be exercised directly by tests.

use anyhow::{Context, Result};
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::{mpsc, watch};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Source address is outside the authorised peer's range.
    DenyAddress,
    /// Address is authorised but the connection limit is already reached.
    DenyLimit,
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
pub fn decide(peer: IpAddr, allow: &IpNet, active: usize, max: usize) -> Decision {
    if !allow.contains(&normalize(peer)) {
        return Decision::DenyAddress;
    }
    if active >= max {
        return Decision::DenyLimit;
    }
    Decision::Allow
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
    allow: IpNet,
    vnc_socket: PathBuf,
    max_connections: usize,
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
        match decide(ip, &allow, current, max_connections) {
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

    match UnixStream::connect(&vnc_socket).await {
        Ok(mut upstream) => {
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
        Err(e) => {
            let _ = events
                .send(GateEvent::Failed {
                    error: format!("connecting to wayvnc socket: {e}"),
                })
                .await;
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
    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn authorised_host_is_admitted() {
        assert_eq!(
            decide(ip("10.0.0.3"), &net("10.0.0.3/32"), 0, 1),
            Decision::Allow
        );
    }

    #[test]
    fn neighbouring_host_is_refused() {
        assert_eq!(
            decide(ip("10.0.0.4"), &net("10.0.0.3/32"), 0, 1),
            Decision::DenyAddress
        );
        assert_eq!(
            decide(ip("10.0.1.3"), &net("10.0.0.3/32"), 0, 1),
            Decision::DenyAddress
        );
    }

    #[test]
    fn ipv4_mapped_source_matches_ipv4_rule() {
        // What a dual-stack listener actually reports for an IPv4 client.
        assert_eq!(normalize(ip("::ffff:10.0.0.3")), ip("10.0.0.3"));
        assert_eq!(
            decide(ip("::ffff:10.0.0.3"), &net("10.0.0.3/32"), 0, 1),
            Decision::Allow
        );
        assert_eq!(
            decide(ip("::ffff:10.0.0.4"), &net("10.0.0.3/32"), 0, 1),
            Decision::DenyAddress
        );
    }

    #[test]
    fn mapped_form_does_not_leak_across_families() {
        // An IPv6 rule must not be satisfied by an IPv4 client arriving mapped.
        assert_eq!(
            decide(ip("::ffff:10.0.0.3"), &net("::/0"), 0, 1),
            Decision::DenyAddress
        );
        // ...and a real IPv6 address is still matched normally.
        assert_eq!(
            decide(ip("fd00::3"), &net("fd00::3/128"), 0, 1),
            Decision::Allow
        );
        assert_eq!(
            decide(ip("fd00::4"), &net("fd00::3/128"), 0, 1),
            Decision::DenyAddress
        );
    }

    #[test]
    fn subnet_rules_match_their_members_only() {
        let n = net("10.0.0.0/24");
        assert_eq!(decide(ip("10.0.0.1"), &n, 0, 1), Decision::Allow);
        assert_eq!(decide(ip("10.0.0.255"), &n, 0, 1), Decision::Allow);
        assert_eq!(decide(ip("10.0.1.0"), &n, 0, 1), Decision::DenyAddress);
    }

    #[test]
    fn connection_limit_is_enforced_after_the_address_check() {
        // At the limit, an authorised peer is refused...
        assert_eq!(
            decide(ip("10.0.0.3"), &net("10.0.0.3/32"), 1, 1),
            Decision::DenyLimit
        );
        // ...and an unauthorised one is refused for the stronger reason.
        assert_eq!(
            decide(ip("10.0.0.9"), &net("10.0.0.3/32"), 1, 1),
            Decision::DenyAddress
        );
        assert_eq!(
            decide(ip("10.0.0.3"), &net("10.0.0.3/32"), 1, 2),
            Decision::Allow
        );
    }

    #[test]
    fn loopback_is_not_implicitly_trusted() {
        assert_eq!(
            decide(ip("127.0.0.1"), &net("10.0.0.3/32"), 0, 1),
            Decision::DenyAddress
        );
    }
}
