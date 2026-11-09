//! End-to-end tests for the access gate.
//!
//! These drive the real accept loop and the real forwarding path, with a
//! stand-in echo server on the Unix socket in place of wayvnc. The point is
//! to prove the properties the design depends on: an unauthorised source gets
//! nothing, an authorised one gets a transparent byte pipe, and revocation
//! takes effect on connections that are already established.

use ipnet::IpNet;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;
use swayshare::gate::{self, GateEvent, Policy, Revoker};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UnixListener};
use tokio::sync::mpsc;

/// Stand in for wayvnc: echo everything back, so the test can tell whether
/// bytes really traversed the gate.
async fn spawn_echo_server(path: &Path) {
    let listener = UnixListener::bind(path).expect("binding the stand-in wayvnc socket");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
}

struct Harness {
    listen: SocketAddr,
    revoker: Revoker,
    events: mpsc::Receiver<GateEvent>,
    _dir: TempDir,
}

/// Minimal scratch directory that cleans up on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("swayshare-test-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Start a gate on loopback that admits `allow` and permits `max` connections.
async fn harness(tag: &str, allow: &str, max: usize) -> Harness {
    harness_with(tag, allow, max, None).await
}

/// Start a gate on loopback, optionally requiring a named interface.
async fn harness_with(
    tag: &str,
    allow: &str,
    max: usize,
    required_interface: Option<&str>,
) -> Harness {
    let dir = TempDir::new(tag);
    let socket = dir.0.join("vnc.sock");
    spawn_echo_server(&socket).await;

    // Port 0 lets the OS pick, so concurrent tests never collide.
    let listener = gate::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let listen = listener.local_addr().unwrap();

    let (tx, rx) = mpsc::channel(32);
    let (revoker, cancel) = Revoker::new();
    let policy = Policy {
        allow: allow.parse::<IpNet>().unwrap(),
        required_interface: required_interface.map(str::to_string),
        max_connections: max,
    };

    tokio::spawn(gate::serve(listener, policy, socket, tx, cancel));

    Harness {
        listen,
        revoker,
        events: rx,
        _dir: dir,
    }
}

/// Connect with a chosen source address, so a request can arrive from an
/// address the gate is not supposed to trust.
async fn connect_from(source: Ipv4Addr, target: SocketAddr) -> TcpStream {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(SocketAddr::from((source, 0))).unwrap();
    socket
        .connect(target)
        .await
        .expect("the gate should always accept the TCP handshake")
}

/// Read with a timeout; `None` means the peer never sent anything.
async fn read_with_timeout(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buf = [0u8; 64];
    match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
        Ok(Ok(0)) => None, // clean EOF: the gate dropped us
        Ok(Ok(n)) => Some(buf[..n].to_vec()),
        Ok(Err(_)) => None, // reset: also a refusal
        Err(_) => panic!("timed out waiting for the gate to respond"),
    }
}

#[tokio::test]
async fn authorised_peer_gets_a_transparent_byte_pipe() {
    let mut h = harness("allow", "127.0.0.1/32", 1).await;
    let mut client = connect_from(Ipv4Addr::LOCALHOST, h.listen).await;

    client.write_all(b"RFB 003.008\n").await.unwrap();
    let echoed = read_with_timeout(&mut client)
        .await
        .expect("expected the echo back");
    assert_eq!(
        echoed, b"RFB 003.008\n",
        "the gate must not alter the stream"
    );

    match h.events.recv().await.unwrap() {
        GateEvent::Accepted { ip, active } => {
            assert_eq!(ip.to_string(), "127.0.0.1");
            assert_eq!(active, 1);
        }
        other => panic!("expected an Accepted event, got {other:?}"),
    }
}

#[tokio::test]
async fn unauthorised_source_is_dropped_and_told_nothing() {
    // The gate trusts 127.0.0.1 only; we arrive as 127.0.0.2.
    let mut h = harness("deny", "127.0.0.1/32", 1).await;
    let mut client = connect_from(Ipv4Addr::new(127, 0, 0, 2), h.listen).await;

    client.write_all(b"RFB 003.008\n").await.ok();
    assert!(
        read_with_timeout(&mut client).await.is_none(),
        "an unauthorised client must receive no bytes at all"
    );

    match h.events.recv().await.unwrap() {
        GateEvent::Rejected { ip, decision } => {
            assert_eq!(ip.to_string(), "127.0.0.2");
            assert_eq!(decision, gate::Decision::DenyAddress);
        }
        other => panic!("expected a Rejected event, got {other:?}"),
    }
}

#[tokio::test]
async fn revocation_tears_down_an_established_session() {
    let h = harness("revoke", "127.0.0.1/32", 1).await;
    let mut client = connect_from(Ipv4Addr::LOCALHOST, h.listen).await;

    // Prove the session is live before revoking it.
    client.write_all(b"ping").await.unwrap();
    assert_eq!(read_with_timeout(&mut client).await.unwrap(), b"ping");

    h.revoker.revoke();

    assert!(
        read_with_timeout(&mut client).await.is_none(),
        "revoking must drop connections that are already established"
    );
}

#[tokio::test]
async fn revocation_also_closes_the_listener() {
    let h = harness("revoke-listener", "127.0.0.1/32", 1).await;
    h.revoker.revoke();

    // The accept loop owns the listener, so once it exits the port is gone.
    // Retry briefly: the task needs a moment to wake and return.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let attempt = TcpStream::connect(h.listen).await;
        match attempt {
            Err(_) => return, // port closed - what we want
            Ok(mut stream) => {
                // Linux keeps the backlog briefly; a connection that gets no
                // data and is closed is equally proof the gate is gone.
                if read_with_timeout(&mut stream).await.is_none()
                    && tokio::time::Instant::now() > deadline
                {
                    return;
                }
            }
        }
        if tokio::time::Instant::now() > deadline {
            panic!("the listener was still accepting after revocation");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn connection_limit_refuses_a_second_viewer() {
    let h = harness("limit", "127.0.0.1/32", 1).await;

    let mut first = connect_from(Ipv4Addr::LOCALHOST, h.listen).await;
    first.write_all(b"one").await.unwrap();
    assert_eq!(read_with_timeout(&mut first).await.unwrap(), b"one");

    let mut second = connect_from(Ipv4Addr::LOCALHOST, h.listen).await;
    second.write_all(b"two").await.ok();
    assert!(
        read_with_timeout(&mut second).await.is_none(),
        "the second viewer must be refused while the first holds the slot"
    );

    // The first session is unaffected by the refusal.
    first.write_all(b"still here").await.unwrap();
    assert_eq!(read_with_timeout(&mut first).await.unwrap(), b"still here");
}

#[tokio::test]
async fn a_slot_is_released_when_a_viewer_leaves() {
    let mut h = harness("release", "127.0.0.1/32", 1).await;

    let mut first = connect_from(Ipv4Addr::LOCALHOST, h.listen).await;
    first.write_all(b"one").await.unwrap();
    assert_eq!(read_with_timeout(&mut first).await.unwrap(), b"one");
    drop(first);

    // Wait for the gate to observe the close and decrement its counter.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if let Ok(Some(GateEvent::Closed { active, .. })) =
            tokio::time::timeout(Duration::from_millis(100), h.events.recv()).await
        {
            assert_eq!(active, 0);
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "never saw the close event"
        );
    }

    let mut second = connect_from(Ipv4Addr::LOCALHOST, h.listen).await;
    second.write_all(b"two").await.unwrap();
    assert_eq!(
        read_with_timeout(&mut second).await.unwrap(),
        b"two",
        "the freed slot should admit the next viewer"
    );
}

#[tokio::test]
async fn a_connection_over_the_required_interface_is_admitted() {
    // Loopback traffic really does route over "lo", so this exercises the
    // kernel route lookup rather than a stubbed one.
    let mut h = harness_with("iface-ok", "127.0.0.1/32", 1, Some("lo")).await;
    let mut client = connect_from(Ipv4Addr::LOCALHOST, h.listen).await;

    client.write_all(b"hello").await.unwrap();
    assert_eq!(
        read_with_timeout(&mut client).await.unwrap(),
        b"hello",
        "a peer on the required interface should be forwarded normally"
    );
    match h.events.recv().await.unwrap() {
        GateEvent::Accepted { .. } => {}
        other => panic!("expected Accepted, got {other:?}"),
    }
}

#[tokio::test]
async fn an_authorised_address_on_the_wrong_interface_is_refused() {
    // This is the whole point of the rule: the CIDR matches, and the
    // connection is still refused because it did not arrive over wg0.
    let mut h = harness_with(
        "iface-wrong",
        "127.0.0.1/32",
        1,
        Some("wg-not-a-real-iface"),
    )
    .await;
    let mut client = connect_from(Ipv4Addr::LOCALHOST, h.listen).await;

    client.write_all(b"hello").await.ok();
    assert!(
        read_with_timeout(&mut client).await.is_none(),
        "an address-authorised peer on the wrong interface must get no bytes"
    );
    match h.events.recv().await.unwrap() {
        GateEvent::Rejected { decision, .. } => {
            assert_eq!(decision, gate::Decision::DenyInterface);
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
}

#[tokio::test]
async fn an_over_broad_cidr_is_contained_by_the_interface_rule() {
    // The failure this rule exists to survive: the CIDR is wide open, so the
    // address check alone would admit anything. The interface check must still
    // hold the line.
    let mut h = harness_with("iface-broad", "0.0.0.0/0", 1, Some("wg-not-a-real-iface")).await;
    let mut client = connect_from(Ipv4Addr::LOCALHOST, h.listen).await;

    client.write_all(b"hello").await.ok();
    assert!(
        read_with_timeout(&mut client).await.is_none(),
        "a wide-open CIDR must not be enough to get through on its own"
    );
    match h.events.recv().await.unwrap() {
        GateEvent::Rejected { decision, .. } => {
            assert_eq!(decision, gate::Decision::DenyInterface);
        }
        other => panic!("expected Rejected, got {other:?}"),
    }

    // ...and with the correct interface the same wide CIDR does let it in,
    // proving the refusal above came from the interface rule and nothing else.
    let ok = harness_with("iface-broad-ok", "0.0.0.0/0", 1, Some("lo")).await;
    let mut client = connect_from(Ipv4Addr::LOCALHOST, ok.listen).await;
    client.write_all(b"hello").await.unwrap();
    assert_eq!(read_with_timeout(&mut client).await.unwrap(), b"hello");
}
