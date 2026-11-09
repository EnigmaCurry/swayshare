//! Integration tests for the synchronous control-socket client.
//!
//! This is the path the configuration window uses, so it is exercised against
//! a real daemon process rather than a mock. No wayvnc or compositor is
//! needed: every request here is answerable in the "off" state.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use swayshare::ipc::{self, Request, Response, State};

/// Scratch XDG environment for one test, removed on drop.
///
/// Paths are kept short on purpose: `sockaddr_un.sun_path` is 108 bytes, and
/// a long temp path would fail the bind rather than the test's actual subject.
struct Sandbox {
    root: PathBuf,
    daemon: Option<Child>,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        let root = PathBuf::from(format!("/tmp/ss-it-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for sub in ["config", "data", "run"] {
            std::fs::create_dir_all(root.join(sub)).unwrap();
        }
        Self { root, daemon: None }
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_swayshare"));
        cmd.env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("XDG_DATA_HOME", self.root.join("data"))
            .env("XDG_RUNTIME_DIR", self.root.join("run"))
            // Keep notifications out of the developer's session bus.
            .env_remove("DBUS_SESSION_BUS_ADDRESS");
        cmd
    }

    fn socket(&self) -> PathBuf {
        self.root.join("run/swayshare/control.sock")
    }

    /// Start a daemon and wait for its control socket to answer.
    fn start_daemon(&mut self) {
        let child = self
            .command()
            .arg("daemon")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawning the daemon");
        self.daemon = Some(child);
        wait_for(&self.socket(), Duration::from_secs(10));
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        if let Some(child) = &mut self.daemon {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn wait_for(socket: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::os::unix::net::UnixStream::connect(socket).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the daemon never started listening on {}", socket.display());
}

#[test]
fn status_round_trips_without_a_runtime() {
    let mut sb = Sandbox::new("status");
    sb.start_daemon();

    let response = ipc::blocking::request(&sb.socket(), &Request::Status)
        .and_then(ipc::expect_ok)
        .expect("status should succeed against a live daemon");
    match response {
        Response::Status(status) => {
            assert_eq!(status.state, State::Off, "a fresh daemon must be off");
            assert_eq!(status.connections, 0);
            assert!(status.peer.is_none());
        }
        other => panic!("unexpected reply: {other:?}"),
    }
}

#[test]
fn daemon_errors_surface_as_rust_errors() {
    let mut sb = Sandbox::new("errors");
    sb.start_daemon();

    // Both of these are refused by the daemon in the off state; the client
    // must turn the error variant into an `Err` rather than returning it.
    let invite = ipc::blocking::request(&sb.socket(), &Request::Invite).and_then(ipc::expect_ok);
    let message = invite
        .expect_err("invite should fail when nothing is shared")
        .to_string();
    assert!(message.contains("sharing is off"), "got: {message}");

    let stop = ipc::blocking::request(&sb.socket(), &Request::Stop).and_then(ipc::expect_ok);
    assert!(
        stop.is_err(),
        "stopping when already off should be an error"
    );

    let unknown = ipc::blocking::request(
        &sb.socket(),
        &Request::Start {
            peer: "nobody".into(),
            minutes: None,
            mode: Default::default(),
        },
    )
    .and_then(ipc::expect_ok);
    let message = unknown
        .expect_err("an unknown peer should fail")
        .to_string();
    assert!(
        message.contains("nobody"),
        "the error should name the peer: {message}"
    );
}

#[test]
fn an_absent_daemon_is_reported_clearly() {
    // No daemon started: the message has to be actionable, because this is
    // what the configuration window shows the user.
    let sb = Sandbox::new("absent");
    let error = ipc::blocking::request(&sb.socket(), &Request::Status)
        .expect_err("there is no daemon to talk to");
    let message = format!("{error:#}");
    assert!(
        message.contains("not running"),
        "expected an actionable message, got: {message}"
    );
}

#[test]
fn shutdown_stops_the_daemon() {
    let mut sb = Sandbox::new("shutdown");
    sb.start_daemon();

    ipc::blocking::request(&sb.socket(), &Request::Shutdown)
        .and_then(ipc::expect_ok)
        .expect("shutdown should be accepted");

    // The daemon removes its socket on the way out.
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if std::os::unix::net::UnixStream::connect(sb.socket()).is_err() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the control socket still answers after shutdown");
}

#[test]
fn concurrent_clients_are_each_answered() {
    let mut sb = Sandbox::new("concurrent");
    sb.start_daemon();
    let socket = sb.socket();

    // The daemon handles each control connection in its own task; make sure a
    // burst from several threads does not cross replies or deadlock.
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let socket = socket.clone();
            std::thread::spawn(move || {
                ipc::blocking::request(&socket, &Request::Status).and_then(ipc::expect_ok)
            })
        })
        .collect();

    for handle in handles {
        match handle.join().expect("worker thread panicked") {
            Ok(Response::Status(status)) => assert_eq!(status.state, State::Off),
            other => panic!("unexpected reply: {other:?}"),
        }
    }
}
