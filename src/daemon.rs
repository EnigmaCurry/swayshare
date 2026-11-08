//! The long-lived supervisor: state machine, control socket, gate and wayvnc.
//!
//! The daemon starts in [`State::Off`] with no listener bound, and returns to
//! it whenever anything goes wrong. Every transition out of a sharing session
//! closes the listener, drops live connections and erases the session
//! credentials, so the failure mode is always "no access".

use crate::config::{self, Config, Peer};
use crate::gate::{self, Decision, GateEvent, Revoker};
use crate::identity::Identity;
use crate::invite;
use crate::ipc::{Request, Response, Session, State, Status};
use crate::notify;
use crate::paths;
use crate::secret::Secret;
use crate::wayvnc::Wayvnc;
use anyhow::{Context, Result, bail};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

/// How long to wait for wayvnc to actually be gone before reporting a stop.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Everything belonging to one sharing session.
///
/// Dropping or stopping this is what revokes access, so nothing here is
/// shared outside the daemon's event loop.
struct ActiveSession {
    peer: Peer,
    listen: SocketAddr,
    username: String,
    password: Secret,
    fingerprint: String,
    /// Fires the cancellation that drops every proxied connection.
    revoker: Revoker,
    /// Closing this tells the supervisor task to kill wayvnc.
    wayvnc_stop: Option<oneshot::Sender<()>>,
    /// Resolves once wayvnc is confirmed dead and its config file erased.
    wayvnc_done: oneshot::Receiver<()>,
    connections: usize,
    expires_at: Option<Instant>,
}

/// Internal events folded into the daemon's single event loop.
enum Event {
    Gate(GateEvent),
    /// wayvnc exited without being asked to.
    WayvncExited(String),
}

pub struct Daemon {
    identity: Identity,
    runtime_dir: PathBuf,
    session: Option<ActiveSession>,
    events: mpsc::Sender<Event>,
    /// Set by `Request::Shutdown`; the event loop exits after replying.
    shutdown_requested: bool,
}

/// A control-socket request paired with the channel its reply goes back on.
type Call = (Request, oneshot::Sender<Response>);

impl Daemon {
    /// Bind the control socket and run until told to shut down.
    pub async fn run() -> Result<()> {
        let runtime_dir = paths::runtime_dir()?;
        let socket_path = runtime_dir.join("control.sock");
        let listener = bind_control_socket(&socket_path).await?;

        // Generated eagerly so a first-run failure surfaces at daemon start
        // rather than in the middle of a support call.
        let identity = Identity::ensure()?;
        eprintln!("swayshare: identity SHA256:{}", identity.fingerprint);

        let (events_tx, mut events_rx) = mpsc::channel::<Event>(64);
        let (calls_tx, mut calls_rx) = mpsc::channel::<Call>(16);

        tokio::spawn(accept_calls(listener, calls_tx));

        let mut daemon = Daemon {
            identity,
            runtime_dir,
            session: None,
            events: events_tx,
            shutdown_requested: false,
        };

        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .context("installing SIGINT handler")?;
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .context("installing SIGTERM handler")?;

        eprintln!("swayshare: daemon ready, sharing is off");

        loop {
            // Captured before the select so the timer future borrows nothing.
            let deadline = daemon.session.as_ref().and_then(|s| s.expires_at);

            tokio::select! {
                Some((req, reply)) = calls_rx.recv() => {
                    let resp = daemon.handle(req).await;
                    let _ = reply.send(resp);
                    if daemon.shutdown_requested {
                        break;
                    }
                }
                Some(event) = events_rx.recv() => daemon.handle_event(event).await,
                _ = sleep_until_opt(deadline) => {
                    daemon.stop_session("the session timer expired").await;
                }
                _ = sigint.recv() => {
                    eprintln!("swayshare: interrupted");
                    break;
                }
                _ = sigterm.recv() => {
                    eprintln!("swayshare: terminated");
                    break;
                }
            }
        }

        // Fail closed on the way out, whatever the reason for leaving.
        daemon.stop_session("the daemon is exiting").await;
        paths::remove_if_present(&socket_path);
        Ok(())
    }

    async fn handle(&mut self, req: Request) -> Response {
        let result = match req {
            Request::Status => Ok(Response::Status(self.status())),
            Request::Start { peer, minutes } => self.start_session(&peer, minutes).await,
            Request::Stop => {
                if self.session.is_none() {
                    Err(anyhow::anyhow!("sharing is already off"))
                } else {
                    self.stop_session("stopped by the user").await;
                    Ok(Response::Ok)
                }
            }
            Request::Invite => self.invite(),
            Request::Shutdown => {
                self.shutdown_requested = true;
                Ok(Response::Ok)
            }
        };
        match result {
            Ok(resp) => resp,
            Err(e) => Response::Error {
                message: format_error(&e),
            },
        }
    }

    fn status(&self) -> Status {
        match &self.session {
            None => Status::off(),
            Some(s) => Status {
                state: if s.connections > 0 {
                    State::Connected
                } else {
                    State::Listening
                },
                peer: Some(s.peer.name.clone()),
                cidr: Some(s.peer.cidr.to_string()),
                listen: Some(s.listen.to_string()),
                connections: s.connections,
                expires_in_seconds: s.remaining_seconds(),
            },
        }
    }

    fn invite(&self) -> Result<Response> {
        let Some(s) = &self.session else {
            bail!("sharing is off; start a session first");
        };
        Ok(Response::Session(s.describe()))
    }

    /// Enable sharing for one peer.
    ///
    /// Any existing session is torn down first: switching peers must never
    /// leave the previous peer's access in place.
    async fn start_session(&mut self, peer_name: &str, minutes: Option<u64>) -> Result<Response> {
        let cfg = Config::load()?;
        let peer = cfg
            .find_peer(peer_name)
            .cloned()
            .with_context(|| format!("no such peer: {peer_name}"))?;

        if config::requires_force(&peer.cidr) {
            bail!(
                "peer '{}' covers {} which is too broad to share with; \
                 re-add it with a narrower CIDR",
                peer.name,
                peer.cidr
            );
        }

        // Resolve and bind before touching the existing session, so a failure
        // here does not take down a working one.
        let ip = config::resolve_listen_ip(&cfg.network)?;
        let listen = SocketAddr::new(ip, cfg.network.port);

        if self.session.is_some() {
            self.stop_session("switching to a new peer").await;
        }

        let password = Secret::generate()?;
        let username = cfg.security.username.clone();

        let mut wayvnc =
            Wayvnc::spawn(&self.runtime_dir, &username, &password, &self.identity).await?;

        let listener = match gate::bind(listen).await {
            Ok(l) => l,
            Err(e) => {
                // No listener means no session; do not leave wayvnc running
                // with a live password file.
                wayvnc.shutdown().await;
                return Err(e);
            }
        };

        let vnc_socket = wayvnc.vnc_socket.clone();
        let (revoker, cancel) = Revoker::new();

        // The supervisor task owns the child so the event loop can learn about
        // an unexpected exit without holding a mutable borrow across awaits.
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let (done_tx, done_rx) = oneshot::channel::<()>();
        let events = self.events.clone();
        tokio::spawn(async move {
            tokio::select! {
                status = wayvnc.wait() => {
                    let text = match status {
                        Ok(s) => s.to_string(),
                        Err(e) => format!("wait failed: {e}"),
                    };
                    let _ = events.send(Event::WayvncExited(text)).await;
                }
                _ = stop_rx => {}
            }
            wayvnc.shutdown().await;
            let _ = done_tx.send(());
        });

        let (gate_events, mut gate_rx) = mpsc::channel::<GateEvent>(64);
        let forward = self.events.clone();
        tokio::spawn(async move {
            while let Some(ev) = gate_rx.recv().await {
                if forward.send(Event::Gate(ev)).await.is_err() {
                    break;
                }
            }
        });

        tokio::spawn(gate::serve(
            listener,
            peer.cidr,
            vnc_socket,
            cfg.security.max_connections,
            gate_events,
            cancel,
        ));

        let minutes = minutes.unwrap_or(cfg.security.default_session_minutes);
        let expires_at = (minutes > 0).then(|| Instant::now() + Duration::from_secs(minutes * 60));

        let session = ActiveSession {
            peer,
            listen,
            username,
            password,
            fingerprint: self.identity.fingerprint.clone(),
            revoker,
            wayvnc_stop: Some(stop_tx),
            wayvnc_done: done_rx,
            connections: 0,
            expires_at,
        };

        eprintln!(
            "swayshare: listening on {} for {} ({})",
            session.listen, session.peer.name, session.peer.cidr
        );
        notify::session_started(&session.peer.name, &session.listen.to_string());

        let described = session.describe();
        self.session = Some(session);
        Ok(Response::Session(described))
    }

    /// Revoke everything and return to [`State::Off`]. Idempotent.
    async fn stop_session(&mut self, reason: &str) {
        let Some(mut session) = self.session.take() else {
            return;
        };

        // Order matters: cancel live connections first so no frames are
        // delivered while we are tearing wayvnc down.
        session.revoker.revoke();
        if let Some(stop) = session.wayvnc_stop.take() {
            let _ = stop.send(());
        }
        match tokio::time::timeout(SHUTDOWN_GRACE, &mut session.wayvnc_done).await {
            Ok(_) => {}
            Err(_) => eprintln!("swayshare: warning: wayvnc did not confirm shutdown in time"),
        }

        eprintln!("swayshare: sharing off ({reason})");
        notify::session_stopped(reason);
    }

    async fn handle_event(&mut self, event: Event) {
        match event {
            Event::Gate(GateEvent::Accepted { ip, active }) => {
                if let Some(s) = &mut self.session {
                    s.connections = active;
                    eprintln!("swayshare: {ip} connected ({active} active)");
                    notify::client_connected(&s.peer.name, &ip.to_string());
                }
            }
            Event::Gate(GateEvent::Closed { ip, active }) => {
                if let Some(s) = &mut self.session {
                    s.connections = active;
                    eprintln!("swayshare: {ip} disconnected ({active} active)");
                    notify::client_disconnected(&s.peer.name);
                }
            }
            Event::Gate(GateEvent::Rejected { ip, decision }) => {
                let reason = match decision {
                    Decision::DenyAddress => "address not authorised",
                    Decision::DenyLimit => "connection limit reached",
                    Decision::Allow => return,
                };
                eprintln!("swayshare: refused {ip} ({reason})");
                notify::rejected(&ip.to_string(), reason);
            }
            Event::Gate(GateEvent::Failed { error }) => {
                eprintln!("swayshare: gate failure: {error}");
                self.stop_session("the access gate failed").await;
            }
            Event::WayvncExited(status) => {
                eprintln!("swayshare: wayvnc exited unexpectedly ({status})");
                self.stop_session("wayvnc exited").await;
            }
        }
    }
}

impl ActiveSession {
    fn remaining_seconds(&self) -> Option<u64> {
        let at = self.expires_at?;
        Some(at.saturating_duration_since(Instant::now()).as_secs())
    }

    fn describe(&self) -> Session {
        Session {
            peer: self.peer.name.clone(),
            cidr: self.peer.cidr.to_string(),
            address: self.listen.ip().to_string(),
            port: self.listen.port(),
            username: self.username.clone(),
            password: self.password.expose().to_string(),
            fingerprint: self.fingerprint.clone(),
            expires_in_seconds: self.remaining_seconds(),
        }
    }
}

async fn sleep_until_opt(deadline: Option<Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// Bind the control socket, refusing to start a second daemon.
async fn bind_control_socket(path: &Path) -> Result<UnixListener> {
    if path.exists() {
        // A socket that still answers means a live daemon; one that does not
        // is a leftover from a crash and is safe to replace.
        if UnixStream::connect(path).await.is_ok() {
            bail!(
                "a swayshare daemon is already running on {}",
                path.display()
            );
        }
        paths::remove_if_present(path);
    }
    let listener = UnixListener::bind(path)
        .with_context(|| format!("binding control socket {}", path.display()))?;
    // Belt and braces: the containing directory is already 0700.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restricting {}", path.display()))?;
    Ok(listener)
}

/// Accept control connections and forward one request each to the event loop.
async fn accept_calls(listener: UnixListener, calls: mpsc::Sender<Call>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        let calls = calls.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_call(stream, calls).await {
                eprintln!("swayshare: control connection error: {e}");
            }
        });
    }
}

async fn serve_call(stream: UnixStream, calls: mpsc::Sender<Call>) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    if reader.read_line(&mut line).await? == 0 {
        return Ok(());
    }

    let response = match serde_json::from_str::<Request>(line.trim_end()) {
        Ok(req) => {
            let (tx, rx) = oneshot::channel();
            if calls.send((req, tx)).await.is_err() {
                Response::Error {
                    message: "the daemon is shutting down".into(),
                }
            } else {
                rx.await.unwrap_or(Response::Error {
                    message: "the daemon dropped the request".into(),
                })
            }
        }
        Err(e) => Response::Error {
            message: format!("malformed request: {e}"),
        },
    };

    let mut text = serde_json::to_string(&response)?;
    text.push('\n');
    write_half.write_all(text.as_bytes()).await?;
    write_half.flush().await?;
    Ok(())
}

/// Flatten an `anyhow` chain into one line for the IPC reply.
fn format_error(e: &anyhow::Error) -> String {
    let mut parts = vec![e.to_string()];
    parts.extend(e.chain().skip(1).map(|c| c.to_string()));
    parts.join(": ")
}

/// Print a status block for humans.
pub fn render_status(status: &Status) -> String {
    let mut out = String::new();
    match status.state {
        State::Off => out.push_str("Sharing is off\n"),
        State::Listening => out.push_str("Sharing is on - waiting for a connection\n"),
        State::Connected => out.push_str("Sharing is on - someone is connected\n"),
    }
    if let (Some(peer), Some(cidr)) = (&status.peer, &status.cidr) {
        out.push_str(&format!("  Peer:        {peer} ({cidr})\n"));
    }
    if let Some(listen) = &status.listen {
        out.push_str(&format!("  Listening:   {listen}\n"));
    }
    if status.state != State::Off {
        out.push_str(&format!("  Connections: {}\n", status.connections));
    }
    if let Some(secs) = status.expires_in_seconds {
        out.push_str(&format!("  Expires in:  {}\n", invite::humanize(secs)));
    }
    out
}
