//! The long-lived supervisor: state machine, control socket, gate and wayvnc.
//!
//! The daemon starts in [`State::Off`] with no listener bound, and returns to
//! it whenever anything goes wrong. Every transition out of a sharing session
//! closes the listener, drops live connections and erases the session
//! credentials, so the failure mode is always "no access".

use crate::config::{self, Config, Peer};
use crate::gate::{self, GateEvent, Policy, Revoker};
use crate::identity::Identity;
use crate::invite;
use crate::ipc::{AccessMode, Request, Response, Session, State, Status};
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
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;

/// How long to wait for wayvnc to actually be gone before reporting a stop.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// How often to ask wayvnc whether a connected client has authenticated yet.
///
/// Authentication has no event of its own, so the state is discovered by
/// polling `client-list`. Short enough that the "someone is in" notification
/// does not lag perceptibly behind the password being accepted.
const AUTH_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Everything belonging to one sharing session.
///
/// Dropping or stopping this is what revokes access, so nothing here is
/// shared outside the daemon's event loop.
struct ActiveSession {
    peer: Peer,
    listen: SocketAddr,
    /// Fixed for the life of the session; see [`AccessMode`].
    mode: AccessMode,
    username: String,
    /// The current one-time password. Rotated on every disconnect so a secret
    /// read aloud once cannot be reused for a later connection.
    password: Secret,
    /// How many words a freshly minted password should have.
    password_words: usize,
    fingerprint: String,
    /// Fires the cancellation that drops every proxied connection.
    revoker: Revoker,
    /// Closing this tells the supervisor task to kill wayvnc.
    wayvnc_stop: Option<oneshot::Sender<()>>,
    /// Resolves once wayvnc is confirmed dead and its config file erased.
    wayvnc_done: oneshot::Receiver<()>,
    /// Tells the auth monitor whether it is worth polling wayvnc right now.
    /// Only true while a connected client has not yet authenticated, so an
    /// idle or fully-authenticated session makes no control-socket traffic.
    poll: watch::Sender<bool>,
    connections: usize,
    /// How many connected clients have passed authentication. Distinct from
    /// `connections`, which counts bare TCP connections the moment they are
    /// admitted - before any password is checked.
    authenticated: usize,
    /// Whether the "someone is in" notification has fired for the current
    /// occupant, so the matching "they are gone" notification fires once too.
    announced_auth: bool,
    expires_at: Option<Instant>,
}

/// Ownership handles for one supervised wayvnc subprocess.
struct WayvncHandles {
    /// Send to kill wayvnc now.
    stop: oneshot::Sender<()>,
    /// Resolves once the kill completed and the password file was erased.
    done: oneshot::Receiver<()>,
    /// Stable path the gate forwards admitted connections to.
    vnc_socket: PathBuf,
    /// Stable path the auth monitor queries.
    control_socket: PathBuf,
}

/// Internal events folded into the daemon's single event loop.
enum Event {
    Gate(GateEvent),
    /// The authenticated-client count reported by the wayvnc monitor changed.
    Auth {
        authenticated: usize,
    },
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

/// How long the shutdown path waits for a reply to reach the client.
const REPLY_FLUSH_GRACE: Duration = Duration::from_secs(2);

/// A control-socket request, the channel its reply goes back on, and an
/// acknowledgement that the reply actually reached the socket.
struct Call {
    request: Request,
    reply: oneshot::Sender<Response>,
    /// Resolves once [`serve_call`] has flushed the reply.
    ///
    /// Only the shutdown path waits on this, and it has to: the reply is
    /// written by a separate task, and returning from `run` drops the tokio
    /// runtime, which aborts that task. Without the wait, a shutdown that
    /// succeeded reports itself to the client as a dropped connection.
    written: oneshot::Receiver<()>,
}

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
                Some(call) = calls_rx.recv() => {
                    let resp = daemon.handle(call.request).await;
                    let _ = call.reply.send(resp);
                    if daemon.shutdown_requested {
                        // Let the reply reach the client before the runtime
                        // goes away underneath the task that writes it.
                        let _ =
                            tokio::time::timeout(REPLY_FLUSH_GRACE, call.written).await;
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
            Request::Start {
                peer,
                minutes,
                mode,
            } => self.start_session(&peer, minutes, mode).await,
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
                // Authentication outranks a bare connection: a connected peer
                // who has not yet passed the password is not "in" yet.
                state: if s.authenticated > 0 {
                    State::Authenticated
                } else if s.connections > 0 {
                    State::Connected
                } else {
                    State::Listening
                },
                peer: Some(s.peer.name.clone()),
                cidr: Some(s.peer.cidr.to_string()),
                listen: Some(s.listen.to_string()),
                connections: s.connections,
                authenticated: s.authenticated,
                mode: Some(s.mode),
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
    async fn start_session(
        &mut self,
        peer_name: &str,
        minutes: Option<u64>,
        mode: AccessMode,
    ) -> Result<Response> {
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

        // A fresh one-time password the owner reads aloud when someone
        // connects; see `rotate_password` for why it is replaced on disconnect.
        let password = Secret::passphrase(cfg.security.password_words)?;
        let username = cfg.security.username.clone();

        let handles = self.spawn_wayvnc(&username, &password, mode).await?;

        let listener = match gate::bind(listen).await {
            Ok(l) => l,
            Err(e) => {
                // No listener means no session; do not leave wayvnc running
                // with a live password file.
                let _ = handles.stop.send(());
                let _ = tokio::time::timeout(SHUTDOWN_GRACE, handles.done).await;
                return Err(e);
            }
        };

        let vnc_socket = handles.vnc_socket.clone();
        let control_socket = handles.control_socket.clone();
        let (revoker, cancel) = Revoker::new();

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
            Policy {
                allow: peer.cidr,
                // Binding to the interface's address is not enough on its own;
                // see `Policy::required_interface`.
                required_interface: cfg.network.interface.clone(),
                max_connections: cfg.security.max_connections,
            },
            vnc_socket,
            gate_events,
            cancel.clone(),
        ));

        // Watch wayvnc for authentication. The gate can only see TCP connects;
        // whether a connected peer has actually passed the password lives in
        // wayvnc, which has no event for it - hence the poll. Shares the
        // session's cancellation, so it stops the instant access is revoked,
        // and only polls while `poll_rx` says there is something to learn.
        let (poll_tx, poll_rx) = watch::channel(false);
        tokio::spawn(monitor_auth(
            control_socket,
            self.events.clone(),
            cancel,
            poll_rx,
        ));

        let minutes = minutes.unwrap_or(cfg.security.default_session_minutes);
        let expires_at = (minutes > 0).then(|| Instant::now() + Duration::from_secs(minutes * 60));

        let session = ActiveSession {
            peer,
            listen,
            mode,
            username,
            password,
            password_words: cfg.security.password_words,
            fingerprint: self.identity.fingerprint.clone(),
            revoker,
            wayvnc_stop: Some(handles.stop),
            wayvnc_done: handles.done,
            poll: poll_tx,
            connections: 0,
            authenticated: 0,
            announced_auth: false,
            expires_at,
        };

        eprintln!(
            "swayshare: listening on {} for {} ({}, {})",
            session.listen,
            session.peer.name,
            session.peer.cidr,
            session.mode.label()
        );
        notify::session_started(
            &session.peer.name,
            &session.listen.to_string(),
            session.mode,
        );

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

    /// Start wayvnc and the task that supervises it, on the session's fixed
    /// sockets. Shared by the first start and by every password rotation.
    ///
    /// The returned handles own the subprocess's life: send on `stop` to kill
    /// it, and await `done` to know the kill finished and the password file
    /// was erased.
    async fn spawn_wayvnc(
        &self,
        username: &str,
        password: &Secret,
        mode: AccessMode,
    ) -> Result<WayvncHandles> {
        let mut wayvnc =
            Wayvnc::spawn(&self.runtime_dir, username, password, &self.identity, mode).await?;
        let vnc_socket = wayvnc.vnc_socket.clone();
        let control_socket = wayvnc.control_socket.clone();

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

        Ok(WayvncHandles {
            stop: stop_tx,
            done: done_rx,
            vnc_socket,
            control_socket,
        })
    }

    /// Mint a new one-time password and restart wayvnc with it.
    ///
    /// Called after the last client disconnects, while nothing is connected, so
    /// the brief restart disrupts no one. It is what makes each connection need
    /// a freshly spoken secret: the password just used is now dead. wayvnc
    /// comes back on the same sockets, so the gate and auth monitor carry on
    /// unchanged. A failure here fails closed - the session is torn down.
    async fn rotate_password(&mut self) {
        let Some((username, mode, words)) = self
            .session
            .as_ref()
            .map(|s| (s.username.clone(), s.mode, s.password_words))
        else {
            return;
        };

        // Stop the current wayvnc and wait for it to confirm it is gone.
        if let Some(stop) = self.session.as_mut().and_then(|s| s.wayvnc_stop.take()) {
            let _ = stop.send(());
        }
        if let Some(s) = self.session.as_mut() {
            let _ = tokio::time::timeout(SHUTDOWN_GRACE, &mut s.wayvnc_done).await;
        }

        let password = match Secret::passphrase(words) {
            Ok(p) => p,
            Err(e) => {
                self.stop_session(&format!("could not mint a new password: {e}"))
                    .await;
                return;
            }
        };
        match self.spawn_wayvnc(&username, &password, mode).await {
            Ok(handles) => {
                if let Some(s) = self.session.as_mut() {
                    s.password = password;
                    s.wayvnc_stop = Some(handles.stop);
                    s.wayvnc_done = handles.done;
                }
                eprintln!("swayshare: minted a fresh password for the next connection");
            }
            Err(e) => {
                self.stop_session(&format!(
                    "wayvnc could not restart to rotate the password: {e}"
                ))
                .await;
            }
        }
    }

    async fn handle_event(&mut self, event: Event) {
        match event {
            Event::Gate(GateEvent::Accepted { ip, active }) => {
                if let Some(s) = &mut self.session {
                    s.connections = active;
                    // A TCP connection, not yet a session: no screen is shared
                    // and no input is injected until the password is accepted.
                    eprintln!("swayshare: {ip} connected, awaiting authentication ({active} open)");
                    // The popup the owner reads down the phone: who is
                    // connecting, and the one-time password to let them in.
                    notify::client_connecting(&s.peer.name, &ip.to_string(), s.password.expose());
                    // There is now a connection we have not seen authenticate,
                    // so the monitor has a reason to poll.
                    s.update_polling();
                }
            }
            Event::Gate(GateEvent::Closed { ip, active }) => {
                let mut rotate = false;
                if let Some(s) = &mut self.session {
                    s.connections = active;
                    eprintln!("swayshare: {ip} disconnected ({active} open)");
                    // No connections left means nobody is authenticated either;
                    // announce their departure if we announced their arrival.
                    if active == 0 {
                        s.authenticated = 0;
                        if s.announced_auth {
                            s.announced_auth = false;
                            notify::client_left(&s.peer.name, s.mode);
                        }
                        // Burn the password they used; the next connection
                        // gets a fresh one the owner must read anew.
                        rotate = true;
                    }
                    s.update_polling();
                }
                if rotate {
                    self.rotate_password().await;
                }
            }
            Event::Auth { authenticated } => {
                if let Some(s) = &mut self.session {
                    s.authenticated = authenticated;
                    // Once every connection has authenticated there is nothing
                    // left to watch for, so the monitor can go quiet again.
                    s.update_polling();
                    if authenticated > 0 && !s.announced_auth {
                        // The rising edge: someone is now actually in. This is
                        // the alert that matters, and the only one that names
                        // what they can do.
                        s.announced_auth = true;
                        eprintln!(
                            "swayshare: {} authenticated ({})",
                            s.peer.name,
                            s.mode.label()
                        );
                        notify::client_authenticated(&s.peer.name, s.mode);
                    } else if authenticated == 0 && s.announced_auth {
                        s.announced_auth = false;
                        eprintln!("swayshare: {} is no longer authenticated", s.peer.name);
                        notify::client_left(&s.peer.name, s.mode);
                    }
                }
            }
            Event::Gate(GateEvent::Rejected { ip, decision }) => {
                if decision == gate::Decision::Allow {
                    return;
                }
                let reason = decision.reason();
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

    /// Enable the auth monitor only while a connection has yet to authenticate.
    ///
    /// With nobody connected, or everyone connected already authenticated,
    /// there is nothing to learn from wayvnc, so the monitor should not keep
    /// hammering the control socket (which logs every query).
    fn update_polling(&self) {
        let needed = self.connections > self.authenticated;
        self.poll.send_if_modified(|cur| {
            if *cur != needed {
                *cur = needed;
                true
            } else {
                false
            }
        });
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
            mode: self.mode,
            expires_in_seconds: self.remaining_seconds(),
        }
    }
}

/// Poll wayvnc for the authenticated-client count until access is revoked.
///
/// Authentication is the one piece of session state wayvnc exposes only on
/// request, not as an event, so it is discovered by asking `client-list` on a
/// timer. To avoid spamming wayvnc's control socket (and its log), the daemon
/// gates polling through `poll`: it is only on while a connection has yet to
/// authenticate, so a granted-but-empty or fully-authenticated session is
/// silent. Only changes are forwarded. A failed query is swallowed and
/// retried: a transient hiccup talking to the control socket must not be
/// mistaken for "nobody is authenticated", which would wrongly clear the
/// on-screen warning.
async fn monitor_auth(
    control_socket: PathBuf,
    events: mpsc::Sender<Event>,
    mut cancel: watch::Receiver<bool>,
    mut poll: watch::Receiver<bool>,
) {
    let mut last: Option<usize> = None;
    loop {
        // Idle until the daemon says a connection is waiting to authenticate.
        while !*poll.borrow_and_update() {
            tokio::select! {
                biased;
                _ = cancel.changed() => return,
                changed = poll.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
            }
        }

        // A fresh interval fires its first tick immediately, so a connection is
        // checked promptly rather than up to one period later.
        let mut tick = tokio::time::interval(AUTH_POLL_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                _ = cancel.changed() => return,
                changed = poll.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    if !*poll.borrow_and_update() {
                        break; // nothing left to watch; go back to idle
                    }
                }
                _ = tick.tick() => {
                    match crate::wayvnc::authenticated_clients(&control_socket).await {
                        Ok(n) if last != Some(n) => {
                            last = Some(n);
                            if events.send(Event::Auth { authenticated: n }).await.is_err() {
                                return;
                            }
                        }
                        Ok(_) => {}
                        Err(_) => {}
                    }
                }
            }
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

    // Handed to the daemon so the shutdown path can tell when this reply has
    // been written; dropping it without sending resolves the wait too.
    let (written_tx, written_rx) = oneshot::channel();

    let response = match serde_json::from_str::<Request>(line.trim_end()) {
        Ok(req) => {
            let (tx, rx) = oneshot::channel();
            let call = Call {
                request: req,
                reply: tx,
                written: written_rx,
            };
            if calls.send(call).await.is_err() {
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
    let _ = written_tx.send(());
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
        State::Off => out.push_str("Remote access is off\n"),
        State::Listening => out.push_str("Access granted - waiting for them to connect\n"),
        State::Connected => {
            out.push_str("Someone has connected - waiting for them to authenticate\n")
        }
        State::Authenticated => match status.mode {
            Some(AccessMode::ViewOnly) => out.push_str("Someone is watching your screen\n"),
            _ => out.push_str("Someone is controlling your desktop\n"),
        },
    }
    if let (Some(peer), Some(cidr)) = (&status.peer, &status.cidr) {
        out.push_str(&format!("  Peer:        {peer} ({cidr})\n"));
    }
    if let Some(mode) = status.mode {
        out.push_str(&format!("  Access:      {}\n", mode.label()));
    }
    if let Some(listen) = &status.listen {
        out.push_str(&format!("  Listening:   {listen}\n"));
    }
    if status.state != State::Off {
        out.push_str(&format!(
            "  Connections: {} ({} authenticated)\n",
            status.connections, status.authenticated
        ));
    }
    if let Some(secs) = status.expires_in_seconds {
        out.push_str(&format!("  Expires in:  {}\n", invite::humanize(secs)));
    }
    out
}
