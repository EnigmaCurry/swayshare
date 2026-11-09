//! Control protocol between the CLI and the daemon.
//!
//! Newline-delimited JSON over a Unix socket in the 0700 runtime directory.
//! The socket is the daemon's only control surface, so filesystem permissions
//! are what keep other users from enabling sharing.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// What the authorised peer is allowed to do once connected.
///
/// Chosen when access is granted and fixed for the life of the session.
/// wayvnc takes `--disable-input` at startup and offers no way to change it
/// afterwards, so a mid-session switch would mean restarting wayvnc and
/// dropping the peer's connection. Rather than ship a toggle that
/// disconnects, the choice is made up front.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccessMode {
    /// The peer's keyboard and pointer are injected into your session.
    #[default]
    Control,
    /// Frames go out; nothing comes back in.
    ViewOnly,
}

impl AccessMode {
    pub fn is_view_only(self) -> bool {
        matches!(self, AccessMode::ViewOnly)
    }

    /// Short phrase for menus and status lines.
    pub fn label(self) -> &'static str {
        match self {
            AccessMode::Control => "full control",
            AccessMode::ViewOnly => "view only",
        }
    }
}

impl std::fmt::Display for AccessMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            AccessMode::Control => "control",
            AccessMode::ViewOnly => "view-only",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "kebab-case")]
pub enum Request {
    Status,
    Start {
        peer: String,
        /// Session length in minutes; `Some(0)` means no expiry.
        minutes: Option<u64>,
        /// Defaulted so an older client that omits it still means "control",
        /// which is what it would have got before this field existed.
        #[serde(default)]
        mode: AccessMode,
    },
    Stop,
    /// Re-print the invitation for the running session.
    Invite,
    /// Revoke access and exit the daemon.
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Response {
    Status(Status),
    Session(Session),
    Ok,
    Error { message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    /// No listener bound. The only state the daemon starts in.
    Off,
    /// Gate bound, one peer authorised, nobody connected yet.
    Listening,
    /// A remote peer has opened a connection but has not yet passed the
    /// password. Nothing is on their screen and nothing is injected until
    /// they authenticate; this is also what a port scan or a failed attempt
    /// looks like.
    Connected,
    /// A remote peer has authenticated: they can now see the screen, and - in
    /// control mode - drive the keyboard and pointer. This is the state that
    /// means someone is actually in.
    Authenticated,
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            State::Off => f.write_str("off"),
            State::Listening => f.write_str("listening"),
            State::Connected => f.write_str("connected"),
            State::Authenticated => f.write_str("authenticated"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub state: State,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    pub connections: usize,
    /// How many of `connections` have completed authentication. Defaulted so
    /// an older daemon that never sent the field still deserialises.
    #[serde(default)]
    pub authenticated: usize,
    /// `None` only when nothing is shared.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<AccessMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in_seconds: Option<u64>,
}

impl Status {
    pub fn off() -> Self {
        Self {
            state: State::Off,
            peer: None,
            cidr: None,
            listen: None,
            connections: 0,
            authenticated: 0,
            mode: None,
            expires_in_seconds: None,
        }
    }
}

/// Everything the remote peer needs. Carries the plaintext password, so it is
/// only ever sent back over the private control socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub peer: String,
    pub cidr: String,
    pub address: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub fingerprint: String,
    pub mode: AccessMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in_seconds: Option<u64>,
}

/// Send one request to the daemon and read its reply.
pub async fn request(socket: &Path, req: &Request) -> Result<Response> {
    let stream = UnixStream::connect(socket)
        .await
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                anyhow::anyhow!("the swayshare daemon is not running (try: swayshare daemon)")
            }
            _ => anyhow::Error::new(e).context(format!("connecting to {}", socket.display())),
        })?;

    let (read_half, mut write_half) = stream.into_split();
    let line = serde_json::to_string(req).context("encoding request")?;
    write_half.write_all(line.as_bytes()).await?;
    write_half.write_all(b"\n").await?;
    write_half.flush().await?;

    let mut reader = BufReader::new(read_half);
    let mut buf = String::new();
    let n = reader.read_line(&mut buf).await.context("reading reply")?;
    if n == 0 {
        bail!("the daemon closed the connection without replying");
    }
    serde_json::from_str(buf.trim_end()).context("decoding reply")
}

/// Synchronous client, for callers that have no tokio runtime.
///
/// The configuration window runs a GTK main loop rather than a reactor, so it
/// talks to the daemon from worker threads using plain blocking sockets.
pub mod blocking {
    use super::{Request, Response};
    use anyhow::{Context, Result, bail};
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::time::Duration;

    /// Generous enough to cover a `Start` that waits on wayvnc coming up.
    const TIMEOUT: Duration = Duration::from_secs(30);

    pub fn request(socket: &Path, req: &Request) -> Result<Response> {
        let mut stream = UnixStream::connect(socket).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                anyhow::anyhow!("the swayshare daemon is not running (try: swayshare daemon)")
            }
            _ => anyhow::Error::new(e).context(format!("connecting to {}", socket.display())),
        })?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;

        let line = serde_json::to_string(req).context("encoding request")?;
        stream.write_all(line.as_bytes())?;
        stream.write_all(b"\n")?;
        stream.flush()?;

        let mut reader = BufReader::new(stream);
        let mut buf = String::new();
        if reader.read_line(&mut buf).context("reading reply")? == 0 {
            bail!("the daemon closed the connection without replying");
        }
        serde_json::from_str(buf.trim_end()).context("decoding reply")
    }
}

/// Unwrap a response, turning the error variant into an `Err`.
pub fn expect_ok(resp: Response) -> Result<Response> {
    match resp {
        Response::Error { message } => bail!("{message}"),
        other => Ok(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip() {
        for req in [
            Request::Status,
            Request::Start {
                peer: "mike".into(),
                minutes: Some(30),
                mode: AccessMode::Control,
            },
            Request::Start {
                peer: "mike".into(),
                minutes: None,
                mode: AccessMode::ViewOnly,
            },
            Request::Stop,
            Request::Invite,
            Request::Shutdown,
        ] {
            let text = serde_json::to_string(&req).unwrap();
            assert!(!text.contains('\n'), "requests must stay on one line");
            let back: Request = serde_json::from_str(&text).unwrap();
            assert_eq!(format!("{req:?}"), format!("{back:?}"));
        }
    }

    #[test]
    fn a_start_without_a_mode_defaults_to_control() {
        // An older client that does not know about view-only gets exactly the
        // behaviour it would have got before the field existed.
        let req: Request =
            serde_json::from_str(r#"{"command":"start","peer":"mike","minutes":30}"#).unwrap();
        match req {
            Request::Start { mode, .. } => assert_eq!(mode, AccessMode::Control),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn the_mode_survives_the_wire() {
        let req = Request::Start {
            peer: "mike".into(),
            minutes: None,
            mode: AccessMode::ViewOnly,
        };
        let text = serde_json::to_string(&req).unwrap();
        assert!(text.contains("view-only"), "got: {text}");
        match serde_json::from_str::<Request>(&text).unwrap() {
            Request::Start { mode, .. } => assert_eq!(mode, AccessMode::ViewOnly),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn status_off_serialises_without_session_fields() {
        let text = serde_json::to_string(&Status::off()).unwrap();
        assert!(text.contains("\"state\":\"off\""));
        assert!(!text.contains("peer"));
        assert!(!text.contains("listen"));
    }

    #[test]
    fn responses_round_trip() {
        let resp = Response::Status(Status {
            state: State::Connected,
            peer: Some("mike".into()),
            cidr: Some("10.0.0.3/32".into()),
            listen: Some("10.0.0.10:5900".into()),
            connections: 1,
            authenticated: 1,
            mode: Some(AccessMode::ViewOnly),
            expires_in_seconds: Some(1800),
        });
        let back: Response = serde_json::from_str(&serde_json::to_string(&resp).unwrap()).unwrap();
        match back {
            Response::Status(s) => {
                assert_eq!(s.state, State::Connected);
                assert_eq!(s.connections, 1);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn error_responses_become_errors() {
        assert!(
            expect_ok(Response::Error {
                message: "nope".into()
            })
            .is_err()
        );
        assert!(expect_ok(Response::Ok).is_ok());
    }
}
