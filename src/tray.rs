//! StatusNotifierItem tray applet.
//!
//! The tray is a thin front-end over the same control socket the CLI uses, so
//! there is exactly one implementation of the access rules. It either attaches
//! to a daemon that is already running or hosts one in-process; quitting the
//! tray revokes access either way.
//!
//! Menu callbacks are synchronous (that is ksni's contract), so they only push
//! a [`Command`] onto a queue; a worker task performs the IPC and refreshes
//! the displayed state.

use crate::config::{self, Config, Peer};
use crate::daemon::Daemon;
use crate::icon;
use crate::invite;
use crate::ipc::{self, Request, Response, Session, State, Status};
use crate::paths;
use anyhow::{Context, Result, bail};
use ksni::menu::{StandardItem, SubMenu};
use ksni::{MenuItem, TrayMethods};
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::mpsc;

/// How often the displayed state is refreshed.
///
/// Connection *notifications* come from the daemon the instant they happen;
/// this interval only governs how quickly the icon catches up, where a second
/// is imperceptible.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Work requested by a menu click, handled off the ksni callback thread.
#[derive(Debug)]
enum Command {
    Start(String),
    Stop,
    CopyInvitation,
    OpenConfig,
    Quit,
}

pub struct SwayshareTray {
    status: Status,
    peers: Vec<Peer>,
    /// Set when the last action failed, so the menu can say so.
    last_error: Option<String>,
    commands: mpsc::UnboundedSender<Command>,
}

impl SwayshareTray {
    fn new(commands: mpsc::UnboundedSender<Command>) -> Self {
        Self {
            status: Status::off(),
            peers: Config::load().map(|c| c.peers).unwrap_or_default(),
            last_error: None,
            commands,
        }
    }

    fn sharing(&self) -> bool {
        self.status.state != State::Off
    }

    /// One-line summary used for both the menu header and the tooltip.
    fn summary(&self) -> String {
        match self.status.state {
            State::Off => "Sharing off".to_string(),
            State::Listening => match &self.status.peer {
                Some(peer) => format!("Waiting for {peer}"),
                None => "Waiting for a connection".to_string(),
            },
            State::Connected => match &self.status.peer {
                Some(peer) => format!("{peer} is viewing your screen"),
                None => "Someone is viewing your screen".to_string(),
            },
        }
    }

    fn send(&self, command: Command) {
        // The worker outlives the tray, so a send failure means we are already
        // shutting down and there is nothing useful left to do.
        let _ = self.commands.send(command);
    }
}

impl ksni::Tray for SwayshareTray {
    fn id(&self) -> String {
        "swayshare".into()
    }

    fn title(&self) -> String {
        "swayshare".into()
    }

    /// Left click opens the menu: for this application every action is
    /// consequential enough to deserve being picked explicitly.
    const MENU_ON_ACTIVATE: bool = true;

    fn category(&self) -> ksni::Category {
        ksni::Category::SystemServices
    }

    /// Make the item impossible for a host to hide while sharing is on.
    ///
    /// `Passive` invites hosts to hide the icon, which is fine when nothing is
    /// shared and unacceptable when something is.
    fn status(&self) -> ksni::Status {
        match self.status.state {
            State::Off => ksni::Status::Active,
            State::Listening => ksni::Status::Active,
            State::Connected => ksni::Status::NeedsAttention,
        }
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        vec![icon::render(self.status.state)]
    }

    fn attention_icon_pixmap(&self) -> Vec<ksni::Icon> {
        vec![icon::render(State::Connected)]
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        let mut description = String::new();
        if let Some(listen) = &self.status.listen {
            description.push_str(&format!("Listening on {listen}"));
        }
        if let Some(cidr) = &self.status.cidr {
            description.push_str(&format!("\nAuthorised: {cidr}"));
        }
        if let Some(secs) = self.status.expires_in_seconds {
            description.push_str(&format!("\nExpires in {}", invite::humanize(secs)));
        }
        ksni::ToolTip {
            icon_name: String::new(),
            icon_pixmap: vec![icon::render(self.status.state)],
            title: format!("swayshare - {}", self.summary()),
            description,
        }
    }

    fn watcher_online(&self) {
        eprintln!("swayshare: a tray host is available");
    }

    /// Keep waiting for a tray host rather than giving up.
    ///
    /// The tray is typically autostarted from the Sway config, which can win
    /// the race against the bar. Returning `true` keeps retrying so the icon
    /// appears once the bar is up, instead of the user silently never getting
    /// an indicator.
    fn watcher_offline(&self, reason: ksni::OfflineReason) -> bool {
        eprintln!("swayshare: no tray host yet ({reason:?}); will keep trying");
        true
    }

    /// Reload the peer list just before the menu is drawn, so edits made in the
    /// configuration window or on the CLI show up without restarting the tray.
    fn menu_about_to_show(&mut self) {
        if let Ok(cfg) = Config::load() {
            self.peers = cfg.peers;
        }
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let mut items: Vec<MenuItem<Self>> = Vec::new();

        items.push(
            StandardItem {
                label: self.summary(),
                enabled: false,
                ..Default::default()
            }
            .into(),
        );
        if let Some(secs) = self.status.expires_in_seconds {
            items.push(
                StandardItem {
                    label: format!("Expires in {}", invite::humanize(secs)),
                    enabled: false,
                    ..Default::default()
                }
                .into(),
            );
        }
        if let Some(error) = &self.last_error {
            items.push(
                StandardItem {
                    label: format!("Last error: {error}"),
                    enabled: false,
                    ..Default::default()
                }
                .into(),
            );
        }
        items.push(MenuItem::Separator);

        // Peers live in a submenu so that enabling access is never a single
        // stray click on the top-level menu.
        let active = self.status.peer.clone();
        let mut peer_items: Vec<MenuItem<Self>> = Vec::new();
        if self.peers.is_empty() {
            peer_items.push(
                StandardItem {
                    label: "No peers configured".into(),
                    enabled: false,
                    ..Default::default()
                }
                .into(),
            );
        }
        for peer in &self.peers {
            let name = peer.name.clone();
            let is_active = active.as_deref() == Some(name.as_str());
            let too_broad = config::requires_force(&peer.cidr);
            let label = if is_active {
                format!("{} ({}) - active", peer.name, peer.cidr)
            } else if too_broad {
                format!("{} ({}) - too broad", peer.name, peer.cidr)
            } else {
                format!("{} ({})", peer.name, peer.cidr)
            };
            peer_items.push(
                StandardItem {
                    label,
                    enabled: !is_active && !too_broad,
                    activate: Box::new(move |tray: &mut Self| {
                        tray.send(Command::Start(name.clone()))
                    }),
                    ..Default::default()
                }
                .into(),
            );
        }
        items.push(
            SubMenu {
                label: "Enable access for".into(),
                submenu: peer_items,
                ..Default::default()
            }
            .into(),
        );

        items.push(
            StandardItem {
                label: "Copy invitation".into(),
                enabled: self.sharing(),
                activate: Box::new(|tray: &mut Self| tray.send(Command::CopyInvitation)),
                ..Default::default()
            }
            .into(),
        );
        items.push(
            StandardItem {
                label: "Stop sharing".into(),
                enabled: self.sharing(),
                activate: Box::new(|tray: &mut Self| tray.send(Command::Stop)),
                ..Default::default()
            }
            .into(),
        );

        items.push(MenuItem::Separator);
        items.push(
            StandardItem {
                label: "Configure peers...".into(),
                activate: Box::new(|tray: &mut Self| tray.send(Command::OpenConfig)),
                ..Default::default()
            }
            .into(),
        );
        items.push(
            StandardItem {
                label: "Quit (revokes access)".into(),
                activate: Box::new(|tray: &mut Self| tray.send(Command::Quit)),
                ..Default::default()
            }
            .into(),
        );
        items
    }
}

/// Run the tray until the user quits it.
pub async fn run() -> Result<()> {
    let socket = paths::control_socket()?;

    // Host a daemon only if there is not one already; either way the tray
    // speaks to it over the same socket.
    let hosting = tokio::net::UnixStream::connect(&socket).await.is_err();
    let mut daemon_task: Option<tokio::task::JoinHandle<Result<()>>> = if hosting {
        eprintln!("swayshare: starting a daemon in-process");
        Some(tokio::spawn(Daemon::run()))
    } else {
        eprintln!("swayshare: attaching to the running daemon");
        None
    };

    if hosting {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::net::UnixStream::connect(&socket).await.is_err() {
            if let Some(task) = &mut daemon_task
                && task.is_finished()
            {
                // Surface the daemon's own error rather than a timeout.
                return match task.await {
                    Ok(result) => result.context("the in-process daemon failed to start"),
                    Err(e) => bail!("the in-process daemon panicked: {e}"),
                };
            }
            if tokio::time::Instant::now() >= deadline {
                bail!("the in-process daemon did not come up within 5s");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    let (tx, rx) = mpsc::unbounded_channel();
    let handle = SwayshareTray::new(tx)
        // Do not treat a missing tray host as fatal: the icon should appear
        // when the bar starts, which may be after us. Combined with
        // `watcher_offline` returning true, this makes startup order
        // irrelevant.
        .assume_sni_available(true)
        .spawn()
        .await
        .context("registering the tray icon on the session bus")?;

    // Keep the displayed state fresh.
    let poll_handle = handle.clone();
    let poll_socket = socket.clone();
    let poller = tokio::spawn(async move {
        loop {
            let status = fetch_status(&poll_socket).await;
            let changed = poll_handle
                .update(move |tray: &mut SwayshareTray| {
                    let changed = tray.status.state != status.state;
                    tray.status = status;
                    changed
                })
                .await;
            // `None` means the tray is gone, so there is nothing left to poll.
            if changed.is_none() {
                break;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    });

    // The tray is only meaningful while a daemon is there to control, so a
    // daemon that exits for any reason - `swayshare quit` from a terminal, a
    // signal, a startup failure - takes the tray with it. Otherwise the icon
    // would linger, reporting "off" because nothing is answering, and a user
    // could click "Enable access" and get a confusing error.
    let quit_reason = match daemon_task.take() {
        Some(mut task) => {
            let reason = tokio::select! {
                reason = serve_commands(rx, handle.clone(), socket.clone()) => reason,
                result = &mut task => {
                    if let Ok(Err(e)) = result {
                        eprintln!("swayshare: the daemon stopped: {e:#}");
                    }
                    QuitReason::DaemonGone
                }
            };
            if !matches!(reason, QuitReason::DaemonGone) {
                // Let the daemon finish erasing the session before we exit.
                let _ = tokio::time::timeout(Duration::from_secs(6), task).await;
            }
            reason
        }
        None => serve_commands(rx, handle.clone(), socket.clone()).await,
    };
    poller.abort();

    match quit_reason {
        QuitReason::UserQuit => eprintln!("swayshare: tray exiting, access revoked"),
        QuitReason::DaemonGone => eprintln!("swayshare: daemon gone, tray exiting"),
        QuitReason::ChannelClosed => eprintln!("swayshare: tray command channel closed"),
    }

    handle.shutdown();
    Ok(())
}

enum QuitReason {
    /// The user picked Quit from the menu.
    UserQuit,
    /// The daemon this tray was hosting exited.
    DaemonGone,
    ChannelClosed,
}

/// Perform queued menu actions. Returns when the user asks to quit.
async fn serve_commands(
    mut rx: mpsc::UnboundedReceiver<Command>,
    handle: ksni::Handle<SwayshareTray>,
    socket: PathBuf,
) -> QuitReason {
    while let Some(command) = rx.recv().await {
        match command {
            Command::Quit => {
                // Revoke before leaving, and take the daemon with us: an
                // invisible daemon that can still share would be worse than
                // no tray at all.
                if let Err(e) = ipc::request(&socket, &Request::Shutdown).await {
                    eprintln!("swayshare: could not shut the daemon down: {e:#}");
                }
                return QuitReason::UserQuit;
            }
            Command::Start(peer) => {
                let result = request_session(&socket, &peer).await;
                report(&handle, result.map(|_| ())).await;
            }
            Command::Stop => {
                let result = ipc::request(&socket, &Request::Stop)
                    .await
                    .and_then(ipc::expect_ok)
                    .map(|_| ());
                report(&handle, result).await;
            }
            Command::CopyInvitation => {
                let result = match ipc::request(&socket, &Request::Invite)
                    .await
                    .and_then(ipc::expect_ok)
                {
                    Ok(Response::Session(session)) => copy_to_clipboard(&invite::render(&session)),
                    Ok(other) => Err(anyhow::anyhow!("unexpected reply: {other:?}")),
                    Err(e) => Err(e),
                };
                report(&handle, result).await;
            }
            Command::OpenConfig => {
                report(&handle, open_config_window()).await;
            }
        }
        refresh(&handle, &socket).await;
    }
    QuitReason::ChannelClosed
}

async fn request_session(socket: &std::path::Path, peer: &str) -> Result<Session> {
    let req = Request::Start {
        peer: peer.to_string(),
        minutes: None,
    };
    match ipc::expect_ok(ipc::request(socket, &req).await?)? {
        Response::Session(session) => Ok(session),
        other => bail!("unexpected reply: {other:?}"),
    }
}

/// Record the outcome of an action so the menu can show it.
async fn report(handle: &ksni::Handle<SwayshareTray>, result: Result<()>) {
    let message = match result {
        Ok(()) => None,
        Err(e) => {
            eprintln!("swayshare: {e:#}");
            Some(format!("{e:#}"))
        }
    };
    handle
        .update(move |tray: &mut SwayshareTray| tray.last_error = message)
        .await;
}

async fn refresh(handle: &ksni::Handle<SwayshareTray>, socket: &std::path::Path) {
    let status = fetch_status(socket).await;
    handle
        .update(move |tray: &mut SwayshareTray| tray.status = status)
        .await;
}

/// Ask the daemon for its state, treating an unreachable daemon as "off".
async fn fetch_status(socket: &std::path::Path) -> Status {
    match ipc::request(socket, &Request::Status)
        .await
        .and_then(ipc::expect_ok)
    {
        Ok(Response::Status(status)) => status,
        _ => Status::off(),
    }
}

/// Put the invitation on the Wayland clipboard via `wl-copy`.
fn copy_to_clipboard(text: &str) -> Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new("wl-copy")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!("wl-copy not found; install wl-clipboard to copy invitations")
            } else {
                anyhow::Error::new(e).context("running wl-copy")
            }
        })?;
    child
        .stdin
        .as_mut()
        .context("wl-copy stdin was not available")?
        .write_all(text.as_bytes())
        .context("writing the invitation to wl-copy")?;
    let status = child.wait().context("waiting for wl-copy")?;
    if !status.success() {
        bail!("wl-copy exited with {status}");
    }
    Ok(())
}

/// Launch the configuration window as a separate process.
///
/// Keeping it out of this process is what makes "closing the window leaves the
/// tray running" trivially true, and keeps GTK out of the daemon's address
/// space.
fn open_config_window() -> Result<()> {
    use std::os::unix::process::CommandExt;

    let exe = std::env::current_exe().context("locating the swayshare executable")?;
    std::process::Command::new(exe)
        .arg("gui")
        .stdin(std::process::Stdio::null())
        .process_group(0)
        .spawn()
        .context("starting the configuration window")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::IpNet;

    fn tray_with(status: Status, peers: &[(&str, &str)]) -> SwayshareTray {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut tray = SwayshareTray::new(tx);
        tray.status = status;
        tray.peers = peers
            .iter()
            .map(|(name, cidr)| Peer {
                name: (*name).to_string(),
                cidr: cidr.parse::<IpNet>().unwrap(),
            })
            .collect();
        tray
    }

    fn active_status(state: State, peer: &str) -> Status {
        Status {
            state,
            peer: Some(peer.to_string()),
            cidr: Some("10.0.0.3/32".into()),
            listen: Some("10.0.0.10:5900".into()),
            connections: if state == State::Connected { 1 } else { 0 },
            expires_in_seconds: Some(1800),
        }
    }

    /// Flatten the menu to (label, enabled) pairs, descending into submenus.
    fn labels(tray: &SwayshareTray) -> Vec<(String, bool)> {
        fn walk(items: Vec<MenuItem<SwayshareTray>>, out: &mut Vec<(String, bool)>) {
            for item in items {
                match item {
                    MenuItem::Standard(s) => out.push((s.label.clone(), s.enabled)),
                    MenuItem::SubMenu(s) => {
                        out.push((s.label.clone(), s.enabled));
                        walk(s.submenu, out);
                    }
                    _ => {}
                }
            }
        }
        let mut out = Vec::new();
        walk(ksni::Tray::menu(tray), &mut out);
        out
    }

    fn find<'a>(items: &'a [(String, bool)], needle: &str) -> Option<&'a (String, bool)> {
        items.iter().find(|(label, _)| label.contains(needle))
    }

    /// Find a peer entry specifically.
    ///
    /// Plain substring matching is not enough: the status header also contains
    /// the active peer's name, and it is always disabled.
    fn find_peer<'a>(items: &'a [(String, bool)], name: &str) -> &'a (String, bool) {
        let prefix = format!("{name} (");
        items
            .iter()
            .find(|(label, _)| label.starts_with(&prefix))
            .unwrap_or_else(|| panic!("no peer entry for {name} in {items:?}"))
    }

    #[test]
    fn off_state_offers_no_stop_or_invitation() {
        let tray = tray_with(Status::off(), &[("mike", "10.0.0.3/32")]);
        let items = labels(&tray);
        assert!(!find(&items, "Sharing off").unwrap().1);
        assert!(
            !find(&items, "Stop sharing").unwrap().1,
            "stop must be disabled when nothing is shared"
        );
        assert!(!find(&items, "Copy invitation").unwrap().1);
        assert!(find_peer(&items, "mike").1, "mike should be startable");
    }

    #[test]
    fn active_state_enables_stop_and_marks_the_active_peer() {
        let tray = tray_with(
            active_status(State::Listening, "mike"),
            &[("mike", "10.0.0.3/32"), ("jane", "10.0.0.4/32")],
        );
        let items = labels(&tray);
        assert!(find(&items, "Waiting for mike").is_some());
        assert!(find(&items, "Stop sharing").unwrap().1);
        assert!(find(&items, "Copy invitation").unwrap().1);

        let mike = find_peer(&items, "mike");
        assert!(
            mike.0.contains("active"),
            "the active peer should be labelled: {}",
            mike.0
        );
        assert!(!mike.1, "re-selecting the active peer is a no-op");
        assert!(
            find_peer(&items, "jane").1,
            "switching peers stays available"
        );
    }

    #[test]
    fn connected_state_says_who_is_watching() {
        let tray = tray_with(active_status(State::Connected, "mike"), &[]);
        assert_eq!(tray.summary(), "mike is viewing your screen");
        assert!(find(&labels(&tray), "mike is viewing your screen").is_some());
    }

    #[test]
    fn a_too_broad_peer_cannot_be_started_from_the_menu() {
        let tray = tray_with(Status::off(), &[("world", "10.0.0.0/8")]);
        let items = labels(&tray);
        let world = find_peer(&items, "world");
        assert!(world.0.contains("too broad"), "got: {}", world.0);
        assert!(!world.1, "the daemon would refuse it; do not offer it");
    }

    #[test]
    fn an_empty_peer_list_is_explained_rather_than_blank() {
        let tray = tray_with(Status::off(), &[]);
        assert!(find(&labels(&tray), "No peers configured").is_some());
    }

    #[test]
    fn quit_is_always_available_and_warns_about_revocation() {
        for status in [Status::off(), active_status(State::Connected, "mike")] {
            let tray = tray_with(status, &[]);
            let items = labels(&tray);
            let quit = find(&items, "Quit").unwrap();
            assert!(quit.1);
            assert!(
                quit.0.contains("revokes"),
                "the consequence should be stated"
            );
        }
    }

    #[test]
    fn the_item_demands_attention_only_while_someone_is_connected() {
        use ksni::Tray;
        assert!(matches!(
            tray_with(Status::off(), &[]).status(),
            ksni::Status::Active
        ));
        assert!(matches!(
            tray_with(active_status(State::Listening, "mike"), &[]).status(),
            ksni::Status::Active
        ));
        assert!(matches!(
            tray_with(active_status(State::Connected, "mike"), &[]).status(),
            ksni::Status::NeedsAttention
        ));
    }

    #[test]
    fn the_icon_tracks_the_state() {
        use ksni::Tray;
        let off = tray_with(Status::off(), &[]).icon_pixmap();
        let connected = tray_with(active_status(State::Connected, "mike"), &[]).icon_pixmap();
        assert_eq!(off.len(), 1);
        assert_ne!(
            off[0].data, connected[0].data,
            "the icon must change with the state"
        );
    }

    #[test]
    fn menu_clicks_are_queued_rather_than_blocking() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut tray = SwayshareTray::new(tx);
        tray.peers = vec![Peer {
            name: "mike".into(),
            cidr: "10.0.0.3/32".parse().unwrap(),
        }];

        // Drive the real menu callback for the peer entry.
        let items = ksni::Tray::menu(&tray);
        let mut activated = false;
        for item in items {
            if let MenuItem::SubMenu(sub) = item {
                for entry in sub.submenu {
                    if let MenuItem::Standard(s) = entry
                        && s.label.contains("mike")
                    {
                        (s.activate)(&mut tray);
                        activated = true;
                    }
                }
            }
        }
        assert!(activated, "expected to find the peer entry");
        match rx
            .try_recv()
            .expect("the click should have queued a command")
        {
            Command::Start(peer) => assert_eq!(peer, "mike"),
            other => panic!("unexpected command: {other:?}"),
        }
    }
}
