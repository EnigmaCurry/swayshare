//! State of the configuration window, with no GTK in it.
//!
//! The window's behaviour lives here as a plain state machine: [`reduce`]
//! folds an [`Event`] into the [`Model`] and returns the [`Effect`]s the shell
//! must carry out. Rendering is a separate step that reads the model and
//! nothing else.
//!
//! The split exists for two reasons. It makes the window's behaviour testable
//! without a display - a headless wlroots seat has no input devices, so the
//! GTK layer cannot be driven by synthetic clicks and nothing above it could
//! previously be asserted on. And it removes a class of bug: the old code
//! recomputed button sensitivity in a helper called from five places, and read
//! widget state back out to decide other widget state, so a missed call site
//! meant a silently wrong window.
//!
//! This module is deliberately **not** behind the `gui` feature. It is pure
//! Rust, so its tests run even in a build without GTK.

use crate::config::{self, Peer};
use crate::invite;
use crate::ipc::{AccessMode, Request, Session, State, Status};
use ipnet::IpNet;

/// A line of feedback shown under the controls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub text: String,
    pub is_error: bool,
}

impl Message {
    fn info(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            is_error: false,
        }
    }
    fn error(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            is_error: true,
        }
    }
}

/// Everything the window displays.
#[derive(Debug, Clone)]
pub struct Model {
    pub status: Status,
    pub peers: Vec<Peer>,
    /// Index into `peers`, not a widget row: the two are kept in step by
    /// [`Event::PeersLoaded`] clamping it.
    pub selected: Option<usize>,
    /// The session whose invitation is on display, if any.
    pub session: Option<Session>,
    pub minutes: u64,
    pub view_only: bool,
    pub message: Option<Message>,
    /// An invitation request for a session this window did not start is in
    /// flight. Stops one request per poll tick.
    adopting: bool,
}

/// Something that happened: a widget was used, or a worker came back.
#[derive(Debug, Clone)]
pub enum Event {
    // --- from the widgets ---
    SelectionChanged(Option<usize>),
    MinutesChanged(u64),
    ViewOnlyToggled(bool),
    AddClicked { name: String, cidr: String },
    RemoveClicked,
    EnableClicked,
    StopClicked,
    CopyClicked,
    CopyPasswordClicked,
    // --- from workers and the poller ---
    StatusPolled(Status),
    PeersLoaded(Vec<Peer>),
    PeerAdded { name: String, cidr: IpNet },
    PeerRemoved { name: String },
    SessionStarted(Session),
    InvitationFetched { session: Session, copy: bool },
    SessionStopped,
    Failed(String),
}

/// Work for the shell to perform. The model never does I/O itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Send a request to the daemon.
    Send(Request),
    /// Ask the daemon for the running session's invitation. `copy` says
    /// whether the result should also go to the clipboard.
    FetchInvitation {
        copy: bool,
    },
    AddPeer {
        name: String,
        cidr: IpNet,
    },
    RemovePeer {
        name: String,
    },
    ReloadPeers,
    SaveDefaultMinutes(u64),
    CopyToClipboard(String),
    ClearPeerEntries,
}

impl Model {
    pub fn new(peers: Vec<Peer>, minutes: u64) -> Self {
        Self {
            status: Status::off(),
            peers,
            selected: None,
            session: None,
            minutes,
            view_only: false,
            message: None,
            adopting: false,
        }
    }

    // --- derived view state; the renderer reads these and nothing else ---

    pub fn selected_peer(&self) -> Option<&Peer> {
        self.peers.get(self.selected?)
    }

    pub fn sharing(&self) -> bool {
        self.status.state != State::Off
    }

    pub fn can_enable(&self) -> bool {
        self.selected_peer().is_some()
    }

    pub fn can_stop(&self) -> bool {
        self.sharing()
    }

    /// Copying works whenever something is shared: if the invitation is not
    /// cached, the daemon is asked for it.
    pub fn can_copy(&self) -> bool {
        self.sharing()
    }

    pub fn heading(&self) -> &'static str {
        match self.status.state {
            State::Off => "Remote access off",
            State::Listening => "Access granted - waiting for them to connect",
            State::Connected => "Someone connected - waiting for them to authenticate",
            State::Authenticated => match self.status.mode {
                Some(AccessMode::ViewOnly) => "Someone is watching your screen",
                _ => "Someone is controlling your desktop",
            },
        }
    }

    pub fn detail(&self) -> String {
        let mut out = String::new();
        if let (Some(peer), Some(cidr)) = (&self.status.peer, &self.status.cidr) {
            out.push_str(&format!("Authorised: {peer} ({cidr})"));
        }
        if let Some(listen) = &self.status.listen {
            out.push_str(&format!("\nListening on {listen}"));
        }
        if let Some(mode) = self.status.mode {
            out.push_str(&format!("\nAccess: {}", mode.label()));
        }
        if let Some(secs) = self.status.expires_in_seconds {
            out.push_str(&format!("\nExpires in {}", invite::humanize(secs)));
        }
        if out.is_empty() {
            out.push_str("No peer is authorised.");
        }
        out
    }

    /// The one-time password to read aloud, if someone is waiting on it.
    ///
    /// Gated on the state rather than on merely holding a session: the
    /// password is rotated the instant a peer disconnects, so a value from a
    /// previous connection is spent, and showing it would have the owner
    /// dictate something that cannot work.
    pub fn password_to_read(&self) -> Option<&str> {
        match self.status.state {
            State::Connected => self.session.as_ref().map(|s| s.password.as_str()),
            _ => None,
        }
    }

    /// The invitation pane's contents; empty when there is nothing to show.
    pub fn invitation(&self) -> String {
        self.session
            .as_ref()
            .map(invite::render)
            .unwrap_or_default()
    }

    /// One display row per peer: name, range, and the risk note if any.
    pub fn peer_rows(&self) -> Vec<PeerRow<'_>> {
        self.peers
            .iter()
            .map(|peer| PeerRow {
                name: &peer.name,
                cidr: peer.cidr.to_string(),
                note: config::breadth_warning(&peer.cidr).map(|_| {
                    if config::requires_force(&peer.cidr) {
                        "too broad to share"
                    } else {
                        "range, not one host"
                    }
                }),
            })
            .collect()
    }

    fn access_mode(&self) -> AccessMode {
        if self.view_only {
            AccessMode::ViewOnly
        } else {
            AccessMode::Control
        }
    }
}

/// A peer as the list should display it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRow<'a> {
    pub name: &'a str,
    pub cidr: String,
    pub note: Option<&'static str>,
}

/// Fold one event into the model, returning the work the shell must do.
pub fn reduce(model: &mut Model, event: Event) -> Vec<Effect> {
    match event {
        Event::SelectionChanged(index) => {
            model.selected = index.filter(|i| *i < model.peers.len());
            Vec::new()
        }
        Event::MinutesChanged(minutes) => {
            model.minutes = minutes;
            Vec::new()
        }
        Event::ViewOnlyToggled(on) => {
            model.view_only = on;
            Vec::new()
        }

        Event::AddClicked { name, cidr } => add_clicked(model, name, cidr),

        Event::RemoveClicked => match model.selected_peer() {
            Some(peer) => vec![Effect::RemovePeer {
                name: peer.name.clone(),
            }],
            None => {
                model.message = Some(Message::error("Select a peer to remove."));
                Vec::new()
            }
        },

        Event::EnableClicked => enable_clicked(model),

        Event::StopClicked => vec![Effect::Send(Request::Stop)],

        Event::CopyClicked => match &model.session {
            Some(session) => {
                model.message = Some(Message::info("Invitation copied to the clipboard."));
                vec![Effect::CopyToClipboard(invite::render(session))]
            }
            // Not cached: ask the daemon and copy on the way back.
            None => vec![Effect::FetchInvitation { copy: true }],
        },

        Event::CopyPasswordClicked => match model.password_to_read() {
            Some(password) => {
                let password = password.to_string();
                // Said aloud by design, but a chat window is sometimes the
                // only channel there is, and dictating it letter by letter
                // from a screen is where it gets mistyped.
                model.message = Some(Message::info("One-time password copied."));
                vec![Effect::CopyToClipboard(password)]
            }
            // Nobody is waiting, so there is nothing current to copy; saying
            // so beats silently putting a spent secret on the clipboard.
            None => {
                model.message = Some(Message::info(
                    "There is no live password: nobody is waiting to connect.",
                ));
                Vec::new()
            }
        },

        Event::StatusPolled(status) => status_polled(model, status),

        Event::PeersLoaded(peers) => {
            // Hold the selection on the same *peer*, not the same row.
            // Peers are kept sorted by name and can be added or removed from
            // the tray or the CLI while this window is open, so an index taken
            // before the reload can silently come to mean somebody else - and
            // the next click on "Enable access" would hand them the desktop.
            let was = model
                .selected
                .and_then(|i| model.peers.get(i))
                .map(|p| p.name.clone());
            model.peers = peers;
            model.selected = was.and_then(|name| model.peers.iter().position(|p| p.name == name));
            Vec::new()
        }

        Event::PeerAdded { name, cidr } => {
            let note = config::breadth_warning(&cidr)
                .map(|w| format!(" Note: {w}."))
                .unwrap_or_default();
            model.message = Some(Message::info(format!("Added {name} ({cidr}).{note}")));
            vec![Effect::ClearPeerEntries, Effect::ReloadPeers]
        }

        Event::PeerRemoved { name } => {
            // Removing a peer does not revoke a session already running for
            // it; say so rather than let the user assume it did.
            let running_for_them = model
                .status
                .peer
                .as_deref()
                .is_some_and(|active| active == name);
            let caveat = if running_for_them {
                " The session already running for it is unaffected; revoke access to end it."
            } else {
                ""
            };
            model.message = Some(Message::info(format!("Removed {name}.{caveat}")));
            vec![Effect::ReloadPeers]
        }

        Event::SessionStarted(session) => {
            model.message = Some(Message::info(format!(
                "Access enabled for {}.",
                session.peer
            )));
            model.session = Some(session);
            Vec::new()
        }

        Event::InvitationFetched { session, copy } => {
            model.adopting = false;
            let effects = if copy {
                model.message = Some(Message::info("Invitation copied to the clipboard."));
                vec![Effect::CopyToClipboard(invite::render(&session))]
            } else {
                model.message = Some(Message::info(format!(
                    "Showing the session started elsewhere for {}.",
                    session.peer
                )));
                Vec::new()
            };
            model.session = Some(session);
            effects
        }

        Event::SessionStopped => {
            model.session = None;
            model.message = Some(Message::info("Access revoked."));
            Vec::new()
        }

        Event::Failed(text) => {
            // Clear the in-flight flag too: otherwise a failed adoption would
            // wedge it, and the invitation would never be fetched again for
            // the life of the session.
            model.adopting = false;
            model.message = Some(Message::error(text));
            Vec::new()
        }
    }
}

fn add_clicked(model: &mut Model, name: String, cidr: String) -> Vec<Effect> {
    let name = name.trim().to_string();
    let cidr_text = cidr.trim();
    if name.is_empty() || cidr_text.is_empty() {
        model.message = Some(Message::error("Enter both a name and an address."));
        return Vec::new();
    }

    let cidr = match config::parse_cidr(cidr_text) {
        Ok(cidr) => cidr,
        Err(e) => {
            model.message = Some(Message::error(format!("{e:#}")));
            return Vec::new();
        }
    };
    // The same policy the CLI and the daemon apply. Refusing here means the
    // user cannot create a peer that could never be started.
    if config::requires_force(&cidr) {
        let warning = config::breadth_warning(&cidr).unwrap_or_default();
        model.message = Some(Message::error(format!(
            "{warning}. Add it with `swayshare add --force` if you really mean it."
        )));
        return Vec::new();
    }
    vec![Effect::AddPeer { name, cidr }]
}

fn enable_clicked(model: &mut Model) -> Vec<Effect> {
    let Some(peer) = model.selected_peer().cloned() else {
        model.message = Some(Message::error("Select a peer first."));
        return Vec::new();
    };
    let mode = model.access_mode();
    model.message = Some(Message::info(format!(
        "Starting a {} session for {}...",
        mode.label(),
        peer.name
    )));
    vec![
        // Keep the CLI and tray agreeing with whatever was chosen here.
        Effect::SaveDefaultMinutes(model.minutes),
        Effect::Send(Request::Start {
            peer: peer.name,
            minutes: Some(model.minutes),
            mode,
        }),
    ]
}

fn status_polled(model: &mut Model, status: Status) -> Vec<Effect> {
    let previous = model.status.state;
    model.status = status;

    if model.status.state == State::Off {
        model.adopting = false;
        // A session that ended elsewhere must not leave credentials on show.
        model.session = None;
        return Vec::new();
    }

    // Someone has just opened a connection and is waiting to be let in. The
    // password is minted fresh for each connection, so whatever this window
    // is holding belongs to a previous one; fetch the live one before it is
    // put on screen for the owner to read aloud.
    if model.status.state == State::Connected && previous != State::Connected {
        model.adopting = true;
        return vec![Effect::FetchInvitation { copy: false }];
    }

    if model.session.is_none() && !model.adopting {
        // Sharing was enabled from the tray or the CLI. Pull the invitation in
        // so the window is useful whoever started the session; the flag keeps
        // this to one request rather than one per poll.
        model.adopting = true;
        return vec![Effect::FetchInvitation { copy: false }];
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(name: &str, cidr: &str) -> Peer {
        Peer {
            name: name.into(),
            cidr: cidr.parse().unwrap(),
        }
    }

    fn model() -> Model {
        Model::new(
            vec![peer("mike", "10.0.0.3/32"), peer("jane", "10.0.0.4/32")],
            60,
        )
    }

    fn status(state: State, peer: &str, mode: AccessMode) -> Status {
        Status {
            state,
            peer: Some(peer.into()),
            cidr: Some("10.0.0.3/32".into()),
            listen: Some("10.0.0.10:5900".into()),
            connections: if matches!(state, State::Off | State::Listening) {
                0
            } else {
                1
            },
            authenticated: if state == State::Authenticated { 1 } else { 0 },
            mode: Some(mode),
            expires_in_seconds: Some(1800),
        }
    }

    fn session(peer: &str) -> Session {
        Session {
            peer: peer.into(),
            cidr: "10.0.0.3/32".into(),
            address: "10.0.0.10".into(),
            port: 5900,
            username: "support".into(),
            password: "EXAMPLE".into(),
            fingerprint: "AA:BB".into(),
            mode: AccessMode::Control,
            expires_in_seconds: Some(1800),
        }
    }

    fn message(m: &Model) -> String {
        m.message
            .as_ref()
            .map(|x| x.text.clone())
            .unwrap_or_default()
    }

    // --- sensitivity, which used to be recomputed by hand in five places ---

    #[test]
    fn enabling_requires_a_selection() {
        let mut m = model();
        assert!(!m.can_enable(), "nothing is selected yet");
        reduce(&mut m, Event::SelectionChanged(Some(0)));
        assert!(m.can_enable());
        reduce(&mut m, Event::SelectionChanged(None));
        assert!(!m.can_enable());
    }

    #[test]
    fn stopping_and_copying_require_a_live_session() {
        let mut m = model();
        assert!(!m.can_stop());
        assert!(!m.can_copy());
        reduce(
            &mut m,
            Event::StatusPolled(status(State::Listening, "mike", AccessMode::Control)),
        );
        assert!(m.can_stop());
        assert!(m.can_copy());
        reduce(&mut m, Event::StatusPolled(Status::off()));
        assert!(!m.can_stop());
        assert!(!m.can_copy());
    }

    #[test]
    fn a_selection_follows_its_peer_when_the_list_is_reordered() {
        // Peers are stored sorted by name, so one added from the tray or the
        // CLI shifts every index after it. Holding the index would quietly
        // repoint the selection at a different person, and granting access is
        // one click away.
        let mut m = model();
        reduce(&mut m, Event::SelectionChanged(Some(1)));
        assert_eq!(m.selected_peer().unwrap().name, "jane");

        reduce(
            &mut m,
            Event::PeersLoaded(vec![
                peer("alice", "10.0.0.1/32"),
                peer("jane", "10.0.0.4/32"),
                peer("mike", "10.0.0.3/32"),
            ]),
        );
        assert_eq!(
            m.selected_peer().map(|p| p.name.as_str()),
            Some("jane"),
            "the selection must follow the peer, not the row"
        );
    }

    #[test]
    fn a_stale_selection_cannot_point_at_the_wrong_peer() {
        // The bug this guards: jane is selected, mike is removed elsewhere,
        // and index 1 now means something different - or nothing at all.
        let mut m = model();
        reduce(&mut m, Event::SelectionChanged(Some(1)));
        assert_eq!(m.selected_peer().unwrap().name, "jane");

        reduce(
            &mut m,
            Event::PeersLoaded(vec![peer("mike", "10.0.0.3/32")]),
        );
        assert!(
            m.selected_peer().is_none(),
            "a selection past the end must be dropped, not reinterpreted"
        );
        assert!(!m.can_enable());
    }

    #[test]
    fn an_out_of_range_selection_is_ignored() {
        let mut m = model();
        reduce(&mut m, Event::SelectionChanged(Some(99)));
        assert!(m.selected_peer().is_none());
    }

    // --- adding a peer: validation happens before any I/O ---

    #[test]
    fn adding_requires_both_fields() {
        let mut m = model();
        for (name, cidr) in [("", "10.0.0.5"), ("bob", ""), ("  ", "  ")] {
            let effects = reduce(
                &mut m,
                Event::AddClicked {
                    name: name.into(),
                    cidr: cidr.into(),
                },
            );
            assert!(effects.is_empty(), "nothing should be written to disk");
            assert_eq!(message(&m), "Enter both a name and an address.");
        }
    }

    #[test]
    fn a_bare_address_is_accepted_as_a_host_route() {
        let mut m = model();
        let effects = reduce(
            &mut m,
            Event::AddClicked {
                name: " bob ".into(),
                cidr: " 10.0.0.5 ".into(),
            },
        );
        assert_eq!(
            effects,
            vec![Effect::AddPeer {
                name: "bob".into(),
                cidr: "10.0.0.5/32".parse().unwrap(),
            }],
            "whitespace is trimmed and a bare address becomes a /32"
        );
    }

    #[test]
    fn a_malformed_address_never_reaches_the_config() {
        let mut m = model();
        let effects = reduce(
            &mut m,
            Event::AddClicked {
                name: "bob".into(),
                cidr: "not-an-address".into(),
            },
        );
        assert!(effects.is_empty());
        assert!(m.message.as_ref().unwrap().is_error);
        assert!(message(&m).contains("not an IP address"), "{}", message(&m));
    }

    #[test]
    fn a_too_broad_range_is_refused_with_a_way_forward() {
        // The window must apply the same policy as the CLI and the daemon,
        // so it cannot create a peer that could never be started.
        let mut m = model();
        let effects = reduce(
            &mut m,
            Event::AddClicked {
                name: "world".into(),
                cidr: "10.0.0.0/8".into(),
            },
        );
        assert!(effects.is_empty(), "a /8 must not be written to the config");
        assert!(m.message.as_ref().unwrap().is_error);
        assert!(message(&m).contains("--force"), "{}", message(&m));
    }

    #[test]
    fn a_merely_broad_range_is_allowed_but_flagged() {
        let mut m = model();
        let effects = reduce(
            &mut m,
            Event::AddClicked {
                name: "office".into(),
                cidr: "10.0.9.0/24".into(),
            },
        );
        assert_eq!(effects.len(), 1, "a /24 is permitted");
        reduce(
            &mut m,
            Event::PeerAdded {
                name: "office".into(),
                cidr: "10.0.9.0/24".parse().unwrap(),
            },
        );
        assert!(
            message(&m).contains("Note:"),
            "the breadth should be called out: {}",
            message(&m)
        );
    }

    #[test]
    fn a_successful_add_clears_the_entries_and_reloads() {
        let mut m = model();
        let effects = reduce(
            &mut m,
            Event::PeerAdded {
                name: "bob".into(),
                cidr: "10.0.0.5/32".parse().unwrap(),
            },
        );
        assert_eq!(effects, vec![Effect::ClearPeerEntries, Effect::ReloadPeers]);
    }

    // --- removing ---

    #[test]
    fn removing_without_a_selection_says_so() {
        let mut m = model();
        assert!(reduce(&mut m, Event::RemoveClicked).is_empty());
        assert_eq!(message(&m), "Select a peer to remove.");
    }

    #[test]
    fn removing_a_peer_with_a_live_session_warns_that_access_remains() {
        let mut m = model();
        reduce(
            &mut m,
            Event::StatusPolled(status(State::Connected, "mike", AccessMode::Control)),
        );
        reduce(
            &mut m,
            Event::PeerRemoved {
                name: "mike".into(),
            },
        );
        assert!(
            message(&m).contains("unaffected"),
            "deleting the peer must not imply the session ended: {}",
            message(&m)
        );
    }

    #[test]
    fn removing_an_idle_peer_does_not_warn() {
        let mut m = model();
        reduce(
            &mut m,
            Event::StatusPolled(status(State::Connected, "mike", AccessMode::Control)),
        );
        reduce(
            &mut m,
            Event::PeerRemoved {
                name: "jane".into(),
            },
        );
        assert!(!message(&m).contains("unaffected"), "{}", message(&m));
    }

    // --- enabling ---

    #[test]
    fn enabling_sends_the_selected_peer_duration_and_mode() {
        let mut m = model();
        reduce(&mut m, Event::SelectionChanged(Some(1)));
        reduce(&mut m, Event::MinutesChanged(30));
        reduce(&mut m, Event::ViewOnlyToggled(true));

        let effects = reduce(&mut m, Event::EnableClicked);
        assert_eq!(
            effects,
            vec![
                Effect::SaveDefaultMinutes(30),
                Effect::Send(Request::Start {
                    peer: "jane".into(),
                    minutes: Some(30),
                    mode: AccessMode::ViewOnly,
                }),
            ]
        );
        assert!(message(&m).contains("view only"), "{}", message(&m));
    }

    #[test]
    fn full_control_is_the_default_mode() {
        let mut m = model();
        reduce(&mut m, Event::SelectionChanged(Some(0)));
        match &reduce(&mut m, Event::EnableClicked)[1] {
            Effect::Send(Request::Start { mode, .. }) => {
                assert_eq!(*mode, AccessMode::Control)
            }
            other => panic!("unexpected effect: {other:?}"),
        }
    }

    #[test]
    fn enabling_without_a_selection_does_nothing() {
        let mut m = model();
        assert!(reduce(&mut m, Event::EnableClicked).is_empty());
        assert_eq!(message(&m), "Select a peer first.");
    }

    // --- the invitation, and adopting a session started elsewhere ---

    #[test]
    fn a_session_started_elsewhere_is_adopted_exactly_once() {
        let mut m = model();
        let first = reduce(
            &mut m,
            Event::StatusPolled(status(State::Listening, "mike", AccessMode::Control)),
        );
        assert_eq!(first, vec![Effect::FetchInvitation { copy: false }]);

        // Further polls while the request is in flight must not pile up.
        for _ in 0..3 {
            let again = reduce(
                &mut m,
                Event::StatusPolled(status(State::Listening, "mike", AccessMode::Control)),
            );
            assert!(
                again.is_empty(),
                "one request per session, not one per poll"
            );
        }

        reduce(
            &mut m,
            Event::InvitationFetched {
                session: session("mike"),
                copy: false,
            },
        );
        assert!(m.invitation().contains("10.0.0.10"));
        assert!(message(&m).contains("started elsewhere"), "{}", message(&m));
    }

    #[test]
    fn a_failed_adoption_is_retried_on_the_next_poll() {
        // Regression: the flag used to be cleared only on success, so one
        // failed request meant the invitation was never fetched again for the
        // life of the session.
        let mut m = model();
        let live = status(State::Listening, "mike", AccessMode::Control);
        assert_eq!(
            reduce(&mut m, Event::StatusPolled(live.clone())),
            vec![Effect::FetchInvitation { copy: false }]
        );
        reduce(&mut m, Event::Failed("daemon went away".into()));
        assert_eq!(
            reduce(&mut m, Event::StatusPolled(live)),
            vec![Effect::FetchInvitation { copy: false }],
            "a failure must not wedge the adoption flag"
        );
    }

    #[test]
    fn the_password_is_shown_only_while_someone_waits_to_type_it() {
        let mut m = model();
        m.session = Some(session("mike"));

        m.status = status(State::Connected, "mike", AccessMode::Control);
        assert_eq!(
            m.password_to_read(),
            Some(session("mike").password.as_str()),
            "the owner has to be able to read it aloud"
        );

        // Rotated the moment they disconnect, so a value held from a previous
        // connection must never be offered as if it were current.
        for state in [State::Off, State::Listening, State::Authenticated] {
            m.status = status(state, "mike", AccessMode::Control);
            assert_eq!(
                m.password_to_read(),
                None,
                "no password may be shown in {state:?}"
            );
        }
    }

    #[test]
    fn nothing_is_shown_before_the_live_password_arrives() {
        let mut m = model();
        m.status = status(State::Connected, "mike", AccessMode::Control);
        assert_eq!(m.password_to_read(), None);
    }

    #[test]
    fn a_new_connection_refetches_the_password() {
        // The one held is from the previous connection and is already spent,
        // so arriving in this state has to ask the daemon again.
        let mut m = model();
        m.session = Some(session("mike"));
        m.status = status(State::Listening, "mike", AccessMode::Control);

        let effects = reduce(
            &mut m,
            Event::StatusPolled(status(State::Connected, "mike", AccessMode::Control)),
        );
        assert_eq!(effects, vec![Effect::FetchInvitation { copy: false }]);

        // But not once per poll tick while they are still sitting there.
        let again = reduce(
            &mut m,
            Event::StatusPolled(status(State::Connected, "mike", AccessMode::Control)),
        );
        assert_eq!(
            again,
            Vec::new(),
            "one request per connection, not per poll"
        );
    }

    #[test]
    fn copying_the_password_puts_the_live_one_on_the_clipboard() {
        let mut m = model();
        m.session = Some(session("mike"));
        m.status = status(State::Connected, "mike", AccessMode::Control);

        let effects = reduce(&mut m, Event::CopyPasswordClicked);
        assert_eq!(
            effects,
            vec![Effect::CopyToClipboard(session("mike").password)]
        );
        assert!(message(&m).contains("copied"), "{}", message(&m));
    }

    #[test]
    fn a_spent_password_is_never_copied() {
        // The session is still cached after they leave, but its password has
        // been rotated; copying it would hand over something that cannot work.
        let mut m = model();
        m.session = Some(session("mike"));
        m.status = status(State::Listening, "mike", AccessMode::Control);

        let effects = reduce(&mut m, Event::CopyPasswordClicked);
        assert_eq!(effects, Vec::new(), "nothing may reach the clipboard");
        assert!(message(&m).contains("no live password"), "{}", message(&m));
    }

    #[test]
    fn the_invitation_is_dropped_when_the_session_ends() {
        let mut m = model();
        reduce(
            &mut m,
            Event::StatusPolled(status(State::Listening, "mike", AccessMode::Control)),
        );
        reduce(
            &mut m,
            Event::InvitationFetched {
                session: session("mike"),
                copy: false,
            },
        );
        assert!(!m.invitation().is_empty());

        reduce(&mut m, Event::StatusPolled(Status::off()));
        assert!(
            m.invitation().is_empty(),
            "credentials from a finished session must not stay on screen"
        );
    }

    #[test]
    fn copying_uses_the_cached_invitation_when_there_is_one() {
        let mut m = model();
        reduce(&mut m, Event::SessionStarted(session("mike")));
        let effects = reduce(&mut m, Event::CopyClicked);
        match effects.as_slice() {
            [Effect::CopyToClipboard(text)] => assert!(text.contains("10.0.0.10")),
            other => panic!("unexpected effects: {other:?}"),
        }
    }

    #[test]
    fn copying_without_a_cached_invitation_asks_the_daemon() {
        let mut m = model();
        assert_eq!(
            reduce(&mut m, Event::CopyClicked),
            vec![Effect::FetchInvitation { copy: true }]
        );
        let effects = reduce(
            &mut m,
            Event::InvitationFetched {
                session: session("mike"),
                copy: true,
            },
        );
        assert!(matches!(effects.as_slice(), [Effect::CopyToClipboard(_)]));
        assert!(message(&m).contains("copied"), "{}", message(&m));
    }

    // --- what the window says ---

    #[test]
    fn the_heading_distinguishes_watching_from_controlling() {
        let mut m = model();
        assert_eq!(m.heading(), "Remote access off");
        reduce(
            &mut m,
            Event::StatusPolled(status(State::Authenticated, "mike", AccessMode::Control)),
        );
        assert_eq!(m.heading(), "Someone is controlling your desktop");
        reduce(
            &mut m,
            Event::StatusPolled(status(State::Authenticated, "mike", AccessMode::ViewOnly)),
        );
        assert_eq!(m.heading(), "Someone is watching your screen");
    }

    #[test]
    fn the_detail_line_covers_the_whole_session() {
        let mut m = model();
        assert_eq!(m.detail(), "No peer is authorised.");
        reduce(
            &mut m,
            Event::StatusPolled(status(State::Listening, "mike", AccessMode::ViewOnly)),
        );
        let detail = m.detail();
        for expected in ["mike", "10.0.0.3/32", "10.0.0.10:5900", "view only", "30m"] {
            assert!(
                detail.contains(expected),
                "{expected:?} missing from {detail:?}"
            );
        }
    }

    #[test]
    fn peer_rows_flag_risky_ranges() {
        let m = Model::new(
            vec![
                peer("mike", "10.0.0.3/32"),
                peer("office", "10.0.9.0/24"),
                peer("world", "10.0.0.0/8"),
            ],
            60,
        );
        let rows = m.peer_rows();
        assert_eq!(rows[0].note, None, "a host route needs no warning");
        assert_eq!(rows[1].note, Some("range, not one host"));
        assert_eq!(rows[2].note, Some("too broad to share"));
    }

    #[test]
    fn failures_are_reported_as_errors() {
        let mut m = model();
        reduce(&mut m, Event::Failed("the daemon is not running".into()));
        let msg = m.message.as_ref().unwrap();
        assert!(msg.is_error);
        assert_eq!(msg.text, "the daemon is not running");
    }

    #[test]
    fn stopping_asks_the_daemon_and_clears_on_confirmation() {
        let mut m = model();
        reduce(&mut m, Event::SessionStarted(session("mike")));
        assert_eq!(
            reduce(&mut m, Event::StopClicked),
            vec![Effect::Send(Request::Stop)]
        );
        // The session is only cleared once the daemon confirms, not on click.
        assert!(!m.invitation().is_empty());
        reduce(&mut m, Event::SessionStopped);
        assert!(m.invitation().is_empty());
        assert_eq!(message(&m), "Access revoked.");
    }
}
