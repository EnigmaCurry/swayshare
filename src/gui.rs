//! GTK4 configuration window.
//!
//! This runs as its own process, launched from the tray or with
//! `swayshare gui`. Keeping it separate is what makes "closing the window
//! leaves the tray running" true by construction, and keeps GTK out of the
//! daemon's address space.
//!
//! Peer edits are written straight to the config file; anything that affects
//! live access goes through the daemon's control socket, so the window has no
//! privileged path of its own. Requests run on worker threads and report back
//! through an async channel, because enabling a session waits on wayvnc and
//! would otherwise freeze the UI.

use crate::config::{self, Config, Peer};
use crate::invite;
use crate::ipc::{self, AccessMode, Request, Response, Session, State, Status};
use crate::paths;
use anyhow::Result;
use gtk::prelude::*;
use gtk4 as gtk;
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

const APP_ID: &str = "tech.rymcg.swayshare";
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Results arriving from worker threads.
enum UiEvent {
    Status(Status),
    Started(Session),
    /// Fetched because the user asked to copy it.
    Invitation(Session),
    /// Fetched because a session is running that this window did not start.
    AdoptedInvitation(Session),
    Stopped,
    Error(String),
}

struct Ui {
    socket: PathBuf,
    events: async_channel::Sender<UiEvent>,

    state_label: gtk::Label,
    detail_label: gtk::Label,
    message_label: gtk::Label,
    peer_list: gtk::ListBox,
    name_entry: gtk::Entry,
    cidr_entry: gtk::Entry,
    minutes: gtk::SpinButton,
    /// Ticked to grant a session the peer cannot type into.
    view_only: gtk::CheckButton,
    enable_button: gtk::Button,
    stop_button: gtk::Button,
    copy_button: gtk::Button,
    add_button: gtk::Button,
    remove_button: gtk::Button,
    invitation: gtk::TextView,

    /// Mirrors the rows in `peer_list`, so a selected row index maps to a peer.
    peers: RefCell<Vec<Peer>>,
    /// The session whose invitation is currently displayed, if any.
    session: RefCell<Option<Session>>,
    /// Guards against re-requesting the invitation on every poll tick.
    adopting: std::cell::Cell<bool>,
}

pub fn run() -> Result<()> {
    let app = gtk::Application::builder().application_id(APP_ID).build();
    app.connect_activate(build_window);
    // Our own argv has already been consumed by clap; GTK must not see it.
    let empty: [&str; 0] = [];
    app.run_with_args(&empty);
    Ok(())
}

fn build_window(app: &gtk::Application) {
    let socket = match paths::control_socket() {
        Ok(path) => path,
        Err(e) => {
            present_fatal(app, &format!("{e:#}"));
            return;
        }
    };

    let (tx, rx) = async_channel::bounded::<UiEvent>(32);

    let ui = Rc::new(Ui {
        socket: socket.clone(),
        events: tx.clone(),
        state_label: gtk::Label::builder()
            .label("Checking...")
            .xalign(0.0)
            .css_classes(["title-2"])
            .build(),
        detail_label: gtk::Label::builder()
            .label("")
            .xalign(0.0)
            .wrap(true)
            .build(),
        message_label: gtk::Label::builder()
            .label("")
            .xalign(0.0)
            .wrap(true)
            .build(),
        peer_list: gtk::ListBox::builder()
            .selection_mode(gtk::SelectionMode::Single)
            .build(),
        name_entry: gtk::Entry::builder()
            .placeholder_text("name, e.g. mike")
            .build(),
        cidr_entry: gtk::Entry::builder()
            .placeholder_text("address or CIDR, e.g. 10.0.0.3/32")
            .hexpand(true)
            .build(),
        minutes: gtk::SpinButton::with_range(0.0, 1440.0, 5.0),
        view_only: gtk::CheckButton::with_label("View only"),
        enable_button: gtk::Button::with_label("Enable access"),
        stop_button: gtk::Button::with_label("Revoke access"),
        copy_button: gtk::Button::with_label("Copy invitation"),
        add_button: gtk::Button::with_label("Add"),
        remove_button: gtk::Button::with_label("Remove selected peer"),
        invitation: gtk::TextView::builder()
            .editable(false)
            .monospace(true)
            .cursor_visible(false)
            .left_margin(8)
            .right_margin(8)
            .top_margin(8)
            .bottom_margin(8)
            .build(),
        peers: RefCell::new(Vec::new()),
        session: RefCell::new(None),
        adopting: std::cell::Cell::new(false),
    });

    ui.enable_button.add_css_class("suggested-action");
    ui.stop_button.add_css_class("destructive-action");
    ui.message_label.add_css_class("dim-label");

    let cfg = Config::load().unwrap_or_default();
    ui.minutes
        .set_value(cfg.security.default_session_minutes as f64);
    ui.minutes.set_tooltip_text(Some(
        "Minutes before access is revoked automatically. 0 means no expiry.\n\
         Saved as the default when you enable access.",
    ));

    let window = gtk::ApplicationWindow::builder()
        .application(app)
        .title("swayshare")
        .default_width(560)
        .default_height(680)
        .child(&layout(&ui))
        .build();

    wire_actions(&ui);
    reload_peers(&ui);
    render_status(&ui, &Status::off());

    // Drain worker results on the GTK main loop.
    {
        let ui = Rc::clone(&ui);
        gtk::glib::spawn_future_local(async move {
            while let Ok(event) = rx.recv().await {
                handle_event(&ui, event);
            }
        });
    }

    // Poll the daemon for state in the background.
    {
        let tx = tx.clone();
        std::thread::spawn(move || {
            loop {
                let status = match ipc::blocking::request(&socket, &Request::Status)
                    .and_then(ipc::expect_ok)
                {
                    // A daemon that is not running means nothing is shared,
                    // which is a legitimate state rather than an error.
                    Ok(Response::Status(status)) => status,
                    _ => Status::off(),
                };
                if tx.send_blocking(UiEvent::Status(status)).is_err() {
                    break; // the window is gone
                }
                std::thread::sleep(POLL_INTERVAL);
            }
        });
    }

    window.present();
}

fn layout(ui: &Rc<Ui>) -> gtk::Box {
    let root = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(16)
        .margin_top(16)
        .margin_bottom(16)
        .margin_start(16)
        .margin_end(16)
        .build();

    // --- current state ---
    let status_box = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(4)
        .margin_top(8)
        .margin_bottom(8)
        .margin_start(8)
        .margin_end(8)
        .build();
    status_box.append(&ui.state_label);
    status_box.append(&ui.detail_label);
    let stop_row = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(8)
        .margin_top(8)
        .build();
    stop_row.append(&ui.stop_button);
    stop_row.append(&ui.copy_button);
    status_box.append(&stop_row);
    root.append(
        &gtk::Frame::builder()
            .label("Status")
            .child(&status_box)
            .build(),
    );

    // --- peers ---
    let peers_box = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(8)
        .margin_top(8)
        .margin_bottom(8)
        .margin_start(8)
        .margin_end(8)
        .build();
    peers_box.append(
        &gtk::ScrolledWindow::builder()
            .child(&ui.peer_list)
            .vexpand(true)
            .min_content_height(140)
            .has_frame(true)
            .build(),
    );

    let add_row = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(8)
        .build();
    add_row.append(&ui.name_entry);
    add_row.append(&ui.cidr_entry);
    add_row.append(&ui.add_button);
    peers_box.append(&add_row);

    let remove_row = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .build();
    remove_row.append(&ui.remove_button);
    peers_box.append(&remove_row);
    root.append(
        &gtk::Frame::builder()
            .label("Peers")
            .child(&peers_box)
            .build(),
    );

    // --- grant access ---
    let grant_box = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(8)
        .margin_top(8)
        .margin_bottom(8)
        .margin_start(8)
        .margin_end(8)
        .build();
    grant_box.append(&gtk::Label::new(Some("Minutes:")));
    grant_box.append(&ui.minutes);
    grant_box.append(&ui.view_only);
    grant_box.append(&gtk::Box::builder().hexpand(true).build());
    grant_box.append(&ui.enable_button);
    root.append(
        &gtk::Frame::builder()
            .label("Grant access")
            .child(&grant_box)
            .build(),
    );

    // --- invitation ---
    root.append(
        &gtk::Frame::builder()
            .label("Invitation")
            .child(
                &gtk::ScrolledWindow::builder()
                    .child(&ui.invitation)
                    .min_content_height(170)
                    .build(),
            )
            .build(),
    );
    root.append(&ui.message_label);
    root
}

fn wire_actions(ui: &Rc<Ui>) {
    {
        let ui = Rc::clone(ui);
        ui.add_button
            .clone()
            .connect_clicked(move |_| add_peer(&ui));
    }
    {
        let ui = Rc::clone(ui);
        ui.remove_button
            .clone()
            .connect_clicked(move |_| remove_peer(&ui));
    }
    {
        let ui = Rc::clone(ui);
        ui.cidr_entry
            .clone()
            .connect_activate(move |_| add_peer(&ui));
    }
    {
        let ui = Rc::clone(ui);
        ui.enable_button
            .clone()
            .connect_clicked(move |_| enable_access(&ui));
    }
    {
        let ui = Rc::clone(ui);
        ui.stop_button.clone().connect_clicked(move |_| {
            dispatch(&ui, Request::Stop, |_| UiEvent::Stopped);
        });
    }
    {
        let ui = Rc::clone(ui);
        ui.copy_button
            .clone()
            .connect_clicked(move |button| copy_invitation(&ui, button));
    }
    {
        // Enabling depends on there being a selection.
        let ui = Rc::clone(ui);
        ui.peer_list
            .clone()
            .connect_row_selected(move |_, _| refresh_sensitivity(&ui));
    }
}

/// Rebuild the peer rows from the config file on disk.
fn reload_peers(ui: &Rc<Ui>) {
    let cfg = match Config::load() {
        Ok(cfg) => cfg,
        Err(e) => {
            set_message(ui, &format!("Could not read the config: {e:#}"), true);
            return;
        }
    };

    while let Some(child) = ui.peer_list.first_child() {
        ui.peer_list.remove(&child);
    }
    for peer in &cfg.peers {
        let row = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(12)
            .margin_top(6)
            .margin_bottom(6)
            .margin_start(8)
            .margin_end(8)
            .build();
        row.append(&gtk::Label::builder().label(&peer.name).xalign(0.0).build());
        row.append(
            &gtk::Label::builder()
                .label(peer.cidr.to_string())
                .xalign(0.0)
                .css_classes(["dim-label"])
                .build(),
        );
        // Name the risk in the list itself, not only on failure.
        if let Some(_warning) = config::breadth_warning(&peer.cidr) {
            let text = if config::requires_force(&peer.cidr) {
                "too broad to share"
            } else {
                "range, not one host"
            };
            row.append(&gtk::Box::builder().hexpand(true).build());
            row.append(
                &gtk::Label::builder()
                    .label(text)
                    .css_classes(["warning", "dim-label"])
                    .build(),
            );
        }
        ui.peer_list
            .append(&gtk::ListBoxRow::builder().child(&row).build());
    }
    *ui.peers.borrow_mut() = cfg.peers;
    refresh_sensitivity(ui);
}

fn selected_peer(ui: &Rc<Ui>) -> Option<Peer> {
    let index = ui.peer_list.selected_row()?.index();
    if index < 0 {
        return None;
    }
    ui.peers.borrow().get(index as usize).cloned()
}

fn add_peer(ui: &Rc<Ui>) {
    let name = ui.name_entry.text().trim().to_string();
    let cidr_text = ui.cidr_entry.text().trim().to_string();
    if name.is_empty() || cidr_text.is_empty() {
        set_message(ui, "Enter both a name and an address.", true);
        return;
    }

    let cidr = match config::parse_cidr(&cidr_text) {
        Ok(cidr) => cidr,
        Err(e) => return set_message(ui, &format!("{e:#}"), true),
    };
    // The same policy the CLI and the daemon apply; refusing here means the
    // user cannot create a peer that could never be started.
    if config::requires_force(&cidr) {
        let warning = config::breadth_warning(&cidr).unwrap_or_default();
        return set_message(
            ui,
            &format!("{warning}. Add it with `swayshare add --force` if you really mean it."),
            true,
        );
    }

    let result = Config::load().and_then(|mut cfg| {
        cfg.add_peer(&name, cidr)?;
        cfg.save()?;
        Ok(())
    });
    match result {
        Ok(()) => {
            ui.name_entry.set_text("");
            ui.cidr_entry.set_text("");
            let note = config::breadth_warning(&cidr)
                .map(|w| format!(" Note: {w}."))
                .unwrap_or_default();
            set_message(ui, &format!("Added {name} ({cidr}).{note}"), false);
            reload_peers(ui);
        }
        Err(e) => set_message(ui, &format!("{e:#}"), true),
    }
}

fn remove_peer(ui: &Rc<Ui>) {
    let Some(peer) = selected_peer(ui) else {
        return set_message(ui, "Select a peer to remove.", true);
    };
    let result = Config::load().and_then(|mut cfg| {
        cfg.remove_peer(&peer.name)?;
        cfg.save()?;
        Ok(())
    });
    match result {
        Ok(()) => {
            let active = ui.session.borrow().as_ref().map(|s| s.peer.clone());
            let caveat = if active.as_deref() == Some(peer.name.as_str()) {
                " The session already running for it is unaffected; stop it to revoke access."
            } else {
                ""
            };
            set_message(ui, &format!("Removed {}.{caveat}", peer.name), false);
            reload_peers(ui);
        }
        Err(e) => set_message(ui, &format!("{e:#}"), true),
    }
}

fn enable_access(ui: &Rc<Ui>) {
    let Some(peer) = selected_peer(ui) else {
        return set_message(ui, "Select a peer first.", true);
    };
    let minutes = ui.minutes.value().round() as u64;
    // Fixed for the life of the session: wayvnc takes --disable-input only at
    // startup, so this cannot be changed later without disconnecting them.
    let mode = if ui.view_only.is_active() {
        AccessMode::ViewOnly
    } else {
        AccessMode::Control
    };

    // Remember the chosen duration, so the CLI and tray agree with the window.
    if let Ok(mut cfg) = Config::load()
        && cfg.security.default_session_minutes != minutes
    {
        cfg.security.default_session_minutes = minutes;
        let _ = cfg.save();
    }

    set_message(
        ui,
        &format!("Starting a {} session for {}...", mode.label(), peer.name),
        false,
    );
    ui.enable_button.set_sensitive(false);
    dispatch(
        ui,
        Request::Start {
            peer: peer.name,
            minutes: Some(minutes),
            mode,
        },
        |response| match response {
            Response::Session(session) => UiEvent::Started(session),
            other => UiEvent::Error(format!("unexpected reply: {other:?}")),
        },
    );
}

fn copy_invitation(ui: &Rc<Ui>, button: &gtk::Button) {
    let text = ui.session.borrow().as_ref().map(invite::render);
    match text {
        Some(text) => {
            // GTK owns the Wayland clipboard here, so no wl-copy is needed.
            button.clipboard().set_text(&text);
            set_message(ui, "Invitation copied to the clipboard.", false);
        }
        None => {
            // Nothing cached: ask the daemon, then copy on the way back.
            dispatch(ui, Request::Invite, |response| match response {
                Response::Session(session) => UiEvent::Invitation(session),
                other => UiEvent::Error(format!("unexpected reply: {other:?}")),
            });
        }
    }
}

/// Run a request on a worker thread and post the outcome back to the UI.
fn dispatch<F>(ui: &Rc<Ui>, request: Request, map: F)
where
    F: FnOnce(Response) -> UiEvent + Send + 'static,
{
    let socket = ui.socket.clone();
    let events = ui.events.clone();
    std::thread::spawn(move || {
        let event = match ipc::blocking::request(&socket, &request).and_then(ipc::expect_ok) {
            Ok(response) => map(response),
            Err(e) => UiEvent::Error(format!("{e:#}")),
        };
        let _ = events.send_blocking(event);
    });
}

fn handle_event(ui: &Rc<Ui>, event: UiEvent) {
    match event {
        UiEvent::Status(status) => render_status(ui, &status),
        UiEvent::Started(session) => {
            set_message(ui, &format!("Access enabled for {}.", session.peer), false);
            show_invitation(ui, session);
        }
        UiEvent::Invitation(session) => {
            let text = invite::render(&session);
            show_invitation(ui, session);
            ui.copy_button.clipboard().set_text(&text);
            set_message(ui, "Invitation copied to the clipboard.", false);
        }
        UiEvent::AdoptedInvitation(session) => {
            ui.adopting.set(false);
            set_message(
                ui,
                &format!(
                    "Showing the session started elsewhere for {}.",
                    session.peer
                ),
                false,
            );
            show_invitation(ui, session);
        }
        UiEvent::Stopped => {
            *ui.session.borrow_mut() = None;
            ui.invitation.buffer().set_text("");
            set_message(ui, "Access revoked.", false);
        }
        UiEvent::Error(message) => set_message(ui, &message, true),
    }
    refresh_sensitivity(ui);
}

fn show_invitation(ui: &Rc<Ui>, session: Session) {
    ui.invitation.buffer().set_text(&invite::render(&session));
    *ui.session.borrow_mut() = Some(session);
    refresh_sensitivity(ui);
}

fn render_status(ui: &Rc<Ui>, status: &Status) {
    ui.state_label.set_label(match status.state {
        State::Off => "Remote access off",
        State::Listening => "Access granted - waiting for them to connect",
        State::Connected => match status.mode {
            Some(AccessMode::ViewOnly) => "Someone is watching your screen",
            _ => "Someone is controlling your desktop",
        },
    });

    let mut detail = String::new();
    if let (Some(peer), Some(cidr)) = (&status.peer, &status.cidr) {
        detail.push_str(&format!("Authorised: {peer} ({cidr})"));
    }
    if let Some(listen) = &status.listen {
        detail.push_str(&format!("\nListening on {listen}"));
    }
    if let Some(mode) = status.mode {
        detail.push_str(&format!("\nAccess: {}", mode.label()));
    }
    if let Some(secs) = status.expires_in_seconds {
        detail.push_str(&format!("\nExpires in {}", invite::humanize(secs)));
    }
    if detail.is_empty() {
        detail.push_str("No peer is authorised.");
    }
    ui.detail_label.set_label(&detail);

    // A session that ended elsewhere must not leave stale credentials on show.
    if status.state == State::Off {
        ui.adopting.set(false);
        if ui.session.borrow().is_some() {
            *ui.session.borrow_mut() = None;
            ui.invitation.buffer().set_text("");
        }
    } else if ui.session.borrow().is_none() && !ui.adopting.get() {
        // Sharing was enabled from the tray or the CLI. Pull the invitation in
        // so the window is useful no matter where the session came from; the
        // flag keeps this to one request rather than one per poll.
        ui.adopting.set(true);
        dispatch(ui, Request::Invite, |response| match response {
            Response::Session(session) => UiEvent::AdoptedInvitation(session),
            other => UiEvent::Error(format!("unexpected reply: {other:?}")),
        });
    }

    let sharing = status.state != State::Off;
    ui.stop_button.set_sensitive(sharing);
    ui.copy_button.set_sensitive(sharing);
    ui.enable_button.set_sensitive(selected_peer(ui).is_some());
}

fn refresh_sensitivity(ui: &Rc<Ui>) {
    let has_selection = selected_peer(ui).is_some();
    ui.enable_button.set_sensitive(has_selection);
    let sharing = ui.session.borrow().is_some() || ui.stop_button.is_sensitive();
    ui.copy_button.set_sensitive(sharing);
}

fn set_message(ui: &Rc<Ui>, message: &str, is_error: bool) {
    ui.message_label.set_label(message);
    if is_error {
        ui.message_label.remove_css_class("dim-label");
        ui.message_label.add_css_class("error");
        eprintln!("swayshare: {message}");
    } else {
        ui.message_label.remove_css_class("error");
        ui.message_label.add_css_class("dim-label");
    }
}

/// Show an error in a window of its own, for failures that prevent startup.
fn present_fatal(app: &gtk::Application, message: &str) {
    let label = gtk::Label::builder()
        .label(message)
        .wrap(true)
        .margin_top(24)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .build();
    gtk::ApplicationWindow::builder()
        .application(app)
        .title("swayshare")
        .child(&label)
        .build()
        .present();
}
