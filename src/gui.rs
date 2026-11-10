//! GTK4 shell around [`crate::window`].
//!
//! This runs as its own process, launched from the tray or with
//! `swayshare gui`. Keeping it separate is what makes "closing the window
//! leaves the tray running" true by construction, and keeps GTK out of the
//! daemon's address space.
//!
//! All behaviour lives in [`crate::window`]; this file only translates
//! between that model and GTK. Every signal turns into a
//! [`window::Event`], [`window::reduce`] decides what it means, the
//! resulting [`window::Effect`]s are carried out here, and then [`render`]
//! writes the whole model onto the widgets. Nothing reads state back out of a
//! widget, and there is exactly one place that sets widget properties.
//!
//! Peer edits are written straight to the config file; anything that affects
//! live access goes through the daemon's control socket, so the window has no
//! privileged path of its own. Requests run on worker threads and report back
//! through an async channel, because enabling a session waits on wayvnc and
//! would otherwise freeze the UI.

use crate::config::Config;
use crate::identity::{self, Identity};
use crate::ipc::{self, Request, Response};
use crate::paths;
use crate::window::{self, Effect, Event, Model};
use anyhow::Result;
use gtk::prelude::*;
use gtk::{gdk, gio};
use gtk4 as gtk;
use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

const APP_ID: &str = "tech.rymcg.swayshare";
const POLL_INTERVAL: Duration = Duration::from_secs(1);

struct Widgets {
    heading: gtk::Label,
    detail: gtk::Label,
    message: gtk::Label,
    peer_list: gtk::ListBox,
    name_entry: gtk::Entry,
    cidr_entry: gtk::Entry,
    minutes: gtk::SpinButton,
    view_only: gtk::CheckButton,
    enable_button: gtk::Button,
    stop_button: gtk::Button,
    copy_button: gtk::Button,
    add_button: gtk::Button,
    remove_button: gtk::Button,
    invitation: gtk::TextView,
    /// The handle the certificate is dragged out of. See [`wire`] for why
    /// this is a drag source rather than a button.
    cert_drag: gtk::Box,
}

struct Ui {
    socket: PathBuf,
    events: async_channel::Sender<Event>,
    model: RefCell<Model>,
    widgets: Widgets,
    /// The peer rows currently on screen, so an unchanged list is not torn
    /// down and rebuilt on every poll tick.
    shown_peers: RefCell<Vec<crate::config::Peer>>,
    /// Set while the list is being rebuilt, so GTK's own selection signals
    /// during the teardown are not mistaken for the user clicking.
    rebuilding: Cell<bool>,
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
        Err(e) => return present_fatal(app, &format!("{e:#}")),
    };

    let cfg = Config::load().unwrap_or_default();
    let (tx, rx) = async_channel::bounded::<Event>(32);

    let widgets = Widgets {
        heading: gtk::Label::builder()
            .label("")
            .xalign(0.0)
            .css_classes(["title-2"])
            .build(),
        detail: gtk::Label::builder()
            .label("")
            .xalign(0.0)
            .wrap(true)
            .build(),
        message: gtk::Label::builder()
            .label("")
            .xalign(0.0)
            .wrap(true)
            .css_classes(["dim-label"])
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
        cert_drag: {
            let row = gtk::Box::builder()
                .orientation(gtk::Orientation::Horizontal)
                .spacing(6)
                .margin_top(4)
                .margin_bottom(4)
                .margin_start(8)
                .margin_end(8)
                .build();
            row.append(&gtk::Image::from_icon_name("application-certificate"));
            // The name alone looked like a static label; saying so outright is
            // the only reliable affordance for a drag source.
            row.append(
                &gtk::Label::builder()
                    .label(format!("{} (drag and drop me)", identity::export_name()))
                    .build(),
            );
            row
        },
        invitation: gtk::TextView::builder()
            .editable(false)
            .monospace(true)
            .cursor_visible(false)
            .left_margin(8)
            .right_margin(8)
            .top_margin(8)
            .bottom_margin(8)
            .build(),
    };
    widgets.enable_button.add_css_class("suggested-action");
    widgets.cert_drag.set_tooltip_text(Some(
        "The certificate your helper needs. Drag it into your chat and send it.\n\
             Enable access first, so it covers the address you are sharing from.",
    ));
    // The only hint that this is picked up rather than clicked.
    widgets.cert_drag.set_cursor_from_name(Some("grab"));
    widgets.stop_button.add_css_class("destructive-action");
    widgets
        .minutes
        .set_value(cfg.security.default_session_minutes as f64);
    widgets.minutes.set_tooltip_text(Some(
        "Minutes before access is revoked automatically. 0 means no expiry.\n\
         Saved as the default when you enable access.",
    ));
    widgets.view_only.set_tooltip_text(Some(
        "They see the screen but cannot type or click.\n\
         Fixed for the session: it cannot be changed without disconnecting them.",
    ));

    let ui = Rc::new(Ui {
        socket: socket.clone(),
        events: tx.clone(),
        model: RefCell::new(Model::new(cfg.peers, cfg.security.default_session_minutes)),
        widgets,
        shown_peers: RefCell::new(Vec::new()),
        rebuilding: Cell::new(false),
    });

    let window = gtk::ApplicationWindow::builder()
        .application(app)
        .title("swayshare")
        .default_width(560)
        .default_height(680)
        .child(&layout(&ui))
        .build();

    wire(&ui);
    render(&ui);

    // Drain worker results on the GTK main loop.
    {
        let ui = Rc::clone(&ui);
        gtk::glib::spawn_future_local(async move {
            while let Ok(event) = rx.recv().await {
                apply(&ui, event);
            }
        });
    }

    // Poll the daemon for state in the background.
    std::thread::spawn(move || {
        loop {
            let status =
                match ipc::blocking::request(&socket, &Request::Status).and_then(ipc::expect_ok) {
                    // A daemon that is not running means nothing is shared, which
                    // is a legitimate state rather than an error.
                    Ok(Response::Status(status)) => status,
                    _ => crate::ipc::Status::off(),
                };
            if tx.send_blocking(Event::StatusPolled(status)).is_err() {
                break; // the window is gone
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    });

    window.present();
}

/// Fold an event into the model, carry out what it asks for, then redraw.
///
/// This is the only path by which anything changes, so the widgets cannot
/// drift from the model.
fn apply(ui: &Rc<Ui>, event: Event) {
    let effects = {
        let mut model = ui.model.borrow_mut();
        window::reduce(&mut model, event)
    };
    for effect in effects {
        perform(ui, effect);
    }
    render(ui);
}

fn perform(ui: &Rc<Ui>, effect: Effect) {
    match effect {
        Effect::Send(request) => send(ui, request),
        Effect::FetchInvitation { copy } => fetch_invitation(ui, copy),

        Effect::AddPeer { name, cidr } => {
            let result = Config::load().and_then(|mut cfg| {
                cfg.add_peer(&name, cidr)?;
                cfg.save()?;
                Ok(())
            });
            post(
                ui,
                match result {
                    Ok(()) => Event::PeerAdded { name, cidr },
                    Err(e) => Event::Failed(format!("{e:#}")),
                },
            );
        }

        Effect::RemovePeer { name } => {
            let result = Config::load().and_then(|mut cfg| {
                cfg.remove_peer(&name)?;
                cfg.save()?;
                Ok(())
            });
            post(
                ui,
                match result {
                    Ok(()) => Event::PeerRemoved { name },
                    Err(e) => Event::Failed(format!("{e:#}")),
                },
            );
        }

        Effect::ReloadPeers => {
            let event = match Config::load() {
                Ok(cfg) => Event::PeersLoaded(cfg.peers),
                Err(e) => Event::Failed(format!("Could not read the config: {e:#}")),
            };
            post(ui, event);
        }

        Effect::SaveDefaultMinutes(minutes) => {
            // Best effort: failing to remember the duration must not stop a
            // session from starting.
            if let Ok(mut cfg) = Config::load()
                && cfg.security.default_session_minutes != minutes
            {
                cfg.security.default_session_minutes = minutes;
                let _ = cfg.save();
            }
        }

        Effect::CopyToClipboard(text) => {
            // GTK owns the Wayland clipboard here, so no wl-copy is needed.
            ui.widgets.copy_button.clipboard().set_text(&text);
        }

        Effect::ClearPeerEntries => {
            ui.widgets.name_entry.set_text("");
            ui.widgets.cidr_entry.set_text("");
        }
    }
}

/// Queue an event rather than recursing into [`apply`].
fn post(ui: &Rc<Ui>, event: Event) {
    let _ = ui.events.send_blocking(event);
}

/// Run a request on a worker thread and post the outcome back.
fn send(ui: &Rc<Ui>, request: Request) {
    let socket = ui.socket.clone();
    let events = ui.events.clone();
    std::thread::spawn(move || {
        let event = match ipc::blocking::request(&socket, &request).and_then(ipc::expect_ok) {
            Err(e) => Event::Failed(format!("{e:#}")),
            Ok(response) => match (&request, response) {
                (Request::Start { .. }, Response::Session(session)) => {
                    Event::SessionStarted(session)
                }
                (Request::Stop, _) => Event::SessionStopped,
                (_, other) => Event::Failed(format!("unexpected reply: {other:?}")),
            },
        };
        let _ = events.send_blocking(event);
    });
}

fn fetch_invitation(ui: &Rc<Ui>, copy: bool) {
    let socket = ui.socket.clone();
    let events = ui.events.clone();
    std::thread::spawn(move || {
        let event = match ipc::blocking::request(&socket, &Request::Invite).and_then(ipc::expect_ok)
        {
            Ok(Response::Session(session)) => Event::InvitationFetched { session, copy },
            Ok(other) => Event::Failed(format!("unexpected reply: {other:?}")),
            Err(e) => Event::Failed(format!("{e:#}")),
        };
        let _ = events.send_blocking(event);
    });
}

/// Write the whole model onto the widgets.
///
/// The only function that sets widget state, so there is no "did I remember
/// to refresh this" question to get wrong.
fn render(ui: &Rc<Ui>) {
    let model = ui.model.borrow();
    let w = &ui.widgets;

    w.heading.set_label(model.heading());
    w.detail.set_label(&model.detail());

    match &model.message {
        Some(message) => {
            w.message.set_label(&message.text);
            if message.is_error {
                w.message.remove_css_class("dim-label");
                w.message.add_css_class("error");
                eprintln!("swayshare: {}", message.text);
            } else {
                w.message.remove_css_class("error");
                w.message.add_css_class("dim-label");
            }
        }
        None => w.message.set_label(""),
    }

    w.enable_button.set_sensitive(model.can_enable());
    w.stop_button.set_sensitive(model.can_stop());
    w.copy_button.set_sensitive(model.can_copy());

    // Only touch the buffer when it would actually change: rewriting it every
    // second would fight the user's scroll position.
    let invitation = model.invitation();
    let buffer = w.invitation.buffer();
    let (start, end) = buffer.bounds();
    if buffer.text(&start, &end, false) != invitation {
        buffer.set_text(&invitation);
    }

    if *ui.shown_peers.borrow() != model.peers {
        drop(model);
        rebuild_peer_list(ui);
    }
}

/// Rebuild the peer rows, preserving the model's selection.
fn rebuild_peer_list(ui: &Rc<Ui>) {
    let model = ui.model.borrow();
    let list = &ui.widgets.peer_list;

    // Tearing rows down makes GTK emit row-selected; ignore it, because the
    // user did not do it and the model already knows what is selected.
    ui.rebuilding.set(true);
    while let Some(child) = list.first_child() {
        list.remove(&child);
    }

    for row in model.peer_rows() {
        let line = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(12)
            .margin_top(6)
            .margin_bottom(6)
            .margin_start(8)
            .margin_end(8)
            .build();
        line.append(&gtk::Label::builder().label(row.name).xalign(0.0).build());
        line.append(
            &gtk::Label::builder()
                .label(&row.cidr)
                .xalign(0.0)
                .css_classes(["dim-label"])
                .build(),
        );
        // Name the risk in the list itself, not only on failure.
        if let Some(note) = row.note {
            line.append(&gtk::Box::builder().hexpand(true).build());
            line.append(
                &gtk::Label::builder()
                    .label(note)
                    .css_classes(["warning", "dim-label"])
                    .build(),
            );
        }
        list.append(&gtk::ListBoxRow::builder().child(&line).build());
    }

    if let Some(index) = model.selected
        && let Some(row) = list.row_at_index(index as i32)
    {
        list.select_row(Some(&row));
    }
    ui.rebuilding.set(false);

    *ui.shown_peers.borrow_mut() = model.peers.clone();
}

fn wire(ui: &Rc<Ui>) {
    macro_rules! on {
        ($widget:expr, $connect:ident, $make:expr) => {{
            let ui = Rc::clone(ui);
            #[allow(clippy::redundant_closure_call)]
            $widget.clone().$connect(move |_| {
                let make: fn(&Rc<Ui>) -> Event = $make;
                apply(&ui, make(&ui));
            });
        }};
    }

    on!(ui.widgets.add_button, connect_clicked, |ui| {
        Event::AddClicked {
            name: ui.widgets.name_entry.text().to_string(),
            cidr: ui.widgets.cidr_entry.text().to_string(),
        }
    });
    on!(ui.widgets.cidr_entry, connect_activate, |ui| {
        Event::AddClicked {
            name: ui.widgets.name_entry.text().to_string(),
            cidr: ui.widgets.cidr_entry.text().to_string(),
        }
    });
    on!(ui.widgets.remove_button, connect_clicked, |_| {
        Event::RemoveClicked
    });
    on!(ui.widgets.enable_button, connect_clicked, |_| {
        Event::EnableClicked
    });
    on!(ui.widgets.stop_button, connect_clicked, |_| {
        Event::StopClicked
    });
    on!(ui.widgets.copy_button, connect_clicked, |_| {
        Event::CopyClicked
    });
    on!(ui.widgets.minutes, connect_value_changed, |ui| {
        Event::MinutesChanged(ui.widgets.minutes.value().round() as u64)
    });
    on!(ui.widgets.view_only, connect_toggled, |ui| {
        Event::ViewOnlyToggled(ui.widgets.view_only.is_active())
    });

    // The certificate is the one thing a helper needs that is not in the
    // invitation text, and it lives somewhere nobody should have to go
    // looking for. So it is draggable: pick it up here, drop it in a chat.
    {
        let drag = gtk::DragSource::new();
        drag.set_actions(gdk::DragAction::COPY);
        // Drag a snapshot of the handle itself, so what the pointer carries
        // is recognisably the thing that was picked up.
        drag.set_icon(
            Some(&gtk::WidgetPaintable::new(Some(&ui.widgets.cert_drag))),
            0,
            0,
        );
        let for_errors = Rc::clone(ui);
        drag.connect_prepare(move |_, _, _| {
            // A gdk::FileList and not hand-rolled text/uri-list: GTK's own
            // serialisers for it include the document-portal path, which is
            // what lets a sandboxed chat client read what it is handed.
            match Identity::export_pem() {
                Ok(path) => {
                    let files = gdk::FileList::from_array(&[gio::File::for_path(path)]);
                    Some(gdk::ContentProvider::for_value(&files.to_value()))
                }
                Err(e) => {
                    // Returning None just means nothing is dragged, which on
                    // its own looks like the window ignoring the gesture.
                    post(&for_errors, Event::Failed(format!("{e:#}")));
                    None
                }
            }
        });
        ui.widgets.cert_drag.add_controller(drag);
    }

    {
        let ui = Rc::clone(ui);
        ui.widgets
            .peer_list
            .clone()
            .connect_row_selected(move |_, row| {
                if ui.rebuilding.get() {
                    return;
                }
                let index = row.map(|r| r.index()).filter(|i| *i >= 0);
                apply(&ui, Event::SelectionChanged(index.map(|i| i as usize)));
            });
    }
}

fn layout(ui: &Rc<Ui>) -> gtk::Box {
    let w = &ui.widgets;
    let root = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(16)
        .margin_top(16)
        .margin_bottom(16)
        .margin_start(16)
        .margin_end(16)
        .build();

    let status_box = padded_box(gtk::Orientation::Vertical, 4);
    status_box.append(&w.heading);
    status_box.append(&w.detail);
    let buttons = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(8)
        .margin_top(8)
        .build();
    buttons.append(&w.stop_button);
    buttons.append(&w.copy_button);
    buttons.append(&gtk::Frame::builder().child(&w.cert_drag).build());
    status_box.append(&buttons);
    root.append(
        &gtk::Frame::builder()
            .label("Status")
            .child(&status_box)
            .build(),
    );

    let peers_box = padded_box(gtk::Orientation::Vertical, 8);
    peers_box.append(
        &gtk::ScrolledWindow::builder()
            .child(&w.peer_list)
            .vexpand(true)
            .min_content_height(140)
            .has_frame(true)
            .build(),
    );
    let add_row = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(8)
        .build();
    add_row.append(&w.name_entry);
    add_row.append(&w.cidr_entry);
    add_row.append(&w.add_button);
    peers_box.append(&add_row);
    let remove_row = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .build();
    remove_row.append(&w.remove_button);
    peers_box.append(&remove_row);
    root.append(
        &gtk::Frame::builder()
            .label("Peers")
            .child(&peers_box)
            .build(),
    );

    let grant_box = padded_box(gtk::Orientation::Horizontal, 8);
    grant_box.append(&gtk::Label::new(Some("Minutes:")));
    grant_box.append(&w.minutes);
    grant_box.append(&w.view_only);
    grant_box.append(&gtk::Box::builder().hexpand(true).build());
    grant_box.append(&w.enable_button);
    root.append(
        &gtk::Frame::builder()
            .label("Grant access")
            .child(&grant_box)
            .build(),
    );

    root.append(
        &gtk::Frame::builder()
            .label("Invitation")
            .child(
                &gtk::ScrolledWindow::builder()
                    .child(&w.invitation)
                    .min_content_height(170)
                    .build(),
            )
            .build(),
    );
    root.append(&w.message);
    root
}

fn padded_box(orientation: gtk::Orientation, spacing: i32) -> gtk::Box {
    gtk::Box::builder()
        .orientation(orientation)
        .spacing(spacing)
        .margin_top(8)
        .margin_bottom(8)
        .margin_start(8)
        .margin_end(8)
        .build()
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
