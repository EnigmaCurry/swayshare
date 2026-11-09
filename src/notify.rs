//! Desktop notifications for the events the user must not miss.
//!
//! Every call is best-effort: a missing notification daemon must never affect
//! whether sharing starts or stops.

use crate::ipc::AccessMode;
use std::sync::atomic::{AtomicU32, Ordering};

/// Server-assigned id of the last notification we posted, or 0 for none yet.
///
/// Reusing it as the next notification's `replaces_id` makes the series
/// collapse into a single, updating bubble instead of a growing stack: the
/// events swayshare reports (connecting, authenticated, disconnected) are a
/// timeline where only the latest state matters.
static LAST_ID: AtomicU32 = AtomicU32::new(0);

fn send(summary: String, body: String, critical: bool) {
    // notify-rust talks D-Bus synchronously; keep it off the event loop.
    tokio::task::spawn_blocking(move || {
        let mut n = notify_rust::Notification::new();
        n.summary(&summary)
            .body(&body)
            .appname("swayshare")
            .icon("video-display");
        // Replace the previous bubble rather than add to it. A stale id (its
        // notification already dismissed) is harmless: the server just posts a
        // fresh one.
        let prev = LAST_ID.load(Ordering::Relaxed);
        if prev != 0 {
            n.id(prev);
        }
        if critical {
            n.urgency(notify_rust::Urgency::Critical);
        }
        if let Ok(handle) = n.show() {
            LAST_ID.store(handle.id(), Ordering::Relaxed);
        }
    });
}

pub fn session_started(peer: &str, listen: &str, mode: AccessMode) {
    let what = match mode {
        AccessMode::Control => "take the controls",
        AccessMode::ViewOnly => "connect (view only)",
    };
    send(
        "Remote access enabled".into(),
        format!("Waiting for {peer} to {what} on {listen}."),
        false,
    );
}

pub fn client_connecting(peer: &str, ip: &str, password: &str) {
    // A connection has opened but the password has not been checked yet, so
    // nothing is shared or injected until it is. This is the popup the owner
    // acts on: it carries the one-time password to read aloud to the person on
    // the phone. Critical urgency so it stays up long enough to dictate, and
    // because handing it out is the deliberate decision to grant access.
    send(
        format!("{peer} is connecting from {ip}"),
        format!(
            "Read this one-time password to let them in:\n\n    {password}\n\n\
             Only share it with the person you trust. Nothing is on screen \
             until they enter it."
        ),
        true,
    );
}

pub fn client_authenticated(peer: &str, mode: AccessMode) {
    // The notification that must not be missed: the peer has passed the
    // password and is now actually in. It names what they can do, because
    // "authenticated" alone does not tell you whether your keyboard is shared.
    let (summary, body) = match mode {
        AccessMode::Control => (
            "Someone is controlling your desktop",
            format!("{peer} authenticated and now has keyboard and pointer control."),
        ),
        AccessMode::ViewOnly => (
            "Someone is watching your screen",
            format!("{peer} authenticated. View only - they cannot type or click."),
        ),
    };
    send(summary.into(), body, true);
}

pub fn client_left(peer: &str, mode: AccessMode) {
    let summary = match mode {
        AccessMode::Control => "You have the controls back",
        AccessMode::ViewOnly => "Nobody is watching",
    };
    send(summary.into(), format!("{peer} has disconnected."), false);
}

pub fn rejected(ip: &str, reason: &str) {
    send(
        "Connection refused".into(),
        format!("{ip} was refused: {reason}."),
        false,
    );
}

pub fn session_stopped(reason: &str) {
    send(
        "Remote access revoked".into(),
        format!("Access ended: {reason}."),
        false,
    );
}
