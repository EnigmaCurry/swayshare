//! Desktop notifications for the events the user must not miss.
//!
//! Every call is best-effort: a missing notification daemon must never affect
//! whether sharing starts or stops.

fn send(summary: String, body: String, critical: bool) {
    // notify-rust talks D-Bus synchronously; keep it off the event loop.
    tokio::task::spawn_blocking(move || {
        let mut n = notify_rust::Notification::new();
        n.summary(&summary)
            .body(&body)
            .appname("swayshare")
            .icon("video-display");
        if critical {
            n.urgency(notify_rust::Urgency::Critical);
        }
        let _ = n.show();
    });
}

pub fn session_started(peer: &str, listen: &str) {
    send(
        "Remote access enabled".into(),
        format!("Waiting for {peer} to take the controls on {listen}."),
        false,
    );
}

pub fn client_connected(peer: &str, ip: &str) {
    // The one notification that must not be missed: from here on, someone
    // else's keystrokes land in this session.
    send(
        "Someone is controlling your desktop".into(),
        format!("{peer} connected from {ip} and now has keyboard and pointer control."),
        true,
    );
}

pub fn client_disconnected(peer: &str) {
    send(
        "You have the controls back".into(),
        format!("{peer} has disconnected."),
        false,
    );
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
