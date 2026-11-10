//! Rendering of the invitation the user sends to their helper.

use crate::ipc::{AccessMode, Session};

/// Format the connection details as a block the user can paste into a chat.
///
/// The fingerprint is included so the remote user can confirm they are
/// talking to the same machine as last time.
pub fn render(session: &Session) -> String {
    let mut out = String::new();
    out.push_str("Remote support invitation\n");
    out.push_str("-------------------------\n");
    out.push_str("Client:   TigerVNC, Remmina, or any VeNCrypt-capable client\n");
    out.push_str(&format!("Address:  {}:{}\n", session.address, session.port));
    out.push_str(&format!("Username: {}\n", session.username));
    out.push_str(&format!("TLS cert: SHA256:{}\n", session.fingerprint));
    // The password is deliberately absent: it is a one-time secret minted when
    // you connect and read aloud, different every time. See the note below.
    out.push_str("Password: I will read it to you when you connect\n");
    out.push('\n');
    // Say plainly what the recipient is being handed, so they know whether
    // they are driving or watching before they connect.
    match session.mode {
        AccessMode::Control => {
            out.push_str("You will have full control of the screen, keyboard and pointer,\n");
            out.push_str("at the same time as me.\n");
        }
        AccessMode::ViewOnly => {
            out.push_str("This is a view-only session: you will see my screen, but\n");
            out.push_str("your keyboard and mouse will not reach it.\n");
        }
    }
    out.push('\n');
    // Without the certificate a strict client cannot verify us and simply
    // refuses; and the one real trap is that clients ask for up to four
    // certificate files when only this one is used, so say so outright.
    out.push_str("I will also send you swayshare.pem - the certificate your client\n");
    out.push_str("checks this machine against. Compare its fingerprint with the one\n");
    out.push_str("above. Only one field wants it: in Remmina that is \"CA certificate\",\n");
    out.push_str("and the CRL, client certificate and client key fields must be left\n");
    out.push_str("empty.\n");
    out.push('\n');
    out.push_str("Connect through the VPN tunnel. When you connect I will read\n");
    out.push_str("you a one-time password to type in - it is different every\n");
    out.push_str("time. Only connections from your own address are accepted\n");
    out.push_str(&format!("({}).\n", session.cidr));
    if let Some(secs) = session.expires_in_seconds {
        out.push_str(&format!(
            "Access expires automatically in {}.\n",
            humanize(secs)
        ));
    }
    out
}

/// A short, human-readable duration: "45m", "1h 30m", "20s".
pub fn humanize(seconds: u64) -> String {
    let h = seconds / 3600;
    let m = (seconds % 3600) / 60;
    let s = seconds % 60;
    if h > 0 && m > 0 {
        format!("{h}h {m}m")
    } else if h > 0 {
        format!("{h}h")
    } else if m > 0 {
        format!("{m}m")
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Session {
        Session {
            peer: "mike".into(),
            cidr: "10.0.0.3/32".into(),
            address: "10.0.0.10".into(),
            port: 5900,
            username: "support".into(),
            password: "ABCDEFGH".into(),
            fingerprint: "AA:BB:CC".into(),
            mode: AccessMode::Control,
            expires_in_seconds: Some(3600),
        }
    }

    #[test]
    fn invitation_contains_everything_needed_to_connect() {
        let text = render(&session());
        assert!(text.contains("10.0.0.10:5900"));
        assert!(text.contains("support"));
        assert!(text.contains("SHA256:AA:BB:CC"));
        assert!(text.contains("10.0.0.3/32"));
        assert!(text.contains("expires automatically in 1h"));
    }

    #[test]
    fn the_invitation_explains_the_certificate_and_which_field_takes_it() {
        // A helper cannot guess either of these, and getting the second one
        // wrong is what makes a working setup look like a broken client.
        let text = render(&session());
        assert!(
            text.contains("swayshare.pem"),
            "the invitation must say a certificate is coming: {text}"
        );
        assert!(
            text.contains("CA certificate"),
            "it must name the field the certificate goes in: {text}"
        );
        assert!(
            text.contains("must be left\nempty"),
            "it must say the other certificate fields stay empty: {text}"
        );
    }

    #[test]
    fn the_invitation_never_prints_the_live_password() {
        // The password is a per-connection secret the owner reads aloud; it
        // must not leak into a pasteable invitation.
        let text = render(&session());
        assert!(
            !text.contains("ABCDEFGH"),
            "the live password must not appear in the invitation: {text}"
        );
        assert!(text.contains("one-time password"));
    }

    #[test]
    fn the_invitation_says_whether_they_can_type() {
        let control = render(&session());
        assert!(
            control.contains("full control"),
            "a control invitation must say so: {control}"
        );
        assert!(!control.contains("view-only"));

        let mut view = session();
        view.mode = AccessMode::ViewOnly;
        let text = render(&view);
        assert!(
            text.contains("view-only"),
            "a view-only invitation must say so: {text}"
        );
        assert!(
            text.contains("will not reach"),
            "it should be explicit that their input is dropped: {text}"
        );
        assert!(!text.contains("full control"));
    }

    #[test]
    fn expiry_line_is_omitted_when_there_is_none() {
        let mut s = session();
        s.expires_in_seconds = None;
        assert!(!render(&s).contains("expires"));
    }

    #[test]
    fn durations_read_naturally() {
        assert_eq!(humanize(20), "20s");
        assert_eq!(humanize(60), "1m");
        assert_eq!(humanize(2700), "45m");
        assert_eq!(humanize(3600), "1h");
        assert_eq!(humanize(5400), "1h 30m");
    }
}
