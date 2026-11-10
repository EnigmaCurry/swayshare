//! Command-line interface.
//!
//! Peer management touches the config file directly; everything that affects
//! live access goes through the daemon over the control socket.

use crate::config::{self, Config};
use crate::daemon::{self, Daemon};
use crate::identity::{self, Identity};
use crate::invite;
use crate::ipc::{self, AccessMode, Request, Response};
use crate::paths;
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "swayshare",
    about = "Temporary, peer-scoped remote desktop access for Sway, Hyprland \
             and other wlroots compositors",
    long_about = "swayshare hands one named peer temporary control of your \
                  wlroots (Sway, Hyprland, ...) desktop - screen, keyboard and \
                  pointer, at the same time as you. \
                  wayvnc carries the desktop over a private Unix socket; swayshare \
                  decides who may reach it, when, and for how long.",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Add a peer you would be willing to hand the controls to
    Add {
        /// Short name, e.g. "mike"
        name: String,
        /// Address or range the peer connects from, e.g. 10.0.0.3/32
        cidr: String,
        /// Accept a range wider than a /24
        #[arg(long)]
        force: bool,
    },
    /// Remove a peer
    #[command(visible_alias = "remove")]
    Rm { name: String },
    /// List configured peers
    #[command(visible_alias = "peers")]
    List,
    /// Hand the controls to one peer
    Start {
        name: String,
        /// Let them watch without being able to type or click
        ///
        /// Fixed for the session: wayvnc accepts this only at startup, so it
        /// cannot be changed later without disconnecting them.
        #[arg(long)]
        view_only: bool,
        /// Minutes before access is revoked automatically
        #[arg(long, value_name = "MINUTES")]
        minutes: Option<u64>,
        /// Do not expire the session automatically
        #[arg(long, conflicts_with = "minutes")]
        no_expire: bool,
        /// Fail instead of starting a daemon when none is running
        #[arg(long)]
        no_spawn: bool,
    },
    /// Take the controls back immediately
    Stop,
    /// Show who currently has access
    Status {
        /// Emit JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// Re-print the invitation for the running session
    Invite {
        /// Emit the session as JSON, including the current one-time password
        #[arg(long)]
        json: bool,
    },
    /// Run the supervisor in the foreground
    Daemon,
    /// Run the tray applet (hosts a daemon if none is running)
    Tray,
    /// Open the configuration window
    Gui,
    /// Revoke access and exit the running daemon
    Quit,
    /// Print the TLS certificate the remote viewer needs
    ///
    /// The certificate is public; send it to the person you are inviting.
    /// Their client verifies this machine against it, and strict clients
    /// refuse to connect without it. In Remmina it goes in the "CA
    /// certificate" field - the CRL, client certificate and client key
    /// fields are unused and must be left empty.
    Cert,
    /// Print the config file path
    #[command(name = "config-path")]
    ConfigPath,
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?;
    runtime.block_on(dispatch(cli.command))
}

async fn dispatch(command: Command) -> Result<()> {
    match command {
        Command::Add { name, cidr, force } => add_peer(&name, &cidr, force),
        Command::Rm { name } => remove_peer(&name),
        Command::List => list_peers(),
        Command::Start {
            name,
            view_only,
            minutes,
            no_expire,
            no_spawn,
        } => {
            // `Some(0)` is the wire encoding for "no expiry"; `None` means
            // "use the configured default".
            let minutes = if no_expire { Some(0) } else { minutes };
            let mode = if view_only {
                AccessMode::ViewOnly
            } else {
                AccessMode::Control
            };
            start(&name, minutes, mode, no_spawn).await
        }
        Command::Stop => simple(Request::Stop, "Access revoked.").await,
        Command::Status { json } => status(json).await,
        Command::Invite { json } => show_invite(json).await,
        Command::Cert => show_cert().await,
        Command::Daemon => Daemon::run().await,
        Command::Tray => crate::tray::run().await,
        Command::Gui => run_gui(),
        Command::Quit => simple(Request::Shutdown, "Daemon stopped.").await,
        Command::ConfigPath => {
            println!("{}", paths::config_file()?.display());
            Ok(())
        }
    }
}

/// The configuration window is optional at compile time, so a build without
/// it fails with an explanation rather than an unknown subcommand.
#[cfg(feature = "gui")]
fn run_gui() -> Result<()> {
    crate::gui::run()
}

#[cfg(not(feature = "gui"))]
fn run_gui() -> Result<()> {
    bail!(
        "this swayshare was built without the configuration window \
         (rebuild with the default features to enable it)"
    )
}

fn add_peer(name: &str, cidr: &str, force: bool) -> Result<()> {
    let parsed = config::parse_cidr(cidr)?;
    if let Some(warning) = config::breadth_warning(&parsed) {
        if config::requires_force(&parsed) && !force {
            bail!("{warning}\nRe-run with --force if that is really what you want.");
        }
        eprintln!("warning: {warning}");
    }

    let mut cfg = Config::load()?;
    cfg.add_peer(name, parsed)?;
    cfg.save()?;
    println!("Added peer {name} ({parsed}).");
    Ok(())
}

fn remove_peer(name: &str) -> Result<()> {
    let mut cfg = Config::load()?;
    let peer = cfg.remove_peer(name)?;
    cfg.save()?;
    println!("Removed peer {} ({}).", peer.name, peer.cidr);
    eprintln!("note: this does not stop a session already running for that peer.");
    Ok(())
}

fn list_peers() -> Result<()> {
    let cfg = Config::load()?;
    if cfg.peers.is_empty() {
        println!("No peers configured. Add one with: swayshare add <name> <cidr>");
        return Ok(());
    }
    let width = cfg.peers.iter().map(|p| p.name.len()).max().unwrap_or(4);
    for peer in &cfg.peers {
        let note = match config::breadth_warning(&peer.cidr) {
            Some(_) if config::requires_force(&peer.cidr) => "  (too broad to share)",
            Some(_) => "  (range, not a single host)",
            None => "",
        };
        println!("{:width$}  {}{}", peer.name, peer.cidr, note, width = width);
    }
    Ok(())
}

async fn start(name: &str, minutes: Option<u64>, mode: AccessMode, no_spawn: bool) -> Result<()> {
    let socket = paths::control_socket()?;
    if !daemon_is_running(&socket).await {
        if no_spawn {
            bail!("the swayshare daemon is not running (try: swayshare daemon)");
        }
        spawn_daemon(&socket).await?;
    }

    let req = Request::Start {
        peer: name.to_string(),
        minutes,
        mode,
    };
    match ipc::expect_ok(ipc::request(&socket, &req).await?)? {
        Response::Session(session) => {
            print!("{}", invite::render(&session));
            Ok(())
        }
        other => bail!("unexpected reply from the daemon: {other:?}"),
    }
}

async fn simple(req: Request, message: &str) -> Result<()> {
    let socket = paths::control_socket()?;
    ipc::expect_ok(ipc::request(&socket, &req).await?)?;
    println!("{message}");
    Ok(())
}

async fn status(json: bool) -> Result<()> {
    let socket = paths::control_socket()?;
    // A daemon that is not running is not an error: it means "off", which is
    // exactly what a status bar or keybinding wants to hear.
    let status = if daemon_is_running(&socket).await {
        match ipc::expect_ok(ipc::request(&socket, &Request::Status).await?)? {
            Response::Status(s) => s,
            other => bail!("unexpected reply from the daemon: {other:?}"),
        }
    } else {
        ipc::Status::off()
    };

    if json {
        println!("{}", serde_json::to_string(&status)?);
    } else {
        print!("{}", daemon::render_status(&status));
    }
    Ok(())
}

async fn show_invite(json: bool) -> Result<()> {
    let socket = paths::control_socket()?;
    match ipc::expect_ok(ipc::request(&socket, &Request::Invite).await?)? {
        Response::Session(session) => {
            if json {
                // Carries the live password: the owner can always read their
                // own secret, and scripts need it to drive a real client.
                println!("{}", serde_json::to_string(&session)?);
            } else {
                print!("{}", invite::render(&session));
            }
            Ok(())
        }
        other => bail!("unexpected reply from the daemon: {other:?}"),
    }
}

/// Print the stored certificate, for the owner to pass on to their helper.
///
/// The PEM goes to stdout alone, so redirecting it produces a file a client
/// can use directly; the fingerprint, the name to save it under and any
/// warning are commentary and go to stderr.
async fn show_cert() -> Result<()> {
    let Some(pem) = Identity::stored_pem()? else {
        bail!(
            "no certificate yet - one is generated when the daemon first runs \
             (try: swayshare start <peer>)"
        );
    };
    print!("{pem}");
    eprintln!(
        "swayshare: SHA256:{}",
        identity::fingerprint_from_pem(&pem)?
    );
    // The recipient may be holding certificates from several people, so
    // suggest the name that says which machine this one is for.
    eprintln!("swayshare: save this as {}", identity::export_name());

    // A certificate sent before access is granted may not name the address
    // that gets shared, in which case granting access reissues it and the
    // copy the helper is holding stops verifying. Better to say so than to
    // let them discover it as a handshake failure.
    let socket = paths::control_socket()?;
    if daemon_is_running(&socket).await
        && let Ok(Response::Status(status)) = ipc::request(&socket, &Request::Status).await
        && status.state == ipc::State::Off
    {
        eprintln!(
            "swayshare: nothing is shared right now, so this certificate may still be \
             reissued to cover the address you share from. Send it after 'swayshare start'."
        );
    }
    Ok(())
}

async fn daemon_is_running(socket: &std::path::Path) -> bool {
    tokio::net::UnixStream::connect(socket).await.is_ok()
}

/// Start a detached daemon so `swayshare start` works from a keybinding.
///
/// The child is put in its own process group, so closing the terminal that
/// launched it does not take the session down with it.
async fn spawn_daemon(socket: &std::path::Path) -> Result<()> {
    use std::os::unix::process::CommandExt;

    let exe = std::env::current_exe().context("locating the swayshare executable")?;
    let log_path: PathBuf = paths::runtime_dir()?.join("daemon.log");
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("opening {}", log_path.display()))?;

    let mut cmd = std::process::Command::new(exe);
    cmd.arg("daemon")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(log.try_clone()?))
        .stderr(std::process::Stdio::from(log));
    cmd.process_group(0);
    cmd.spawn().context("starting the swayshare daemon")?;

    // Wait for the control socket rather than guessing at a fixed delay.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if daemon_is_running(socket).await {
            eprintln!(
                "note: started a swayshare daemon; its log is at {}",
                log_path.display()
            );
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    bail!(
        "the swayshare daemon did not come up within 5s; see {}",
        log_path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_the_documented_invocations() {
        use clap::CommandFactory;
        Cli::command().debug_assert();

        let cli = Cli::try_parse_from(["swayshare", "add", "mike", "10.0.0.3/32"]).unwrap();
        assert!(matches!(cli.command, Command::Add { .. }));

        let cli = Cli::try_parse_from(["swayshare", "start", "mike", "--minutes", "30"]).unwrap();
        match cli.command {
            Command::Start { name, minutes, .. } => {
                assert_eq!(name, "mike");
                assert_eq!(minutes, Some(30));
            }
            other => panic!("unexpected: {other:?}"),
        }

        let cli = Cli::try_parse_from(["swayshare", "start", "mike", "--view-only"]).unwrap();
        match cli.command {
            Command::Start { view_only, .. } => assert!(view_only),
            other => panic!("unexpected: {other:?}"),
        }
        let cli = Cli::try_parse_from(["swayshare", "start", "mike"]).unwrap();
        match cli.command {
            Command::Start { view_only, .. } => {
                assert!(!view_only, "full control is the default")
            }
            other => panic!("unexpected: {other:?}"),
        }

        assert!(Cli::try_parse_from(["swayshare", "status"]).is_ok());
        assert!(Cli::try_parse_from(["swayshare", "tray"]).is_ok());
        assert!(Cli::try_parse_from(["swayshare", "gui"]).is_ok());
        assert!(Cli::try_parse_from(["swayshare", "stop"]).is_ok());
        // --minutes and --no-expire are contradictory.
        assert!(
            Cli::try_parse_from([
                "swayshare",
                "start",
                "mike",
                "--minutes",
                "5",
                "--no-expire"
            ])
            .is_err()
        );
    }
}
