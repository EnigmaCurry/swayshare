# swayshare

Temporary, peer-scoped remote desktop access for [Sway](https://swaywm.org) —
a "helping hands" tool for when someone you trust needs to see your screen.

[wayvnc](https://github.com/any1/wayvnc) does the screen sharing. swayshare
decides *who* may reach it, *when*, and for *how long*, and it needs no root
privileges and no firewall changes to do that.

## How it works

wayvnc is started on a Unix-domain socket inside a 0700 runtime directory, so
it has no network presence at all. swayshare binds the only TCP listener and
forwards connections to that socket — but only from the single peer you have
authorised:

```
  Mike's VNC viewer                 your machine
  10.0.0.3                          ┌──────────────────────────────────┐
      │                             │  swayshare gate                  │
      │   existing WireGuard        │  10.0.0.10:5900                  │
      └────────── tunnel ──────────►│    ↓ source in 10.0.0.3/32 ?     │
                                    │    ↓ under the connection limit? │
                                    │  ──────────────────────────────  │
                                    │    ↓ $XDG_RUNTIME_DIR/swayshare/ │
                                    │      vnc.sock  (0700, no TCP)    │
                                    │    ↓                             │
                                    │  wayvnc  →  Sway                 │
                                    └──────────────────────────────────┘
```

The gate forwards bytes verbatim, so wayvnc's own authentication and
encryption run end to end between the viewer and wayvnc. swayshare never holds
the session key material in a form it could use to read the stream.

This is an *additional* restriction layered on top of your VPN and host
firewall, not a replacement for either. The host firewall must already permit
the port over the tunnel.

## Status

Milestone 1 of 3 is complete: a working CLI. The tray applet (milestone 2) and
the configuration GUI (milestone 3) are not written yet.

## Install

On NixOS:

```sh
nix run github:enigmacurry/swayshare -- status      # try it
nix profile install github:enigmacurry/swayshare    # keep it
```

From source — `wayvnc` 0.10 or newer must be on `PATH`:

```sh
cargo build --release
nix develop            # or: nix shell nixpkgs#wayvnc
```

## Quickstart

```sh
# Tell swayshare where to listen. Peers are reached over your own VPN;
# swayshare does not manage the tunnel.
$EDITOR "$(swayshare config-path)"

# Record the people who may be granted access.
swayshare add mike 10.0.0.3/32
swayshare add jane 10.0.0.4          # a bare address becomes a /32
swayshare list

# Grant Mike access for 30 minutes and print an invitation to send him.
swayshare start mike --minutes 30

# Check on it, or revoke it the moment you are done.
swayshare status
swayshare stop
```

`swayshare start` prints everything the remote user needs:

```
Remote support invitation
-------------------------
Viewer:   TigerVNC (or any VeNCrypt-capable client)
Address:  10.0.0.10:5900
Username: support
Password: EXAMPLE0PASSWORD0NOT0REAL0
TLS cert: SHA256:5C:A1:F9:4B:...

Connect through the VPN tunnel. The password is valid for this
session only, and only connections from your own address are
accepted (10.0.0.3/32).
Access expires automatically in 30m.
```

### Sway keybindings

`swayshare start` launches the daemon itself if it is not already running, so
it works straight from a binding:

```
bindsym $mod+Shift+s exec swayshare start mike --minutes 30
bindsym $mod+Shift+x exec swayshare stop
```

`swayshare status --json` is meant for a status bar:

```json
{"state":"connected","peer":"mike","cidr":"10.0.0.3/32",
 "listen":"10.0.0.10:5900","connections":1,"expires_in_seconds":1583}
```

## Configuration

`~/.config/swayshare/config.toml`:

```toml
[network]
# Bind to whichever address this interface currently has. Resolved at every
# session start, so a tunnel that comes and goes is picked up each time.
interface = "wg0"
# ...or pin an address outright. Takes precedence over `interface`.
# address = "10.0.0.10"
port = 5900

[security]
max_connections = 1
default_session_minutes = 60   # 0 disables automatic expiry
username = "support"

[[peers]]
name = "mike"
cidr = "10.0.0.3/32"

[[peers]]
name = "jane"
cidr = "10.0.0.4/32"
```

Session passwords are never written here. They live only in a 0600 file in
`$XDG_RUNTIME_DIR/swayshare/`, which is erased when sharing stops.

If neither `interface` nor `address` is set, swayshare refuses to start a
session rather than falling back to a wildcard bind. The same applies when a
configured interface has no address: a tunnel that is down is reported, never
worked around.

## Security model

What swayshare guarantees:

- **Off by default.** The daemon starts with no listener bound, and returns to
  that state on stop, on expiry, if wayvnc dies, if the gate fails, and on
  exit. There is no path that leaves a listener up without an authorised peer.
- **One peer at a time.** Enabling a different peer tears down the current
  session and mints a new password first.
- **Immediate revocation.** `stop` closes the listener *and* drops
  connections that are already established — it does not wait for the viewer.
- **Fresh credentials per session.** 130 bits of entropy from the system
  CSPRNG, zeroized in memory on drop and deleted from disk on stop.
- **A stable server identity.** The TLS key pair is generated once and kept,
  so the remote user sees the same fingerprint every time and can pin it. Only
  the password rotates.
- **Authentication is not optional.** wayvnc is configured so that the "None"
  security type is never offered; `scripts/e2e-smoke.sh` asserts this against
  a real wayvnc.
- **No privileges.** No root, no setuid, no firewall mutation. Access control
  is entirely in userspace, which is also why it is portable across distros.

What it does **not** do:

- It does not manage your VPN. Peers must already be reachable through it.
- It does not defend against a peer whose address has been taken over by
  someone else. Source-address filtering is only as strong as the tunnel
  underneath it, which is why `/32`s and WireGuard are the intended setup.
- Ranges wider than a `/24` are refused outright; a `/24` warns. "One named
  person" is the unit of trust here, and a subnet is not that.
- It does not restrict what the remote user does once connected. wayvnc grants
  full keyboard and pointer control.

## Testing

```sh
cargo test                     # unit + gate integration tests
nix develop -c ./scripts/e2e-smoke.sh
```

`scripts/e2e-smoke.sh` runs a real wayvnc on a headless Sway and checks the
properties above end to end: that a VNC stream really traverses the gate, that
authentication is enforced, that an unauthorised source receives no bytes at
all, that stop revokes immediately, and that no credentials are left behind.

## Roadmap

1. **CLI** — done.
2. **Tray applet** — a StatusNotifierItem (`ksni`) for Waybar: peer selection,
   a connection indicator and one-click stop.
3. **Configuration GUI** — GTK4 peer editor, invitation copying, expiry
   settings.

Deliberately out of scope: managing the WireGuard tunnel itself.

## License

MIT
