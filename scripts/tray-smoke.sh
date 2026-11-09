#!/usr/bin/env bash
#
# Verify the tray applet over D-Bus, on an isolated session bus.
#
# Checks that the StatusNotifierItem really is exported and that it reflects
# the daemon's state: the icon changes when sharing starts, the item asks for
# attention while someone is connected, and the menu enables/disables the
# right entries.
#
# It runs under `dbus-run-session`, so it never registers an icon on your real
# session bus or disturbs your actual tray.
#
# Usage:  nix shell nixpkgs#wayvnc --command ./scripts/tray-smoke.sh
set -u

BIN=${SWAYSHARE_BIN:-$(dirname "$0")/../target/debug/swayshare}
BIN=$(realpath "$BIN")
PORT=${SWAYSHARE_TEST_PORT:-15901}
FAILURES=0

pass() { echo "  PASS: $*"; }
fail() { echo "  FAIL: $*"; FAILURES=$((FAILURES + 1)); }

[ -x "$BIN" ] || { echo "no swayshare binary at $BIN; run cargo build first"; exit 1; }
command -v busctl >/dev/null || { echo "busctl is required"; exit 1; }
command -v dbus-run-session >/dev/null || { echo "dbus-run-session is required"; exit 1; }

# Everything below runs inside a private bus.
CLIENT=$(realpath "$(dirname "$0")/vnc_client.py")

exec dbus-run-session -- bash -s "$BIN" "$PORT" "$CLIENT" <<'INNER'
set -u
BIN=$1
PORT=$2
# Passed in because $0 is "bash" inside `bash -s`, so dirname would be wrong.
CLIENT=$3
FAILURES=0
pass() { echo "  PASS: $*"; }
fail() { echo "  FAIL: $*"; FAILURES=$((FAILURES + 1)); }

SB=$(mktemp -d /tmp/swayshare-tray.XXXXXX)
export XDG_CONFIG_HOME="$SB/config" XDG_DATA_HOME="$SB/data" XDG_RUNTIME_DIR="$SB/run"
mkdir -p "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_RUNTIME_DIR"

cleanup() {
  [ -n "${TRAY_PID:-}" ] && kill "$TRAY_PID" 2>/dev/null
  [ -n "${SWAY_PID:-}" ] && kill "$SWAY_PID" 2>/dev/null
  sleep 0.3
  rm -rf "$SB"
}
trap cleanup EXIT

echo "== private session bus: ${DBUS_SESSION_BUS_ADDRESS%%,*} =="

# A headless sway, so a real session can actually be started.
if command -v wayvnc >/dev/null && command -v sway >/dev/null; then
  echo "set \$mod Mod4" > "$SB/sway.conf"
  WLR_BACKENDS=headless WLR_LIBINPUT_NO_DEVICES=1 WLR_RENDERER=pixman \
    sway --config "$SB/sway.conf" > "$SB/sway.log" 2>&1 &
  SWAY_PID=$!
  for _ in $(seq 100); do
    for sock in "$XDG_RUNTIME_DIR"/wayland-*; do
      case "$sock" in *.lock) continue ;; esac
      if [ -S "$sock" ]; then export WAYLAND_DISPLAY="$(basename "$sock")"; break 2; fi
    done
    sleep 0.1
  done
  LIVE=${WAYLAND_DISPLAY:+yes}
else
  LIVE=""
  echo "  (wayvnc/sway unavailable: checking the off state only)"
fi

"$BIN" add tester 127.0.0.1/32 >/dev/null
python3 - "$XDG_CONFIG_HOME/swayshare/config.toml" "$PORT" <<'PY'
import sys
path, port = sys.argv[1], sys.argv[2]
text = open(path).read().replace(
    "[network]\nport = 5900", f'[network]\naddress = "127.0.0.1"\nport = {port}'
)
open(path, "w").write(text)
PY

echo "== starting the tray (it should host a daemon itself) =="
"$BIN" tray > "$SB/tray.log" 2>&1 &
TRAY_PID=$!

# Wait for the item to claim its well-known name on the bus.
SNI=""
for _ in $(seq 100); do
  SNI=$(busctl --user --list --no-legend --no-pager 2>/dev/null \
        | awk '{print $1}' | grep '^org.kde.StatusNotifierItem-' | head -1)
  [ -n "$SNI" ] && break
  sleep 0.1
done
if [ -z "$SNI" ]; then
  fail "no StatusNotifierItem appeared on the bus"
  echo "--- tray log ---"; cat "$SB/tray.log"
  exit 1
fi
pass "item registered as $SNI"

prop() {
  busctl --user --no-pager get-property "$SNI" /StatusNotifierItem \
    org.kde.StatusNotifierItem "$1" 2>/dev/null
}
# Hash the pixmap bytes so we can tell icons apart without printing them.
icon_digest() {
  busctl --user --no-pager get-property "$SNI" /StatusNotifierItem \
    org.kde.StatusNotifierItem IconPixmap 2>/dev/null | sha256sum | cut -c1-16
}
# Dump the dbusmenu layout as text. Recursion depth is a positive number
# because both busctl and gdbus would parse the spec's "-1" as an option.
menu_layout() {
  busctl --user --no-pager call "$SNI" /MenuBar com.canonical.dbusmenu \
    GetLayout iias 0 5 0 2>/dev/null
}

echo "== off state =="
[ "$(prop Id)" = 's "swayshare"' ] && pass "Id is swayshare" || fail "unexpected Id: $(prop Id)"
case "$(prop Status)" in
  *Active*) pass "Status is Active (host must not hide the icon)" ;;
  *) fail "unexpected Status: $(prop Status)" ;;
esac
ICON_OFF=$(icon_digest)
[ -n "$ICON_OFF" ] && pass "IconPixmap is exported ($ICON_OFF)" || fail "no IconPixmap"

LAYOUT_OFF=$(menu_layout)
if [ -z "$LAYOUT_OFF" ]; then
  fail "the dbusmenu layout could not be read"
else
  echo "$LAYOUT_OFF" | grep -q "Remote access off" && pass "menu header says 'Remote access off'" \
    || fail "menu header missing"
  echo "$LAYOUT_OFF" | grep -q "Hand the controls to" \
    && pass "full-control submenu present" || fail "full-control submenu missing"
  echo "$LAYOUT_OFF" | grep -q "Grant view-only access to" \
    && pass "view-only submenu present" || fail "view-only submenu missing"
  echo "$LAYOUT_OFF" | grep -q "tester" && pass "configured peer is listed" \
    || fail "peer 'tester' not listed"
  echo "$LAYOUT_OFF" | grep -q "revokes access" && pass "quit warns about revocation" \
    || fail "quit entry missing"
fi

if [ -n "$LIVE" ]; then
  echo "== starting a real session; the item must react =="
  "$BIN" start tester --minutes 5 >/dev/null 2>&1 || fail "could not start a session"
  # The tray polls once a second.
  sleep 2.5

  ICON_ON=$(icon_digest)
  [ "$ICON_ON" != "$ICON_OFF" ] && pass "icon changed when sharing started ($ICON_ON)" \
    || fail "icon did not change when sharing started"

  LAYOUT_ON=$(menu_layout)
  echo "$LAYOUT_ON" | grep -q "Waiting for tester to connect" \
    && pass "menu header tracks the session" || fail "menu header did not update"

  echo "== connect, and the item should demand attention =="
  python3 - "$PORT" <<'PY' &
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
s.recv(12)
time.sleep(6)   # hold the connection open while the tray is inspected
s.close()
PY
  VIEWER=$!
  sleep 3
  case "$(prop Status)" in
    *NeedsAttention*) pass "Status is NeedsAttention while connected" ;;
    *) fail "expected NeedsAttention while connected, got: $(prop Status)" ;;
  esac
  ICON_CONN=$(icon_digest)
  [ "$ICON_CONN" != "$ICON_ON" ] && pass "icon changed again on connect ($ICON_CONN)" \
    || fail "icon did not change on connect"
  echo "$(menu_layout)" | grep -q "has the controls" \
    && pass "menu says who has the controls" || fail "menu did not report the connected peer"
  wait $VIEWER 2>/dev/null

  echo "== a view-only session must look different from a control session =="
  "$BIN" stop >/dev/null 2>&1
  sleep 1.5
  "$BIN" start tester --minutes 5 --view-only >/dev/null 2>&1 \
    || fail "could not start a view-only session"
  sleep 2.5
  ICON_VIEW_WAIT=$(icon_digest)
  python3 "$CLIENT" --port "$PORT" \
    --password "$("$BIN" invite | grep '^Password:' | awk '{print $2}')" \
    --ca "$XDG_DATA_HOME/swayshare/tls/cert.pem" --hold 6 >/dev/null 2>&1 &
  VIEWER2=$!
  sleep 3
  ICON_VIEW_CONN=$(icon_digest)
  [ "$ICON_VIEW_CONN" != "$ICON_CONN" ] \
    && pass "connected view-only icon differs from connected-with-control ($ICON_VIEW_CONN)" \
    || fail "view-only and full control look identical in the tray"
  [ "$ICON_VIEW_CONN" != "$ICON_VIEW_WAIT" ] \
    && pass "the icon still changes on connect in view-only mode" \
    || fail "the icon did not change when the view-only peer connected"
  echo "$(menu_layout)" | grep -q "is watching" \
    && pass "menu says they are watching, not driving" \
    || fail "menu did not distinguish watching from driving"
  wait $VIEWER2 2>/dev/null

  echo "== stop =="
  "$BIN" stop >/dev/null 2>&1
  sleep 2.5
  [ "$(icon_digest)" = "$ICON_OFF" ] && pass "icon returned to the off glyph" \
    || fail "icon did not return to off"
  case "$(prop Status)" in
    *Active*) pass "Status back to Active" ;;
    *) fail "unexpected Status after stop: $(prop Status)" ;;
  esac
fi

echo "== quitting the tray must revoke and take the daemon with it =="
"$BIN" quit >/dev/null 2>&1
sleep 1
kill -0 "$TRAY_PID" 2>/dev/null && fail "the tray process is still running" \
  || pass "tray exited"
[ -S "$XDG_RUNTIME_DIR/swayshare/control.sock" ] \
  && fail "the control socket outlived the daemon" || pass "daemon is gone"
pgrep -x -u "$(id -u)" wayvnc >/dev/null && fail "wayvnc outlived the tray" \
  || pass "wayvnc is not running"

echo
if [ "$FAILURES" -eq 0 ]; then
  echo "all tray checks passed"
else
  echo "$FAILURES tray check(s) failed"
  echo "--- tray log ---"; cat "$SB/tray.log"
fi
exit "$FAILURES"
INNER
