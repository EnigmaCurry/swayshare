#!/usr/bin/env bash
#
# Verify the GTK4 configuration window under a headless Sway.
#
# Scope note: a headless wlroots seat has no input devices (`swaymsg -t
# get_seats` reports capabilities 0), so neither Sway's cursor IPC nor the
# virtual-keyboard protocol can deliver events to the client. Synthetic
# clicking is therefore not possible here. What this script does check is that
# the window maps, renders, and tracks the daemon's state - the poll path that
# connects the UI to the rest of the system. The logic behind each control
# (CIDR parsing, the breadth policy, config writes, the control protocol) is
# covered by unit and integration tests instead.
#
# It runs under `dbus-run-session`, for the same reason the tray suite does:
# a GtkApplication is single-instance per application ID on the session bus,
# so on a developer's own desktop - where a swayshare window is quite likely
# to be open already - launching one here would hand off to that window and
# exit without ever mapping one of its own. The failure looks exactly like
# the window being broken.
#
# Usage:  nix develop -c ./scripts/gui-smoke.sh
set -u

if [ -z "${SWAYSHARE_GUI_SMOKE_BUS:-}" ]; then
  command -v dbus-run-session >/dev/null \
    || { echo "dbus-run-session is required (try: nix develop)"; exit 1; }
  export SWAYSHARE_GUI_SMOKE_BUS=1
  exec dbus-run-session -- "$0" "$@"
fi

BIN=${SWAYSHARE_BIN:-$(dirname "$0")/../target/debug/swayshare}
BIN=$(realpath "$BIN")
PORT=${SWAYSHARE_TEST_PORT:-15902}
SHOTS=${SWAYSHARE_SHOT_DIR:-/tmp/swayshare-gui-shots}
FAILURES=0

pass() { echo "  PASS: $*"; }
fail() { echo "  FAIL: $*"; FAILURES=$((FAILURES + 1)); }

for tool in wayvnc sway grim swaymsg; do
  command -v "$tool" >/dev/null || { echo "$tool is required (try: nix develop)"; exit 1; }
done
[ -x "$BIN" ] || { echo "no swayshare binary at $BIN"; exit 1; }

SB=$(mktemp -d /tmp/ss-gui.XXXXXX)
mkdir -p "$SB"/{config,data,run} "$SHOTS"
export XDG_CONFIG_HOME="$SB/config" XDG_DATA_HOME="$SB/data" XDG_RUNTIME_DIR="$SB/run"

cleanup() {
  "$BIN" quit >/dev/null 2>&1
  [ -n "${SWAY_PID:-}" ] && kill "$SWAY_PID" 2>/dev/null
  sleep 0.3
  rm -rf "$SB"
}
trap cleanup EXIT

echo "== headless sway =="
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
[ -n "${WAYLAND_DISPLAY:-}" ] || { echo "sway never came up"; cat "$SB/sway.log"; exit 1; }
export SWAYSOCK=$(ls "$XDG_RUNTIME_DIR"/sway-ipc.* 2>/dev/null | head -1)

# Loopback, so a test connection is actually admitted by the gate: the
# window's connected-but-not-yet-authenticated state cannot be reached
# otherwise, and that is where the one-time password is shown.
"$BIN" add mike 127.0.0.1/32 >/dev/null
python3 - "$XDG_CONFIG_HOME/swayshare/config.toml" "$PORT" <<'PY'
import sys
path, port = sys.argv[1], sys.argv[2]
text = open(path).read().replace(
    "[network]\nport = 5900", f'[network]\naddress = "127.0.0.1"\nport = {port}'
)
open(path, "w").write(text)
PY

"$BIN" daemon > "$SB/daemon.log" 2>&1 &
for _ in $(seq 100); do [ -S "$XDG_RUNTIME_DIR/swayshare/control.sock" ] && break; sleep 0.1; done

echo "== opening the window =="
"$BIN" gui > "$SB/gui.log" 2>&1 &
APP_ID=""
for _ in $(seq 150); do
  APP_ID=$(swaymsg -t get_tree 2>/dev/null | python3 -c "import json,sys
t=json.load(sys.stdin)
def walk(n):
    if n.get('app_id'): print(n['app_id'])
    for c in n.get('nodes',[])+n.get('floating_nodes',[]): walk(c)
walk(t)" | grep swayshare | head -1)
  [ -n "$APP_ID" ] && break
  sleep 0.2
done
if [ "$APP_ID" = "tech.rymcg.swayshare" ]; then
  pass "window mapped as $APP_ID"
else
  fail "the configuration window never appeared"
  if grep -q "built without the configuration window" "$SB/gui.log"; then
    echo "  cause: $BIN was built without the gui feature."
    echo "  A --no-default-features build writes to the same path; run: cargo build"
  fi
  echo "--- gui log ---"; cat "$SB/gui.log"; exit 1
fi
sleep 2.5

shot() { grim "$SHOTS/$1.png" 2>/dev/null; }

# Compare two screenshots: "same" or "different", ignoring PNG metadata by
# decoding to raw pixels.
compare() {
  python3 - "$SHOTS/$1.png" "$SHOTS/$2.png" <<'PY'
import sys, zlib, struct
def raw(path):
    data = open(path, "rb").read()
    out, i = b"", 8
    while i < len(data):
        ln = struct.unpack(">I", data[i:i+4])[0]
        typ = data[i+4:i+8]
        if typ == b"IDAT":
            out += data[i+8:i+8+ln]
        i += 12 + ln
    return zlib.decompress(out)
a, b = raw(sys.argv[1]), raw(sys.argv[2])
if a == b:
    print("same")
else:
    diff = sum(1 for x, y in zip(a, b) if x != y)
    print(f"different ({diff * 100 // max(len(a), 1)}% of bytes)")
PY
}

shot 01-off
if [ -s "$SHOTS/01-off.png" ]; then
  SIZE=$(stat -c%s "$SHOTS/01-off.png")
  [ "$SIZE" -gt 5000 ] && pass "window rendered (${SIZE} byte screenshot)" \
    || fail "screenshot is suspiciously small: ${SIZE} bytes"
else
  fail "no screenshot captured"
fi

echo "== the window must follow a session started elsewhere =="
"$BIN" start mike --minutes 5 >/dev/null 2>&1 || fail "could not start a session from the CLI"
sleep 4          # one poll tick, plus the invitation round trip
shot 02-sharing
RESULT=$(compare 01-off 02-sharing)
case "$RESULT" in
  different*) pass "the window re-rendered when sharing began ($RESULT)" ;;
  *)          fail "the window did not react to the session starting" ;;
esac

echo "== the one-time password appears while someone waits to type it =="
# On a machine with no notification daemon this is the only place the owner
# can read it from, so the session cannot proceed without it. A bare TCP
# connect is exactly what that state looks like: connected, not yet in.
python3 - "$PORT" <<'PROBEPY' &
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
s.recv(12)
time.sleep(8)   # hold it open while the window is inspected
s.close()
PROBEPY
PROBE=$!
sleep 4
shot 04-awaiting
RESULT=$(compare 02-sharing 04-awaiting)
case "$RESULT" in
  different*) pass "the window re-rendered when they connected ($RESULT)" ;;
  *)          fail "the window did not react to a waiting connection" ;;
esac
wait $PROBE 2>/dev/null
sleep 3
shot 05-left
RESULT=$(compare 04-awaiting 05-left)
case "$RESULT" in
  different*) pass "the password row went away when they left ($RESULT)" ;;
  *)          fail "the password row is still showing with nobody waiting" ;;
esac

echo "== and must drop the invitation when the session ends =="
"$BIN" stop >/dev/null 2>&1
sleep 3
shot 03-stopped
RESULT=$(compare 02-sharing 03-stopped)
case "$RESULT" in
  different*) pass "the window re-rendered when sharing stopped ($RESULT)" ;;
  *)          fail "the window still shows the finished session" ;;
esac
RESULT=$(compare 01-off 03-stopped)
case "$RESULT" in
  same) pass "the window returned to exactly its off-state appearance" ;;
  *)    echo "  NOTE: off-state render differs slightly after a session ($RESULT)" ;;
esac

echo "== the window logged nothing alarming =="
# GTK's headless software-rendering warnings are expected here and are not
# swayshare's; only our own messages are interesting.
if grep -E "^swayshare:" "$SB/gui.log" >/dev/null 2>&1; then
  fail "the window reported an error: $(grep -E '^swayshare:' "$SB/gui.log" | head -1)"
else
  pass "no swayshare-level errors"
fi

echo "== the window survives its daemon going away =="
"$BIN" quit >/dev/null 2>&1
sleep 2
if swaymsg -t get_tree 2>/dev/null | grep -q "tech.rymcg.swayshare"; then
  pass "window stays open and degrades to 'off' when the daemon exits"
else
  fail "the window disappeared when the daemon exited"
fi

echo
if [ "$FAILURES" -eq 0 ]; then
  echo "all GUI checks passed (screenshots in $SHOTS)"
else
  echo "$FAILURES GUI check(s) failed"
  echo "--- gui log ---"; cat "$SB/gui.log"
fi
exit "$FAILURES"
