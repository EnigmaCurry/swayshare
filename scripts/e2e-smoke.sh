#!/usr/bin/env bash
#
# End-to-end smoke test against a real wayvnc on a headless Sway.
#
# Checks the properties milestone 1 exists to prove:
#   * a VNC stream really traverses TCP -> gate -> wayvnc's unix socket
#   * wayvnc requires authentication (it must not offer "None" security)
#   * a source address outside the peer's CIDR gets no bytes at all
#   * stop revokes the listener and kills wayvnc immediately
#   * no session credentials are left on disk
#
# Everything runs in a scratch XDG environment on loopback, so it touches
# neither your real config nor your real desktop session.
#
# Usage:  nix shell nixpkgs#wayvnc --command ./scripts/e2e-smoke.sh
set -u

BIN=${SWAYSHARE_BIN:-$(dirname "$0")/../target/debug/swayshare}
BIN=$(realpath "$BIN")
PORT=${SWAYSHARE_TEST_PORT:-15900}
SB=$(mktemp -d /tmp/swayshare-e2e.XXXXXX)
FAILURES=0

pass() { echo "  PASS: $*"; }
fail() { echo "  FAIL: $*"; FAILURES=$((FAILURES + 1)); }

cleanup() {
  "$BIN" quit >/dev/null 2>&1
  [ -n "${SWAY_PID:-}" ] && kill "$SWAY_PID" 2>/dev/null
  sleep 0.3
  rm -rf "$SB"
}
trap cleanup EXIT

export XDG_CONFIG_HOME="$SB/config" XDG_DATA_HOME="$SB/data" XDG_RUNTIME_DIR="$SB/run"
mkdir -p "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_RUNTIME_DIR"

command -v wayvnc >/dev/null || { echo "wayvnc not on PATH; try: nix shell nixpkgs#wayvnc"; exit 1; }
command -v sway   >/dev/null || { echo "sway not on PATH"; exit 1; }
[ -x "$BIN" ] || { echo "no swayshare binary at $BIN; run cargo build first"; exit 1; }

echo "== starting a headless sway =="
# A binding that leaves a trace on disk whenever the keysym 'a' reaches the
# compositor. This is how we tell real input injection from a flag that was
# merely passed to wayvnc.
cat > "$SB/sway.conf" <<EOF
set \$mod Mod4
bindsym a exec touch $SB/KEY_ARRIVED
EOF
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
[ -n "${WAYLAND_DISPLAY:-}" ] || { echo "headless sway never came up:"; cat "$SB/sway.log"; exit 1; }
echo "  WAYLAND_DISPLAY=$WAYLAND_DISPLAY"

echo "== configuring a loopback peer =="
"$BIN" add tester 127.0.0.1/32 >/dev/null
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

echo "== start =="
if ! "$BIN" start tester --minutes 5 > "$SB/invite.txt" 2>&1; then
  echo "could not start a session:"; cat "$SB/invite.txt"; cat "$SB/daemon.log"; exit 1
fi
grep -q "Password:" "$SB/invite.txt" && pass "invitation printed with credentials" \
  || fail "invitation is missing credentials"
"$BIN" status | sed 's/^/  /'

echo "== authorised source reaches wayvnc and is challenged for auth =="
python3 - "$PORT" <<'PY'
import socket, sys
port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), timeout=5)
s.settimeout(5)
try:
    banner = s.recv(12)
    if not banner.startswith(b"RFB "):
        print(f"  FAIL: expected an RFB greeting, got {banner!r}"); sys.exit(1)
    print(f"  PASS: real wayvnc greeting through the gate ({banner.decode().strip()})")

    # Complete the version handshake, then inspect the offered security types.
    s.sendall(b"RFB 003.008\n")
    count = s.recv(1)[0]
    if count == 0:
        print("  FAIL: server refused the connection outright"); sys.exit(1)
    types = set(s.recv(count))
    print(f"  security types offered: {sorted(types)}")
    if 1 in types:
        print("  FAIL: 'None' security is on offer - authentication is NOT enforced")
        sys.exit(1)
    print("  PASS: 'None' security is not offered; authentication is enforced")
    # 19 = VeNCrypt, 5/6 = RSA-AES, 129/130 = RSA-AES-256.
    if types & {19, 5, 6, 129, 130}:
        print("  PASS: an encrypted security type is offered")
    else:
        print("  FAIL: no encrypted security type on offer")
        sys.exit(1)
finally:
    s.close()
PY
[ $? -eq 0 ] || FAILURES=$((FAILURES + 1))

echo "== unauthorised source gets nothing =="
python3 - "$PORT" <<'PY'
import socket, sys
port = int(sys.argv[1])
s = socket.socket()
# 127.0.0.0/8 is all local, so 127.0.0.2 is a real source outside the peer CIDR.
s.bind(("127.0.0.2", 0))
s.settimeout(5)
s.connect(("127.0.0.1", port))
try:
    data = s.recv(12)
    if data == b"":
        print("  PASS: connection closed with no data")
    else:
        print(f"  FAIL: leaked {data!r} to an unauthorised source"); sys.exit(1)
except ConnectionResetError:
    print("  PASS: connection reset, no data")
except socket.timeout:
    print("  FAIL: hung open instead of being refused"); sys.exit(1)
finally:
    s.close()
PY
[ $? -eq 0 ] || FAILURES=$((FAILURES + 1))

echo "== a real client authenticates and its input reaches the desktop =="
CA="$XDG_DATA_HOME/swayshare/tls/cert.pem"
PASSWORD=$(grep '^Password:' "$SB/invite.txt" | awk '{print $2}')
CLIENT="$(dirname "$0")/vnc_client.py"
rm -f "$SB/KEY_ARRIVED"
if python3 "$CLIENT" --port "$PORT" --password "$PASSWORD" --ca "$CA" \
     --send-key 0x61 --repeat 3 --hold 1 > "$SB/client.log" 2>&1; then
  pass "VeNCrypt session completed, certificate verified against our own cert"
else
  fail "the authenticated session failed: $(tail -2 "$SB/client.log")"
fi
sleep 1.5
[ -e "$SB/KEY_ARRIVED" ] \
  && pass "the remote key press reached Sway (full control works)" \
  || fail "a control session did not deliver input to the compositor"

echo "== the wrong password is refused =="
if python3 "$CLIENT" --port "$PORT" --password WRONGWRONGWRONGWRONGWRONG0 --ca "$CA" \
     --expect-auth-failure > "$SB/badpw.log" 2>&1; then
  pass "a bad password is rejected"
else
  fail "bad-password handling is wrong: $(tail -2 "$SB/badpw.log")"
fi

echo "== a view-only session connects but cannot type =="
"$BIN" stop >/dev/null 2>&1
sleep 0.5
"$BIN" start tester --minutes 5 --view-only > "$SB/invite-view.txt" 2>&1 \
  || fail "could not start a view-only session"
grep -q "view-only" "$SB/invite-view.txt" \
  && pass "the invitation tells the recipient it is view-only" \
  || fail "the view-only invitation does not say so"
MODE=$("$BIN" status --json | python3 -c 'import json,sys; print(json.load(sys.stdin).get("mode"))')
[ "$MODE" = "view-only" ] && pass "the daemon reports mode=view-only" \
  || fail "expected mode=view-only, got: $MODE"

VIEW_PASSWORD=$(grep '^Password:' "$SB/invite-view.txt" | awk '{print $2}')
rm -f "$SB/KEY_ARRIVED"
if python3 "$CLIENT" --port "$PORT" --password "$VIEW_PASSWORD" --ca "$CA" \
     --send-key 0x61 --repeat 3 --hold 1 > "$SB/client-view.log" 2>&1; then
  pass "the view-only session still connects and shows the desktop"
else
  fail "the view-only session would not connect: $(tail -2 "$SB/client-view.log")"
fi
sleep 1.5
[ -e "$SB/KEY_ARRIVED" ] \
  && fail "a view-only session delivered a key press to the compositor" \
  || pass "the key press was dropped - view-only really is view-only"

echo "== the interface requirement confines access beyond the CIDR =="
set_interface() {
  python3 - "$XDG_CONFIG_HOME/swayshare/config.toml" "$1" <<'CFG'
import re, sys
path, iface = sys.argv[1], sys.argv[2]
text = open(path).read()
text = re.sub(r'^interface = .*\n', '', text, flags=re.M)
if iface:
    text = text.replace("[network]\n", f'[network]\ninterface = "{iface}"\n', 1)
open(path, "w").write(text)
CFG
}

# Require an interface the loopback peer cannot possibly arrive on. The CIDR
# still matches, so anything that gets through did so on the address alone.
"$BIN" stop >/dev/null 2>&1
set_interface "swayshare-no-such-iface"
"$BIN" start tester --minutes 5 >/dev/null 2>&1 \
  || fail "could not start a session with an interface requirement"
python3 - "$PORT" <<'CHK'
import socket, sys
port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), timeout=5)
s.settimeout(5)
try:
    data = s.recv(12)
    if data == b"":
        print("  PASS: refused despite the CIDR matching")
    else:
        print(f"  FAIL: leaked {data!r} - the interface rule did not hold"); sys.exit(1)
except ConnectionResetError:
    print("  PASS: reset despite the CIDR matching")
except socket.timeout:
    print("  FAIL: hung open instead of being refused"); sys.exit(1)
finally:
    s.close()
CHK
[ $? -eq 0 ] || FAILURES=$((FAILURES + 1))

# Now name the interface the peer really does arrive on; the same CIDR and the
# same client must be let through, proving the refusal above came from the
# interface rule and nothing else.
"$BIN" stop >/dev/null 2>&1
set_interface "lo"
"$BIN" start tester --minutes 5 > "$SB/invite-lo.txt" 2>&1 \
  || fail "could not start a session requiring lo"
LO_PASSWORD=$(grep '^Password:' "$SB/invite-lo.txt" | awk '{print $2}')
if python3 "$CLIENT" --port "$PORT" --password "$LO_PASSWORD" --ca "$CA" \
     --hold 1 > "$SB/client-lo.log" 2>&1; then
  pass "the same peer is admitted once the correct interface is required"
else
  fail "requiring the real interface broke a legitimate session: $(tail -2 "$SB/client-lo.log")"
fi

# Leave the config as the later checks expect it.
set_interface ""

echo "== stop revokes immediately =="
"$BIN" stop >/dev/null
sleep 0.3
[ "$("$BIN" status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])')" = off ] \
  && pass "state is off" || fail "state did not return to off"
python3 - "$PORT" <<'PY'
import socket, sys
port = int(sys.argv[1])
try:
    socket.create_connection(("127.0.0.1", port), timeout=2).close()
    print(f"  FAIL: port {port} still accepts connections after stop"); sys.exit(1)
except OSError:
    print("  PASS: port refused after stop")
PY
[ $? -eq 0 ] || FAILURES=$((FAILURES + 1))

# -x matches the process name only: -f would also match this script's own
# command line, which contains the pattern.
pgrep -x -u "$(id -u)" wayvnc >/dev/null \
  && fail "wayvnc is still running" || pass "wayvnc was terminated"

leftovers=$(ls -A "$XDG_RUNTIME_DIR/swayshare/" | grep -v '^control.sock$' || true)
[ -z "$leftovers" ] && pass "no session credentials left on disk" \
  || fail "leftover files in the runtime dir: $leftovers"

echo
if [ "$FAILURES" -eq 0 ]; then
  echo "all end-to-end checks passed"
else
  echo "$FAILURES end-to-end check(s) failed"
  echo "--- daemon log ---"; cat "$SB/daemon.log"
fi
exit "$FAILURES"
