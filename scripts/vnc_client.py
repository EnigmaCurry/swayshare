#!/usr/bin/env python3
"""A minimal VeNCrypt VNC client, for testing swayshare end to end.

Existing command-line viewers want a display and cannot take a VeNCrypt
password non-interactively, which makes them awkward to drive from a test.
This speaks just enough of RFB 3.8 + VeNCrypt X509Plain to authenticate for
real, optionally verify the server certificate, and send input events.

It is a test tool, not a viewer: it never decodes a framebuffer.

Exit status is 0 on success and non-zero on any failure, so a shell test can
simply check it.
"""

import argparse
import socket
import ssl
import struct
import sys
import time

# VeNCrypt sub-types we understand, most preferred first.
X509_PLAIN = 262
TLS_PLAIN = 259
VENCRYPT = 19


def fail(message):
    print(f"vnc_client: {message}", file=sys.stderr)
    sys.exit(1)


def recv_exact(sock, n):
    """Read exactly n bytes or die; short reads here are always a bug."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            fail(f"connection closed after {len(buf)} of {n} expected bytes")
        buf += chunk
    return buf


def handshake(sock, username, password, ca_file, verbose, server_name=None):
    def log(msg):
        if verbose:
            print(f"  {msg}")

    banner = recv_exact(sock, 12)
    if not banner.startswith(b"RFB "):
        fail(f"not an RFB server, got {banner!r}")
    log(f"server banner: {banner.decode().strip()}")
    sock.sendall(b"RFB 003.008\n")

    count = recv_exact(sock, 1)[0]
    if count == 0:
        reason_len = struct.unpack(">I", recv_exact(sock, 4))[0]
        fail(f"server refused: {recv_exact(sock, reason_len).decode(errors='replace')}")
    types = list(recv_exact(sock, count))
    log(f"security types offered: {types}")
    if 1 in types:
        fail("server offers 'None' security - authentication is not enforced")
    if VENCRYPT not in types:
        fail(f"server does not offer VeNCrypt, only {types}")

    sock.sendall(bytes([VENCRYPT]))

    major, minor = recv_exact(sock, 2)
    log(f"VeNCrypt version {major}.{minor}")
    if (major, minor) < (0, 2):
        fail(f"unsupported VeNCrypt version {major}.{minor}")
    sock.sendall(bytes([0, 2]))
    if recv_exact(sock, 1)[0] != 0:
        fail("server rejected VeNCrypt 0.2")

    n_subtypes = recv_exact(sock, 1)[0]
    subtypes = list(struct.unpack(f">{n_subtypes}I", recv_exact(sock, 4 * n_subtypes)))
    log(f"VeNCrypt sub-types: {subtypes}")

    chosen = next((s for s in (X509_PLAIN, TLS_PLAIN) if s in subtypes), None)
    if chosen is None:
        fail(f"no supported VeNCrypt sub-type in {subtypes}")
    log(f"choosing sub-type {chosen}")
    sock.sendall(struct.pack(">I", chosen))

    if recv_exact(sock, 1)[0] == 0:
        fail("server refused the chosen VeNCrypt sub-type")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    verify_name = None
    if ca_file and chosen == X509_PLAIN:
        # Verifying against swayshare's stored certificate proves the identity
        # it advertises in the invitation is the one actually presented.
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=ca_file)
        log(f"verifying the server certificate against {ca_file}")
        if server_name:
            # A real viewer also checks that the certificate *names* the
            # address it dialled; wlvncc and gtk-vnc both refuse outright when
            # it does not. Invitations only ever carry a bare IP, so this is
            # what holds swayshare to issuing an IP SAN for the bound address.
            context.check_hostname = True
            verify_name = server_name
            log(f"requiring the certificate to name {server_name}")
    else:
        context.verify_mode = ssl.CERT_NONE
        if chosen == TLS_PLAIN:
            # Anonymous TLS has no certificate to check.
            context.set_ciphers("ALL:@SECLEVEL=0")
    try:
        tls = context.wrap_socket(sock, server_hostname=verify_name)
    except ssl.SSLError as e:
        fail(f"TLS handshake failed: {e}")
    log(f"TLS established: {tls.version()}")

    user = username.encode()
    pw = password.encode()
    tls.sendall(struct.pack(">II", len(user), len(pw)) + user + pw)

    result = struct.unpack(">I", recv_exact(tls, 4))[0]
    if result != 0:
        reason = ""
        try:
            reason_len = struct.unpack(">I", recv_exact(tls, 4))[0]
            reason = recv_exact(tls, reason_len).decode(errors="replace")
        except SystemExit:
            pass
        fail(f"authentication rejected (result {result}) {reason}")
    log("authenticated")

    tls.sendall(bytes([1]))  # ClientInit, shared
    init = recv_exact(tls, 24)
    width, height = struct.unpack(">HH", init[:4])
    name_len = struct.unpack(">I", init[20:24])[0]
    name = recv_exact(tls, name_len).decode(errors="replace")
    log(f"desktop {name!r} {width}x{height}")
    return tls


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--username", default="support")
    ap.add_argument("--password", required=True)
    ap.add_argument("--ca", help="PEM file to verify the server certificate against")
    ap.add_argument("--check-hostname", action="store_true",
                    help="also require the certificate to name --host, as real viewers do")
    ap.add_argument("--source", help="bind this source address before connecting")
    ap.add_argument("--send-key", type=lambda v: int(v, 0), default=None,
                    help="X11 keysym to press and release, e.g. 0x61 for 'a'")
    ap.add_argument("--repeat", type=int, default=1, help="how many times to send it")
    ap.add_argument("--hold", type=float, default=0.0,
                    help="seconds to stay connected afterwards")
    ap.add_argument("--expect-auth-failure", action="store_true",
                    help="succeed only if authentication is rejected")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if args.expect_auth_failure:
        # Run the handshake in a child so its fail() exit can be inspected.
        import subprocess
        argv = [sys.executable, __file__, "--host", args.host, "--port", str(args.port),
                "--username", args.username, "--password", args.password]
        if args.ca:
            argv += ["--ca", args.ca]
        if args.check_hostname:
            argv += ["--check-hostname"]
        proc = subprocess.run(argv, capture_output=True, text=True)
        if proc.returncode == 0:
            fail("authentication succeeded but should have been rejected")
        if "authentication rejected" not in proc.stderr:
            fail(f"failed for the wrong reason: {proc.stderr.strip()}")
        print("  rejected as expected")
        return

    sock = socket.socket()
    if args.source:
        sock.bind((args.source, 0))
    sock.settimeout(15)
    try:
        sock.connect((args.host, args.port))
    except OSError as e:
        fail(f"could not connect to {args.host}:{args.port}: {e}")

    tls = handshake(sock, args.username, args.password, args.ca, args.verbose,
                    args.host if args.check_hostname else None)

    if args.send_key is not None:
        for _ in range(args.repeat):
            tls.sendall(struct.pack(">BBHI", 4, 1, 0, args.send_key))  # down
            tls.sendall(struct.pack(">BBHI", 4, 0, 0, args.send_key))  # up
            time.sleep(0.2)
        print(f"  sent keysym {args.send_key:#x} x{args.repeat}")

    if args.hold:
        time.sleep(args.hold)
    tls.close()
    print("  session completed")


if __name__ == "__main__":
    main()
