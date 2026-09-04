#!/usr/bin/env bash
# umbra-pt-proxy — end-to-end relay test (hermetic, loopback only).
#
#   usage: tests/relay.sh PROXY_BIN MOCKBRIDGE_BIN
#
# Wires a SOCKS5 client (python3, binary-safe) through the proxy into
# the test-only mock obfs4 bridge (tests/mockbridge.c) and asserts echo
# round-trips: sub-frame, multi-packet, and >64 KiB streams, plus the
# fail-closed path against a bridge that closes mid-handshake.

set -euo pipefail

PROXY_BIN=${1:?proxy binary}
MOCK_BIN=${2:?mockbridge binary}

WORKDIR=$(mktemp -d)
MOCK_PORT=$(shuf -i 20000-42000 -n 1)
PROXY_PORT=$(shuf -i 43000-61000 -n 1)
MOCK_PID=""
PROXY_PID=""

cleanup() {
    [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null || true
    [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null || true
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

# --- Mock bridge up; grab its freshly generated cert. -----------------
"$MOCK_BIN" "$MOCK_PORT" > "$WORKDIR/mock.out" 2> "$WORKDIR/mock.err" &
MOCK_PID=$!
CERT=""
for _ in $(seq 1 50); do
    [ -s "$WORKDIR/mock.out" ] && break
    sleep 0.1
done
CERT=$(sed -n 's/^CERT //p' "$WORKDIR/mock.out")
[ -n "$CERT" ] || fail "mockbridge did not print a cert"

# --- Proxy up. ---------------------------------------------------------
"$PROXY_BIN" --socks "127.0.0.1:$PROXY_PORT" --obfs4-cert "$CERT" \
    2> "$WORKDIR/proxy.err" &
PROXY_PID=$!
sleep 0.5
kill -0 "$PROXY_PID" 2>/dev/null || {
    cat "$WORKDIR/proxy.err" >&2
    fail "proxy exited at startup"
}

# --- Echo round-trips through the tunnel. ------------------------------
MOCK_PORT="$MOCK_PORT" PROXY_PORT="$PROXY_PORT" python3 - <<'PYEOF'
import os
import socket
import sys

mock_port = int(os.environ["MOCK_PORT"])
proxy_port = int(os.environ["PROXY_PORT"])


def socks5_connect(port):
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=15)
    s.sendall(b"\x05\x01\x00")
    resp = s.recv(2)
    assert resp == b"\x05\x00", f"method reply: {resp!r}"
    req = (
        b"\x05\x01\x00\x01"
        + socket.inet_aton("127.0.0.1")
        + port.to_bytes(2, "big")
    )
    s.sendall(req)
    resp = s.recv(10)
    assert resp[:2] == b"\x05\x00", f"connect reply: {resp!r}"
    return s


def recv_exact(s, n):
    out = b""
    while len(out) < n:
        chunk = s.recv(n - len(out))
        if not chunk:
            raise AssertionError(f"eof after {len(out)}/{n} bytes")
        out += chunk
    return out


s = socks5_connect(mock_port)

# 1. Sub-frame payload.
p1 = bytes((i * 31) % 256 for i in range(1000))
s.sendall(p1)
assert recv_exact(s, len(p1)) == p1, "echo mismatch (1000 B)"

# 2. Multi-packet payload (> 1427) and obfs4's multi-frame path.
p2 = bytes((i * 7) % 256 for i in range(5000))
s.sendall(p2)
assert recv_exact(s, len(p2)) == p2, "echo mismatch (5000 B)"

# 3. Stream larger than the 64 KiB accumulation comfort zone.
p3 = bytes((i * 13) % 256 for i in range(100_000))
s.sendall(p3)
assert recv_exact(s, len(p3)) == p3, "echo mismatch (100000 B)"

s.close()
print("ok - echo round-trips (1 KB / 5 KB / 100 KB)")
PYEOF

# --- Fail-closed: a bridge that accepts and closes mid-handshake. ------
export WORKDIR
CLOSE_PORT=$(shuf -i 20000-42000 -n 1)
CLOSE_PORT="$CLOSE_PORT" python3 - <<'PYEOF' &
import os
import socket

port = int(os.environ["CLOSE_PORT"])
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(1)
with open(os.environ["WORKDIR"] + "/closer.ready", "w") as f:
    f.write("ready")
conn, _ = srv.accept()
conn.close()  # handshake bytes are never answered
srv.close()
PYEOF
CLOSER_PID=$!
export WORKDIR
for _ in $(seq 1 50); do
    [ -f "$WORKDIR/closer.ready" ] && break
    sleep 0.1
done

CLOSE_PORT="$CLOSE_PORT" PROXY_PORT="$PROXY_PORT" python3 - <<'PYEOF'
import os
import socket

proxy_port = int(os.environ["PROXY_PORT"])
close_port = int(os.environ["CLOSE_PORT"])

s = socket.create_connection(("127.0.0.1", proxy_port), timeout=15)
s.sendall(b"\x05\x01\x00")
assert s.recv(2) == b"\x05\x00"
req = (
    b"\x05\x01\x00\x01"
    + socket.inet_aton("127.0.0.1")
    + close_port.to_bytes(2, "big")
)
s.sendall(req)
resp = s.recv(10)
# The TCP dial succeeded, so 0x00 is legal; the obfs4 handshake must
# then fail closed and the tunnel must die WITHOUT any plaintext relay.
assert resp[:2] == b"\x05\x00", f"connect reply: {resp!r}"
s.sendall(b"must never reach a bridge")
drained = s.recv(64)
assert drained == b"", f"tunnel leaked plaintext: {drained!r}"
s.close()
print("ok - bridge close mid-handshake fails closed")
PYEOF
wait "$CLOSER_PID" 2>/dev/null || true

# --- Both sides still healthy after the chaos. --------------------------
kill -0 "$PROXY_PID" 2>/dev/null || fail "proxy died during the tests"
kill -0 "$MOCK_PID" 2>/dev/null || fail "mockbridge died during the tests"

echo "relay: all tests passed"
