#!/usr/bin/env bash
# umbra-pt-proxy — live interop test against the REAL reference
# implementation (roadmap step 6), not our own tests/mockbridge.c.
#
#   usage: tests/interop.sh PROXY_BIN INTEROP_BRIDGE_BIN
#
# tests/interop/ builds and drives the actual, unmodified upstream
# lyrebird obfs4 server (gitlab.torproject.org/tpo/anti-censorship/
# pluggable-transports/lyrebird, pinned to the same commit
# tests/govectors/ uses for the byte-exact vectors). This closes the
# one gap tests/relay.sh can't: a bug shared between our client and our
# own C mock bridge would pass relay.sh but fail here.
#
# Structure mirrors tests/relay.sh (the bridge prints "CERT <b64>" on
# its first stdout line; same SOCKS5 client, same echo payloads) but
# only exercises the three iat-modes — the mid-handshake-close
# fail-closed path is already covered by relay.sh and doesn't depend on
# which bridge implementation answers.

set -euo pipefail

PROXY_BIN=${1:?proxy binary}
BRIDGE_BIN=${2:?interop-bridge binary}

WORKDIR=$(mktemp -d)
BRIDGE_PORT=$(shuf -i 20000-42000 -n 1)
PROXY_PID=""

cleanup() {
    [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null || true
    [ -n "${BRIDGE_PID:-}" ] && kill "$BRIDGE_PID" 2>/dev/null || true
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

# --- Real lyrebird server up; grab its freshly generated cert. ---------
"$BRIDGE_BIN" "$BRIDGE_PORT" > "$WORKDIR/bridge.out" 2> "$WORKDIR/bridge.err" &
BRIDGE_PID=$!
for _ in $(seq 1 50); do
    [ -s "$WORKDIR/bridge.out" ] && break
    sleep 0.1
done
CERT=$(sed -n 's/^CERT //p' "$WORKDIR/bridge.out")
[ -n "$CERT" ] || {
    cat "$WORKDIR/bridge.err" >&2
    fail "interop-bridge did not print a cert"
}

# --- Echo round-trips through the tunnel, per iat-mode. ----------------
run_echo() { # iat_mode
    local mode=$1
    local port
    port=$(shuf -i 43000-61000 -n 1)

    "$PROXY_BIN" --socks "127.0.0.1:$port" --obfs4-cert "$CERT" \
        --iat-mode "$mode" 2> "$WORKDIR/proxy.$mode.err" &
    PROXY_PID=$!
    sleep 0.5
    kill -0 "$PROXY_PID" 2>/dev/null || {
        cat "$WORKDIR/proxy.$mode.err" >&2
        fail "proxy exited at startup (iat-mode $mode)"
    }

    BRIDGE_PORT="$BRIDGE_PORT" PROXY_PORT="$port" python3 - <<'PYEOF'
import os
import socket

bridge_port = int(os.environ["BRIDGE_PORT"])
proxy_port = int(os.environ["PROXY_PORT"])


def socks5_connect(port):
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=30)
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


s = socks5_connect(bridge_port)

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
PYEOF

    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
    PROXY_PID=""
    echo "ok - echo round-trips (1 KB / 5 KB / 100 KB) against the REAL lyrebird, iat-mode $mode"
}

run_echo 0
run_echo 1
run_echo 2

kill -0 "$BRIDGE_PID" 2>/dev/null || fail "interop-bridge died during the tests"

echo "interop: all tests passed against the reference (Go) lyrebird implementation"
