#!/usr/bin/env bash
# umbra-pt-proxy SOCKS5 integration tests (RFC 1928 front-end).
#
# Hermetic: drives the loopback listener with raw bytes over bash
# /dev/tcp — no external tools, no network. Covers: method negotiation,
# CONNECT reply codes (refused / unsupported command / success-then-
# fail-closed tunnel teardown), the domain address form, and protocol
# garbage.
#
# Usage: tests/socks5.sh [path-to-binary]   (default build/umbra-pt-proxy)

set -u

BIN="${1:-build/umbra-pt-proxy}"
PORT=19470
TARGET=19471
FAIL=0

# The SOCKS5 layer never inspects the cert; any well-formed one does
# (this is the fixtures' cert from tests/vectors_fixtures.h).
DUMMY_CERT="oKGio6SlpqeoqaqrrK2ur7CxsrOIt9D+sdvcnN76KoFFA+4rvlRo4Xo9AGjk+CO/L5TRQg"

cleanup() {
    [ -n "${PROXY_PID:-}" ] && kill "$PROXY_PID" 2>/dev/null
    [ -n "${TARGET_PID:-}" ] && kill "$TARGET_PID" 2>/dev/null
}
trap cleanup EXIT

"$BIN" --socks "127.0.0.1:$PORT" --obfs4-cert "$DUMMY_CERT" 2>/dev/null &
PROXY_PID=$!
# A second instance acts as the "upstream bridge" listener for the
# success-path dial test.
"$BIN" --socks "127.0.0.1:$TARGET" --obfs4-cert "$DUMMY_CERT" 2>/dev/null &
TARGET_PID=$!
sleep 0.4

check() { # name expected actual
    if [ "$2" = "$3" ]; then
        echo "ok - $1"
    else
        echo "FAIL - $1 (want [$2], got [$3])"
        FAIL=1
    fi
}

# hex_dump: read N bytes from fd 3 as a hex string.
hex_dump() { # nbytes
    timeout 3 head -c "$1" <&3 | od -An -v -tx1 | tr -d ' \n'
}

# greet: open a connection and run the method negotiation with the
# given method list; leaves fd 3 open and prints the 2-byte reply.
greet() { # methods_hex
    exec 3<>"/dev/tcp/127.0.0.1/$PORT" || return 1
    printf '%b' "$1" >&3
    hex_dump 2
}

# --- 1. no-auth greeting is accepted ---
OUT=$(greet '\x05\x01\x00'); exec 3<&- 3>&-
check "greeting no-auth" "0500" "$OUT"

# --- 2. a methods list without no-auth is rejected (05 ff) ---
OUT=$(greet '\x05\x01\x02'); exec 3<&- 3>&-
check "greeting without no-auth rejected" "05ff" "$OUT"

# --- 3. CONNECT to a refused port maps to 0x05 ---
exec 3<>"/dev/tcp/127.0.0.1/$PORT"
printf '\x05\x01\x00' >&3
GREET=$(hex_dump 2)
printf '\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x09' >&3
OUT=$(hex_dump 10)
exec 3<&- 3>&-
check "greeting inside connect flow" "0500" "$GREET"
check "connect refused -> 0x05" "05050001000000000000" "$OUT"

# --- 4. BIND is not supported (0x07) ---
exec 3<>"/dev/tcp/127.0.0.1/$PORT"
printf '\x05\x01\x00\x05\x02\x00\x01\x7f\x00\x00\x01\x00\x09' >&3
OUT=$(hex_dump 2; hex_dump 10)
exec 3<&- 3>&-
check "bind -> 0x07" "050005070001000000000000" "$OUT"

# --- 5. CONNECT to a live listener succeeds (0x00); the tunnel then
#        dies fail-closed: the "upstream" is another proxy instance that
#        never speaks obfs4, so the handshake aborts. ---
exec 3<>"/dev/tcp/127.0.0.1/$PORT"
printf '\x05\x01\x00\x05\x01\x00\x01\x7f\x00\x00\x01\x4c\x0f' >&3
OUT=$(hex_dump 2; hex_dump 10)
exec 3<&- 3>&-
check "connect to live upstream -> 0x00" "050005000001000000000000" "$OUT"

# --- 6. DOMAIN address form (localhost:9, refused -> 0x05) ---
exec 3<>"/dev/tcp/127.0.0.1/$PORT"
printf '\x05\x01\x00\x05\x01\x00\x03\x09localhost\x00\x09' >&3
OUT=$(hex_dump 2; hex_dump 10)
exec 3<&- 3>&-
check "domain form refused -> 0x05" "050005050001000000000000" "$OUT"

# --- 7. wrong version byte: connection closed, no reply ---
OUT=$(greet '\x04\x01\x00'); exec 3<&- 3>&-
check "bad version closes silently" "" "$OUT"

if [ "$FAIL" -eq 0 ]; then
    echo "socks5: all tests passed"
else
    echo "socks5: FAILURES" >&2
fi
exit "$FAIL"
