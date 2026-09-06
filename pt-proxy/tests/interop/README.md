# interop-bridge — real lyrebird server for live interop testing

**Dev tooling only. Never built into, linked by, or shipped with any
Umbra or umbra-pt-proxy binary.**

`tests/mockbridge.c` (used by `tests/relay.sh`) is our own C
reimplementation of the obfs4 server side — good for a fast, hermetic,
ASan/UBSan-covered end-to-end test, but a bug shared between it and the
client would go undetected. This program closes that gap: it runs the
actual, unmodified upstream reference server
(`gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird`),
pinned to the **same commit** `tests/govectors/` already uses for the
byte-exact vectors: `fc105a03c0e0acc2479301c361c012ffed359c43`. If that
pin is ever bumped, bump it in both places together.

`lyrebird`'s `obfs4.Transport.ServerFactory` needs only a state
directory and a `pt.Args`; with none of `node-id`/`private-key`/
`drbg-seed` supplied it self-generates a fresh identity and reports the
resulting bridge-line `cert=` value via the factory's `Args()` — no
manual key wiring, no PT-launcher env-var protocol.

## Build

```sh
cd tests/interop
go build -o ../../build/interop-bridge .
```

Requires network access on first build (module fetch); `make
interop-test` from the parent directory does this automatically.

## Run

```sh
./interop-bridge PORT
```

Prints `CERT <base64>` on its first stdout line (same format
`tests/mockbridge.c` uses — same test harness scrapes either one), then
accepts one connection at a time, runs the real obfs4 server handshake
via `WrapConn`, and echoes payloads back.
