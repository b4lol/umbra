# umbra-pt-proxy — Standalone Pluggable Transport Proxy

> **Status: PARTIAL — NOT FUNCTIONAL.** The listener, SOCKS5 front-end
> and the obfs4 ntor/Elligator handshake are in place and verified
> byte-exact against the Go reference; the framing layer (roadmap step
> 4) is NOT implemented, so no real traffic can flow yet. Do not deploy.

A standalone, OS-managed pluggable-transport client proxy for Umbra's
censorship-circumvention path (TODO B.1, **ADR-030**). It runs as a
separate process and exposes a **loopback-only SOCKS5 endpoint**; Umbra
(`umbra serve` / `send --onion` / `tui` with `--pt-socks`) connects to
that endpoint through arti's unmanaged-transport support. Umbra never
spawns, links, or loads this binary.

## Why C here? (the ADR-030 scoped exception)

Umbra's language policy (ADR-011) bans C/C++ from the project. ADR-030
records a scoped, owner-granted exception for THIS component only,
because no maintained pure-Rust PT client library exists (the Rust
`obfs4` crate is unaudited 0.1.x; reference PT implementations are Go,
also banned in-process). The exception buys nothing for free — it moves
the risk into a component that is:

1. **Process-isolated**: a memory fault here can never corrupt an Umbra
   process; the only shared surface is a loopback SOCKS5 socket.
2. **Loopback-bound**: the listener refuses to bind anything but
   `127.0.0.1`/`::1`, enforced in code before any socket call.
3. **Separately gated**: builds with `-Wall -Wextra -Werror` plus the
   full hardening flag set, and MUST pass ASan/UBSan test runs before
   any "functional" claim is made (see Roadmap).

## Build

Dependencies: a C11 compiler, `make`, and the system **libsodium**
development package (`libsodium-devel` / `libsodium-dev`; X25519,
HMAC-SHA256, HKDF-SHA256, CSPRNG). **Monocypher 4.0.3** (Elligator 2
only) is vendored under `vendor/monocypher/` — tarball SHA-256
`8cc9bc341a66249016db9bd70e9142d8d0aef9945973744b1ac05dbc55d8ee66`,
upstream SHA-512 verified at import time. Vendored files are built
with a relaxed warning set (documented in the Makefile); the hardening
mitigations still apply.

```sh
make            # hardened release build into build/umbra-pt-proxy
make sanitize   # ASan+UBSan builds (proxy + vector tests)
make test       # SOCKS5 integration tests
make vectors    # obfs4 handshake vector tests (normal + ASan builds)
make clean
```

## Roadmap (each step gated on the previous one)

1. [x] Skeleton: loopback-only SOCKS5 listener, hardening flags,
       hygiene rules (explicit_bzero on teardown paths).
2. [x] SOCKS5 CONNECT handshake (RFC 1928, no-auth only, loopback
       peers) with exact reply codes, bounded parsing, I/O deadlines,
       and a deadline-guarded non-blocking upstream dial — integration
       tested (`make test`, also under ASan/UBSan). The data relay is
       deliberately DISABLED until obfs4 lands: a successful dial is
       answered and immediately torn down with a stderr diagnostic.
3. [x] obfs4 handshake: X25519 + Elligator 2 representative, ntor
       variant — implemented per the Go reference (lyrebird), which is
       the deployed wire definition, and verified BYTE-EXACT against
       fixtures dumped from it (`make vectors`, also under ASan/UBSan;
       see `tests/govectors/`). Scope note: the module is compiled and
       tested but NOT yet wired into the connection path — the relay
       stays disabled until step 4 lands. Constant-time properties come
       from libsodium + Monocypher (audited upstreams); the glue code
       here performs no secret-dependent branching beyond the reference
       implementation's own mark scan.
4. [ ] obfs4 framing (length-obfuscated frames, NaCl-secretbox
       equivalent — primitive choice must be re-reviewed then).
5. [ ] iat-mode timing obfuscation.
6. [ ] Interop tests against the reference (Go) lyrebird, ASan/UBSan
       clean, fuzz harness for the handshake parser.

## Non-goals

- No Snowflake (no viable C/Rust client stack; documented in ADR-030).
- No server/bridge side — client proxy only.
- Never linked into or spawned by an Umbra binary; distribution and
  lifecycle are the operator's responsibility.
