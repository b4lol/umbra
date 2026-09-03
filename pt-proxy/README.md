# umbra-pt-proxy — Standalone Pluggable Transport Proxy (Skeleton)

> **Status: SKELETON — NOT FUNCTIONAL.** The listener, argument handling
> and hardening scaffolding are in place; the obfs4 protocol itself is
> NOT implemented. Do not deploy.

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

```sh
make            # hardened release build into build/umbra-pt-proxy
make sanitize   # ASan+UBSan build into build/umbra-pt-proxy-asan
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
3. [ ] obfs4 handshake: X25519 + Elligator 2 representative, ntor
       variant per the obfs4 spec — requires a constant-time field
       arithmetic audit BEFORE first use.
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
