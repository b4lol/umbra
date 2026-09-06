// Command interop-bridge is TEST-ONLY tooling for umbra-pt-proxy's
// tests/interop.sh (roadmap step 6). It is never built into, linked by,
// or shipped with any Umbra or umbra-pt-proxy binary.
//
// Unlike tests/mockbridge.c — our own C reimplementation of the obfs4
// server side, used by tests/relay.sh — this program runs the actual,
// unmodified upstream reference implementation
// (gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird,
// pinned to the same commit tests/govectors/ already uses for the
// byte-exact vectors: fc105a03c0e0acc2479301c361c012ffed359c43). A bug
// shared between umbra-pt-proxy's client and tests/mockbridge.c would
// not be caught by tests/relay.sh alone; this program closes that gap
// by driving the client against independently-written server code.
//
// lyrebird's obfs4.Transport.ServerFactory needs only a state directory
// and a (possibly empty) pt.Args; with no node-id/private-key/drbg-seed
// supplied it generates a fresh identity itself and reports the
// resulting bridge-line "cert=" argument through the returned
// factory's Args(). That value uses the same standard base64 alphabet
// (padded, trimmed to the unpadded 70-char form by lyrebird itself) as
// obfs4_cert_parse's sodium_base64_VARIANT_ORIGINAL[_NO_PADDING]
// decoding, so no format translation is needed on either side.
package main

import (
	"fmt"
	"io"
	"net"
	"os"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/base"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/obfs4"
)

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "interop-bridge: "+format+"\n", args...)
	os.Exit(1)
}

func handle(sf base.ServerFactory, raw net.Conn) {
	defer raw.Close()

	conn, err := sf.WrapConn(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "interop-bridge: handshake failed: %v\n", err)
		return
	}
	defer conn.Close()

	// Plain echo, exactly like tests/mockbridge.c's echo loop: every
	// payload the (real, unmodified) obfs4 server hands back after
	// unwrapping is written straight back out over the same wrapped
	// connection.
	_, _ = io.Copy(conn, conn)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s PORT\n", os.Args[0])
		os.Exit(2)
	}

	stateDir, err := os.MkdirTemp("", "umbra-interop-lyrebird-")
	if err != nil {
		fatal("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(stateDir)

	var transport obfs4.Transport
	factory, err := transport.ServerFactory(stateDir, &pt.Args{})
	if err != nil {
		fatal("ServerFactory: %v", err)
	}

	cert, ok := factory.Args().Get("cert")
	if !ok {
		fatal("server factory produced no cert= argument")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:"+os.Args[1])
	if err != nil {
		fatal("Listen: %v", err)
	}
	defer ln.Close()

	// tests/relay.sh and tests/interop.sh both scrape this exact line
	// ("CERT <b64>") from the bridge's first line of stdout.
	fmt.Printf("CERT %s\n", cert)
	os.Stdout.Sync()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// One connection at a time is deliberate, mirroring
		// tests/mockbridge.c: the tests only ever open one tunnel at
		// a time, and sequential handling keeps failures unambiguous.
		handle(factory, conn)
	}
}
