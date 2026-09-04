# umbra-pt-proxy build — hardening flags are mandatory (ADR-030 gate):
# any weakening of CFLAGS/LDFLAGS must come with a DECISIONS.md entry.

CC      ?= cc
CFLAGS  ?= -O2
# Baseline warnings-as-errors + exploit mitigations. _FORTIFY_SOURCE=3
# needs optimization on; the ASan build drops it (incompatible).
HARDEN  := -std=c11 -Wall -Wextra -Werror -Wpedantic -Wconversion \
           -fstack-protector-strong -fstack-clash-protection \
           -fno-strict-aliasing -fPIE -D_FORTIFY_SOURCE=3
LDFLAGS += -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack

# libsodium (system package) provides X25519, HMAC-SHA256, HKDF-SHA256,
# SHA-512, XSalsa20-Poly1305, CSPRNG and constant-time helpers.
SODIUM_CFLAGS := $(shell pkg-config --cflags libsodium)
SODIUM_LIBS   := $(shell pkg-config --libs libsodium)

# Vendored Monocypher (vendor/monocypher/, see README for version/hash)
# is upstream-audited constant-time code used ONLY for Elligator 2. It
# is built with a RELAXED warning set (no -Wconversion/-Werror): our
# warning dialect is not portable to upstream code, and modifying the
# vendored files would defeat the audit trail. Hardening mitigations
# (stack protector, PIE, sanitizer instrumentation) still apply.
VENDOR_WARN := -std=c11

BUILD   := build
# The obfs4 modules are linked into the proxy: the relay is live.
SRC     := src/main.c src/socks5.c src/relay.c src/obfs4.c \
           src/obfs4_frame.c src/obfs4_packet.c src/siphash24.c
HEADERS := src/obfs4.h src/obfs4_frame.h src/obfs4_packet.h \
           src/siphash24.h src/relay.h src/socks5.h
# Protocol modules reused by the test binaries (no main/socks5/relay).
PROTO   := src/obfs4.c src/obfs4_frame.c src/obfs4_packet.c \
           src/siphash24.c
VENDOR  := vendor/monocypher/monocypher.c

.PHONY: all sanitize test vectors relay-test clean

all: $(BUILD)/umbra-pt-proxy

$(BUILD)/umbra-pt-proxy: $(SRC) $(HEADERS) $(BUILD)/monocypher.o
	mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(HARDEN) $(SODIUM_CFLAGS) $(SRC) \
	    $(BUILD)/monocypher.o -o $@ $(LDFLAGS) $(SODIUM_LIBS)

$(BUILD)/monocypher.o: $(VENDOR)
	mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(VENDOR_WARN) -fPIE -c $(VENDOR) -o $@

$(BUILD)/monocypher-asan.o: $(VENDOR)
	mkdir -p $(BUILD)
	$(CC) $(VENDOR_WARN) -g -O1 -fsanitize=address,undefined \
	    -fno-omit-frame-pointer -c $(VENDOR) -o $@

# Byte-exact vector tests against the Go reference (tests/govectors/).
$(BUILD)/vectors: tests/vectors.c tests/vectors_fixtures.h $(PROTO) $(HEADERS) $(BUILD)/monocypher.o
	mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(HARDEN) $(SODIUM_CFLAGS) tests/vectors.c $(PROTO) \
	    $(BUILD)/monocypher.o -o $@ $(LDFLAGS) $(SODIUM_LIBS)

# Test-only mock obfs4 bridge (server side) for the relay test. NEVER
# installed; CI/dev tooling only.
$(BUILD)/mockbridge: tests/mockbridge.c $(PROTO) $(HEADERS) $(BUILD)/monocypher.o
	mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(HARDEN) $(SODIUM_CFLAGS) tests/mockbridge.c $(PROTO) \
	    $(BUILD)/monocypher.o -o $@ $(LDFLAGS) $(SODIUM_LIBS)

# ASan+UBSan gate build: every protocol-parser change MUST pass this
# before merge (ADR-030 audit gate). NOTE: LeakSanitizer needs
# ptrace_scope=0; on hardened kernels run tests with
# LSAN_OPTIONS=detect_leaks=0 (the ASan/UBSan checks still run).
sanitize: $(SRC) $(HEADERS) $(VENDOR) $(BUILD)/monocypher-asan.o
	mkdir -p $(BUILD)
	$(CC) -std=c11 -Wall -Wextra -Werror -Wpedantic -g -O1 \
	    -fsanitize=address,undefined -fno-omit-frame-pointer \
	    $(SODIUM_CFLAGS) $(SRC) $(BUILD)/monocypher-asan.o \
	    -o $(BUILD)/umbra-pt-proxy-asan $(SODIUM_LIBS)
	$(CC) -std=c11 -Wall -Wextra -Werror -Wpedantic -g -O1 \
	    -fsanitize=address,undefined -fno-omit-frame-pointer \
	    $(SODIUM_CFLAGS) tests/vectors.c $(PROTO) \
	    $(BUILD)/monocypher-asan.o -o $(BUILD)/vectors-asan \
	    $(SODIUM_LIBS)
	$(CC) -std=c11 -Wall -Wextra -Werror -Wpedantic -g -O1 \
	    -fsanitize=address,undefined -fno-omit-frame-pointer \
	    $(SODIUM_CFLAGS) tests/mockbridge.c $(PROTO) \
	    $(BUILD)/monocypher-asan.o -o $(BUILD)/mockbridge-asan \
	    $(SODIUM_LIBS)

# Protocol integration tests (bash + /dev/tcp; no external tools).
test: $(BUILD)/umbra-pt-proxy
	LSAN_OPTIONS=detect_leaks=0 bash tests/socks5.sh

# Handshake/framing vector tests, normal and ASan/UBSan builds.
vectors: $(BUILD)/vectors sanitize
	LSAN_OPTIONS=detect_leaks=0 $(BUILD)/vectors
	LSAN_OPTIONS=detect_leaks=0 $(BUILD)/vectors-asan

# End-to-end relay test: proxy <-> mock obfs4 bridge (test-only server),
# SOCKS5-driven, echo round-trips. Runs against the normal AND the
# ASan/UBSan builds of both binaries.
relay-test: $(BUILD)/umbra-pt-proxy $(BUILD)/mockbridge sanitize
	LSAN_OPTIONS=detect_leaks=0 bash tests/relay.sh \
	    $(BUILD)/umbra-pt-proxy $(BUILD)/mockbridge
	LSAN_OPTIONS=detect_leaks=0 bash tests/relay.sh \
	    $(BUILD)/umbra-pt-proxy-asan $(BUILD)/mockbridge-asan

clean:
	rm -rf $(BUILD)
