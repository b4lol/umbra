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
# SHA-512, CSPRNG and constant-time helpers for src/obfs4.c.
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
SRC     := src/main.c src/socks5.c
OBFS4   := src/obfs4.c
VENDOR  := vendor/monocypher/monocypher.c

.PHONY: all sanitize test vectors clean

all: $(BUILD)/umbra-pt-proxy $(BUILD)/obfs4.o

$(BUILD)/umbra-pt-proxy: $(SRC)
	mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(HARDEN) $(SRC) -o $@ $(LDFLAGS)

# Compile gate for the obfs4 handshake module (full hardening set). It
# is deliberately NOT linked into the proxy binary yet: the relay stays
# disabled until the framing layer lands (roadmap step 4).
$(BUILD)/obfs4.o: $(OBFS4) src/obfs4.h
	mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(HARDEN) $(SODIUM_CFLAGS) -c $(OBFS4) -o $@

$(BUILD)/monocypher.o: $(VENDOR)
	mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(VENDOR_WARN) -fPIE -c $(VENDOR) -o $@

$(BUILD)/monocypher-asan.o: $(VENDOR)
	mkdir -p $(BUILD)
	$(CC) $(VENDOR_WARN) -g -O1 -fsanitize=address,undefined \
	    -fno-omit-frame-pointer -c $(VENDOR) -o $@

# Byte-exact vector tests against the Go reference (tests/govectors/).
$(BUILD)/vectors: tests/vectors.c tests/vectors_fixtures.h $(OBFS4) $(BUILD)/monocypher.o
	mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(HARDEN) $(SODIUM_CFLAGS) tests/vectors.c $(OBFS4) \
	    $(BUILD)/monocypher.o -o $@ $(LDFLAGS) $(SODIUM_LIBS)

# ASan+UBSan gate build: every protocol-parser change MUST pass this
# before merge (ADR-030 audit gate). NOTE: LeakSanitizer needs
# ptrace_scope=0; on hardened kernels run tests with
# LSAN_OPTIONS=detect_leaks=0 (the ASan/UBSan checks still run).
sanitize: $(SRC) $(OBFS4) $(VENDOR) $(BUILD)/monocypher-asan.o
	mkdir -p $(BUILD)
	$(CC) -std=c11 -Wall -Wextra -Werror -Wpedantic -g -O1 \
	    -fsanitize=address,undefined -fno-omit-frame-pointer \
	    $(SRC) -o $(BUILD)/umbra-pt-proxy-asan
	$(CC) -std=c11 -Wall -Wextra -Werror -Wpedantic -g -O1 \
	    -fsanitize=address,undefined -fno-omit-frame-pointer \
	    $(SODIUM_CFLAGS) tests/vectors.c $(OBFS4) \
	    $(BUILD)/monocypher-asan.o -o $(BUILD)/vectors-asan \
	    $(SODIUM_LIBS)

# Protocol integration tests (bash + /dev/tcp; no external tools).
test: $(BUILD)/umbra-pt-proxy
	LSAN_OPTIONS=detect_leaks=0 bash tests/socks5.sh

# Handshake vector tests, normal and ASan/UBSan builds.
vectors: $(BUILD)/vectors sanitize
	LSAN_OPTIONS=detect_leaks=0 $(BUILD)/vectors
	LSAN_OPTIONS=detect_leaks=0 $(BUILD)/vectors-asan

clean:
	rm -rf $(BUILD)
