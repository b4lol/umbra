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

BUILD   := build
SRC     := src/main.c

.PHONY: all sanitize clean

all: $(BUILD)/umbra-pt-proxy

$(BUILD)/umbra-pt-proxy: $(SRC)
	mkdir -p $(BUILD)
	$(CC) $(CFLAGS) $(HARDEN) $(SRC) -o $@ $(LDFLAGS)

# ASan+UBSan gate build: every protocol-parser change MUST pass this
# before merge (ADR-030 audit gate).
sanitize: $(SRC)
	mkdir -p $(BUILD)
	$(CC) -std=c11 -Wall -Wextra -Werror -Wpedantic -g -O1 \
	    -fsanitize=address,undefined -fno-omit-frame-pointer \
	    $(SRC) -o $(BUILD)/umbra-pt-proxy-asan

clean:
	rm -rf $(BUILD)
