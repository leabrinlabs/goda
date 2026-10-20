PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk
VERSION := 0.6.13
HOST_CC ?= cc
PYTHON ?= python3
GEN := build/generated

# Host-only development and source checks do not require the console SDK.
NATIVE_GOALS := $(if $(MAKECMDGOALS),$(filter-out host test check-source clean,$(MAKECMDGOALS)),all)
ifneq ($(strip $(NATIVE_GOALS)),)
include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
endif

CPPFLAGS := -I. -Isrc -I$(GEN) -Ivendor/shadowmount/include -Ivendor/zlib -DZ_SOLO
CFLAGS := -O2 -std=gnu11 -Wall -Wextra -Werror
COMMON := src/main.c src/catalog.c src/engine.c src/lifecycle.c src/browser.c src/audit.c \
          src/module_alias.c src/extractor.c src/extract_reader.c \
          vendor/pkg.c vendor/crypto.c vendor/zlib/zutil.c vendor/zlib/inflate.c \
          vendor/zlib/inftrees.c vendor/zlib/inffast.c vendor/zlib/adler32.c vendor/zlib/crc32.c
HOOKS := vendor/shadowmount/src/sm_shellcore_hooks.c vendor/shadowmount/src/sm_shellcore_remote.c \
         vendor/shadowmount/src/sm_shellcore_offsets.c
LAUNCH := src/registration.c src/registration_bridge.S src/launch_gate.c src/runtime_hooks.c src/runtime_bridge.S $(HOOKS)
SHORTCUT := src/shortcut/register.c src/shortcut/panel_bridge.S $(HOOKS)
HEADERS := $(wildcard src/*.h src/shortcut/*.h vendor/*.h vendor/zlib/*.h vendor/shadowmount/include/*.h)
# Wrapper sources include the upstream bridge and offset table directly.
HOOK_INPUTS := vendor/shadowmount/src/sm_shellcore_bridge.S vendor/shadowmount/src/sm_shellcore_offsets.inc
LIBS := -lkernel_sys -lSceSystemService -lSceUserService -lpthread
NATIVE_FLAGS := -DD3TR_REGISTRAR -ffunction-sections -fdata-sections -Wl,--gc-sections

.PHONY: all candidate host panel links copy-fallback test check-source clean
all: candidate
candidate: dist/goda-v$(VERSION).elf
links: candidate
panel: dist/goda-shortcut.elf
copy-fallback: dist/goda-v$(VERSION)-copy.elf
host: dist/loader-host

$(GEN)/ui.h: web/ui.html tools/embed_ui.py
	$(PYTHON) tools/embed_ui.py
$(GEN)/assets.h: assets/brand-compact.png assets/brand-face.png assets/selection.png assets/launch.png tools/embed_assets.py
	$(PYTHON) tools/embed_assets.py
$(GEN)/icon.h: assets/icon0.png tools/embed_icon.py
	$(PYTHON) tools/embed_icon.py

dist/goda-v$(VERSION).elf: $(COMMON) $(LAUNCH) $(HEADERS) $(HOOK_INPUTS) $(GEN)/ui.h $(GEN)/assets.h Makefile
	mkdir -p dist
	$(CC) $(CPPFLAGS) $(CFLAGS) $(NATIVE_FLAGS) -DFL_LINK_VIEWS -o $@ $(COMMON) $(LAUNCH) $(LIBS)
dist/goda-v$(VERSION)-copy.elf: $(COMMON) $(LAUNCH) $(HEADERS) $(HOOK_INPUTS) $(GEN)/ui.h $(GEN)/assets.h Makefile
	mkdir -p dist
	$(CC) $(CPPFLAGS) $(CFLAGS) $(NATIVE_FLAGS) -o $@ $(COMMON) $(LAUNCH) $(LIBS)
dist/goda-shortcut.elf: $(SHORTCUT) $(HEADERS) $(HOOK_INPUTS) $(GEN)/icon.h Makefile
	mkdir -p dist
	$(CC) $(CPPFLAGS) $(CFLAGS) $(NATIVE_FLAGS) -o $@ $(SHORTCUT) $(LIBS)
dist/loader-host: $(COMMON) $(HEADERS) $(GEN)/ui.h $(GEN)/assets.h Makefile
	mkdir -p dist
	$(HOST_CC) $(CPPFLAGS) -DFL_HOST -O1 -g -Wall -Wextra -Werror -o $@ $(COMMON) -lpthread

# Uses synthetic fixtures only. Stop an existing local preview on port 9134 first.
test: host
	$(PYTHON) tools/run_tests.py
check-source:
	$(PYTHON) tools/check_public_source.py
# Keep versioned artifacts and private captures under dist/ intact.
clean:
	rm -rf build/generated
